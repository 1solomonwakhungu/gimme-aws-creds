"""
Debug formatting utilities for gimme-aws-creds.

``--debug`` output is rendered deny-by-default against explicit schemas.
A value is shown only when its field is known *and* the value has that
field's expected type: an enumerated status, factor type or OAuth error, a
bounded number, a fixed-format identifier such as an Okta error code or a
role ARN, or a URL rebuilt from known path segments. A field name alone never
makes a value displayable. Free text (error descriptions, messages,
summaries), unknown fields and the contents of unknown containers are never
printed, and every other value is replaced with ``[REDACTED]`` in full.

Log records are rendered under the same policy. While debug logging is
active a log-record factory replaces every record's message before any
handler sees it:

* text produced by this module's renderers is passed through;
* records from ``gimme_aws_creds`` loggers keep their (code-constant) format
  string, with only numbers, booleans and ``None`` interpolated;
* a short registry of known urllib3 and botocore events is re-rendered from
  their typed arguments, with URLs rebuilt from known path segments;
* every other record, from any library, is reduced to its logger name and
  level.

Exceptions attached to records are reduced to their type and the
traceback's file/line/function frames. Exception messages and source lines
are never printed.
"""
import http
import json
import logging
import re
import sys
import traceback
from collections.abc import Mapping
from urllib.parse import parse_qsl, quote, unquote, urlsplit

logger = logging.getLogger(__name__)

REDACTED = '[REDACTED]'
# Placeholder for a URL path segment that is not a known literal segment.
UNKNOWN_SEGMENT = '[id]'


class SanitizedText(str):
    """Text already rendered deny-by-default by this module.

    A log record whose message is a SanitizedText (with no arguments) is
    shown as is. Any other message goes through the record policy described
    in the module docstring.
    """


# Limits for rendered structures.
_MAX_DEPTH = 8
_MAX_ITEMS = 100
_MAX_PAIRS = 50


def _normalize_name(name):
    """Lower-case a field name and drop separators, so variants compare equal."""
    return re.sub(r'[^a-z0-9]', '', str(name).lower())


# --------------------------------------------------------------------------
# Value types
#
# Each checker returns the value to display, or _INVALID when the value does
# not have the expected type. _INVALID is rendered as [REDACTED].
# --------------------------------------------------------------------------

_INVALID = object()


def _enum(*values):
    allowed = frozenset(values)

    def check(value):
        return value if isinstance(value, str) and value in allowed else _INVALID
    return check


def _bounded_int(low, high):
    def check(value):
        if isinstance(value, bool):
            return _INVALID
        if isinstance(value, int):
            number = value
        elif isinstance(value, str) and re.fullmatch(r'[0-9]{1,12}', value):
            number = int(value)
        else:
            return _INVALID
        return value if low <= number <= high else _INVALID
    return check


def _pattern(regex):
    compiled = re.compile(regex)

    def check(value):
        return value if isinstance(value, str) and compiled.fullmatch(value) else _INVALID
    return check


def _boolean(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ('true', 'false'):
        return value
    return _INVALID


def _hidden(value):
    """Known field whose value is never shown (credentials, free text, PII)."""
    return _INVALID


_OAUTH_SCOPES = frozenset((
    'openid', 'profile', 'email', 'address', 'phone', 'offline_access',
    'groups', 'device_sso', 'okta.apps.sso', 'okta.apps.read',
    'okta.users.read.self', 'okta.myAccount.read', 'interclient_access',
))


def _scope(value):
    if not isinstance(value, str):
        return _INVALID
    parts = value.split(' ')
    if not 1 <= len(parts) <= 16 or any(part not in _OAUTH_SCOPES for part in parts):
        return _INVALID
    return value


def _url(value):
    return _sanitize_url(value) if isinstance(value, str) else _INVALID


_AUTHN_STATUS = _enum(
    'SUCCESS', 'MFA_REQUIRED', 'MFA_CHALLENGE', 'MFA_ENROLL',
    'MFA_ENROLL_ACTIVATE', 'PASSWORD_WARN', 'PASSWORD_EXPIRED',
    'PASSWORD_RESET', 'RECOVERY', 'RECOVERY_CHALLENGE', 'LOCKED_OUT',
    'UNAUTHENTICATED', 'ACTIVE', 'INACTIVE', 'PENDING_ACTIVATION',
    'NOT_SETUP', 'ENROLLED', 'EXPIRED', 'WAITING', 'SUSPENDED',
    'DEPROVISIONED',
)
_FACTOR_RESULT = _enum(
    'SUCCESS', 'WAITING', 'TIMEOUT', 'REJECTED', 'CANCELLED', 'CHALLENGE',
    'ERROR', 'FAILED', 'PASSCODE_REPLAYED', 'TIME_WINDOW_EXCEEDED',
)
_FACTOR_TYPES = (
    'push', 'sms', 'call', 'email', 'question', 'token',
    'token:software:totp', 'token:hardware', 'token:hotp', 'web',
    'webauthn', 'u2f', 'signed_nonce', 'claims_provider', 'password',
)
_FACTOR_TYPE = _enum(*_FACTOR_TYPES)
_PROVIDERS = ('OKTA', 'GOOGLE', 'RSA', 'SYMANTEC', 'YUBICO', 'DUO', 'FIDO', 'CUSTOM')
_PROVIDER = _enum(*_PROVIDERS)
_OAUTH_ERROR = _enum(
    'invalid_request', 'invalid_client', 'invalid_grant',
    'unauthorized_client', 'unsupported_grant_type', 'invalid_scope',
    'authorization_pending', 'slow_down', 'access_denied', 'expired_token',
    'invalid_token', 'insufficient_scope', 'server_error',
    'temporarily_unavailable', 'login_required', 'consent_required',
    'interaction_required', 'invalid_dpop_proof', 'use_dpop_nonce',
)
_TOKEN_TYPE_URNS = (
    'urn:ietf:params:oauth:token-type:access_token',
    'urn:ietf:params:oauth:token-type:id_token',
    'urn:ietf:params:oauth:token-type:refresh_token',
    'urn:ietf:params:oauth:token-type:saml2',
    'urn:ietf:params:oauth:token-type:jwt',
    'urn:okta:oauth:token-type:web_sso_token',
)
_GRANT_TYPE = _enum(
    'authorization_code', 'refresh_token', 'client_credentials', 'password',
    'urn:ietf:params:oauth:grant-type:device_code',
    'urn:ietf:params:oauth:grant-type:token-exchange',
    'urn:ietf:params:oauth:grant-type:saml2-bearer',
    'urn:ietf:params:oauth:grant-type:jwt-bearer',
)
_ISO_TIMESTAMP = _pattern(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})')
_ROLE_ARN = (r'(arn:aws(-[a-z]+)*:iam::\d{12}:(role|saml-provider)/[\w+=,.@/-]{1,512}'
             r'|acs:ram::\d{1,20}:(role|saml-provider)/[\w+=,.@/-]{1,512})')
_OKTA_CLIENT_ID = _pattern(r'0oa[0-9A-Za-z]{17}')

# Object containers whose children are rendered with the same field schema.
_OBJECT = 'object'
_OBJECT_LIST = 'object_list'

# Field schema shared by JSON bodies, form bodies and query strings. Keys are
# normalized names; values are (display name, value type). Fields that are
# not listed are never shown, not even their names.
_FIELDS = {}


def _define(spec, *names):
    for name in names:
        _FIELDS[_normalize_name(name)] = (name, spec)


_define(_hidden,
        # Credentials, codes and session state
        'password', 'passCode', 'answer', 'sessionToken', 'stateToken',
        'device_code', 'user_code', 'access_token', 'id_token',
        'refresh_token', 'actor_token', 'subject_token', 'token',
        'SAMLResponse', 'SAMLAssertion', 'RelayState', '_xsrfToken', 'code',
        'otp', 'mfa_code', 'client_secret', 'client_assertion',
        'code_verifier', 'code_challenge', 'nonce', 'state', 'sid',
        'deviceToken', 'clientData', 'authenticatorData', 'signatureData',
        'attestation', 'credentials', 'verification_uri_complete',
        # Redirect targets can carry tokens
        'fromURI', 'redirect_uri', 'href', 'redirectUrl',
        # Free text and identities
        'errorSummary', 'error_description', 'message', 'errorCauses',
        'errorLink', 'errorId', 'username', 'login', 'user', 'profile',
        'id', 'factorId', '_links', 'name', 'label',
        )
_define(_AUTHN_STATUS, 'status')
_define(_FACTOR_RESULT, 'factorResult')
_define(_FACTOR_TYPE, 'factorType')
_define(_PROVIDER, 'provider', 'vendorName')
_define(_ISO_TIMESTAMP, 'expiresAt')
_define(_bounded_int(0, 86400), 'expires_in', 'interval')
_define(_bounded_int(100, 599), 'statusCode')
_define(_enum('Bearer', 'DPoP', 'N_A'), 'token_type')
_define(_enum(*_TOKEN_TYPE_URNS), 'issued_token_type', 'subject_token_type',
        'actor_token_type', 'requested_token_type')
_define(_GRANT_TYPE, 'grant_type')
_define(_enum('code', 'token', 'id_token', 'code id_token'), 'response_type')
_define(_scope, 'scope')
_define(_OAUTH_ERROR, 'error')
_define(_pattern(r'E\d{7}'), 'errorCode')
_define(_OKTA_CLIENT_ID, 'client_id')
_define(_url, 'verification_uri')
_define(_boolean, 'rememberDevice', 'multiOptionalFactorEnroll',
        'warnBeforePasswordExpired', 'autoPush', 'forcePrompt',
        'checkAccountSetupComplete', 'hideBgImage')
_define(_enum('FIDO_WEBAUTHN'), 'enrolledFactor')
# AWS STS form fields (the assertion is listed as hidden above)
_define(_enum('AssumeRoleWithSAML', 'AssumeRole', 'GetCallerIdentity'), 'Action')
_define(_pattern(r'\d{4}-\d{2}-\d{2}'), 'Version')
_define(_bounded_int(900, 43200), 'DurationSeconds')
_define(_pattern(_ROLE_ARN), 'RoleArn', 'PrincipalArn')
# Containers
_define(_OBJECT, '_embedded', 'factor', 'options')
_define(_OBJECT_LIST, 'factors')


def _lookup(fields, key):
    """Return (display name, spec) for a known field, or None."""
    entry = fields.get(_normalize_name(key))
    if entry is None:
        return None
    canonical, spec = entry
    text = str(key)
    display = text if re.fullmatch(r'[A-Za-z0-9_-]{1,64}', text) else canonical
    return display, spec


def _check(spec, value):
    if value is None or value == '':
        return value
    result = spec(value)
    return REDACTED if result is _INVALID else result


# --------------------------------------------------------------------------
# URL rendering
# --------------------------------------------------------------------------

# Literal path segments of the endpoints this client calls. Every other
# segment (IDs, app names, tokens of any length) is shown as [id].
_PATH_SEGMENTS = frozenset((
    'api', 'v1', 'authn', 'factors', 'verify', 'poll', 'cancel', 'resend',
    'lifecycle', 'activate', 'introspect', 'oauth2', 'device', 'authorize',
    'token', 'default', 'login', 'sessionCookieRedirect', 'second-factor',
    'sso', 'saml', 'user', 'verify_password', 'settings', 'setup', 'home',
    'amazon_aws', 'app', 'enduser', '.well-known', 'okta-organization',
    'signin', 'idp', 'idx', 'identify', 'challenge', 'answer', 'enroll',
    'interact', 'keys', 'userinfo', 'revoke', 'sessions', 'me', 'users',
    'UserHome', 'aws', 'alibaba',
))

_SCHEME = _enum('http', 'https')
_HOST_RE = re.compile(
    r'(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*'
    r'|\d{1,3}(\.\d{1,3}){3}|(?=[0-9a-f.]*:)[0-9a-f:.]{2,45}'
)


def _safe_host(host):
    text = str(host or '').lower()
    return text if _HOST_RE.fullmatch(text) else '[host]'


def _sanitize_path(path):
    rendered = []
    for segment in str(path).split('/'):
        if segment == '':
            rendered.append('')
            continue
        literal = unquote(segment)
        rendered.append(literal if literal in _PATH_SEGMENTS else UNKNOWN_SEGMENT)
    return '/'.join(rendered)


def _encode_value(value):
    return quote(str(value), safe='/[]')


def _render_pairs(pairs, joiner):
    """Render form or query pairs; unknown names are counted, not shown."""
    rendered = []
    unknown = 0
    for index, (key, value) in enumerate(pairs):
        if index >= _MAX_PAIRS:
            unknown += len(pairs) - _MAX_PAIRS
            break
        entry = _lookup(_FIELDS, key)
        if entry is None or entry[1] in (_OBJECT, _OBJECT_LIST):
            unknown += 1
            continue
        display, spec = entry
        shown = _check(spec, value)
        if shown == REDACTED:
            rendered.append(f'{display}={REDACTED}')
        else:
            rendered.append(f'{display}={_encode_value(shown)}')
    if unknown:
        rendered.append(f'[{unknown} unrecognized parameter{"s" if unknown != 1 else ""} omitted]')
    return joiner.join(rendered)


def _sanitize_url(url):
    """Render a URL from its scheme, host, port, known path segments and query schema."""
    if url is None:
        return ''
    text = str(url)
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return '[unparseable URL omitted]'

    origin = ''
    if parts.netloc:
        scheme = parts.scheme if _SCHEME(parts.scheme) is not _INVALID else '[scheme]'
        userinfo = f'{REDACTED}@' if '@' in parts.netloc else ''
        host = _safe_host(parts.hostname)
        if ':' in host:
            host = f'[{host}]'
        if port is not None:
            host = f'{host}:{port}'
        origin = f'{scheme}://{userinfo}{host}'
    elif parts.scheme:
        origin = (parts.scheme if _SCHEME(parts.scheme) is not _INVALID else '[scheme]') + ':'

    rendered = origin + _sanitize_path(parts.path)
    if parts.query:
        rendered += '?' + _render_pairs(parse_qsl(parts.query, keep_blank_values=True), '&')
    if parts.fragment:
        rendered += '#' + REDACTED
    return rendered


# --------------------------------------------------------------------------
# Structured bodies
# --------------------------------------------------------------------------

def _omitted_note(count, noun):
    return f'{count} unrecognized {noun}{"s" if count != 1 else ""}'


def _sanitize_object(value, depth):
    result = {}
    unknown = 0
    for index, (key, item) in enumerate(value.items()):
        if index >= _MAX_ITEMS:
            unknown += len(value) - _MAX_ITEMS
            break
        entry = _lookup(_FIELDS, key)
        if entry is None:
            unknown += 1
            continue
        display, spec = entry
        while display in result:
            display += "'"
        result[display] = _sanitize_field(spec, item, depth + 1)
    if unknown:
        result['[omitted]'] = _omitted_note(unknown, 'field')
    return result


def _sanitize_field(spec, value, depth):
    if depth > _MAX_DEPTH:
        return '[nested data omitted]'
    if spec == _OBJECT:
        if isinstance(value, Mapping):
            return _sanitize_object(value, depth)
        return _check(_hidden, value)
    if spec == _OBJECT_LIST:
        if isinstance(value, list):
            items = [_sanitize_object(item, depth + 1) if isinstance(item, Mapping)
                     else _check(_hidden, item) for item in value[:_MAX_ITEMS]]
            if len(value) > _MAX_ITEMS:
                items.append(f'[{len(value) - _MAX_ITEMS} more items omitted]')
            return items
        return _check(_hidden, value)
    if isinstance(value, (Mapping, list)):
        return REDACTED if value else value
    return _check(spec, value)


def _sanitize_structure(value, depth=0):
    """Render parsed JSON-like data against the field schema."""
    if isinstance(value, Mapping):
        return _sanitize_object(value, depth)
    if isinstance(value, (list, tuple)):
        return _sanitize_field(_OBJECT_LIST, list(value), depth)
    return _check(_hidden, value)


_FORM_BODY_RE = re.compile(r'[A-Za-z0-9_.%~+-]+=[^&\s]*(&[^=&\s]+(=[^&\s]*)?)*')


def _render_body_text(text, content_type=''):
    """Render a decoded body: JSON and form data by schema, anything else as a summary."""
    stripped = text.strip()
    if not stripped:
        return ''
    try:
        parsed = json.loads(stripped)
    except ValueError:
        pass
    else:
        return json.dumps(_sanitize_structure(parsed), indent=2)

    if 'x-www-form-urlencoded' in str(content_type).lower() or _FORM_BODY_RE.fullmatch(stripped):
        pairs = parse_qsl(stripped, keep_blank_values=True)
        if pairs:
            return _render_pairs(pairs, '\n')

    return _body_summary(len(text), 'chars', content_type)


_MEDIA_TYPES = frozenset((
    'application/json', 'application/problem+json', 'application/xml',
    'application/x-www-form-urlencoded', 'application/octet-stream',
    'application/javascript', 'application/x-amz-json-1.0',
    'application/x-amz-json-1.1', 'application/ion+json',
    'application/jwk-set+json', 'text/html', 'text/plain', 'text/xml',
    'text/javascript', 'text/css', 'multipart/form-data',
))


def _content_type_label(content_type):
    media_type = str(content_type or '').split(';', 1)[0].strip().lower()
    return media_type if media_type in _MEDIA_TYPES else ''


def _body_summary(size, unit, content_type):
    kind = _content_type_label(content_type)
    return f'[body omitted: {size} {unit}{", " + kind if kind else ""}]'


def _header_value(headers, name):
    try:
        for key, value in headers.items():
            if str(key).lower() == name:
                return str(value)
    except AttributeError:
        pass
    return ''


# --------------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------------

def _media_type(value):
    label = _content_type_label(value)
    return label or _INVALID


_HTTP_DATE = _pattern(r'(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} '
                      r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} '
                      r'\d{2}:\d{2}:\d{2} GMT')

_HEADERS = {}


def _define_header(spec, *names):
    for name in names:
        _HEADERS[_normalize_name(name)] = (name, spec)


_define_header(_media_type, 'Content-Type')
_define_header(_bounded_int(0, 10 ** 12), 'Content-Length')
_define_header(_bounded_int(0, 86400), 'Retry-After')
_define_header(_bounded_int(0, 10 ** 10), 'X-Rate-Limit-Limit',
               'X-Rate-Limit-Remaining', 'X-Rate-Limit-Reset')
_define_header(_HTTP_DATE, 'Date')
_define_header(_enum('gzip', 'deflate', 'br', 'identity'), 'Content-Encoding')
_define_header(_enum('chunked'), 'Transfer-Encoding')
_define_header(_enum('keep-alive', 'close'), 'Connection')
_define_header(_url, 'Location')
_define_header(_hidden,
               'Authorization', 'Proxy-Authorization', 'Cookie', 'Set-Cookie',
               'X-Okta-Session-Id', 'X-Okta-XsrfToken', 'X-CSRF-Token',
               'X-Amz-Security-Token', 'User-Agent', 'X-Okta-User-Agent-Extended',
               'Accept', 'Accept-Encoding', 'Accept-Language', 'Host', 'Server',
               'Cache-Control', 'Origin', 'Referer')

# Request IDs are shown under an explicit policy: they must come from a
# response header listed here, match the server's fixed format (Okta's
# base64url request ID or an AWS UUID), and must not repeat any text the
# client sent in the matching request. They are server-assigned correlation
# IDs needed for support cases; anything else in these headers is hidden.
_REQUEST_ID_HEADERS = ('x-okta-request-id', 'x-amzn-requestid',
                       'x-amz-request-id', 'x-request-id')
_REQUEST_ID_RE = re.compile(
    r'[A-Za-z0-9_-]{20,40}'
    r'|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
)
for _name in _REQUEST_ID_HEADERS:
    _HEADERS[_normalize_name(_name)] = (_name, 'request_id')


def _request_text(request):
    """Every value the client sent in a request, used for the request-ID echo check."""
    if request is None:
        return ''
    parts = [str(getattr(request, 'url', '') or '')]
    body = getattr(request, 'body', None)
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode('utf-8', 'replace')
    if isinstance(body, str):
        parts.append(body)
    headers = getattr(request, 'headers', None) or {}
    try:
        parts.extend(str(value) for value in headers.values())
    except AttributeError:
        pass
    text = '\n'.join(parts)
    return text + '\n' + unquote(text)


def _safe_request_id(value, sent=''):
    text = str(value or '')
    if not _REQUEST_ID_RE.fullmatch(text) or (sent and text in sent):
        return _INVALID
    return text


def _render_headers(headers, request=None):
    """Return [(name, rendered value)] and the number of unrecognized headers."""
    rendered = []
    unknown = 0
    try:
        items = list(headers.items())
    except AttributeError:
        return rendered, unknown
    sent = None
    for key, value in items:
        entry = _HEADERS.get(_normalize_name(key))
        if entry is None:
            unknown += 1
            continue
        canonical, spec = entry
        text = str(key)
        display = text if re.fullmatch(r'[A-Za-z0-9-]{1,64}', text) else canonical
        if value in (None, ''):
            rendered.append((display, value))
        elif spec == 'request_id':
            if sent is None:
                sent = _request_text(request)
            shown = _safe_request_id(value, sent)
            rendered.append((display, REDACTED if shown is _INVALID else shown))
        else:
            rendered.append((display, _check(spec, str(value))))
    return rendered, unknown


_METHOD = _enum('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')


class DebugFormatter:
    """Formats HTTP request/response data for readable, redacted debug output"""

    # ANSI color codes (disabled if not a TTY)
    COLORS_ENABLED = hasattr(sys.stderr, 'isatty') and sys.stderr.isatty()

    # Color definitions
    CYAN = '\033[96m' if COLORS_ENABLED else ''
    GREEN = '\033[92m' if COLORS_ENABLED else ''
    YELLOW = '\033[93m' if COLORS_ENABLED else ''
    RED = '\033[91m' if COLORS_ENABLED else ''
    BLUE = '\033[94m' if COLORS_ENABLED else ''
    MAGENTA = '\033[95m' if COLORS_ENABLED else ''
    BOLD = '\033[1m' if COLORS_ENABLED else ''
    DIM = '\033[2m' if COLORS_ENABLED else ''
    RESET = '\033[0m' if COLORS_ENABLED else ''

    @classmethod
    def _header_lines(cls, headers, request=None):
        rendered, unknown = _render_headers(headers, request)
        lines = [f"    {cls.DIM}{key}:{cls.RESET} {value}" for key, value in rendered]
        if unknown:
            lines.append(f"    {cls.DIM}[{_omitted_note(unknown, 'header')} omitted]{cls.RESET}")
        return lines

    @classmethod
    def format_request(cls, request):
        """Format an HTTP request for debug output"""
        lines = []

        lines.append("")
        lines.append(f"{cls.CYAN}{cls.BOLD}{'─' * 70}{cls.RESET}")
        lines.append(f"{cls.GREEN}{cls.BOLD}▶ REQUEST{cls.RESET}")
        lines.append(f"{cls.CYAN}{cls.BOLD}{'─' * 70}{cls.RESET}")
        method = str(getattr(request, 'method', '') or '')
        if _METHOD(method) is _INVALID:
            method = '[method]'
        request_url = _sanitize_url(getattr(request, 'url', ''))
        lines.append(f"  {cls.BOLD}{method}{cls.RESET} {cls.BLUE}{request_url}{cls.RESET}")

        headers = getattr(request, 'headers', None) or {}
        lines.append(f"\n  {cls.YELLOW}Headers:{cls.RESET}")
        lines.extend(cls._header_lines(headers))

        body = getattr(request, 'body', None)
        if body:
            lines.append(f"\n  {cls.YELLOW}Body:{cls.RESET}")
            body_str = cls._format_body(body, _header_value(headers, 'content-type'))
            for line in body_str.split('\n'):
                lines.append(f"    {line}")

        return SanitizedText('\n'.join(lines))

    @classmethod
    def format_response(cls, response):
        """Format an HTTP response for debug output"""
        lines = []

        status_code = getattr(response, 'status_code', None)
        if isinstance(status_code, bool) or not isinstance(status_code, int):
            status_code = '[status]'
        status_color = cls._get_status_color(status_code)
        reason = cls._safe_reason(status_code, getattr(response, 'reason', ''))
        headers = getattr(response, 'headers', None) or {}
        request = getattr(response, 'request', None)

        details = []
        elapsed = getattr(response, 'elapsed', None)
        if elapsed is not None and hasattr(elapsed, 'total_seconds'):
            try:
                details.append(f"{float(elapsed.total_seconds()) * 1000:.0f} ms")
            except (TypeError, ValueError):
                pass
        sent = None
        for name in _REQUEST_ID_HEADERS:
            request_id = _header_value(headers, name)
            if request_id:
                if sent is None:
                    sent = _request_text(request)
                shown = _safe_request_id(request_id, sent)
                if shown is not _INVALID:
                    details.append(f"request id {shown}")
                break
        detail_str = f" {cls.DIM}({', '.join(details)}){cls.RESET}" if details else ''

        lines.append(f"\n  {cls.MAGENTA}{cls.BOLD}◀ RESPONSE{cls.RESET}")
        lines.append(f"  {status_color}{cls.BOLD}{status_code}{cls.RESET} {reason}{detail_str}")

        lines.append(f"\n  {cls.YELLOW}Headers:{cls.RESET}")
        lines.extend(cls._header_lines(headers, request))

        lines.append(f"\n  {cls.YELLOW}Body:{cls.RESET}")
        body_str = cls._format_response_body(response, _header_value(headers, 'content-type'))
        for line in body_str.split('\n'):
            lines.append(f"    {line}")

        lines.append(f"{cls.CYAN}{cls.BOLD}{'─' * 70}{cls.RESET}")
        lines.append("")

        return SanitizedText('\n'.join(lines))

    @staticmethod
    def _safe_reason(status_code, reason):
        """Show the reason phrase only when it is the standard phrase for the status."""
        reason = str(reason or '')
        if not reason:
            return ''
        try:
            phrase = http.HTTPStatus(status_code).phrase
        except (ValueError, TypeError):
            return '[reason omitted]'
        return phrase if reason.lower() == phrase.lower() else '[reason omitted]'

    @classmethod
    def _format_response_body(cls, response, content_type=''):
        json_method = getattr(response, 'json', None)
        parsed = _NOT_PARSED = object()
        if callable(json_method):
            try:
                parsed = json_method()
            except Exception:  # noqa: BLE001 - any parse failure falls back to a summary
                parsed = _NOT_PARSED
        if parsed is not _NOT_PARSED:
            return json.dumps(_sanitize_structure(parsed), indent=2)
        try:
            text = response.text
        except Exception:  # noqa: BLE001
            return _body_summary('unknown', 'size', content_type)
        if not isinstance(text, str):
            return _body_summary('unknown', 'size', content_type)
        return _render_body_text(text, content_type)

    @classmethod
    def _get_status_color(cls, status_code):
        """Return appropriate color for HTTP status code"""
        if not isinstance(status_code, int):
            return cls.RESET
        if 200 <= status_code < 300:
            return cls.GREEN
        elif 300 <= status_code < 400:
            return cls.YELLOW
        elif 400 <= status_code < 500:
            return cls.RED
        elif status_code >= 500:
            return cls.RED + cls.BOLD
        return cls.RESET

    @classmethod
    def _format_body(cls, body, content_type=''):
        """Format a request body: JSON and form data by schema, anything else as a summary"""
        if isinstance(body, (bytes, bytearray)):
            try:
                body = bytes(body).decode('utf-8')
            except UnicodeDecodeError:
                return _body_summary(len(body), 'bytes', content_type)
        if not isinstance(body, str):
            return '[streamed body omitted]'
        return _render_body_text(body, content_type)

    @classmethod
    def _mask_sensitive_dict(cls, data):
        """Return parsed data rendered against the field schema"""
        return _sanitize_structure(data)

    @classmethod
    def _mask_sensitive_headers(cls, headers):
        """Return headers rendered against the header schema"""
        rendered, unknown = _render_headers(headers)
        result = {}
        for key, value in rendered:
            while key in result:
                key += "'"
            result[key] = value
        if unknown:
            result['[omitted]'] = _omitted_note(unknown, 'header')
        return result


# --------------------------------------------------------------------------
# Log records
# --------------------------------------------------------------------------

_PACKAGE_LOGGER = 'gimme_aws_creds'
_LOGGER_NAME_RE = re.compile(r'[A-Za-z0-9_.-]{1,100}')
_HTTP_VERSION = _enum('HTTP/0.9', 'HTTP/1.0', 'HTTP/1.1', 'HTTP/2', 'HTTP/2.0', 'HTTP/3')
_PORT = _bounded_int(0, 65535)
_COUNT = _bounded_int(0, 10 ** 9)


def _shown(spec, value):
    result = spec(value)
    return REDACTED if result is _INVALID else result


def _urllib3_origin(scheme, host, port):
    scheme = _shown(_SCHEME, scheme)
    port_text = '' if port is None else f':{_shown(_PORT, port)}'
    return f'{scheme}://{_safe_host(host)}{port_text}'


def _urllib3_request(args):
    scheme, host, port, method, url, version, status, length = args
    url_text = _sanitize_url(url) if isinstance(url, str) else REDACTED
    if not url_text.startswith(('http://', 'https://', '/')):
        url_text = REDACTED
    length_text = 'None' if length is None else _shown(_COUNT, length)
    return (f'{_urllib3_origin(scheme, host, port)} "{_shown(_METHOD, method)} '
            f'{url_text} {_shown(_HTTP_VERSION, version)}" '
            f'{_shown(_bounded_int(100, 599), status)} {length_text}')


def _urllib3_new_connection(kind):
    def render(args):
        number, host, port = args
        return (f'Starting new {kind} connection ({_shown(_COUNT, number)}): '
                f'{_safe_host(host)}:{_shown(_PORT, port)}')
    return render


def _botocore_request(args):
    operation = args[0]
    name = getattr(operation, 'name', None)
    if name is None and isinstance(operation, str):
        match = re.fullmatch(r'OperationModel\(name=([A-Za-z0-9]{1,64})\)', operation)
        name = match.group(1) if match else None
    if not isinstance(name, str) or not re.fullmatch(r'[A-Z][A-Za-z0-9]{0,63}', name):
        name = REDACTED
    return f'Making request for operation {name} [parameters omitted]'


# (logger name, format string, argument count) -> renderer of typed arguments
_KNOWN_EVENTS = {
    ('urllib3.connectionpool', '%s://%s:%s "%s %s %s" %s %s', 8): _urllib3_request,
    ('urllib3.connectionpool', 'Starting new HTTPS connection (%d): %s:%s', 3):
        _urllib3_new_connection('HTTPS'),
    ('urllib3.connectionpool', 'Starting new HTTP connection (%d): %s:%s', 3):
        _urllib3_new_connection('HTTP'),
    ('urllib3.connectionpool', 'Resetting dropped connection: %s', 1):
        lambda args: f'Resetting dropped connection: {_safe_host(args[0])}',
    ('botocore.endpoint', 'Making request for %s with params: %s', 2): _botocore_request,
}


def _safe_arg(value):
    """Interpolation value for a package log template: numbers, booleans and None only."""
    if isinstance(value, SanitizedText) or value is None or isinstance(value, (bool, int, float)):
        return value
    return REDACTED


def _format_package_message(msg, args):
    if not isinstance(msg, str):
        return '[log message omitted: not text]'
    if not args:
        return msg
    if isinstance(args, Mapping):
        safe_args = {key: _safe_arg(value) for key, value in args.items()}
    else:
        safe_args = tuple(_safe_arg(value) for value in args)
    try:
        return msg % safe_args
    except (TypeError, ValueError, KeyError, IndexError):
        return '[log message omitted: arguments do not match the format]'


def _render_record_message(record):
    """Return (message, omitted) for a record under the record policy."""
    msg, args = record.msg, record.args
    if isinstance(msg, SanitizedText) and not args:
        return msg, False
    name = str(record.name)
    if isinstance(msg, str) and isinstance(args, tuple):
        renderer = _KNOWN_EVENTS.get((name, msg, len(args)))
        if renderer is not None:
            return renderer(args), False
    if name == _PACKAGE_LOGGER or name.startswith(_PACKAGE_LOGGER + '.'):
        return _format_package_message(msg, args), False
    shown_name = name if _LOGGER_NAME_RE.fullmatch(name) else '[logger]'
    return f'[{shown_name} {record.levelname} message omitted]', True


_TYPE_NAME_RE = re.compile(r'[A-Za-z_][\w.<>]{0,199}')


def _exception_type_name(exc_type):
    module = getattr(exc_type, '__module__', '') or ''
    qualname = getattr(exc_type, '__qualname__', '') or ''
    name = qualname if module in ('builtins', '') else f'{module}.{qualname}'
    return name if _TYPE_NAME_RE.fullmatch(name) else '[exception type]'


def _frame_lines(tb):
    lines = []
    for frame in traceback.extract_tb(tb, limit=50):
        lines.append(f'  File "{frame.filename}", line {frame.lineno}, in {frame.name}')
    return lines


def _safe_exception_text(exc_info):
    """Traceback frames and exception types only; no messages or source lines."""
    _type, value, tb = exc_info
    chain = []
    seen = set()
    current = value
    while current is not None and id(current) not in seen and len(chain) < 5:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or (None if current.__suppress_context__ else current.__context__)
    if not chain:
        return _exception_type_name(_type) if _type else '[exception omitted]'
    blocks = []
    for index, exc in enumerate(reversed(chain)):
        if index:
            blocks.append('\nDuring handling of the above exception, another exception occurred:\n')
        frames = _frame_lines(exc.__traceback__ if exc is not value else (tb or exc.__traceback__))
        if frames:
            blocks.append('Traceback (most recent call last; messages and source lines omitted):')
            blocks.extend(frames)
        blocks.append(f'{_exception_type_name(type(exc))} [message omitted]')
    return '\n'.join(blocks)


_STACK_LINE_RE = re.compile(r'Stack \(most recent call last\):|\s+File ".*", line \d+, in [\w<>.]+')


def _safe_stack_info(stack_info):
    lines = [line for line in str(stack_info).split('\n') if _STACK_LINE_RE.fullmatch(line)]
    return '\n'.join(lines)


def _is_rendered(record):
    """True only if the record still holds exactly the text this module rendered.

    A boolean flag is not enough: ``logging.makeLogRecord`` creates a record
    through the factory and then overwrites its attributes from a dict.
    """
    rendered = getattr(record, 'gimme_aws_creds_rendered', None)
    return (isinstance(rendered, tuple) and len(rendered) == 3
            and record.msg is rendered[0] and record.exc_text is rendered[1]
            and record.stack_info is rendered[2]
            and not record.args and not record.exc_info)


def _mark_rendered(record):
    record.gimme_aws_creds_rendered = (record.msg, record.exc_text, record.stack_info)


def _sanitize_record(record):
    """Replace a record's message, arguments and exception text with policy-rendered text."""
    if _is_rendered(record):
        return
    message, omitted = _render_record_message(record)
    record.msg = SanitizedText(message)
    record.args = None
    if record.exc_info:
        record.exc_text = _safe_exception_text(record.exc_info)
        record.exc_info = None
    elif record.exc_text:
        record.exc_text = '[exception text omitted]'
    if record.stack_info:
        record.stack_info = _safe_stack_info(record.stack_info)
    record.gimme_aws_creds_omitted = omitted
    _mark_rendered(record)


def _blank_record(record):
    record.msg = SanitizedText('[log record omitted: rendering failed]')
    record.args = None
    record.exc_info = None
    record.exc_text = None
    record.stack_info = None
    record.gimme_aws_creds_omitted = True
    _mark_rendered(record)


def _make_redacting_record_factory(base_factory):
    def redacting_record_factory(*args, **kwargs):
        record = base_factory(*args, **kwargs)
        try:
            _sanitize_record(record)
        except Exception:  # noqa: BLE001 - never let raw text through on failure
            _blank_record(record)
        return record

    redacting_record_factory.gimme_aws_creds_redacting = True
    redacting_record_factory.base_factory = base_factory
    return redacting_record_factory


def install_redacting_record_factory():
    """Make every new log record carry only policy-rendered text. Idempotent."""
    current = logging.getLogRecordFactory()
    if getattr(current, 'gimme_aws_creds_redacting', False):
        return current
    factory = _make_redacting_record_factory(current)
    logging.setLogRecordFactory(factory)
    return factory


# --------------------------------------------------------------------------
# Resolved configuration
# --------------------------------------------------------------------------

def _config_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ('true', 'false', 'yes', 'no', 'on', 'off', '1', '0'):
        return value
    return _INVALID


def _config_path(value):
    """Local file locations (config and credential file paths) are shown."""
    text = str(value)
    return text if len(text) <= 1024 and text.isprintable() else _INVALID


def _config_list(item_spec):
    def check(value):
        if isinstance(value, (list, tuple)):
            items = list(value)
        elif isinstance(value, str):
            items = [item.strip() for item in value.split(',')]
        else:
            return _INVALID
        if not items or len(items) > 50 or any(item_spec(item) is _INVALID for item in items):
            return _INVALID
        return value
    return check


def _config_url(value):
    if isinstance(value, str) and re.match(r'[A-Za-z][A-Za-z0-9+.-]*://', value):
        return _sanitize_url(value)
    return _INVALID


def _gimme_creds_server(value):
    if value in ('appurl', 'internal'):
        return value
    return _config_url(value)


# Profile and credential-profile names are configuration section labels the
# user chose; they also appear as INI section headers in plain-text files.
_PROFILE_NAME = _pattern(r'[A-Za-z0-9_.@-][A-Za-z0-9 _.@-]{0,63}')
_REGION = _pattern(r'[a-z]{2}(-[a-z]+)+-\d{1,2}')
_ROLE_ARNS = _config_list(_pattern(_ROLE_ARN + '|all'))

_CONFIG_TYPES = {}


def _define_config(spec, *keys):
    for key in keys:
        _CONFIG_TYPES[key] = spec


_define_config(_config_bool,
               'verify_ssl_certs', 'resolve', 'remember_device', 'force_classic',
               'open_browser', 'disable_keychain', 'enable_alicloud', 'debug',
               'action_configure', 'action_list_profiles', 'action_list_roles',
               'action_store_json_creds', 'action_register_device',
               'action_setup_fido_authenticator', 'write_aws_creds',
               'resolve_aws_alias', 'include_path', 'enable_keychain', 'insecure',
               'GIMME_AWS_CREDS_ENABLE_ALICLOUD')
_define_config(_bounded_int(0, 129600),
               'aws_default_duration', 'alibaba_cloud_default_duration',
               'device_flow_timeout', 'AWS_DEFAULT_DURATION')
_define_config(_enum('export', 'json', 'windows'),
               'output_format', 'action_output_format', 'GIMME_AWS_CREDS_OUTPUT_FORMAT')
_define_config(_enum('classic', 'identity_engine'), 'okta_platform')
_define_config(_FACTOR_TYPE, 'preferred_mfa_type')
_define_config(_PROVIDER, 'preferred_mfa_provider')
_define_config(_pattern(r'[a-z]{3}[0-9A-Za-z]{17}'), 'preferred_mfa_factor_id')
_define_config(_enum('Duo Push', 'Passcode', 'Phone Call'), 'duo_universal_factor')
_define_config(_scope, 'device_flow_scope')
_define_config(_OKTA_CLIENT_ID, 'client_id', 'GIMME_AWS_CREDS_CLIENT_ID')
_define_config(_pattern(r'aus[0-9A-Za-z]{17}|default'), 'okta_auth_server', 'OKTA_AUTH_SERVER')
_define_config(_config_url, 'okta_org_url', 'app_url', 'alicloud_saml_url')
_define_config(_gimme_creds_server, 'gimme_creds_server')
_define_config(_REGION, 'aws_region', 'alicloud_region', 'AWS_STS_REGION')
_define_config(_ROLE_ARNS, 'aws_rolename', 'roles', 'AWS_ROLE_ARN')
_define_config(_PROFILE_NAME,
               'conf_profile', 'profile', 'cred_profile', 'aws_cred_profile',
               'inherits', 'GIMME_AWS_CREDS_CRED_PROFILE')
_define_config(_config_path, 'OKTA_CONFIG', 'AWS_SHARED_CREDENTIALS_FILE')
_define_config(_hidden,
               # Credentials and codes
               'api_key', 'mfa_code', 'device_token', 'okta_password',
               'okta_mfa_code', 'password', 'OKTA_API_KEY', 'OKTA_MFA_CODE',
               'OKTA_DEVICE_TOKEN', 'OKTA_PASSWORD',
               # Identities and free text
               'username', 'okta_username', 'OKTA_USERNAME', 'aws_appname')


def _mask_config_value(key, value):
    """Show a config value only when its key is known and the value has the key's type."""
    if value is None or value == '' or value is False or value == [] or value == ():
        return value
    spec = _CONFIG_TYPES.get(str(key))
    if spec is None:
        return REDACTED
    if spec is _hidden:
        return REDACTED
    result = spec(value)
    return REDACTED if result is _INVALID else result


# Config attributes (on Config object) that we display alongside the
# profile-merged conf_dict. Only attributes meaningful to the user.
# (aws_default_duration is intentionally omitted: it's derived from conf_dict
# and reported there with the correct profile/env/cli source.)
_CONFIG_OBJECT_ATTRS = (
    'OKTA_CONFIG',
    'conf_profile',
    'username',
    'api_key',
    'verify_ssl_certs',
    'app_url',
    'resolve',
    'mfa_code',
    'remember_device',
    'device_token',
    'output_format',
    'force_classic',
    'open_browser',
    'disable_keychain',
    'enable_alicloud',
    'roles',
    'cred_profile',
    'debug',
    'action_configure',
    'action_list_profiles',
    'action_list_roles',
    'action_store_json_creds',
    'action_register_device',
    'action_setup_fido_authenticator',
    'action_output_format',
)

_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}')


def format_resolved_configuration(config, conf_dict, env_overrides_applied=None,
                                  cli_overrides_applied=None):
    """Format the resolved configuration for --debug output.

    Shows:
      - Configuration file path (and whether OKTA_CONFIG env var set it)
      - Active profile and inheritance chain
      - CLI arguments explicitly provided
      - Environment variables affecting configuration
      - Effective Config object attributes
      - Effective profile-merged conf_dict, with the source of each value

    Values are shown only for known keys whose value has the expected type.
    Keys this module does not know are counted, not listed.

    :param config: gimme_aws_creds.config.Config instance (after get_args() and
        get_config_dict() have run)
    :param conf_dict: the merged profile config dict
    :param env_overrides_applied: dict of {conf_key: env_var_name} for env vars
        that overrode profile values in conf_dict
    :param cli_overrides_applied: dict of {conf_key: cli_flag_name} for CLI
        flags that overrode profile values in conf_dict
    """
    env_overrides_applied = env_overrides_applied or {}
    cli_overrides_applied = cli_overrides_applied or {}

    df = DebugFormatter
    bar = f"{df.CYAN}{df.BOLD}{'═' * 70}{df.RESET}"
    sub_bar = f"{df.CYAN}{'─' * 70}{df.RESET}"

    lines = ['']
    lines.append(bar)
    lines.append(f"{df.CYAN}{df.BOLD}  RESOLVED CONFIGURATION{df.RESET}")
    lines.append(bar)
    lines.append('')

    # --- Configuration file ---
    okta_config_path = _mask_config_value('OKTA_CONFIG', getattr(config, 'OKTA_CONFIG', None))
    env_used_in_init = getattr(config, '_env_used_in_init', {}) or {}
    if 'OKTA_CONFIG' in env_used_in_init:
        path_source = 'env: OKTA_CONFIG'
    else:
        path_source = 'default location (~/.okta_aws_login_config)'
    lines.append(
        f"  {df.YELLOW}Configuration file:{df.RESET} {okta_config_path} "
        f"{df.DIM}[{path_source}]{df.RESET}"
    )

    # --- Active profile / inheritance chain ---
    conf_profile = _mask_config_value('conf_profile', getattr(config, 'conf_profile', None))
    if 'profile' in (getattr(config, '_cli_args_provided', {}) or {}):
        profile_source = 'cli: --profile'
    elif conf_profile == 'DEFAULT':
        profile_source = 'default'
    else:
        profile_source = 'set programmatically'
    lines.append(
        f"  {df.YELLOW}Active profile:{df.RESET}     {conf_profile} "
        f"{df.DIM}[{profile_source}]{df.RESET}"
    )

    chain = getattr(config, '_inheritance_chain', []) or []
    if len(chain) > 1:
        lines.append(
            f"  {df.YELLOW}Inheritance chain:{df.RESET}  "
            + ' -> '.join(str(_mask_config_value('inherits', name)) for name in chain)
            + f" {df.DIM}(child overrides parent){df.RESET}"
        )
    lines.append('')

    # --- CLI arguments provided ---
    cli_args_provided = getattr(config, '_cli_args_provided', {}) or {}
    if cli_args_provided:
        lines.append(f"  {df.YELLOW}CLI arguments provided:{df.RESET}")
        for dest in sorted(cli_args_provided.keys(), key=str):
            if not _NAME_RE.fullmatch(str(dest)):
                continue
            display = _mask_config_value(dest, cli_args_provided[dest])
            flag = '--' + str(dest).replace('_', '-')
            lines.append(f"    {flag} = {display}")
        lines.append('')

    # --- Environment variables affecting configuration ---
    env_used = dict(env_used_in_init)
    for conf_key, env_var in env_overrides_applied.items():
        env_used[env_var] = {
            'sets': f'conf_dict.{conf_key}',
            'value': config.ui.environ.get(env_var) if hasattr(config, 'ui') else None,
        }
    if env_used:
        lines.append(f"  {df.YELLOW}Environment variables affecting configuration:{df.RESET}")
        for env_name in sorted(env_used.keys(), key=str):
            if not _NAME_RE.fullmatch(str(env_name)):
                continue
            info = env_used[env_name]
            display = _mask_config_value(env_name, info.get('value'))
            sets = str(info.get('sets', ''))
            if not re.fullmatch(r'(conf_dict\.)?[A-Za-z_][A-Za-z0-9_.]{0,80}|', sets):
                sets = '[target]'
            lines.append(
                f"    {env_name} = {display} "
                f"{df.DIM}-> {sets}{df.RESET}"
            )
        lines.append('')

    # --- Config object attributes ---
    lines.append(f"  {df.YELLOW}Config object (CLI/env/runtime values):{df.RESET}")
    lines.append(sub_bar)
    for attr in _CONFIG_OBJECT_ATTRS:
        if not hasattr(config, attr):
            continue
        value = getattr(config, attr)
        display = _mask_config_value(attr, value)
        source = _config_attr_source(config, attr, env_used_in_init)
        lines.append(_format_kv_line(attr, display, source))
    lines.append('')

    # --- Effective profile-merged conf_dict ---
    profile_sources = getattr(config, '_profile_value_sources', {}) or {}
    lines.append(f"  {df.YELLOW}Effective profile config (merged conf_dict):{df.RESET}")
    lines.append(sub_bar)
    if conf_dict:
        unknown = 0
        for key in sorted(conf_dict.keys(), key=str):
            if key not in _CONFIG_TYPES:
                unknown += 1
                continue
            value = conf_dict[key]
            display = _mask_config_value(key, value)
            if key in cli_overrides_applied:
                source = f"cli: {cli_overrides_applied[key]}"
            elif key in env_overrides_applied:
                source = f"env: {env_overrides_applied[key]}"
            elif key in profile_sources:
                source = f"profile: {_mask_config_value('inherits', profile_sources[key])}"
            else:
                source = "computed/default"
            lines.append(_format_kv_line(key, display, source))
        if unknown:
            lines.append(f"    {df.DIM}[{_omitted_note(unknown, 'key')} omitted]{df.RESET}")
    else:
        lines.append(f"    {df.DIM}(empty){df.RESET}")
    lines.append('')
    lines.append(bar)
    lines.append('')

    return SanitizedText('\n'.join(lines))


def _config_attr_source(config, attr, env_used_in_init):
    """Best-effort determination of where a Config attribute came from."""
    cli_args = getattr(config, '_cli_args_provided', {}) or {}

    cli_attr_to_flag = {
        'username': '--username',
        'mfa_code': '--mfa-code',
        'remember_device': '--remember-device',
        'output_format': '--output-format',
        'action_output_format': '--output-format',
        'roles': '--roles',
        'cred_profile': '--aws-cred-profile',
        'conf_profile': '--profile',
        'debug': '--debug',
        'enable_alicloud': '--enable-alicloud',
        'force_classic': '--force-classic',
        'open_browser': '--open-browser',
        'disable_keychain': '--disable-keychain',
        'resolve': '--resolve',
        'action_configure': '--action-configure',
        'action_list_profiles': '--action-list-profiles',
        'action_list_roles': '--action-list-roles',
        'action_store_json_creds': '--action-store-json-creds',
        'action_register_device': '--action-register-device',
        'action_setup_fido_authenticator': '--action-setup-fido-authenticator',
    }
    cli_attr_to_dest = {
        'username': 'username',
        'mfa_code': 'mfa_code',
        'remember_device': 'remember_device',
        'output_format': 'output_format',
        'action_output_format': 'output_format',
        'roles': 'roles',
        'cred_profile': 'aws_cred_profile',
        'conf_profile': 'profile',
        'debug': 'debug',
        'enable_alicloud': 'enable_alicloud',
        'force_classic': 'force_classic',
        'open_browser': 'open_browser',
        'disable_keychain': 'disable_keychain',
        'resolve': 'resolve',
        'action_configure': 'action_configure',
        'action_list_profiles': 'action_list_profiles',
        'action_list_roles': 'action_list_roles',
        'action_store_json_creds': 'action_store_json_creds',
        'action_register_device': 'action_register_device',
        'action_setup_fido_authenticator': 'action_setup_fido_authenticator',
    }

    if attr == 'verify_ssl_certs':
        if 'insecure' in cli_args:
            return 'cli: --insecure'
        return 'default'
    if attr == 'OKTA_CONFIG':
        if 'OKTA_CONFIG' in env_used_in_init:
            return 'env: OKTA_CONFIG'
        return 'default'
    if attr == 'username':
        if 'username' in cli_args:
            return 'cli: --username'
        if 'OKTA_USERNAME' in env_used_in_init:
            return 'env: OKTA_USERNAME'
        return 'default/unset'
    if attr == 'api_key':
        if 'OKTA_API_KEY' in env_used_in_init:
            return 'env: OKTA_API_KEY'
        return 'default/unset'

    if attr in cli_attr_to_dest and cli_attr_to_dest[attr] in cli_args:
        return f"cli: {cli_attr_to_flag[attr]}"
    return 'default'


def _format_kv_line(key, value, source):
    """Render a single 'key = value [source]' line with consistent alignment."""
    df = DebugFormatter
    key_str = f"{str(key):<32}"
    value_str = str(value) if value is not None else 'None'
    if len(value_str) > 60:
        value_str = value_str[:60] + '...'
    return f"    {df.BOLD}{key_str}{df.RESET} = {value_str:<40} {df.DIM}[{source}]{df.RESET}"


def create_debug_response_hook(mask_func=None):
    """Create a response hook for requests library that logs redacted debug info"""

    def debug_response_hook(response, *args, **kwargs):
        """Log request and response details for debugging"""
        try:
            logger.debug(DebugFormatter.format_request(response.request))
            logger.debug(DebugFormatter.format_response(response))
        except Exception as exc:  # noqa: BLE001 - debug output must never break a request
            logger.debug('[debug output unavailable: %s]',
                         SanitizedText(_exception_type_name(type(exc))))
        return response

    return debug_response_hook


class _CleanDebugFormatter(logging.Formatter):
    """Prints records bare, applying the record policy to any record not yet rendered."""

    def format(self, record):
        if not _is_rendered(record):
            # The record was created without our factory (for example via
            # logging.makeLogRecord); render a copy under the same policy.
            record = logging.makeLogRecord(dict(record.__dict__))
            try:
                _sanitize_record(record)
            except Exception:  # noqa: BLE001
                _blank_record(record)
        parts = [str(record.msg)]
        if record.exc_text:
            parts.append(str(record.exc_text))
        if record.stack_info:
            parts.append(str(record.stack_info))
        return '\n'.join(parts)


class _DropOmittedDebugRecords(logging.Filter):
    """Keep the console free of placeholders for unrecognized third-party DEBUG records."""

    def filter(self, record):
        return not (record.levelno <= logging.DEBUG
                    and getattr(record, 'gimme_aws_creds_omitted', False))


def setup_debug_logging():
    """Configure logging for debug output with a clean, policy-rendered format"""
    install_redacting_record_factory()

    # Set up the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler with our clean formatter
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(_CleanDebugFormatter())
    console_handler.addFilter(_DropOmittedDebugRecords())
    root_logger.addHandler(console_handler)

    # Set the gimme-aws-creds logger
    gac_logger = logging.getLogger('gimme_aws_creds')
    gac_logger.setLevel(logging.DEBUG)
