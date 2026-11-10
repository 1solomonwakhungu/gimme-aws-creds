"""
Debug formatting utilities for gimme-aws-creds.

``--debug`` output is rendered deny-by-default: only the HTTP method, the
sanitized origin and path, the status, the elapsed time and values whose
field names are on an explicit allowlist are shown. Every other value in
query strings, form and JSON bodies, headers and configuration is replaced
with ``[REDACTED]`` in full; no prefix or fragment of a value is kept. Bodies
that cannot be parsed as JSON or form data are summarized, never printed.

All log records emitted while debug logging is active, including records
from third-party libraries and their tracebacks, also pass through a
best-effort free-text redactor before any handler sees them.
"""
import json
import logging
import re
import sys
import traceback
from collections.abc import Mapping
from urllib.parse import parse_qsl, quote, unquote, urlsplit

logger = logging.getLogger(__name__)

REDACTED = '[REDACTED]'


class SanitizedText(str):
    """Debug text already rendered deny-by-default by this module.

    Log records whose message is a SanitizedText (with no arguments) are not
    run through the free-text redactor again, which would otherwise mangle
    allowlisted values such as ``token:software:totp``.
    """

# Longest value shown for an allowlisted field before truncation.
_MAX_VALUE_CHARS = 256
# Limits for nested structures in rendered bodies.
_MAX_DEPTH = 20
_MAX_ITEMS = 100
# Longest URL nesting followed while sanitizing redirect-style parameters.
_MAX_URL_DEPTH = 4

# Field names (normalized: lower case, alphanumerics only) whose values are
# shown in debug output. Everything else is redacted. Keep entries limited to
# fields that never carry credentials, codes, or session state.
_SAFE_VALUE_FIELDS = frozenset((
    # Okta authn / factor metadata
    'status', 'factorresult', 'factortype', 'provider', 'vendorname',
    'type', 'expiresat', 'recoverytype', 'name', 'label', 'templated',
    'enabled', 'allow', 'hints', 'method',
    # OAuth metadata
    'expiresin', 'interval', 'tokentype', 'issuedtokentype',
    'requestedtokentype', 'actortokentype', 'subjecttokentype', 'scope',
    'granttype', 'responsetype', 'clientid', 'audience',
    # Errors
    'error', 'errordescription', 'errorcode', 'errorsummary', 'errorid',
    'errorlink', 'errorcauses', 'statuscode', 'message',
    # AWS STS request metadata (no assertion or credential fields)
    'action', 'version', 'durationseconds', 'rolearn', 'principalarn',
    'region',
    # Navigation (rendered through the URL sanitizer)
    'fromuri', 'redirecturi', 'verificationuri', 'href', 'url', 'urlpath',
    'location',
    # Request headers / transport metadata
    'contenttype', 'contentlength', 'accept', 'acceptencoding',
    'acceptlanguage', 'useragent', 'host', 'date', 'server', 'connection',
    'cachecontrol', 'contentencoding', 'transferencoding', 'retryafter',
    'xoktarequestid', 'xrequestid', 'xamznrequestid', 'xamzrequestid',
    'xratelimitlimit', 'xratelimitremaining', 'xratelimitreset',
))

# Allowlisted fields whose values are URLs and must be sanitized recursively.
_URL_VALUE_FIELDS = frozenset((
    'fromuri', 'redirecturi', 'verificationuri', 'href', 'url', 'urlpath',
    'location',
))

# HTTP headers whose values are shown (normalized names).
_SAFE_HEADERS = frozenset((
    'contenttype', 'contentlength', 'accept', 'acceptencoding',
    'acceptlanguage', 'useragent', 'host', 'date', 'server', 'connection',
    'cachecontrol', 'contentencoding', 'transferencoding', 'retryafter',
    'location', 'xoktarequestid', 'xrequestid', 'xamznrequestid',
    'xamzrequestid', 'xratelimitlimit', 'xratelimitremaining',
    'xratelimitreset',
))

_REQUEST_ID_HEADERS = ('x-okta-request-id', 'x-amzn-requestid',
                       'x-amz-request-id', 'x-request-id')

# Fragments of normalized field names that mark a value as secret in free
# text. Structured rendering does not depend on this list: it redacts every
# field that is not allowlisted.
_SENSITIVE_NAME_FRAGMENTS = (
    'password', 'passwd', 'passphrase', 'passcode', 'pwd', 'secret',
    'token', 'cookie', 'authorization', 'session', 'assertion', 'saml',
    'credential', 'code', 'otp', 'signature', 'nonce', 'challenge',
    'attestation', 'clientdata', 'authenticatordata', 'userhandle',
    'verification', 'apikey', 'privatekey', 'accesskey', 'xsrf', 'csrf',
    'jwt', 'bearer', 'answer',
)
_SENSITIVE_NAMES_EXACT = frozenset(('sid', 'pin', 'pass', 'key', 'state'))


def _normalize_name(name):
    """Lower-case a field name and drop separators, so variants compare equal."""
    return re.sub(r'[^a-z0-9]', '', str(name).lower())


def _is_safe_field(name):
    return _normalize_name(name) in _SAFE_VALUE_FIELDS


def _is_sensitive_name(name):
    """Return True when a field name looks like it carries a secret."""
    norm = _normalize_name(name)
    if norm in _SAFE_VALUE_FIELDS:
        return False
    if norm in _SENSITIVE_NAMES_EXACT:
        return True
    return any(fragment in norm for fragment in _SENSITIVE_NAME_FRAGMENTS)


_DISPLAY_KEY_RE = re.compile(r'[A-Za-z0-9_.:@$ -]{1,64}')
_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*')


def _display_key(key):
    """Field names are shown unless they look like data rather than a name."""
    text = str(key)
    if not _DISPLAY_KEY_RE.fullmatch(text) or _JWT_RE.search(text) or _looks_like_blob(text):
        return '[key]'
    return text


def _truncate(text, limit=_MAX_VALUE_CHARS):
    return text if len(text) <= limit else text[:limit] + '...'


# --------------------------------------------------------------------------
# URL rendering
# --------------------------------------------------------------------------

_PATH_SEGMENT_SECRET_RE = re.compile(r'[A-Za-z0-9._~%+=-]{32,}')


def _sanitize_path(path):
    segments = []
    for segment in path.split('/'):
        base, sep, _params = segment.partition(';')
        if _PATH_SEGMENT_SECRET_RE.fullmatch(base) or _JWT_RE.search(unquote(base)):
            base = REDACTED
        segments.append(base + (sep + REDACTED if sep else ''))
    return '/'.join(segments)


def _encode_value(value):
    return quote(value, safe='/[]')


def _render_pairs(pairs, url_depth, joiner):
    rendered = []
    for key, value in pairs:
        rendered.append(f"{_display_key(key)}={_render_pair_value(key, value, url_depth)}")
    return joiner.join(rendered)


def _render_pair_value(key, value, url_depth):
    if value == '':
        return ''
    norm = _normalize_name(key)
    if norm not in _SAFE_VALUE_FIELDS:
        return REDACTED
    if norm in _URL_VALUE_FIELDS:
        return _encode_value(_sanitize_url(value, url_depth + 1))
    return _encode_value(_safe_text(value))


def _sanitize_url(url, depth=0):
    """Render a URL as origin, path and query keys with allowlisted values only."""
    if url is None:
        return ''
    url = str(url)
    if depth > _MAX_URL_DEPTH:
        return REDACTED
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return '[unparseable URL redacted]'

    origin = ''
    if parts.netloc:
        host = parts.hostname or ''
        if ':' in host:
            host = f'[{host}]'
        if port is not None:
            host = f'{host}:{port}'
        userinfo = f'{REDACTED}@' if '@' in parts.netloc else ''
        origin = f'{parts.scheme}://{userinfo}{host}' if parts.scheme else f'//{userinfo}{host}'
    elif parts.scheme:
        origin = f'{parts.scheme}:'

    rendered = origin + _sanitize_path(parts.path)
    if parts.query:
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        rendered += '?' + _render_pairs(pairs, depth, '&')
    if parts.fragment:
        rendered += '#' + REDACTED
    return rendered


# --------------------------------------------------------------------------
# Structured value rendering
# --------------------------------------------------------------------------

_LONG_BLOB_RE = re.compile(r'(?<![A-Za-z0-9+/_=.-])[A-Za-z0-9+/_=-]{64,}(?![A-Za-z0-9+/_=.-])')


def _looks_like_blob(text):
    for match in _LONG_BLOB_RE.finditer(text):
        blob = match.group(0)
        if re.search(r'[0-9]', blob) and re.search(r'[a-z]', blob) and re.search(r'[A-Z]', blob):
            return True
    return False


def _safe_text(value):
    """Render an allowlisted scalar value, still screening it for secrets.

    Values of allowlisted fields are short metadata, so only embedded query
    strings, authorization schemes, JWTs and credential-like blobs are
    checked; any of those replaces the whole value.
    """
    text = str(value)
    decoded = _decode_repeatedly(text)
    for candidate in {text, decoded}:
        if (_JWT_RE.search(candidate) or _looks_like_blob(candidate)
                or _AUTH_SCHEME_RE.search(candidate)
                or any(_is_sensitive_name(m.group(1)) for m in _ASSIGNMENT_RE.finditer(candidate))
                or _QUERY_PAIR_RE.sub(_redact_query_pair, candidate) != candidate):
            return REDACTED
    return _truncate(text)


def _sanitize_leaf(norm_key, value):
    if value is None or isinstance(value, bool):
        return value
    if value == '':
        return value
    if norm_key not in _SAFE_VALUE_FIELDS:
        return REDACTED
    if isinstance(value, (int, float)):
        return value
    if norm_key in _URL_VALUE_FIELDS:
        return _truncate(_sanitize_url(value))
    return _safe_text(value)


def _sanitize_structure(value, norm_key=None, depth=0):
    """Return a copy of parsed JSON-like data with every non-allowlisted value redacted."""
    if depth > _MAX_DEPTH:
        return '[nested data omitted]'
    if norm_key is not None and _is_sensitive_name(norm_key) and value not in (None, '', {}, []):
        return REDACTED
    if isinstance(value, Mapping):
        result = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_ITEMS:
                result['[omitted]'] = f'{len(value) - _MAX_ITEMS} more fields'
                break
            display = _display_key(key)
            while display in result:
                display += "'"
            result[display] = _sanitize_structure(item, _normalize_name(key), depth + 1)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        result = [_sanitize_structure(item, norm_key, depth + 1) for item in items[:_MAX_ITEMS]]
        if len(items) > _MAX_ITEMS:
            result.append(f'[{len(items) - _MAX_ITEMS} more items omitted]')
        return result
    return _sanitize_leaf(norm_key, value)


_FORM_BODY_RE = re.compile(r'[A-Za-z0-9_.%~+-]+=[^&\s]*(&[^=&\s]+(=[^&\s]*)?)*')


def _render_body_text(text, content_type=''):
    """Render a decoded body: JSON and form data structurally, anything else as a summary."""
    stripped = text.strip()
    if not stripped:
        return ''
    try:
        parsed = json.loads(stripped)
    except ValueError:
        pass
    else:
        return json.dumps(_sanitize_structure(parsed), indent=2)

    if 'x-www-form-urlencoded' in content_type.lower() or _FORM_BODY_RE.fullmatch(stripped):
        pairs = parse_qsl(stripped, keep_blank_values=True)
        if pairs:
            return _render_pairs(pairs, 0, '\n')

    return _body_summary(len(text), 'chars', content_type)


def _body_summary(size, unit, content_type):
    kind = _content_type_label(content_type)
    return f'[body omitted: {size} {unit}{", " + kind if kind else ""}]'


def _content_type_label(content_type):
    if not content_type:
        return ''
    media_type = str(content_type).split(';', 1)[0].strip()
    return media_type if re.fullmatch(r'[\w.+-]+/[\w.+-]+', media_type) else ''


def _header_value(headers, name):
    try:
        for key, value in headers.items():
            if str(key).lower() == name:
                return str(value)
    except AttributeError:
        pass
    return ''


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
    def format_request(cls, request):
        """Format an HTTP request for debug output"""
        lines = []

        lines.append("")
        lines.append(f"{cls.CYAN}{cls.BOLD}{'─' * 70}{cls.RESET}")
        lines.append(f"{cls.GREEN}{cls.BOLD}▶ REQUEST{cls.RESET}")
        lines.append(f"{cls.CYAN}{cls.BOLD}{'─' * 70}{cls.RESET}")
        method = str(getattr(request, 'method', '') or '')
        if not re.fullmatch(r'[A-Za-z]{1,16}', method):
            method = '[method]'
        request_url = _sanitize_url(getattr(request, 'url', ''))
        lines.append(f"  {cls.BOLD}{method}{cls.RESET} {cls.BLUE}{request_url}{cls.RESET}")

        headers = getattr(request, 'headers', None) or {}
        lines.append(f"\n  {cls.YELLOW}Headers:{cls.RESET}")
        for key, value in cls._mask_sensitive_headers(headers).items():
            lines.append(f"    {cls.DIM}{key}:{cls.RESET} {value}")

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
        status_color = cls._get_status_color(status_code)
        reason = _truncate(_redact_sensitive_debug_text(str(getattr(response, 'reason', '') or '')), 80)
        headers = getattr(response, 'headers', None) or {}

        details = []
        elapsed = getattr(response, 'elapsed', None)
        if elapsed is not None and hasattr(elapsed, 'total_seconds'):
            details.append(f"{elapsed.total_seconds() * 1000:.0f} ms")
        for name in _REQUEST_ID_HEADERS:
            request_id = _header_value(headers, name)
            if request_id:
                details.append(f"request id {_safe_text(request_id)}")
                break
        detail_str = f" {cls.DIM}({', '.join(details)}){cls.RESET}" if details else ''

        lines.append(f"\n  {cls.MAGENTA}{cls.BOLD}◀ RESPONSE{cls.RESET}")
        lines.append(f"  {status_color}{cls.BOLD}{status_code}{cls.RESET} {reason}{detail_str}")

        lines.append(f"\n  {cls.YELLOW}Headers:{cls.RESET}")
        for key, value in cls._mask_sensitive_headers(headers).items():
            lines.append(f"    {cls.DIM}{key}:{cls.RESET} {value}")

        lines.append(f"\n  {cls.YELLOW}Body:{cls.RESET}")
        body_str = cls._format_response_body(response, _header_value(headers, 'content-type'))
        for line in body_str.split('\n'):
            lines.append(f"    {line}")

        lines.append(f"{cls.CYAN}{cls.BOLD}{'─' * 70}{cls.RESET}")
        lines.append("")

        return SanitizedText('\n'.join(lines))

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
        """Format a request body: JSON and form data structurally, anything else as a summary"""
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
        """Return parsed data with every non-allowlisted value redacted"""
        return _sanitize_structure(data)

    @classmethod
    def _mask_sensitive_headers(cls, headers):
        """Return headers with every non-allowlisted value fully redacted"""
        result = {}
        try:
            items = list(headers.items())
        except AttributeError:
            return result
        for key, value in items:
            display = _display_key(key)
            norm = _normalize_name(key)
            if value in (None, ''):
                result[display] = value
            elif norm not in _SAFE_HEADERS:
                result[display] = REDACTED
            elif norm == 'location':
                result[display] = _truncate(_sanitize_url(value))
            else:
                result[display] = _safe_text(value)
        return result


# --------------------------------------------------------------------------
# Free-text redaction (log messages, third-party records, exception text)
# --------------------------------------------------------------------------

_SAML_HTML_INPUT_RE = re.compile(r'<input\b[^>]*>', re.IGNORECASE | re.DOTALL)
_HTML_ATTR_RE = re.compile(
    r'''\b(name|id|value)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)''',
    re.IGNORECASE,
)
_ASSUME_ROLE_WITH_SAML_RESPONSE_BODY_RE = re.compile(
    r"(Response body:\s*).*AssumeRoleWithSAMLResponse.*",
    re.IGNORECASE | re.DOTALL,
)
_ASSUME_ROLE_WITH_SAML_RESPONSE_XML_RE = re.compile(
    r"<AssumeRoleWithSAMLResponse\b.*?</AssumeRoleWithSAMLResponse>",
    re.IGNORECASE | re.DOTALL,
)
_XML_ELEMENT_RE = re.compile(
    r'<(?P<tag>[A-Za-z_][\w:.-]*)(?P<attrs>[^<>]*)>(?P<body>[^<]*)</(?P=tag)>',
)
_AUTH_SCHEME_RE = re.compile(
    r'''\b(Bearer|Basic|SSWS|Digest|Negotiate|NTLM|AWS4-HMAC-SHA256)\s+[A-Za-z0-9._~+/=:-]{8,}''',
    re.IGNORECASE,
)
_QUERY_PAIR_RE = re.compile(r'''(?P<pre>[?&])(?P<key>[^=&\s#'"<>]+)=(?P<val>[^&\s#'"<>]*)''')
_COLON_LINE_PAIR_RE = re.compile(
    r'''(?P<q>["']?)(?P<key>\b[A-Za-z_][\w.-]{0,63})(?P=q)(?P<sep>[ \t]*:[ \t]*)(?!["'\s])(?P<val>[^\n,}\]]+)''',
)
_KEY_VALUE_RE = re.compile(
    r'''(?P<q>["']?)(?P<key>\b[A-Za-z_][\w.-]{0,63})(?P=q)(?P<sep>\s*[:=]\s*)'''
    r'''(?P<val>b?"(?:[^"\\]|\\.)*"|b?'(?:[^'\\]|\\.)*'|[^\s&,;}\])'"<>]+)''',
)
_ASSIGNMENT_RE = re.compile(r'([A-Za-z_][\w.-]{0,63})\s*=')
_ENCODED_TOKEN_RE = re.compile(r'\S*%[0-9A-Fa-f]{2}\S*')


def _redact_quoted(value):
    if value[:1] == 'b' and value[1:2] in ('"', "'"):
        return 'b' + value[1] + REDACTED + value[1]
    if value[:1] in ('"', "'"):
        return value[0] + REDACTED + value[0]
    return REDACTED


def _redact_input_tag(match):
    tag = match.group(0)
    attrs = {m.group(1).lower(): m.group(2).strip('"\'') for m in _HTML_ATTR_RE.finditer(tag)}
    field = attrs.get('name') or attrs.get('id') or ''
    if 'value' not in attrs or _is_safe_field(field):
        return tag
    return _HTML_ATTR_RE.sub(
        lambda m: f'{m.group(1)}="{REDACTED}"' if m.group(1).lower() == 'value' else m.group(0),
        tag,
    )


def _redact_query_pair(match):
    if not match.group('val') or match.group('val') == REDACTED or _is_safe_field(match.group('key')):
        return match.group(0)
    return f"{match.group('pre')}{match.group('key')}={REDACTED}"


def _redact_core(text):
    text = _ASSUME_ROLE_WITH_SAML_RESPONSE_BODY_RE.sub(r"\1[AWS STS SAML response redacted]", text)
    text = _ASSUME_ROLE_WITH_SAML_RESPONSE_XML_RE.sub("[AWS STS SAML response redacted]", text)
    text = _SAML_HTML_INPUT_RE.sub(_redact_input_tag, text)
    text = _XML_ELEMENT_RE.sub(
        lambda m: (f"<{m.group('tag')}{m.group('attrs')}>{REDACTED}</{m.group('tag')}>"
                   if _is_sensitive_name(m.group('tag').rsplit(':', 1)[-1]) and m.group('body')
                   else m.group(0)),
        text,
    )
    text = _AUTH_SCHEME_RE.sub(lambda m: f'{m.group(1)} {REDACTED}', text)
    text = _JWT_RE.sub(REDACTED, text)
    text = _QUERY_PAIR_RE.sub(_redact_query_pair, text)
    text = _COLON_LINE_PAIR_RE.sub(
        lambda m: (f"{m.group('q')}{m.group('key')}{m.group('q')}{m.group('sep')}{REDACTED}"
                   if _is_sensitive_name(m.group('key')) else m.group(0)),
        text,
    )
    text = _KEY_VALUE_RE.sub(
        lambda m: (f"{m.group('q')}{m.group('key')}{m.group('q')}{m.group('sep')}"
                   f"{_redact_quoted(m.group('val'))}"
                   if _is_sensitive_name(m.group('key')) else m.group(0)),
        text,
    )
    text = _LONG_BLOB_RE.sub(lambda m: REDACTED if _looks_like_blob(m.group(0)) else m.group(0), text)
    return text


def _decode_repeatedly(token):
    for _ in range(3):
        decoded = unquote(token)
        if decoded == token:
            break
        token = decoded
    return token


def _redact_encoded_token(match):
    token = match.group(0)
    decoded = _decode_repeatedly(token)
    if decoded == token:
        return token
    redacted = _redact_core(decoded)
    return token if redacted == decoded else redacted


def _redact_sensitive_debug_text(text):
    """Best-effort redaction of secrets in free text.

    Query parameters are redacted unless allowlisted; other ``key=value``,
    ``key: value``, quoted-key, XML element and HTML input forms are redacted
    when the field name looks sensitive. Percent-encoded fragments are decoded
    and checked too. Authorization schemes, JWTs and long credential-like
    blobs are redacted wherever they appear.
    """
    if not isinstance(text, str):
        text = str(text)
    text = _ENCODED_TOKEN_RE.sub(_redact_encoded_token, text)
    return _redact_core(text)


def _sanitize_log_arg(arg):
    """Render a log-call argument without exposing secrets it may hold."""
    if arg is None or isinstance(arg, (bool, int, float)):
        return arg
    if isinstance(arg, (bytes, bytearray)):
        return f'[{len(arg)} bytes omitted]'
    if isinstance(arg, (Mapping, list, tuple, set, frozenset)):
        return _sanitize_structure(arg)
    try:
        text = arg if isinstance(arg, str) else str(arg)
    except Exception:  # noqa: BLE001
        return '[unrepresentable value omitted]'
    stripped = text.lstrip()
    if stripped[:1] in ('<',) or stripped[:3] in ("b'<", 'b"<'):
        return f'[{len(text)} chars of markup omitted]'
    if stripped[:1] in ('{', '['):
        try:
            return json.dumps(_sanitize_structure(json.loads(stripped)))
        except ValueError:
            pass
    return _redact_sensitive_debug_text(text)


def _sanitize_record(record):
    """Replace a record's message, arguments and exception text with redacted text."""
    args = record.args
    if isinstance(record.msg, SanitizedText) and not args:
        record.gimme_aws_creds_sanitized = True
    else:
        _redact_record_message(record)
    if record.exc_info:
        record.exc_text = ''.join(traceback.format_exception(*record.exc_info)).rstrip('\n')
        record.exc_info = None
    if record.exc_text:
        record.exc_text = _redact_sensitive_debug_text(record.exc_text)
    if record.stack_info:
        record.stack_info = _redact_sensitive_debug_text(record.stack_info)


def _redact_record_message(record):
    args = record.args
    msg = record.msg if isinstance(record.msg, str) else str(record.msg)
    if args:
        if isinstance(args, Mapping):
            safe_args = _sanitize_structure(args)
        else:
            safe_args = tuple(_sanitize_log_arg(a) for a in args)
        try:
            msg = msg % safe_args
        except (TypeError, ValueError, KeyError):
            msg = f'{msg} {safe_args!r}'
    record.msg = _redact_sensitive_debug_text(msg)
    record.args = None


def _make_redacting_record_factory(base_factory):
    def redacting_record_factory(*args, **kwargs):
        record = base_factory(*args, **kwargs)
        try:
            _sanitize_record(record)
        except Exception:  # noqa: BLE001 - never let raw text through on failure
            record.msg = '[log record omitted: redaction failed]'
            record.args = None
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return record

    redacting_record_factory.gimme_aws_creds_redacting = True
    redacting_record_factory.base_factory = base_factory
    return redacting_record_factory


def install_redacting_record_factory():
    """Make every new log record carry only redacted text. Idempotent."""
    current = logging.getLogRecordFactory()
    if getattr(current, 'gimme_aws_creds_redacting', False):
        return current
    factory = _make_redacting_record_factory(current)
    logging.setLogRecordFactory(factory)
    return factory


# --------------------------------------------------------------------------
# Resolved configuration
# --------------------------------------------------------------------------

# Config object attributes, profile keys, CLI destinations and environment
# variables whose values are shown. Anything else is redacted.
_SAFE_CONFIG_KEYS = frozenset((
    # Config object attributes
    'OKTA_CONFIG', 'conf_profile', 'username', 'verify_ssl_certs', 'app_url',
    'resolve', 'remember_device', 'output_format', 'force_classic',
    'open_browser', 'disable_keychain', 'enable_alicloud', 'roles',
    'cred_profile', 'debug', 'action_configure', 'action_list_profiles',
    'action_list_roles', 'action_store_json_creds', 'action_register_device',
    'action_setup_fido_authenticator', 'action_output_format',
    # Profile (conf_dict) keys
    'okta_org_url', 'okta_auth_server', 'client_id', 'gimme_creds_server',
    'aws_appname', 'aws_rolename', 'write_aws_creds', 'okta_username',
    'resolve_aws_alias', 'include_path', 'preferred_mfa_type',
    'preferred_mfa_provider', 'preferred_mfa_factor_id', 'aws_default_duration',
    'aws_region', 'enable_keychain', 'duo_universal_factor',
    'alibaba_cloud_default_duration', 'alicloud_region', 'alicloud_saml_url',
    'inherits', 'okta_platform', 'device_flow_scope', 'device_flow_timeout',
    # CLI destinations
    'profile', 'insecure', 'aws_cred_profile',
    # Environment variables
    'OKTA_USERNAME', 'OKTA_AUTH_SERVER', 'GIMME_AWS_CREDS_CLIENT_ID',
    'GIMME_AWS_CREDS_CRED_PROFILE', 'GIMME_AWS_CREDS_ENABLE_ALICLOUD',
    'GIMME_AWS_CREDS_OUTPUT_FORMAT', 'AWS_DEFAULT_DURATION', 'AWS_STS_REGION',
    'AWS_SHARED_CREDENTIALS_FILE', 'AWS_ROLE_ARN',
))

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


def _mask_config_value(key, value):
    """Show a config value only when its key is allowlisted and not secret-like."""
    if value is None or value == '' or value is False:
        return value
    if str(key) not in _SAFE_CONFIG_KEYS or _is_sensitive_name(key):
        return REDACTED
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_mask_config_value(key, item) for item in value]
    text = str(value)
    if re.match(r'[A-Za-z][A-Za-z0-9+.-]*://', text):
        return _sanitize_url(text)
    return _safe_text(text)


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

    Values are shown only for allowlisted, non-secret keys.

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
        for dest in sorted(cli_args_provided.keys()):
            value = cli_args_provided[dest]
            display = _mask_config_value(dest, value)
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
        for env_name in sorted(env_used.keys()):
            info = env_used[env_name]
            display = _mask_config_value(env_name, info.get('value'))
            lines.append(
                f"    {env_name} = {display} "
                f"{df.DIM}-> {info.get('sets', '')}{df.RESET}"
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
        for key in sorted(conf_dict.keys()):
            value = conf_dict[key]
            display = _mask_config_value(key, value)
            if key in cli_overrides_applied:
                source = f"cli: {cli_overrides_applied[key]}"
            elif key in env_overrides_applied:
                source = f"env: {env_overrides_applied[key]}"
            elif key in profile_sources:
                source = f"profile: {profile_sources[key]}"
            else:
                source = "computed/default"
            lines.append(_format_kv_line(key, display, source))
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
            logger.debug('[debug output unavailable: %s]', type(exc).__name__)
        return response

    return debug_response_hook


class _CleanDebugFormatter(logging.Formatter):
    """Prints debug records bare and every record through the redactor."""

    def format(self, record):
        if (getattr(record, 'gimme_aws_creds_sanitized', False)
                and isinstance(record.msg, SanitizedText) and not record.args):
            message = str(record.msg)
            if record.exc_text:
                message = f'{message}\n{record.exc_text}'
            return message
        if record.levelno == logging.DEBUG:
            text = record.getMessage()
            if record.exc_text:
                text = f'{text}\n{record.exc_text}'
        else:
            text = super().format(record)
        return _redact_sensitive_debug_text(text)

    def formatException(self, ei):
        return _redact_sensitive_debug_text(super().formatException(ei))

    def formatStack(self, stack_info):
        return _redact_sensitive_debug_text(super().formatStack(stack_info))


def setup_debug_logging():
    """Configure logging for debug output with a clean, redacted format"""
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
    root_logger.addHandler(console_handler)

    # Set the gimme-aws-creds logger
    gac_logger = logging.getLogger('gimme_aws_creds')
    gac_logger.setLevel(logging.DEBUG)
