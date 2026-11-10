"""Regression tests: --debug output must never contain authentication secrets.

Every secret below is a unique synthetic marker. Tests capture what a user
would see (stdout and stderr) and every log record emitted, then assert that
no marker, and no 8-character piece of a marker, survives. They also assert
that safe diagnostics (method, path, status, timing, request ID) remain.

All HTTP traffic is served by an in-process adapter; nothing leaves the host.
"""
import io
import json
import logging
import os
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from datetime import timedelta
from unittest.mock import patch

import requests
from requests.adapters import BaseAdapter

from gimme_aws_creds import debug_formatter
from gimme_aws_creds.common import create_http_session
from gimme_aws_creds.debug_formatter import (
    DebugFormatter,
    _mask_config_value,
    _redact_sensitive_debug_text,
    format_resolved_configuration,
    setup_debug_logging,
)
from gimme_aws_creds.main import GimmeAWSCreds
from gimme_aws_creds.okta_classic import OktaClassicClient
from gimme_aws_creds.okta_identity_engine import OktaIdentityEngine
from tests.user_interface_mock import MockUserInterface

ORG = 'https://example.okta.test'

# Unique synthetic secrets. None share an 8-character window with each other
# or with ordinary debug output.
PASSWORD = 'pwQ7vZ2kLm9xTr4N'
SESSION_TOKEN = 'stK3wY8pRf1aHq6D'
DEVICE_CODE = 'dcM4nB7cXz2LkP9W'
USER_CODE = 'ucH5jV1tGr8EsY3Q'
MFA_CLI = 'mcA6uJ3fNw7ZpD2K'
MFA_ENV = 'meR8yT4qBv1XcL6H'
MFA_CONF = 'mfG2kS9hWn5PjF7U'
OKTA_PASSWORD_ENV = 'opF9dQ3mZr6TwK1B'
XSRF = 'xsJ1pL6vCy4RnM8E'
STATE_TOKEN = 'saN2wE7gKu5HbT3V'
PASSCODE = 'pcZ5rU1kDx8QmG4S'
NESTED = 'neW3tH9bJq2VyA6C'
ACCESS_TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.atK8fP2rYm5LwN7D'
ID_TOKEN = 'itB4sX6nQe1GhR9M'
AUTH_BEARER = 'abP7cW2vLk9TzF4J'
AUTH_SSWS = 'asD1mY8qHr3NxB6K'
COOKIE_SID = 'ckS5gT2wMp7VbQ1H'
COOKIE_DT = 'cdL9eF4jRx6ZnW3A'
SET_COOKIE = 'scV3hK8tBq1YmP5G'
OKTA_SESSION_HEADER = 'ohN6rC2xDw9LfT4E'
SAML_VALUE = 'smQ4yJ7pKz1HcV8R'
VERIFY_URI_CODE = 'vuE2bN5mXt9GqL3W'

SECRETS = {
    name: value for name, value in globals().items()
    if name.isupper() and isinstance(value, str) and name not in ('ORG',)
}


def _windows(secret, size=8):
    return {secret[i:i + size] for i in range(len(secret) - size + 1)}


class LeakAssertions:
    def assertNoSecrets(self, text, secrets=None):
        secrets = SECRETS if secrets is None else secrets
        for name, secret in secrets.items():
            # The JWT header and payload are fixed public strings; check its
            # unique signature part only.
            check = secret.rsplit('.', 1)[-1]
            for window in _windows(check):
                self.assertNotIn(
                    window, text,
                    f'part of synthetic secret {name} survived in debug output',
                )


def _response(request, status=200, body=b'', headers=None, reason='OK'):
    response = requests.Response()
    response.status_code = status
    response.reason = reason
    response.headers.update(headers or {})
    response._content = body if isinstance(body, bytes) else body.encode()
    response.request = request
    response.url = request.url
    return response


class FakeAdapter(BaseAdapter):
    """Serves canned responses chosen by (method, path)."""

    def __init__(self, routes):
        super().__init__()
        self.routes = routes
        self.requests = []

    def send(self, request, **kwargs):
        self.requests.append(request)
        path = requests.utils.urlparse(request.url).path
        status, body, headers = self.routes[(request.method, path)]
        if callable(body):
            body = body(request)
        return _response(request, status, body, headers)

    def close(self):
        pass


@contextmanager
def debug_capture():
    """Enable --debug logging and capture stdout, stderr and every log record."""
    root = logging.getLogger()
    gac = logging.getLogger('gimme_aws_creds')
    saved = (root.handlers[:], root.level, gac.level, logging.getLogRecordFactory())
    stdout, stderr = io.StringIO(), io.StringIO()
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            text = record.getMessage()
            if record.exc_text:
                text += '\n' + record.exc_text
            records.append(text)

    try:
        with patch('sys.stderr', stderr), redirect_stdout(stdout):
            setup_debug_logging()
            root.addHandler(Capture(level=logging.DEBUG))
            yield lambda: '\n'.join([stdout.getvalue(), stderr.getvalue()] + records)
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in saved[0]:
            root.addHandler(handler)
        root.setLevel(saved[1])
        gac.setLevel(saved[2])
        logging.setLogRecordFactory(saved[3])


class TestAuditReproductions(LeakAssertions, unittest.TestCase):
    """The five cases from the security review, at the formatter level."""

    @staticmethod
    def _prepared(method, url, **kwargs):
        return requests.Request(method, url, **kwargs).prepare()

    def test_form_encoded_password(self):
        out = DebugFormatter.format_request(self._prepared(
            'POST', ORG + '/user/verify_password',
            data=f'_xsrfToken={XSRF}&password={PASSWORD}',
            headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
        ))
        self.assertNoSecrets(out)
        self.assertIn('password=[REDACTED]', out)
        self.assertIn('POST https://example.okta.test/user/verify_password', out)

    def test_session_token_in_url(self):
        out = DebugFormatter.format_request(self._prepared(
            'GET', ORG + f'/home/amazon_aws/app/1?sessionToken={SESSION_TOKEN}'))
        self.assertNoSecrets(out)
        self.assertIn('/home/amazon_aws/app/1?sessionToken=[REDACTED]', out)

    def test_device_poll_request(self):
        out = DebugFormatter.format_request(self._prepared(
            'POST', ORG + '/oauth2/v1/token',
            data={'client_id': 'synthetic-client', 'device_code': DEVICE_CODE,
                  'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'},
        ))
        self.assertNoSecrets(out)
        self.assertIn('client_id=synthetic-client', out)
        self.assertIn('grant_type=urn%3Aietf', out)

    def test_device_authorization_response(self):
        request = self._prepared('POST', ORG + '/oauth2/v1/device/authorize')
        response = _response(request, body=json.dumps({
            'device_code': DEVICE_CODE,
            'user_code': USER_CODE,
            'verification_uri': ORG + '/activate',
            'verification_uri_complete': ORG + f'/activate?user_code={VERIFY_URI_CODE}',
            'expires_in': 600,
            'interval': 5,
        }), headers={'Content-Type': 'application/json'})
        out = DebugFormatter.format_response(response)
        self.assertNoSecrets(out)
        self.assertIn('"verification_uri": "https://example.okta.test/activate"', out)
        self.assertIn('"expires_in": 600', out)

    def test_resolved_configuration_mfa_code(self):
        class Config:
            OKTA_CONFIG = '/synthetic/config'
            conf_profile = 'DEFAULT'
            mfa_code = MFA_CLI
            ui = MockUserInterface(environ={'OKTA_MFA_CODE': MFA_ENV})
            _cli_args_provided = {'mfa_code': MFA_CLI}
            _env_used_in_init = {}
            _inheritance_chain = []
            _profile_value_sources = {}

        out = format_resolved_configuration(
            Config(), {'okta_mfa_code': MFA_ENV, 'client_id': 'visible-client'},
            env_overrides_applied={'okta_mfa_code': 'OKTA_MFA_CODE'},
        )
        self.assertNoSecrets(out)
        self.assertIn('--mfa-code = [REDACTED]', out)
        self.assertIn('visible-client', out)


class TestHeaderRedaction(LeakAssertions, unittest.TestCase):

    def test_credential_headers_fully_redacted_in_any_case(self):
        headers = {
            'Authorization': f'Bearer {AUTH_BEARER}',
            'authorization': f'SSWS {AUTH_SSWS}',
            'COOKIE': f'sid={COOKIE_SID}; DT={COOKIE_DT}',
            'X-Okta-Session-Id': OKTA_SESSION_HEADER,
            'x-custom-unknown': NESTED,
            'Content-Type': 'application/json',
            'X-Okta-Request-Id': 'req-abc123',
        }
        out = DebugFormatter._mask_sensitive_headers(headers)
        self.assertNoSecrets(json.dumps(out))
        for name in ('Authorization', 'authorization', 'COOKIE',
                     'X-Okta-Session-Id', 'x-custom-unknown'):
            self.assertEqual(out[name], '[REDACTED]')
        self.assertEqual(out['Content-Type'], 'application/json')
        self.assertEqual(out['X-Okta-Request-Id'], 'req-abc123')

    def test_short_and_long_values_both_fully_redacted(self):
        for value in ('Bearer x', 'Bearer ' + AUTH_BEARER * 4):
            with self.subTest(length=len(value)):
                self.assertEqual(
                    DebugFormatter._mask_sensitive_headers({'Authorization': value}),
                    {'Authorization': '[REDACTED]'},
                )

    def test_location_header_query_and_fragment_redacted(self):
        out = DebugFormatter._mask_sensitive_headers({
            'Location': ORG + f'/app/sso?SessionToken={SESSION_TOKEN}#id_token={ID_TOKEN}',
        })
        self.assertNoSecrets(out['Location'])
        self.assertEqual(
            out['Location'],
            'https://example.okta.test/app/sso?SessionToken=[REDACTED]#[REDACTED]',
        )


class TestStructuredBodies(LeakAssertions, unittest.TestCase):

    def test_nested_json_values_redacted_unless_allowlisted(self):
        body = json.dumps({
            'stateToken': STATE_TOKEN,
            'passCode': PASSCODE,
            'factorType': 'token:software:totp',
            'credentials': {'password': {'value': PASSWORD}},
            'profile': {'answer': NESTED, 'items': [{'anything': NESTED}]},
            'unknownField': ID_TOKEN,
            'status': 'MFA_REQUIRED',
            'number': 123456,
        })
        out = DebugFormatter._format_body(body)
        self.assertNoSecrets(out)
        self.assertIn('"factorType": "token:software:totp"', out)
        self.assertIn('"status": "MFA_REQUIRED"', out)
        self.assertIn('"number": "[REDACTED]"', out)

    def test_allowlisted_field_holding_secret_assignment_is_redacted(self):
        out = DebugFormatter._mask_sensitive_dict({
            'name': f'password={PASSWORD}',
            'errorSummary': f'see /x?sessionToken={SESSION_TOKEN}',
            'message': f'Bearer {AUTH_BEARER}',
            'label': 'Okta Verify',
        })
        self.assertNoSecrets(json.dumps(out))
        self.assertEqual(out['label'], 'Okta Verify')

    def test_escaped_json_key_variant_redacted(self):
        body = '{"session\\u0054oken": "%s", "SESSIONTOKEN": "%s"}' % (SESSION_TOKEN, SESSION_TOKEN)
        self.assertNoSecrets(DebugFormatter._format_body(body))

    def test_form_body_case_and_encoding_variants(self):
        body = (f'PASSWORD={PASSWORD}&pass%77ord={PASSWORD}&pass+word={PASSWORD}'
                f'&mfa_code={MFA_CLI}&Session-Token={SESSION_TOKEN}')
        out = DebugFormatter._format_body(body)
        self.assertNoSecrets(out)

    def test_query_case_and_encoding_variants(self):
        nested = requests.utils.quote(f'/app?sessionToken={SESSION_TOKEN}', safe='')
        double = requests.utils.quote(nested, safe='')
        for query in (
            f'SESSIONTOKEN={SESSION_TOKEN}',
            f'session%54oken={SESSION_TOKEN}',
            f'x=1;sessionToken={SESSION_TOKEN}',
            f'fromURI={nested}',
            f'fromURI={double}',
            f'redirect_uri=https%3A%2F%2Fu%3A{PASSWORD}%40h.test%2Fcb%3Fcode%3D{USER_CODE}',
        ):
            with self.subTest(query=query):
                out = DebugFormatter.format_request(
                    requests.Request('GET', ORG + '/login/x?' + query).prepare())
                self.assertNoSecrets(out)
                self.assertIn('GET https://example.okta.test/login/x?', out)

    def test_url_userinfo_and_secret_path_segment_redacted(self):
        url = f'https://user:{PASSWORD}@example.okta.test/a/{ACCESS_TOKEN}/b;jsessionid={COOKIE_SID}'
        out = DebugFormatter.format_request(requests.Request('GET', url).prepare())
        self.assertNoSecrets(out)
        self.assertIn('https://[REDACTED]@example.okta.test/a/[REDACTED]/b;[REDACTED]', out)

    def test_unparsed_bodies_are_summarized_not_printed(self):
        html = (f'<form><input type="hidden" name="SAMLResponse" value="{SAML_VALUE}"/>'
                f'<input name="password" value="{PASSWORD}"></form>')
        request = requests.Request('GET', ORG + '/app/sso').prepare()
        response = _response(request, body=html, headers={'Content-Type': 'text/html'})
        out = DebugFormatter.format_response(response)
        self.assertNoSecrets(out)
        self.assertIn(f'[body omitted: {len(html)} chars, text/html]', out)
        self.assertEqual(DebugFormatter._format_body(b'\xff\xfe' + PASSWORD.encode()),
                         '[body omitted: 18 bytes]')


class TestConfigValues(unittest.TestCase):

    def test_secret_and_unknown_keys_fully_redacted(self):
        for key in ('mfa_code', 'okta_mfa_code', 'OKTA_MFA_CODE', 'okta_password',
                    'OKTA_PASSWORD', 'device_token', 'api_key', 'some_new_key'):
            with self.subTest(key=key):
                self.assertEqual(_mask_config_value(key, MFA_CLI), '[REDACTED]')

    def test_allowlisted_url_value_is_sanitized(self):
        self.assertEqual(
            _mask_config_value('app_url', ORG + f'/home/app?sessionToken={SESSION_TOKEN}'),
            'https://example.okta.test/home/app?sessionToken=[REDACTED]',
        )


class TestFreeText(LeakAssertions, unittest.TestCase):

    def test_free_text_variants(self):
        cases = [
            f'"GET /home/amazon_aws/app/1?sessionToken={SESSION_TOKEN} HTTP/1.1" 200 None',
            f'Authorization: Bearer {AUTH_BEARER}',
            f'cookie: sid={COOKIE_SID}; DT={COOKIE_DT}',
            f'Cookie:sid={COOKIE_SID}; DT={COOKIE_DT}',
            f"{{'password': '{PASSWORD}', 'passCode': b'{PASSCODE}'}}",
            f'"device_code":"{DEVICE_CODE}"',
            f'mfa_code={MFA_CLI} user_code: {USER_CODE}',
            f'<SessionToken>{SESSION_TOKEN}</SessionToken>',
            f'<input value="{SAML_VALUE}" name="SAMLResponse">',
            f'redirect to /x%3FsessionToken%3D{SESSION_TOKEN}',
            f'token {ACCESS_TOKEN}',
        ]
        for text in cases:
            with self.subTest(text=text[:30]):
                self.assertNoSecrets(_redact_sensitive_debug_text(text))

    def test_safe_text_untouched(self):
        text = 'POST /api/v1/authn status=MFA_REQUIRED token_type=Bearer 200'
        self.assertEqual(_redact_sensitive_debug_text(text), text)


class TestEndToEndDebugRuns(LeakAssertions, unittest.TestCase):
    """Real client code paths with the debug hook, served by a fake adapter."""

    def setUp(self):
        self.ui = MockUserInterface(argv=['--debug'])

    def _mount(self, session, routes):
        adapter = FakeAdapter(routes)
        session.mount('https://', adapter)
        return adapter

    def test_oie_device_authorization_and_polling(self):
        token_body = json.dumps({
            'access_token': ACCESS_TOKEN, 'id_token': ID_TOKEN,
            'token_type': 'Bearer', 'expires_in': 3600, 'scope': 'openid',
        })
        routes = {
            ('POST', '/oauth2/v1/device/authorize'): (200, json.dumps({
                'device_code': DEVICE_CODE, 'user_code': USER_CODE,
                'verification_uri': ORG + '/activate',
                'verification_uri_complete': ORG + f'/activate?user_code={USER_CODE}',
                'expires_in': 600, 'interval': 5,
            }), {'Content-Type': 'application/json', 'X-Okta-Request-Id': 'oie-req-1'}),
            ('POST', '/oauth2/v1/token'): (200, token_body,
                                           {'Content-Type': 'application/json',
                                            'Set-Cookie': f'sid={SET_COOKIE}; Path=/'}),
        }
        with debug_capture() as output:
            client = OktaIdentityEngine(self.ui, ORG, 'synthetic-client', debug=True)
            self._mount(client._http_client, routes)
            started = client._start_device_flow()
            tokens = client._get_user_tokens(started['apiResponse']['device_code'])
        self.assertEqual(tokens['id_token'], ID_TOKEN)
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('POST https://example.okta.test/oauth2/v1/device/authorize', text)
        self.assertIn('POST https://example.okta.test/oauth2/v1/token', text)
        self.assertIn('request id oie-req-1', text)
        self.assertRegex(text, r'200 OK \(\d+ ms')
        self.assertIn('Set-Cookie: [REDACTED]', text)

    def test_classic_session_token_saml_and_nested_json(self):
        saml_html = (
            '<html><body><form method="post" action="https://signin.aws.amazon.com/saml">'
            f'<input type="hidden" name="SAMLResponse" value="{SAML_VALUE}"/>'
            '<input type="hidden" name="RelayState" value=""/></form></body></html>'
        )
        routes = {
            ('GET', '/home/amazon_aws/app/1'): (200, saml_html, {'Content-Type': 'text/html'}),
            ('POST', '/api/v1/authn/factors/f1/verify'): (
                401, json.dumps({'errorCode': 'E0000068', 'errorSummary': 'Invalid Passcode',
                                 'stateToken': STATE_TOKEN}),
                {'Content-Type': 'application/json'}),
        }
        with debug_capture() as output:
            client = OktaClassicClient(self.ui, ORG, use_keyring=False, debug=True)
            self._mount(client._http_client, routes)
            saml = client.get_saml_response(
                ORG + f'/home/amazon_aws/app/1?sessionToken={SESSION_TOKEN}')
            client._http_client.post(
                ORG + '/api/v1/authn/factors/f1/verify',
                json={'stateToken': STATE_TOKEN, 'passCode': PASSCODE,
                      'nested': {'deep': [{'password': PASSWORD, 'answer': NESTED}]}},
                headers={'Authorization': f'SSWS {AUTH_SSWS}',
                         'Cookie': f'sid={COOKIE_SID}; DT={COOKIE_DT}'},
            )
        self.assertEqual(saml['SAMLResponse'], SAML_VALUE)
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('GET https://example.okta.test/home/amazon_aws/app/1?sessionToken=[REDACTED]', text)
        self.assertIn('"errorCode": "E0000068"', text)
        self.assertIn('401', text)

    def test_classic_fido_setup_password_form(self):
        page = ('<html><body><input type="hidden" id="_xsrfToken" '
                f'value="{XSRF}"/></body></html>')
        routes = {
            ('POST', '/user/verify_password'): (200, '{}', {'Content-Type': 'application/json'}),
            ('GET', '/login/second-factor'): (200, '<html></html>', {'Content-Type': 'text/html'}),
        }
        with debug_capture() as output:
            client = OktaClassicClient(self.ui, ORG, use_keyring=False, debug=True)
            adapter = self._mount(client._http_client, routes)
            page_response = _response(requests.Request('GET', ORG + '/x').prepare(), body=page)
            with patch.object(client, '_get_username_password_creds',
                              return_value={'username': 'user@example.test', 'password': PASSWORD}):
                client._verify_password(page_response)
        self.assertIn(PASSWORD, adapter.requests[0].body)
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('password=[REDACTED]', text)
        self.assertIn('POST https://example.okta.test/user/verify_password', text)

    def test_cli_and_env_mfa_code_in_resolved_configuration(self):
        environ = {'OKTA_MFA_CODE': MFA_ENV, 'OKTA_PASSWORD': OKTA_PASSWORD_ENV,
                   'OKTA_USERNAME': 'user@example.test'}
        ui = MockUserInterface(environ=environ,
                               argv=['gimme-aws-creds', '--profile', 'p', '--debug', '--mfa-code', MFA_CLI])
        with open(os.path.join(ui.HOME, '.okta_aws_login_config'), 'w') as f:
            f.write(f'[p]\nokta_org_url = {ORG}\nclient_id = cfg-client\n'
                    f'okta_mfa_code = {MFA_CONF}\n')
        with debug_capture() as output:
            with patch.object(GimmeAWSCreds, 'get_resolver', return_value=None):
                GimmeAWSCreds(ui=ui).generate_config()
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('RESOLVED CONFIGURATION', text)
        self.assertIn('cfg-client', text)
        self.assertIn('--mfa-code = [REDACTED]', text)

    def test_third_party_records_and_tracebacks_are_redacted(self):
        with debug_capture() as output:
            logging.getLogger('urllib3.connectionpool').debug(
                '%s://%s:%s "%s %s %s" %s %s', 'https', 'example.okta.test', 443, 'GET',
                f'/home/amazon_aws/app/1?sessionToken={SESSION_TOKEN}', 'HTTP/1.1', 200, None)
            logging.getLogger('botocore.endpoint').debug(
                'Making request with params: %s',
                {'body': {'Action': 'AssumeRoleWithSAML', 'SAMLAssertion': SAML_VALUE},
                 'headers': {'Authorization': f'Bearer {AUTH_BEARER}'}})
            logging.getLogger('botocore.parsers').debug('Response body:\n%s',
                                                         f'<x><SessionToken>{SESSION_TOKEN}</SessionToken></x>'.encode())
            try:
                raise requests.HTTPError(
                    f'401 Client Error for url: {ORG}/app?sessionToken={SESSION_TOKEN}&otp={MFA_CLI}')
            except requests.HTTPError:
                logging.getLogger('gimme_aws_creds.test').exception('request failed')
            logging.getLogger('some.lib').warning('cookie: sid=%s', COOKIE_SID)
        text = output()
        self.assertNoSecrets(text)
        self.assertIn("'Action': 'AssumeRoleWithSAML'", text)
        self.assertIn('GET /home/amazon_aws/app/1?sessionToken=[REDACTED]', text)
        self.assertIn('HTTPError', text)

    def test_formatting_failure_never_falls_back_to_raw_output(self):
        session = create_http_session(debug=True)
        self._mount(session, {('GET', '/x'): (200, '{}', {})})
        with debug_capture() as output:
            with patch.object(DebugFormatter, 'format_request', side_effect=RuntimeError(PASSWORD)):
                session.get(ORG + f'/x?password={PASSWORD}')
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('[debug output unavailable: RuntimeError]', text)


class TestRecordFactory(unittest.TestCase):

    def test_install_is_idempotent(self):
        saved = logging.getLogRecordFactory()
        logging.setLogRecordFactory(logging.LogRecord)
        try:
            first = debug_formatter.install_redacting_record_factory()
            second = debug_formatter.install_redacting_record_factory()
            self.assertIs(first, second)
            self.assertIs(first.base_factory, logging.LogRecord)
        finally:
            logging.setLogRecordFactory(saved)


if __name__ == '__main__':
    unittest.main()
