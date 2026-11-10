"""Regression tests: --debug output must never contain authentication secrets.

Every secret below is a unique synthetic marker. Tests capture what a user
would see (stdout and stderr) and every log record emitted, then assert that
no marker, and no 8-character piece of a marker, survives. They also assert
that safe diagnostics (method, path, status, timing, request ID) remain.

All HTTP traffic is served by an in-process adapter or a mocked urllib3
connection; nothing leaves the host.
"""
import ast
import io
import json
import logging
import os
import unittest
from contextlib import contextmanager, redirect_stdout
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests
from requests.adapters import BaseAdapter

from gimme_aws_creds import debug_formatter
from gimme_aws_creds.common import create_http_session
from gimme_aws_creds.debug_formatter import (
    DebugFormatter,
    _mask_config_value,
    _sanitize_url,
    format_resolved_configuration,
    setup_debug_logging,
)
from gimme_aws_creds.main import GimmeAWSCreds
from gimme_aws_creds.okta_classic import OktaClassicClient
from gimme_aws_creds.okta_identity_engine import OktaIdentityEngine
from tests.user_interface_mock import MockUserInterface

ORG = 'https://example.okta.test'
CLIENT_ID = '0oa1b2c3d4E5F6g7H8i9'
REQUEST_ID = 'YJ3xqfJ0eXk0b7Ehq7sBjgAAB4o'

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
ECHO = 'ecR7tN2wQk5ZpL8M'
ECHO_ID = 'erT4mW8qZk2NpB6VxC3dLf9Hs1J'

SECRETS = {
    name: value for name, value in globals().items()
    if name.isupper() and isinstance(value, str)
    and name not in ('ORG', 'CLIENT_ID', 'REQUEST_ID')
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
    response.elapsed = timedelta(milliseconds=125)
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
        reason = 'OK' if status == 200 else requests.status_codes._codes[status][0].replace('_', ' ').title()
        return _response(request, status, body, headers, reason=reason)

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
            if record.stack_info:
                text += '\n' + record.stack_info
            records.append(text)

    def output():
        return '\n'.join([stdout.getvalue(), stderr.getvalue()] + records)

    output.stderr = stderr
    output.records = records
    try:
        with patch('sys.stderr', stderr), redirect_stdout(stdout):
            setup_debug_logging()
            root.addHandler(Capture(level=logging.DEBUG))
            yield output
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in saved[0]:
            root.addHandler(handler)
        root.setLevel(saved[1])
        gac.setLevel(saved[2])
        logging.setLogRecordFactory(saved[3])


def _serve(routes, method, url, **kwargs):
    """Send one request through a debug session, so the real hook logs it."""
    session = create_http_session(debug=True)
    session.mount('https://', FakeAdapter(routes))
    return session.request(method, url, **kwargs)


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
        self.assertIn('/home/amazon_aws/app/[id]?sessionToken=[REDACTED]', out)

    def test_device_poll_request(self):
        out = DebugFormatter.format_request(self._prepared(
            'POST', ORG + '/oauth2/v1/token',
            data={'client_id': CLIENT_ID, 'device_code': DEVICE_CODE,
                  'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'},
        ))
        self.assertNoSecrets(out)
        self.assertIn(f'client_id={CLIENT_ID}', out)
        self.assertIn('device_code=[REDACTED]', out)
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
            Config(), {'okta_mfa_code': MFA_ENV, 'client_id': CLIENT_ID},
            env_overrides_applied={'okta_mfa_code': 'OKTA_MFA_CODE'},
        )
        self.assertNoSecrets(out)
        self.assertIn('--mfa-code = [REDACTED]', out)
        self.assertIn(CLIENT_ID, out)


class TestTypedResponseFields(LeakAssertions, unittest.TestCase):
    """Known field names do not make arbitrary values displayable."""

    MALICIOUS_BODIES = [
        {'status': ECHO},
        {'factorResult': ECHO},
        {'factorType': ECHO},
        {'provider': ECHO},
        {'expires_in': ECHO},
        {'interval': ECHO},
        {'scope': ECHO},
        {'scope': f'openid {ECHO}'},
        {'client_id': ECHO},
        {'token_type': ECHO},
        {'error': ECHO},
        {'errorCode': ECHO},
        {'expiresAt': ECHO},
        {'message': ECHO},
        {'message': [ECHO]},
        {'error_description': f'password: {ECHO}'},
        {'error_description': f'password:{ECHO}'},
        {'error_description': ECHO},
        {'errorSummary': f'The password {ECHO} is invalid'},
        {'errorCauses': [{'errorSummary': ECHO}]},
        {'opaque': {'status': ECHO}},
        {'opaque': [{'status': ECHO}]},
        {'_embedded': {'factors': [{'factorType': ECHO, 'opaque': ECHO}]}},
        {'_embedded': {'user': {'profile': {'login': ECHO}}}},
        {'status': {'nested': ECHO}},
        {ECHO: 'SUCCESS'},
    ]

    def test_malicious_values_through_hook_factory_console_and_records(self):
        for body in self.MALICIOUS_BODIES:
            with self.subTest(body=json.dumps(body)[:60]):
                routes = {('GET', '/api/v1/authn'): (
                    400, json.dumps(body), {'Content-Type': 'application/json'})}
                with debug_capture() as output:
                    _serve(routes, 'GET', ORG + '/api/v1/authn')
                text = output()
                self.assertNoSecrets(text)
                self.assertIn('GET https://example.okta.test/api/v1/authn', text)
                self.assertIn('400 Bad Request', text)

    def test_valid_typed_values_are_shown(self):
        body = {
            'status': 'MFA_REQUIRED', 'expiresAt': '2026-11-09T20:00:00.000Z',
            'factorResult': 'WAITING', 'errorCode': 'E0000004',
            'error': 'authorization_pending', 'expires_in': 300,
            'scope': 'openid okta.apps.sso', 'token_type': 'Bearer',
            '_embedded': {'factors': [{'factorType': 'push', 'provider': 'OKTA',
                                       'id': 'opf1b2c3d4E5F6g7H8i9'}]},
        }
        out = DebugFormatter._format_body(json.dumps(body))
        for expected in ('"status": "MFA_REQUIRED"', '"factorResult": "WAITING"',
                         '"errorCode": "E0000004"', '"error": "authorization_pending"',
                         '"expires_in": 300', '"scope": "openid okta.apps.sso"',
                         '"token_type": "Bearer"', '"factorType": "push"',
                         '"provider": "OKTA"', '"expiresAt": "2026-11-09T20:00:00.000Z"',
                         '"id": "[REDACTED]"'):
            self.assertIn(expected, out)

    def test_unknown_fields_are_counted_not_named(self):
        out = DebugFormatter._format_body(json.dumps({ECHO: 1, 'opaque': {'x': 2}, 'status': 'SUCCESS'}))
        self.assertNoSecrets(out)
        self.assertNotIn('opaque', out)
        self.assertIn('"[omitted]": "2 unrecognized fields"', out)

    def test_form_and_query_values_are_typed(self):
        body = f'message={ECHO}&status={ECHO}&grant_type={ECHO}&opaque={ECHO}&{ECHO}=1'
        out = DebugFormatter._format_body(body, 'application/x-www-form-urlencoded')
        self.assertNoSecrets(out)
        self.assertIn('status=[REDACTED]', out)
        self.assertIn('[2 unrecognized parameters omitted]', out)
        url = _sanitize_url(ORG + f'/api?status={ECHO}&rememberDevice=true&opaque={ECHO}')
        self.assertNoSecrets(url)
        self.assertEqual(
            url, 'https://example.okta.test/api?status=[REDACTED]&rememberDevice=true'
                 '&[1 unrecognized parameter omitted]')


class TestUrlPaths(LeakAssertions, unittest.TestCase):

    def test_unknown_path_segments_of_any_length_are_omitted(self):
        for segment in (ECHO, ECHO[:8], ECHO * 3, ACCESS_TOKEN, f'{ECHO};jsessionid={COOKIE_SID}',
                        requests.utils.quote(f'x?sessionToken={SESSION_TOKEN}', safe='')):
            with self.subTest(segment=segment[:20]):
                url = _sanitize_url(ORG + f'/activate/{segment}/verify')
                self.assertNoSecrets(url)
                self.assertEqual(url, 'https://example.okta.test/activate/[id]/verify')

    def test_known_routes_keep_their_shape(self):
        self.assertEqual(
            _sanitize_url(ORG + '/api/v1/authn/factors/opf1b2c3d4E5F6g7H8i9/verify'),
            'https://example.okta.test/api/v1/authn/factors/[id]/verify')
        self.assertEqual(_sanitize_url(ORG + '/oauth2/v1/device/authorize'),
                         'https://example.okta.test/oauth2/v1/device/authorize')

    def test_userinfo_fragment_and_redirects(self):
        nested = requests.utils.quote(f'/app?sessionToken={SESSION_TOKEN}', safe='')
        url = _sanitize_url(f'https://user:{PASSWORD}@example.okta.test/login/x'
                            f'?fromURI={requests.utils.quote(nested, safe="")}#id_token={ID_TOKEN}')
        self.assertNoSecrets(url)
        self.assertEqual(url, 'https://[REDACTED]@example.okta.test/login/[id]?fromURI=[REDACTED]#[REDACTED]')

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
                self.assertIn('GET https://example.okta.test/login/[id]?', out)


class TestHeaderRedaction(LeakAssertions, unittest.TestCase):

    def test_credential_and_unknown_headers_hidden_in_any_case(self):
        headers = {
            'Authorization': f'Bearer {AUTH_BEARER}',
            'authorization': f'SSWS {AUTH_SSWS}',
            'COOKIE': f'sid={COOKIE_SID}; DT={COOKIE_DT}',
            'X-Okta-Session-Id': OKTA_SESSION_HEADER,
            'Server': ECHO,
            'x-custom-unknown': NESTED,
            'Content-Type': 'application/json; charset=utf-8',
            'X-Okta-Request-Id': REQUEST_ID,
        }
        out = DebugFormatter._mask_sensitive_headers(headers)
        self.assertNoSecrets(json.dumps(out))
        for name in ('Authorization', 'authorization', 'COOKIE', 'X-Okta-Session-Id', 'Server'):
            self.assertEqual(out[name], '[REDACTED]')
        self.assertNotIn('x-custom-unknown', out)
        self.assertEqual(out['[omitted]'], '1 unrecognized header')
        self.assertEqual(out['Content-Type'], 'application/json')
        self.assertEqual(out['X-Okta-Request-Id'], REQUEST_ID)

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

    def test_request_id_policy(self):
        """Request IDs: fixed server format only, and never an echo of sent text."""
        self.assertEqual(DebugFormatter._mask_sensitive_headers({'X-Okta-Request-Id': ECHO}),
                         {'X-Okta-Request-Id': '[REDACTED]'})
        uuid = '0f8fad5b-d9cb-469f-a165-70867728950e'
        self.assertEqual(DebugFormatter._mask_sensitive_headers({'x-amzn-RequestId': uuid}),
                         {'x-amzn-RequestId': uuid})
        routes = {('POST', '/api/v1/authn'): (
            200, '{"status": "SUCCESS"}',
            {'Content-Type': 'application/json', 'X-Okta-Request-Id': ECHO_ID})}
        with debug_capture() as output:
            _serve(routes, 'POST', ORG + '/api/v1/authn', json={'password': ECHO_ID})
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('X-Okta-Request-Id: [REDACTED]', text)


class TestStructuredBodies(LeakAssertions, unittest.TestCase):

    def test_nested_json_values_redacted_unless_typed(self):
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
        self.assertIn('"passCode": "[REDACTED]"', out)
        self.assertNotIn('123456', out)

    def test_free_text_fields_are_never_shown(self):
        out = DebugFormatter._mask_sensitive_dict({
            'name': f'password={PASSWORD}',
            'errorSummary': f'see /x?sessionToken={SESSION_TOKEN}',
            'message': f'Bearer {AUTH_BEARER}',
            'label': 'Okta Verify',
        })
        self.assertNoSecrets(json.dumps(out))
        self.assertEqual(set(out.values()), {'[REDACTED]'})

    def test_escaped_json_key_variant_redacted(self):
        body = '{"session\\u0054oken": "%s", "SESSIONTOKEN": "%s"}' % (SESSION_TOKEN, SESSION_TOKEN)
        self.assertNoSecrets(DebugFormatter._format_body(body))

    def test_form_body_case_and_encoding_variants(self):
        body = (f'PASSWORD={PASSWORD}&pass%77ord={PASSWORD}&pass+word={PASSWORD}'
                f'&mfa_code={MFA_CLI}&Session-Token={SESSION_TOKEN}')
        out = DebugFormatter._format_body(body)
        self.assertNoSecrets(out)

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

    def test_nonstandard_reason_phrase_is_omitted(self):
        request = requests.Request('GET', ORG + '/api/v1/authn').prepare()
        out = DebugFormatter.format_response(_response(request, 401, '{}', reason=f'pw {ECHO}'))
        self.assertNoSecrets(out)
        self.assertIn('401 [reason omitted]', out)


class TestConfigValues(LeakAssertions, unittest.TestCase):

    def test_secret_and_unknown_keys_fully_redacted(self):
        for key in ('mfa_code', 'okta_mfa_code', 'OKTA_MFA_CODE', 'okta_password',
                    'OKTA_PASSWORD', 'device_token', 'api_key', 'some_new_key',
                    'okta_username', 'aws_appname'):
            with self.subTest(key=key):
                self.assertEqual(_mask_config_value(key, MFA_CLI), '[REDACTED]')

    def test_known_keys_require_their_type(self):
        for key in ('device_flow_scope', 'client_id', 'okta_auth_server', 'aws_region',
                    'aws_rolename', 'okta_platform', 'preferred_mfa_type',
                    'preferred_mfa_provider', 'output_format', 'aws_default_duration',
                    'write_aws_creds', 'gimme_creds_server', 'duo_universal_factor'):
            with self.subTest(key=key):
                self.assertEqual(_mask_config_value(key, MFA_CLI + '!'), '[REDACTED]')
        self.assertEqual(_mask_config_value('aws_rolename', 'arn:aws:iam::123456789012:role/Dev'),
                         'arn:aws:iam::123456789012:role/Dev')
        self.assertEqual(_mask_config_value('okta_platform', 'classic'), 'classic')
        self.assertEqual(_mask_config_value('aws_default_duration', '3600'), '3600')

    def test_allowlisted_url_value_is_sanitized(self):
        self.assertEqual(
            _mask_config_value('app_url', ORG + f'/home/amazon_aws/{ECHO}/272?sessionToken={SESSION_TOKEN}'),
            'https://example.okta.test/home/amazon_aws/[id]/[id]?sessionToken=[REDACTED]',
        )


class TestEndToEndDebugRuns(LeakAssertions, unittest.TestCase):
    """Real client code paths with the debug hook, served by a fake adapter."""

    def setUp(self):
        self.ui = MockUserInterface(argv=['--debug'])

    def _mount(self, session, routes):
        adapter = FakeAdapter(routes)
        session.mount('https://', adapter)
        return adapter

    def test_known_safe_diagnostics_are_kept(self):
        routes = {('POST', '/api/v1/authn'): (
            200, json.dumps({'status': 'SUCCESS', 'expires_in': 300}),
            {'Content-Type': 'application/json', 'X-Okta-Request-Id': REQUEST_ID})}
        with debug_capture() as output:
            _serve(routes, 'POST', ORG + '/api/v1/authn', json={'password': PASSWORD})
        text = output()
        self.assertNoSecrets(text)
        self.assertRegex(output.stderr.getvalue(), rf'200 OK \(\d+ ms, request id {REQUEST_ID}\)')
        for expected in ('POST https://example.okta.test/api/v1/authn',
                         '"status": "SUCCESS"',
                         '"expires_in": 300', '"password": "[REDACTED]"'):
            self.assertIn(expected, output.stderr.getvalue())

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
            }), {'Content-Type': 'application/json', 'X-Okta-Request-Id': REQUEST_ID}),
            ('POST', '/oauth2/v1/token'): (200, token_body,
                                           {'Content-Type': 'application/json',
                                            'Set-Cookie': f'sid={SET_COOKIE}; Path=/'}),
        }
        with debug_capture() as output:
            client = OktaIdentityEngine(self.ui, ORG, CLIENT_ID, debug=True)
            self._mount(client._http_client, routes)
            started = client._start_device_flow()
            tokens = client._get_user_tokens(started['apiResponse']['device_code'])
        self.assertEqual(tokens['id_token'], ID_TOKEN)
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('POST https://example.okta.test/oauth2/v1/device/authorize', text)
        self.assertIn('POST https://example.okta.test/oauth2/v1/token', text)
        self.assertIn(f'request id {REQUEST_ID}', text)
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
        self.assertIn('GET https://example.okta.test/home/amazon_aws/app/[id]?sessionToken=[REDACTED]', text)
        self.assertIn('POST https://example.okta.test/api/v1/authn/factors/[id]/verify', text)
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
            f.write(f'[p]\nokta_org_url = {ORG}\nclient_id = {CLIENT_ID}\n'
                    f'okta_mfa_code = {MFA_CONF}\ndevice_flow_scope = openid {ECHO}\n')
        with debug_capture() as output:
            with patch.object(GimmeAWSCreds, 'get_resolver', return_value=None):
                GimmeAWSCreds(ui=ui).generate_config()
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('RESOLVED CONFIGURATION', text)
        self.assertIn(CLIENT_ID, text)
        self.assertIn('--mfa-code = [REDACTED]', text)

    def test_formatting_failure_never_falls_back_to_raw_output(self):
        session = create_http_session(debug=True)
        self._mount(session, {('GET', '/x'): (200, '{}', {})})
        with debug_capture() as output:
            with patch.object(DebugFormatter, 'format_request', side_effect=RuntimeError(PASSWORD)):
                session.get(ORG + f'/x?password={PASSWORD}')
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('[debug output unavailable: RuntimeError]', text)


class TestDependencyRecords(LeakAssertions, unittest.TestCase):
    """Library log records are rendered from a registry or omitted."""

    def test_real_urllib3_make_request_with_mocked_connection(self):
        from urllib3.connectionpool import HTTPConnectionPool

        pool = HTTPConnectionPool('example.okta.test')
        conn = Mock()
        conn.is_closed = False
        conn.getresponse.return_value = SimpleNamespace(
            version_string='HTTP/1.1', status=200, length_remaining=0)
        with debug_capture() as output:
            pool._new_conn()
            pool._make_request(conn, 'GET', f'/activate/{USER_CODE}?sessionToken={SESSION_TOKEN}')
            pool._make_request(conn, 'GET', f'/activate/{ECHO * 3}')
        text = output()
        self.assertNoSecrets(text)
        console = output.stderr.getvalue()
        self.assertIn('Starting new HTTP connection (1): example.okta.test:80', console)
        self.assertIn('http://example.okta.test "GET /activate/[id]?sessionToken=[REDACTED] HTTP/1.1" 200 0',
                      console)
        self.assertIn('"GET /activate/[id] HTTP/1.1" 200 0', console)
        self.assertEqual(sum('"GET /activate/[id]' in r for r in output.records), 2)

    def test_registered_template_with_hostile_arguments(self):
        with debug_capture() as output:
            logging.getLogger('urllib3.connectionpool').debug(
                '%s://%s:%s "%s %s %s" %s %s', 'https', 'example.okta.test', 443, 'GET',
                f'https://u:{PASSWORD}@example.okta.test/api?opaque={ECHO}', 'HTTP/1.1', 200, None)
            logging.getLogger('urllib3.connectionpool').debug(
                '%s://%s:%s "%s %s %s" %s %s', ECHO, f'{ECHO}.x', ECHO, ECHO, ECHO, ECHO, ECHO, ECHO)
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('https://[REDACTED]@example.okta.test/api?[1 unrecognized parameter omitted]', text)

    def test_unregistered_records_are_omitted_at_every_level(self):
        cases = [
            ('botocore.endpoint', logging.DEBUG, 'payload=%s', (f'opaque={ECHO}',)),
            ('botocore.endpoint', logging.DEBUG, 'Response body: {"opaque":"%s"}' % ECHO, ()),
            ('botocore.endpoint', logging.DEBUG, 'Making request with params: %s',
             ({'body': {'Action': 'AssumeRoleWithSAML', 'SAMLAssertion': SAML_VALUE}},)),
            ('botocore.parsers', logging.DEBUG, 'Response body:\n%r', (f'<x>{SESSION_TOKEN}</x>'.encode(),)),
            ('some.lib', logging.INFO, 'cookie: sid=%s', (COOKIE_SID,)),
            ('some.lib', logging.WARNING, f'failed opaque={ECHO}', ()),
            ('urllib3.connectionpool', logging.WARNING,
             "Retrying (%r) after connection broken by '%r': %s", ('Retry(total=2)', 'err', f'/x/{ECHO}')),
        ]
        with debug_capture() as output:
            for name, level, msg, args in cases:
                logging.getLogger(name).log(level, msg, *args)
        text = output()
        self.assertNoSecrets(text)
        self.assertEqual(len(output.records), len(cases))
        self.assertIn('[botocore.endpoint DEBUG message omitted]', output.records[0])
        console = output.stderr.getvalue()
        # Unrecognized DEBUG chatter is dropped from the console; higher levels leave a marker.
        self.assertNotIn('DEBUG message omitted', console)
        self.assertIn('[some.lib INFO message omitted]', console)
        self.assertIn('[urllib3.connectionpool WARNING message omitted]', console)

    def test_exception_messages_and_source_lines_are_never_printed(self):
        with debug_capture() as output:
            try:
                try:
                    raise ValueError(f'opaque={ECHO}')
                except ValueError as exc:
                    raise requests.HTTPError(
                        f'401 Client Error for url: https://u:{PASSWORD}@example.okta.test/app?x={MFA_CLI}'
                    ) from exc
            except requests.HTTPError:
                logging.getLogger('gimme_aws_creds.test').exception('request failed')
                logging.getLogger('urllib3.connectionpool').warning('failed', exc_info=True)
            logging.getLogger('gimme_aws_creds.test').debug('where', stack_info=True)
        text = output()
        self.assertNoSecrets(text)
        self.assertIn('request failed', text)
        self.assertIn('requests.exceptions.HTTPError [message omitted]', text)
        self.assertIn('ValueError [message omitted]', text)
        self.assertIn('test_debug_redaction.py", line', text)
        self.assertNotIn('raise requests.HTTPError', text)

    def test_records_created_without_the_factory_are_rendered_by_the_console(self):
        with debug_capture() as output:
            console = logging.getLogger().handlers[0]
            console.handle(logging.makeLogRecord({
                'name': 'some.lib', 'levelno': logging.WARNING, 'levelname': 'WARNING',
                'msg': 'password=%s', 'args': (PASSWORD,), 'exc_text': f'Error: {ECHO}'}))
        self.assertNoSecrets(output.stderr.getvalue())
        self.assertIn('[some.lib WARNING message omitted]', output.stderr.getvalue())
        self.assertIn('[exception text omitted]', output.stderr.getvalue())


class TestLogFormatting(unittest.TestCase):
    """Formatting compatibility without dumping arguments."""

    def test_package_templates_interpolate_numbers_only(self):
        with debug_capture() as output:
            log = logging.getLogger('gimme_aws_creds.x')
            log.info('operation=%(operation)s count=%(count)d',
                     {'operation': 'AssumeRoleWithSAML', 'count': 3})
            log.info('count=%d', 3)
            log.info('ready=%s ratio=%.1f none=%s', True, 0.5, None)
            log.info('value=%d', 'not-a-number')
            log.info('%(missing)s', {'present': 1})
        self.assertEqual(output.records, [
            'operation=[REDACTED] count=3',
            'count=3',
            'ready=True ratio=0.5 none=None',
            '[log message omitted: arguments do not match the format]',
            '[log message omitted: arguments do not match the format]',
        ])
        self.assertNotIn('{', output.stderr.getvalue())

    def test_other_loggers_mapping_style_is_bounded_omission(self):
        with debug_capture() as output:
            logging.getLogger('ordinary').info('operation=%(operation)s count=%(count)d',
                                               {'operation': ECHO, 'count': 3})
        self.assertEqual(output.records, ['[ordinary INFO message omitted]'])

    def test_package_log_calls_use_constant_templates(self):
        """The package-logger policy relies on format strings being code constants."""
        package = Path(debug_formatter.__file__).parent
        allowed_calls = {'format_request', 'format_response', 'format_resolved_configuration'}
        methods = {'debug', 'info', 'warning', 'warn', 'error', 'exception', 'critical', 'log'}
        problems = []
        for path in sorted(package.glob('*.py')):
            tree = ast.parse(path.read_text(), str(path))
            formatted_names = {
                target.id
                for node in ast.walk(tree) if isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Call)
                and getattr(node.value.func, 'id', getattr(node.value.func, 'attr', None)) in allowed_calls
                for target in node.targets if isinstance(target, ast.Name)
            }
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in methods and isinstance(node.func.value, ast.Name)
                        and 'log' in node.func.value.id.lower() and node.args):
                    continue
                arg = node.args[1] if node.func.attr == 'log' and len(node.args) > 1 else node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    continue
                if isinstance(arg, ast.Call) and getattr(arg.func, 'attr', None) in allowed_calls:
                    continue
                if isinstance(arg, ast.Name) and arg.id in formatted_names:
                    continue
                problems.append(f'{path.name}:{node.lineno}')
        self.assertEqual(problems, [])


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
