"""Device authorization polling tests for OktaIdentityEngine (RFC 8628 section 3.5).

A fake clock and a fake HTTP transport drive every case, so the tests never sleep
and never open a network connection.
"""
import base64
import json
import unittest
from collections import namedtuple
from unittest.mock import Mock

import requests

from gimme_aws_creds import errors
from gimme_aws_creds.okta_identity_engine import DeviceAuthorizationSlowDown, OktaIdentityEngine

ORG_URL = 'https://example-oie.okta.com'
CLIENT_ID = '0oa1example2client3'
DEVICE_CODE = '7ba11a95-e564-499a-b9b0-69c01ac6bbf9'
VERIFICATION_URI = ORG_URL + '/activate?user_code=ZWGQJTMP'
TOKEN_URL = ORG_URL + '/oauth2/v1/token'
DEVICE_URL = ORG_URL + '/oauth2/v1/device/authorize'
START = 1000.0
DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code'


def unsigned_jwt(claims):
    def encode(part):
        return base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b'=').decode()
    return '{}.{}.{}'.format(encode({'alg': 'RS256', 'typ': 'JWT'}), encode(claims), 'c2lnbmF0dXJl')


ACCESS_TOKEN = unsigned_jwt({'sub': 'user@example.com'})
PENDING = (400, {'error': 'authorization_pending'})
SLOW_DOWN = (400, {'error': 'slow_down'})
SUCCESS = (200, {
    'token_type': 'Bearer',
    'expires_in': 3600,
    'access_token': ACCESS_TOKEN,
    'id_token': 'id-token',
    'scope': 'openid okta.apps.sso',
})

# A token endpoint outcome that takes ``seconds`` of simulated time.
Slow = namedtuple('Slow', 'seconds outcome')
# A request that uses its whole timeout and then raises ``exception``.
TimedOut = namedtuple('TimedOut', 'exception')
# Marks a device authorization field to leave out of the response.
OMIT = object()


def device_response(**overrides):
    response = {
        'device_code': DEVICE_CODE,
        'user_code': 'ZWGQJTMP',
        'verification_uri': ORG_URL + '/activate',
        'verification_uri_complete': VERIFICATION_URI,
        'expires_in': 600,
        'interval': 5,
    }
    for key, value in overrides.items():
        if value is OMIT:
            response.pop(key, None)
        else:
            response[key] = value
    return response



def make_response(url, status, body):
    response = requests.Response()
    response.url = url
    response.status_code = status
    response.headers['Content-Type'] = 'application/json'
    response._content = json.dumps(body).encode()
    return response


class FakeOkta:
    """Fake monotonic clock and token endpoint for one device authorization flow."""

    def __init__(self, token_outcomes, device=None, request_seconds=0.0):
        self.now = START
        self.token_outcomes = list(token_outcomes)
        self.device = device_response() if device is None else device
        self.request_seconds = request_seconds
        self.sleeps = []
        self.polls = []
        self.request_timeouts = []
        self.token_requests = []
        self.device_requests = []

    @property
    def elapsed(self):
        return self.now - START

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        if seconds < 0:
            raise AssertionError('negative sleep: {}'.format(seconds))
        self.sleeps.append(seconds)
        self.now += seconds

    def post(self, url, **kwargs):
        if url == DEVICE_URL:
            self.device_requests.append(kwargs['data'])
            return make_response(url, 200, self.device)
        if url != TOKEN_URL:
            raise AssertionError('unexpected URL: ' + url)
        if not self.token_outcomes:
            raise AssertionError('unexpected token request at t={}'.format(self.elapsed))
        self.polls.append(self.elapsed)
        self.request_timeouts.append(kwargs['timeout'])
        self.token_requests.append(kwargs['data'])

        outcome = self.token_outcomes.pop(0)
        seconds = self.request_seconds
        if isinstance(outcome, Slow):
            seconds, outcome = outcome
        if isinstance(outcome, TimedOut):
            seconds, outcome = kwargs['timeout'], outcome.exception
        self.now += seconds
        if isinstance(outcome, Exception):
            raise outcome
        status, body = outcome
        return make_response(url, status, body)


class DeviceFlowTestCase(unittest.TestCase):
    def setUp(self):
        self.ui = Mock()

    def make_client(self, fake, **kwargs):
        client = OktaIdentityEngine(self.ui, ORG_URL, CLIENT_ID, False, **kwargs)
        client._http_client.post = fake.post
        client._monotonic = fake.monotonic
        client._sleep = fake.sleep
        return client

    def run_flow(self, fake, **kwargs):
        return self.make_client(fake, **kwargs).auth_session()

    def run_failing_flow(self, fake, exception=errors.GimmeAWSCredsError, **kwargs):
        with self.assertRaises(exception) as context:
            self.run_flow(fake, **kwargs)
        return context.exception

    def warnings(self):
        return [call.args[0] for call in self.ui.warning.call_args_list]

    def assert_no_poll_at_or_after(self, fake, deadline):
        self.assertTrue(all(poll < deadline for poll in fake.polls), fake.polls)


class TestDeviceFlowInterval(DeviceFlowTestCase):

    def test_waits_server_interval_between_polls(self):
        fake = FakeOkta([PENDING, PENDING, SUCCESS], device_response(interval=7))
        result = self.run_flow(fake)
        self.assertEqual(fake.polls, [0, 7, 14])
        self.assertEqual(fake.sleeps, [7, 7])
        self.assertEqual(result['username'], 'user@example.com')
        self.assertEqual(result['access_token'], ACCESS_TOKEN)

    def test_uses_default_interval_when_server_omits_it(self):
        fake = FakeOkta([PENDING, PENDING, SUCCESS], device_response(interval=OMIT))
        self.run_flow(fake)
        self.assertEqual(fake.polls, [0, 5, 10])
        self.assertEqual(self.warnings(), [])

    def test_null_interval_uses_default_without_warning(self):
        fake = FakeOkta([PENDING, SUCCESS], device_response(interval=None))
        self.run_flow(fake)
        self.assertEqual(fake.polls, [0, 5])
        self.assertEqual(self.warnings(), [])

    def test_interval_counts_from_end_of_previous_response(self):
        fake = FakeOkta([PENDING, PENDING, SUCCESS], request_seconds=1)
        self.run_flow(fake)
        self.assertEqual(fake.polls, [0, 6, 12])

    def test_first_poll_success_does_not_sleep(self):
        fake = FakeOkta([SUCCESS])
        self.run_flow(fake)
        self.assertEqual(fake.polls, [0])
        self.assertEqual(fake.sleeps, [])

    def test_slow_down_adds_five_seconds_cumulatively(self):
        fake = FakeOkta([SLOW_DOWN, SLOW_DOWN, PENDING, SUCCESS])
        self.run_flow(fake)
        # Interval 5 -> 10 -> 15, and it stays at 15 after a pending response.
        self.assertEqual(fake.polls, [0, 10, 25, 40])

    def test_connection_timeouts_double_interval(self):
        fake = FakeOkta([
            Slow(2, requests.exceptions.ConnectTimeout('connect timed out')),
            Slow(2, requests.exceptions.ReadTimeout('read timed out')),
            PENDING,
            SUCCESS,
        ])
        self.run_flow(fake)
        # Interval 5 -> 10 -> 20, measured from the end of each failed request.
        self.assertEqual(fake.polls, [0, 12, 34, 54])

    def test_slow_down_after_timeout_backoff_builds_on_backed_off_interval(self):
        fake = FakeOkta([Slow(0, requests.exceptions.ReadTimeout('read timed out')), SLOW_DOWN, SUCCESS])
        self.run_flow(fake)
        # Interval 5 -> 10 (timeout) -> 15 (slow_down).
        self.assertEqual(fake.polls, [0, 10, 25])

    def test_token_request_payload_is_unchanged(self):
        fake = FakeOkta([PENDING, SUCCESS])
        self.run_flow(fake)
        expected = {'client_id': CLIENT_ID, 'device_code': DEVICE_CODE, 'grant_type': DEVICE_GRANT}
        self.assertEqual(fake.token_requests, [expected, expected])


class TestDeviceFlowDeadline(DeviceFlowTestCase):

    def test_default_timeout_is_preserved(self):
        self.assertEqual(OktaIdentityEngine.DEVICE_FLOW_TIMEOUT, 120)
        fake = FakeOkta([PENDING] * 24)
        client = self.make_client(fake)
        self.assertEqual(client._device_flow_timeout, 120)
        with self.assertRaises(errors.GimmeAWSCredsError) as context:
            client.auth_session()
        self.assertEqual(context.exception.message, 'Timeout waiting for device authorization (120 seconds)')
        self.assertEqual(context.exception.return_code, 2)
        self.assertEqual(fake.polls, list(range(0, 120, 5)))
        self.assertLessEqual(fake.elapsed, 120)

    def test_configured_timeout_bounds_polling(self):
        fake = FakeOkta([PENDING] * 3)
        error = self.run_failing_flow(fake, device_flow_timeout=12)
        self.assertEqual(error.message, 'Timeout waiting for device authorization (12 seconds)')
        self.assertEqual(fake.polls, [0, 5, 10])
        self.assert_no_poll_at_or_after(fake, 12)
        self.assertLessEqual(fake.elapsed, 12)

    def test_server_expiry_bounds_polling(self):
        fake = FakeOkta([PENDING] * 3, device_response(expires_in=12))
        error = self.run_failing_flow(fake)
        self.assertIn('expired after 12 seconds', error.message)
        self.assertEqual(error.return_code, 2)
        self.assertEqual(fake.polls, [0, 5, 10])
        self.assert_no_poll_at_or_after(fake, 12)
        self.assertLessEqual(fake.elapsed, 12)

    def test_configured_timeout_wins_when_shorter_than_server_expiry(self):
        fake = FakeOkta([PENDING] * 2, device_response(expires_in=600))
        error = self.run_failing_flow(fake, device_flow_timeout=8)
        self.assertEqual(error.message, 'Timeout waiting for device authorization (8 seconds)')
        self.assertEqual(fake.polls, [0, 5])

    def test_http_time_counts_toward_deadline(self):
        for timeout, polls, elapsed in ((6, [0], 3), (20, [0, 8, 16], 19)):
            with self.subTest(timeout=timeout):
                self.ui.reset_mock()
                fake = FakeOkta([PENDING] * len(polls), request_seconds=3)
                error = self.run_failing_flow(fake, device_flow_timeout=timeout)
                self.assertEqual(
                    error.message, 'Timeout waiting for device authorization ({} seconds)'.format(timeout))
                self.assertEqual(fake.polls, polls)
                self.assertEqual(fake.elapsed, elapsed)
                self.assert_no_poll_at_or_after(fake, timeout)

    def test_request_timeout_is_capped_by_remaining_time(self):
        cases = (
            ('configured timeout', {'device_flow_timeout': 12}, device_response()),
            ('server expiry', {}, device_response(expires_in=12)),
        )
        for name, kwargs, device in cases:
            with self.subTest(name):
                fake = FakeOkta([PENDING] * 3, device)
                self.run_failing_flow(fake, **kwargs)
                self.assertEqual(fake.request_timeouts, [12, 7, 2])

    def test_request_timeout_defaults_to_http_timeout_when_time_remains(self):
        fake = FakeOkta([PENDING, SUCCESS])
        self.run_flow(fake)
        self.assertEqual(fake.request_timeouts, [OktaIdentityEngine.HTTP_TIMEOUT] * 2)

    def test_request_timeout_at_deadline_reports_device_flow_timeout(self):
        fake = FakeOkta([TimedOut(requests.exceptions.ReadTimeout('read timed out'))])
        error = self.run_failing_flow(fake, device_flow_timeout=6)
        self.assertEqual(error.message, 'Timeout waiting for device authorization (6 seconds)')
        self.assertEqual(fake.request_timeouts, [6])
        self.assertEqual(fake.elapsed, 6)

    def test_token_from_request_in_flight_at_deadline_is_used(self):
        fake = FakeOkta([Slow(7, SUCCESS)])
        result = self.run_flow(fake, device_flow_timeout=6)
        self.assertEqual(result['access_token'], ACCESS_TOKEN)
        self.assertEqual(fake.polls, [0])

    def test_no_request_starts_after_deadline_spent_before_first_poll(self):
        fake = FakeOkta([], device_response(expires_in=2))

        def slow_output(*args, **kwargs):
            fake.now += 1

        self.ui.info.side_effect = slow_output
        error = self.run_failing_flow(fake)
        self.assertIn('expired after 2 seconds', error.message)
        self.assertEqual(fake.polls, [])

    def test_fractional_values_are_reported_without_rounding(self):
        fake = FakeOkta([PENDING], device_response(interval=2.5))
        error = self.run_failing_flow(fake, device_flow_timeout=2.5)
        self.assertEqual(error.message, 'Timeout waiting for device authorization (2.5 seconds)')
        self.assertEqual(fake.polls, [0])


class TestDeviceFlowTerminalErrors(DeviceFlowTestCase):

    def test_access_denied_stops_polling(self):
        denied = (400, {'error': 'access_denied', 'error_description': 'The resource owner denied the request.'})
        fake = FakeOkta([PENDING, denied])
        error = self.run_failing_flow(fake)
        self.assertIn('denied', error.message)
        self.assertIn('The resource owner denied the request.', error.message)
        self.assertEqual(error.return_code, 2)
        self.assertEqual(fake.polls, [0, 5])

    def test_expired_token_stops_polling(self):
        fake = FakeOkta([(400, {'error': 'expired_token'})])
        error = self.run_failing_flow(fake)
        self.assertIn('device code expired', error.message)
        self.assertEqual(fake.polls, [0])

    def test_invalid_client_is_not_retried(self):
        rejected = (401, {'error': 'invalid_client', 'error_description': 'Client authentication failed.'})
        fake = FakeOkta([rejected])
        error = self.run_failing_flow(fake)
        self.assertIn(CLIENT_ID, error.message)
        self.assertIn('invalid_client', error.message)
        self.assertIn('Client authentication failed.', error.message)
        self.assertEqual(fake.polls, [0])

    def test_other_oauth_errors_are_not_retried(self):
        for code in ('invalid_grant', 'invalid_request', 'unauthorized_client', 'unsupported_grant_type'):
            with self.subTest(code=code):
                fake = FakeOkta([(400, {'error': code})])
                error = self.run_failing_flow(fake)
                self.assertIn(code, error.message)
                self.assertEqual(fake.polls, [0])

    def test_server_error_without_oauth_error_is_not_retried(self):
        fake = FakeOkta([(500, {'errorSummary': 'Internal error'})])
        error = self.run_failing_flow(fake, exception=requests.exceptions.HTTPError)
        self.assertNotIsInstance(error, DeviceAuthorizationSlowDown)
        self.assertEqual(fake.polls, [0])

    def test_connection_error_is_not_retried(self):
        fake = FakeOkta([requests.exceptions.ConnectionError('connection refused')])
        self.run_failing_flow(fake, exception=requests.exceptions.ConnectionError)
        self.assertEqual(fake.polls, [0])


class TestDeviceFlowTimingValidation(DeviceFlowTestCase):
    INVALID_VALUES = ('soon', '', 0, -5, float('nan'), float('inf'), True, [5], {'seconds': 5}, 10 ** 400)

    def test_invalid_interval_falls_back_to_default(self):
        for value in self.INVALID_VALUES:
            with self.subTest(interval=value):
                self.ui.reset_mock()
                fake = FakeOkta([PENDING, PENDING, SUCCESS], device_response(interval=value))
                self.run_flow(fake)
                self.assertEqual(fake.polls, [0, 5, 10])
                warnings = self.warnings()
                self.assertEqual(len(warnings), 1)
                self.assertIn('interval', warnings[0])

    def test_invalid_expires_in_falls_back_to_configured_timeout(self):
        for value in self.INVALID_VALUES:
            with self.subTest(expires_in=value):
                self.ui.reset_mock()
                fake = FakeOkta([PENDING] * 3, device_response(expires_in=value))
                error = self.run_failing_flow(fake, device_flow_timeout=12)
                self.assertEqual(error.message, 'Timeout waiting for device authorization (12 seconds)')
                self.assertEqual(fake.polls, [0, 5, 10])
                warnings = self.warnings()
                self.assertEqual(len(warnings), 1)
                self.assertIn('expires_in', warnings[0])

    def test_missing_expires_in_uses_configured_timeout_without_warning(self):
        fake = FakeOkta([PENDING] * 3, device_response(expires_in=OMIT))
        error = self.run_failing_flow(fake, device_flow_timeout=12)
        self.assertEqual(error.message, 'Timeout waiting for device authorization (12 seconds)')
        self.assertEqual(self.warnings(), [])

    def test_numeric_strings_are_accepted(self):
        fake = FakeOkta([PENDING] * 3, device_response(interval='7', expires_in='15'))
        error = self.run_failing_flow(fake)
        self.assertIn('expired after 15 seconds', error.message)
        self.assertEqual(fake.polls, [0, 7, 14])
        self.assertEqual(self.warnings(), [])

    def test_invalid_configured_timeout_is_rejected(self):
        for value in (0, -1, float('nan'), float('inf'), 'later', True, [120], 10 ** 400):
            with self.subTest(device_flow_timeout=value):
                with self.assertRaises(errors.GimmeAWSCredsError) as context:
                    OktaIdentityEngine(self.ui, ORG_URL, CLIENT_ID, False, device_flow_timeout=value)
                self.assertIn('device_flow_timeout', context.exception.message)

    def test_valid_configured_timeouts_are_accepted(self):
        for value, expected in ((None, 120), (300, 300), (0.5, 0.5), ('90', 90.0)):
            with self.subTest(device_flow_timeout=value):
                client = OktaIdentityEngine(self.ui, ORG_URL, CLIENT_ID, False, device_flow_timeout=value)
                self.assertEqual(client._device_flow_timeout, expected)


class TestDeviceFlowAlibabaScope(DeviceFlowTestCase):

    def test_alibaba_scope_flow_follows_polling_rules(self):
        scope = 'openid interclient_access'
        success = (200, dict(SUCCESS[1], scope=scope))
        fake = FakeOkta([SLOW_DOWN, PENDING, success])
        result = self.run_flow(fake, device_flow_scope=scope)
        self.assertEqual(fake.device_requests[0]['scope'], scope)
        self.assertEqual(fake.polls, [0, 10, 20])
        self.assertEqual(result['scope'], scope)


class TestGetUserTokensDirectCalls(unittest.TestCase):

    def setUp(self):
        self.client = OktaIdentityEngine(Mock(), ORG_URL, CLIENT_ID, False)
        self.calls = []

    def respond_with(self, status, body):
        def post(url, **kwargs):
            self.calls.append(kwargs)
            return make_response(url, status, body)
        self.client._http_client.post = post

    def test_success_returns_token_response_and_stores_tokens(self):
        self.respond_with(*SUCCESS)
        self.assertEqual(self.client._get_user_tokens(DEVICE_CODE), SUCCESS[1])
        self.assertEqual(self.client._oauth_access_token, ACCESS_TOKEN)
        self.assertEqual(self.client._oauth_id_token, 'id-token')

    def test_pending_returns_none(self):
        self.respond_with(*PENDING)
        self.assertIsNone(self.client._get_user_tokens(DEVICE_CODE))

    def test_slow_down_raises_http_error_subclass(self):
        self.respond_with(*SLOW_DOWN)
        with self.assertRaises(requests.exceptions.HTTPError) as context:
            self.client._get_user_tokens(DEVICE_CODE)
        self.assertIsInstance(context.exception, DeviceAuthorizationSlowDown)
        self.assertEqual(context.exception.response.status_code, 400)

    def test_default_request_timeout_is_http_timeout(self):
        self.respond_with(*PENDING)
        self.client._get_user_tokens(DEVICE_CODE)
        self.assertEqual(self.calls[0]['timeout'], OktaIdentityEngine.HTTP_TIMEOUT)

    def test_explicit_request_timeout_is_used(self):
        self.respond_with(*PENDING)
        self.client._get_user_tokens(DEVICE_CODE, timeout=4.5)
        self.assertEqual(self.calls[0]['timeout'], 4.5)

    def test_unexpected_success_status_is_not_treated_as_pending(self):
        self.respond_with(202, {})
        with self.assertRaises(errors.GimmeAWSCredsError) as context:
            self.client._get_user_tokens(DEVICE_CODE)
        self.assertIn('202', context.exception.message)


if __name__ == '__main__':
    unittest.main()
