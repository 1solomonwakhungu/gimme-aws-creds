"""Exercise polling through the real requests/urllib3 retry path, without sockets."""
import io
import json
import unittest
from unittest.mock import Mock, patch

import urllib3

from gimme_aws_creds.errors import GimmeAWSCredsError
from gimme_aws_creds.okta_identity_engine import OktaIdentityEngine


class TestDevicePollingTransport(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.attempts = []
        self.sleeps = []
        self.client = OktaIdentityEngine(Mock(), 'https://example.invalid', 'synthetic')
        self.client._http_client.trust_env = False
        self.addCleanup(self.client._http_client.close)
        self.client._monotonic = lambda: self.now
        self.client._sleep = self.sleep

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    @staticmethod
    def response(status=200, data=None, headers=None):
        return urllib3.response.HTTPResponse(
            body=io.BytesIO(json.dumps(data or {'access_token': 'synthetic'}).encode()),
            status=status, headers=headers or {'Content-Type': 'application/json'},
            preload_content=False)

    def transport(self, outcome):
        def make_request(pool, conn, method, url, *args, **kwargs):
            self.attempts.append((self.now, kwargs['timeout'].connect_timeout))
            return outcome(pool, url, kwargs)

        patches = (
            patch.object(urllib3.connectionpool.HTTPSConnectionPool, '_make_request', make_request),
            patch('urllib3.util.retry.time.sleep', self.sleep),
        )
        for guard in patches:
            guard.start()
            self.addCleanup(guard.stop)

    def poll(self, budget):
        self.client._device_flow_timeout = budget
        return self.client._poll_for_user_tokens('synthetic-device-code', 5, None, 0)

    def test_connect_timeout_cannot_retry_beyond_deadline(self):
        def timeout(pool, url, kwargs):
            self.now += kwargs['timeout'].connect_timeout
            raise urllib3.exceptions.ConnectTimeoutError('synthetic timeout')

        self.transport(timeout)
        with self.assertRaises(GimmeAWSCredsError):
            self.poll(3)
        self.assertEqual(self.attempts, [(0, 3)])
        self.assertEqual(self.sleeps, [])

    def test_read_timeout_cannot_retry_beyond_deadline(self):
        def timeout(pool, url, kwargs):
            self.now += kwargs['timeout'].read_timeout
            raise urllib3.exceptions.ReadTimeoutError(pool, url, 'synthetic timeout')

        self.transport(timeout)
        with self.assertRaises(GimmeAWSCredsError):
            self.poll(3)
        self.assertEqual(self.attempts, [(0, 3)])
        self.assertEqual(self.sleeps, [])

    def test_read_timeouts_reach_polling_backoff(self):
        def outcome(pool, url, kwargs):
            if len(self.attempts) < 3:
                self.now += 0.25
                raise urllib3.exceptions.ReadTimeoutError(pool, url, 'synthetic timeout')
            return self.response()

        self.transport(outcome)
        self.assertEqual(self.poll(60), {'access_token': 'synthetic'})
        self.assertEqual([at for at, _ in self.attempts], [0, 10.25, 30.5])
        self.assertEqual(self.sleeps, [10, 20])

    def test_repeated_read_timeouts_end_with_cli_timeout(self):
        def timeout(pool, url, kwargs):
            self.now += 0.25
            raise urllib3.exceptions.ReadTimeoutError(pool, url, 'synthetic timeout')

        self.transport(timeout)
        with self.assertRaises(GimmeAWSCredsError) as raised:
            self.poll(120)
        self.assertIn('Timeout waiting for device authorization', raised.exception.message)
        self.assertEqual([at for at, _ in self.attempts], [0, 10.25, 30.5, 70.75])

    def test_retry_after_cannot_hide_terminal_oauth_error(self):
        self.transport(lambda *args: self.response(
            429, {'error': 'access_denied'}, {'Retry-After': '60'}))
        with self.assertRaises(GimmeAWSCredsError) as raised:
            self.poll(3)
        self.assertIn('denied', raised.exception.message)
        self.assertEqual(self.attempts, [(0, 3)])
        self.assertEqual(self.sleeps, [])

    def test_redirect_cannot_start_another_token_request(self):
        self.transport(lambda *args: self.response(
            307, {'message': 'redirect'}, {'Location': '/other-token-endpoint'}))
        with self.assertRaises(GimmeAWSCredsError) as raised:
            self.poll(3)
        self.assertIn('Unexpected HTTP 307', raised.exception.message)
        self.assertEqual(self.attempts, [(0, 3)])

    def test_unrelated_authorization_and_exchange_requests_keep_retries(self):
        for path, grant in (('/oauth2/v1/device/authorize', None),
                            ('/oauth2/v1/token', 'urn:ietf:params:oauth:grant-type:token-exchange')):
            with self.subTest(path=path):
                self.attempts.clear()

                def outcome(pool, url, kwargs):
                    if len(self.attempts) == 1:
                        raise urllib3.exceptions.ConnectTimeoutError('synthetic timeout')
                    return self.response()

                self.transport(outcome)
                response = self.client._http_client.post(
                    'https://example.invalid' + path, data={'grant_type': grant}, timeout=3)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(len(self.attempts), 2)

    def test_polling_preserves_session_cookies_and_response_hooks(self):
        seen = []

        def outcome(pool, url, kwargs):
            seen.append(kwargs['headers']['Cookie'])
            return self.response()

        self.transport(outcome)
        hook = Mock()
        hook.side_effect = lambda response, **kwargs: response
        self.client._http_client.hooks['response'].append(hook)
        self.client._http_client.cookies.set('synthetic', 'cookie')
        self.poll(3)
        self.assertEqual(seen, ['synthetic=cookie'])
        hook.assert_called_once()
