"""Classic SAML failures must not echo the request URL or Okta page text.

These run without --debug: no debug logging or record factory is installed,
so the error message itself has to be free of the session token and of any
value the error page repeats. HTTP is served by an in-process adapter.
"""
import io
import logging
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import requests
from requests.adapters import BaseAdapter

from gimme_aws_creds import errors
from gimme_aws_creds.okta_classic import OktaClassicClient
from tests.user_interface_mock import MockUserInterface

ORG = 'https://example.okta.test'
APP_PATH = '/home/amazon_aws/0oa1b2c3d4E5F6g7H8i9/272'
SESSION_TOKEN = 'stJ4kW9pRx2aLq7D'
PASSWORD = 'pwB6nT3vMz8YcK1H'


def _windows(secret, size=8):
    return {secret[i:i + size] for i in range(len(secret) - size + 1)}


class PageAdapter(BaseAdapter):
    """Returns one HTML page with HTTP 200 for every GET."""

    def __init__(self, page):
        super().__init__()
        self.page = page
        self.urls = []

    def send(self, request, **kwargs):
        self.urls.append(request.url)
        response = requests.Response()
        response.status_code = 200
        response.reason = 'OK'
        response.headers['Content-Type'] = 'text/html'
        response._content = self.page.encode()
        response.request = request
        response.url = request.url
        return response

    def close(self):
        pass


class TestClassicSamlErrors(unittest.TestCase):

    def _client(self, page):
        client = OktaClassicClient(MockUserInterface(), ORG, use_keyring=False, debug=False)
        adapter = PageAdapter(page)
        client._http_client.mount('https://', adapter)
        return client, adapter

    def _fail(self, page):
        client, adapter = self._client(page)
        stdout, stderr = io.StringIO(), io.StringIO()
        # Other tests may leave the --debug record factory installed in this
        # process; use the plain factory so nothing here depends on it.
        saved = logging.getLogRecordFactory()
        logging.setLogRecordFactory(logging.LogRecord)
        try:
            with patch('sys.stderr', stderr), redirect_stdout(stdout):
                with self.assertRaises(errors.GimmeAWSCredsError) as raised:
                    client.get_saml_response(f'{ORG}{APP_PATH}?sessionToken={SESSION_TOKEN}')
                raised.exception.handle_message()
            self.assertIs(logging.getLogRecordFactory(), logging.LogRecord)
        finally:
            logging.setLogRecordFactory(saved)
        self.assertIn(f'sessionToken={SESSION_TOKEN}', adapter.urls[0])
        return raised.exception, stdout.getvalue() + stderr.getvalue()

    def assertNoSecrets(self, text):
        for secret in (SESSION_TOKEN, PASSWORD):
            for window in _windows(secret):
                self.assertNotIn(window, text)

    def test_missing_saml_does_not_echo_session_token_url(self):
        error, output = self._fail('<html><body>No SAML here</body></html>')
        self.assertEqual(error.return_code, 2)
        self.assertEqual(error.message, 'Did not receive SAML Response after successful authentication')
        self.assertNoSecrets(error.message + output)
        self.assertNotIn('sessionToken', error.message + output)
        self.assertIn('Did not receive SAML Response', output)

    def test_error_page_text_is_not_echoed(self):
        page = ('<html><body><div class="error-content">'
                f'Login failed for password {PASSWORD} (sessionToken={SESSION_TOKEN})'
                '</div></body></html>')
        error, output = self._fail(page)
        self.assertEqual(error.return_code, 2)
        self.assertEqual(
            error.message,
            'Did not receive SAML Response after successful authentication '
            '(Okta returned an error page; its text is not shown)')
        self.assertNoSecrets(error.message + output)
        self.assertNotIn('Login failed', error.message + output)

    def test_successful_saml_response_is_still_returned(self):
        page = ('<html><body><form method="post" action="https://signin.aws.amazon.com/saml">'
                '<input type="hidden" name="SAMLResponse" value="PHNhbWw+c3ludGhldGljPC9zYW1sPg=="/>'
                '<input type="hidden" name="RelayState" value=""/></form></body></html>')
        client, _ = self._client(page)
        result = client.get_saml_response(f'{ORG}{APP_PATH}?sessionToken={SESSION_TOKEN}')
        self.assertEqual(result['SAMLResponse'], 'PHNhbWw+c3ludGhldGljPC9zYW1sPg==')
        self.assertEqual(result['TargetUrl'], 'https://signin.aws.amazon.com/saml')


if __name__ == '__main__':
    unittest.main()
