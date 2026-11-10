"""Missing-SAML errors must not copy remote URLs or HTML into CLI output."""
import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import Mock, patch

from gimme_aws_creds import ui
from gimme_aws_creds.errors import GimmeAWSCredsError
from gimme_aws_creds.okta_identity_engine import OktaIdentityEngine


class TestOIESAMLErrors(unittest.TestCase):
    def setUp(self):
        self.client = OktaIdentityEngine(ui.default, 'https://example.invalid', 'synthetic', debug=False)
        self.addCleanup(self.client._http_client.close)
        self.session = {'access_token': 'access-sentinel', 'id_token': 'id-sentinel'}
        self.url = 'https://example.invalid/home/url-sentinel/app?state=state-sentinel'

    def test_missing_saml_does_not_echo_url_or_error_page(self):
        for html in ('<div class="error-content">body-sentinel</div>',
                     '<p>body-sentinel</p>'):
            with self.subTest(html=html), \
                    patch.object(self.client, '_web_sso_token_exchange',
                                 return_value={'access_token': 'sso-sentinel'}), \
                    patch.object(self.client._http_client, 'get',
                                 return_value=Mock(status_code=200, text=html)):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(GimmeAWSCredsError) as raised:
                        self.client.get_saml_response(self.url, self.session)
                    error = raised.exception
                    self.assertEqual(error.return_code, 2)
                    self.assertEqual(error.message,
                                     'Did not receive SAML Response after successful authentication')
                    with self.assertRaises(SystemExit) as exited:
                        error.handle()
                    self.assertEqual(exited.exception.code, 2)
                self.assertEqual(stdout.getvalue(), '\n')
                self.assertIn(error.message, stderr.getvalue())
                visible = str(error) + repr(error.args) + stdout.getvalue() + stderr.getvalue()
                for sentinel in ('url-sentinel', 'state-sentinel', 'body-sentinel',
                                 'access-sentinel', 'id-sentinel', 'sso-sentinel'):
                    self.assertNotIn(sentinel, visible)

    def test_successful_saml_form_is_unchanged(self):
        html = ('<form action="https://cloud.invalid/saml">'
                '<input name="SAMLResponse" value="assertion-sentinel">'
                '<input name="RelayState" value="relay-sentinel"></form>')
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(self.client, '_web_sso_token_exchange',
                          return_value={'access_token': 'sso-sentinel'}), \
                patch.object(self.client._http_client, 'get',
                             return_value=Mock(status_code=200, text=html)), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            result = self.client.get_saml_response(self.url, self.session)
        self.assertEqual(result, {'SAMLResponse': 'assertion-sentinel',
                                  'RelayState': 'relay-sentinel',
                                  'TargetUrl': 'https://cloud.invalid/saml'})
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')
