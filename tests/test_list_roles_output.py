"""Tests for --action-list-roles output, including --output-format json."""
import base64
import io
import json
import os
import shutil
import tempfile
import unittest
from collections import namedtuple
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest.mock import PropertyMock, patch
from xml.sax.saxutils import escape, quoteattr

from gimme_aws_creds import ui
from gimme_aws_creds.alibaba_cloud import ALIBABA_CLOUD_SAML_ROLE_ATTRIBUTE, AlibabaCloudClient
from gimme_aws_creds.aws import AwsResolver
from gimme_aws_creds.common import RoleSet
from gimme_aws_creds.config import Config
from gimme_aws_creds.main import GimmeAWSCreds
from tests import read_fixture
from tests.user_interface_mock import MockUserInterface

AWS_ROLE_ATTRIBUTE = 'https://aws.amazon.com/SAML/Attributes/Role'
ROLE_KEYS = ['idp', 'role', 'friendly_account_name', 'friendly_role_name']

# Values that only exist in the SAML response or the Okta session. None of them
# may appear in the role listing.
SUBJECT_SENTINEL = 'subject-sentinel-6f1c@example.com'
RELAY_STATE_SENTINEL = 'relay-state-sentinel-93ad'
SESSION_SENTINEL = 'okta-session-sentinel-2be7'
DEVICE_TOKEN_SENTINEL = 'device-token-sentinel-c4d0'


def saml_response(attribute_name, values):
    """Build a base64 SAML response with one multi-valued attribute."""
    attribute_values = ''.join(
        '<saml2:AttributeValue>{}</saml2:AttributeValue>'.format(escape(value)) for value in values)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<saml2:Subject><saml2:NameID>{subject}</saml2:NameID></saml2:Subject>'
        '<saml2:AttributeStatement>'
        '<saml2:Attribute Name={name}>{values}</saml2:Attribute>'
        '</saml2:AttributeStatement>'
        '</saml2:Assertion>'
        '</saml2p:Response>'
    ).format(subject=escape(SUBJECT_SENTINEL), name=quoteattr(attribute_name), values=attribute_values)
    return base64.b64encode(xml.encode('utf-8')).decode('ascii')


def saml_data(attribute_name, values):
    return {
        'SAMLResponse': saml_response(attribute_name, values),
        'RelayState': RELAY_STATE_SENTINEL,
        'TargetUrl': 'https://signin.aws.amazon.com/saml',
    }


def parse_listing(test, output):
    """Parse a JSON role listing and check the documented entry shape."""
    entries = json.loads(output, object_pairs_hook=lambda pairs: pairs)
    test.assertIsInstance(entries, list)
    for pairs in entries:
        test.assertEqual([key for key, _ in pairs], ROLE_KEYS)
        for _, value in pairs:
            test.assertIsInstance(value, str)
    return [dict(pairs) for pairs in entries]


class TestRolesToJson(unittest.TestCase):
    """The serializer behind --action-list-roles --output-format json."""

    def test_entries_have_documented_keys_in_order(self):
        roles = [
            RoleSet(idp='arn:aws:iam::123456789012:saml-provider/okta',
                    role='arn:aws:iam::123456789012:role/Admin',
                    friendly_account_name='Account: example (123456789012)',
                    friendly_role_name='Admin'),
        ]
        output = GimmeAWSCreds._roles_to_json(roles)
        self.assertEqual(
            output,
            '[{"idp": "arn:aws:iam::123456789012:saml-provider/okta", '
            '"role": "arn:aws:iam::123456789012:role/Admin", '
            '"friendly_account_name": "Account: example (123456789012)", '
            '"friendly_role_name": "Admin"}]')
        self.assertEqual(list(GimmeAWSCreds.ROLE_LISTING_FIELDS), ROLE_KEYS)

    def test_empty_list(self):
        self.assertEqual(GimmeAWSCreds._roles_to_json([]), '[]')

    def test_preserves_discovery_order(self):
        names = ['zeta', 'alpha', 'mid', 'alpha']
        roles = [RoleSet(idp='idp-{}'.format(i), role='arn:aws:iam::1:role/{}'.format(name),
                         friendly_account_name='', friendly_role_name=name)
                 for i, name in enumerate(names)]
        entries = parse_listing(self, GimmeAWSCreds._roles_to_json(roles))
        self.assertEqual([entry['friendly_role_name'] for entry in entries], names)
        self.assertEqual([entry['idp'] for entry in entries], ['idp-0', 'idp-1', 'idp-2', 'idp-3'])

    def test_escaping_and_unicode(self):
        tricky = [
            'quote " and backslash \\',
            'line\nbreak\r\tand tab',
            'nul \x00 and bell \x07',
            'line separator   paragraph  ',
            'café 日本 \U0001F600',
            '</script>&<>',
        ]
        roles = [RoleSet(idp='idp', role='role-{}'.format(i),
                         friendly_account_name=value, friendly_role_name=value[::-1])
                 for i, value in enumerate(tricky)]
        output = GimmeAWSCreds._roles_to_json(roles)
        self.assertTrue(output.isascii())
        self.assertNotIn('\n', output)
        self.assertNotIn('\r', output)
        entries = parse_listing(self, output)
        self.assertEqual([entry['friendly_account_name'] for entry in entries], tricky)
        self.assertEqual([entry['friendly_role_name'] for entry in entries], [v[::-1] for v in tricky])

    def test_missing_values_become_empty_strings(self):
        roles = [RoleSet(idp='idp', role='role', friendly_account_name=None, friendly_role_name=None)]
        self.assertEqual(parse_listing(self, GimmeAWSCreds._roles_to_json(roles)), [
            {'idp': 'idp', 'role': 'role', 'friendly_account_name': '', 'friendly_role_name': ''},
        ])

    def test_only_listing_fields_are_serialized(self):
        ExtendedRole = namedtuple('ExtendedRole', RoleSet._fields + ('saml_assertion', 'credentials'))
        role = ExtendedRole(idp='idp', role='role', friendly_account_name='acct', friendly_role_name='name',
                            saml_assertion=SUBJECT_SENTINEL, credentials={'secret': SESSION_SENTINEL})
        output = GimmeAWSCreds._roles_to_json([role])
        self.assertEqual(parse_listing(self, output), [
            {'idp': 'idp', 'role': 'role', 'friendly_account_name': 'acct', 'friendly_role_name': 'name'},
        ])
        self.assertNotIn(SUBJECT_SENTINEL, output)
        self.assertNotIn(SESSION_SENTINEL, output)


class TestHandleActionListRolesDisabled(unittest.TestCase):
    """Without --action-list-roles the handler does nothing, whatever the output format."""

    def setUp(self):
        self.test_ui = MockUserInterface(argv=['gimme-aws-creds', '-o', 'json'])
        self.addCleanup(shutil.rmtree, self.test_ui.HOME, ignore_errors=True)
        with open(os.path.join(self.test_ui.HOME, '.okta_aws_login_config'), 'w') as config_file:
            config_file.write('[DEFAULT]\nokta_org_url = https://example.okta.com\n')

    def test_handler_returns_without_discovering_roles(self):
        creds = GimmeAWSCreds(ui=self.test_ui)
        with patch.object(GimmeAWSCreds, 'aws_roles', new_callable=PropertyMock,
                          side_effect=AssertionError('roles must not be discovered')) as aws_roles:
            self.assertIsNone(creds.handle_action_list_roles())
        aws_roles.assert_not_called()


class CliRunTestBase(unittest.TestCase):
    """Runs GimmeAWSCreds.run() with the real CLI user interface and error handling.

    Okta sign-in and SAML retrieval are replaced by a cached session and a
    synthetic SAML response. Everything that could request or store cloud
    credentials, or rewrite the configuration file, fails the test if called.
    """

    CONFIG = (
        '[DEFAULT]\n'
        'okta_org_url = https://example.okta.com\n'
        'gimme_creds_server = appurl\n'
        'app_url = https://example.okta.com/home/amazon_aws/0oaexample/272\n'
        'write_aws_creds = True\n'
        'cred_profile = role\n'
    )

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.config_path = os.path.join(self.home, '.okta_aws_login_config')
        self.aws_credentials = os.path.join(self.home, 'aws-credentials')
        self.alibaba_credentials = os.path.join(self.home, 'aliyun-config.json')

    def write_config(self, extra=''):
        with open(self.config_path, 'w') as config_file:
            config_file.write(self.CONFIG + extra)

    def run_cli(self, args, data, environ=None):
        """Return (exit code, stdout, stderr) for one in-process CLI run."""
        env = {
            'HOME': self.home,
            'AWS_SHARED_CREDENTIALS_FILE': self.aws_credentials,
            'ALIBABA_CLOUD_SHARED_CREDENTIALS_FILE': self.alibaba_credentials,
        }
        env.update(environ or {})
        with open(self.config_path, 'rb') as config_file:
            config_before = config_file.read()
        files_before = sorted(os.listdir(self.home))

        creds = GimmeAWSCreds(ui=ui.CLIUserInterface(environ=env, argv=['gimme-aws-creds'] + list(args)))
        creds.set_okta_platform('identity_engine')
        creds.set_auth_session({
            'session': SESSION_SENTINEL,
            'username': 'synthetic.user',
            'device_token': DEVICE_TOKEN_SENTINEL,
        })

        def fake_saml_data(instance):
            # Stand-ins for messages written while signing in to Okta.
            instance.ui.info('Authentication Success! Calling Gimme-Creds Server...')
            instance.ui.prompt('Synthetic prompt: ')
            return data

        def forbidden(name):
            return AssertionError('{} must not be called while listing roles'.format(name))

        guards = {}
        out, err = io.StringIO(), io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.object(GimmeAWSCreds, 'saml_data', property(fake_saml_data)))
            guards['okta'] = stack.enter_context(patch.object(
                GimmeAWSCreds, 'okta', new_callable=PropertyMock, side_effect=forbidden('okta')))
            for owner, name in [
                (GimmeAWSCreds, '_get_sts_creds'),
                (GimmeAWSCreds, 'prepare_data'),
                (GimmeAWSCreds, 'iter_selected_aws_credentials'),
                (GimmeAWSCreds, 'write_result_action'),
                (GimmeAWSCreds, 'write_credentials_from_data'),
                (GimmeAWSCreds, '_write_aws_credentials'),
                (GimmeAWSCreds, '_write_alibaba_cloud_credentials'),
                (AlibabaCloudClient, 'assume_role_with_saml'),
                (Config, 'update_config_file'),
                (Config, 'write_config_file'),
            ]:
                guards[name] = stack.enter_context(patch.object(owner, name, side_effect=forbidden(name)))
            guards['boto3.client'] = stack.enter_context(
                patch('boto3.client', side_effect=forbidden('boto3.client')))
            stack.enter_context(redirect_stdout(out))
            stack.enter_context(redirect_stderr(err))
            with self.assertRaises(SystemExit) as exit_info:
                creds.run()

        for name, guard in guards.items():
            with self.subTest(guard=name):
                guard.assert_not_called()
        with open(self.config_path, 'rb') as config_file:
            self.assertEqual(config_file.read(), config_before)
        self.assertEqual(sorted(os.listdir(self.home)), files_before)
        self.assertFalse(os.path.exists(self.aws_credentials))
        self.assertFalse(os.path.exists(self.alibaba_credentials))

        stdout, stderr = out.getvalue(), err.getvalue()
        for secret in (data['SAMLResponse'], RELAY_STATE_SENTINEL, SUBJECT_SENTINEL,
                       SESSION_SENTINEL, DEVICE_TOKEN_SENTINEL):
            self.assertNotIn(secret, stdout)
            self.assertNotIn(secret, stderr)
        return exit_info.exception.code, stdout, stderr

    def run_json(self, args, data, environ=None):
        code, stdout, stderr = self.run_cli(args, data, environ)
        self.assertEqual(code, 0)
        self.assertTrue(stdout.endswith('\n'))
        self.assertEqual(stdout.count('\n'), 1, 'the JSON listing must be a single line')
        self.assertIn('Authentication Success!', stderr)
        self.assertIn('Synthetic prompt: ', stderr)
        return parse_listing(self, stdout)


class TestListRolesCliAws(CliRunTestBase):
    PAIRS = [
        'arn:aws:iam::123456789012:saml-provider/okta,arn:aws:iam::123456789012:role/Admin',
        # Role first, provider second: the default resolver accepts either order.
        'arn:aws:iam::210987654321:role/team/ReadOnly,arn:aws:iam::210987654321:saml-provider/okta',
    ]
    EXPECTED = [
        RoleSet(idp='arn:aws:iam::123456789012:saml-provider/okta',
                role='arn:aws:iam::123456789012:role/Admin',
                friendly_account_name='', friendly_role_name=''),
        RoleSet(idp='arn:aws:iam::210987654321:saml-provider/okta',
                role='arn:aws:iam::210987654321:role/team/ReadOnly',
                friendly_account_name='', friendly_role_name=''),
    ]
    EXPECTED_TEXT = (
        "RoleSet(idp='arn:aws:iam::123456789012:saml-provider/okta', "
        "role='arn:aws:iam::123456789012:role/Admin', friendly_account_name='', friendly_role_name='')\n"
        "RoleSet(idp='arn:aws:iam::210987654321:saml-provider/okta', "
        "role='arn:aws:iam::210987654321:role/team/ReadOnly', friendly_account_name='', friendly_role_name='')\n"
    )

    def setUp(self):
        super().setUp()
        self.write_config()

    def test_json_flag_prints_json_array(self):
        for flag in (['-o', 'json'], ['--output-format', 'json'], ['--output-format=json']):
            with self.subTest(flag=flag):
                entries = self.run_json(['--action-list-roles'] + flag, saml_data(AWS_ROLE_ATTRIBUTE, self.PAIRS))
                self.assertEqual(entries, [role._asdict() for role in self.EXPECTED])

    def test_json_flag_before_action_flag(self):
        entries = self.run_json(['-o', 'json', '--action-list-roles'], saml_data(AWS_ROLE_ATTRIBUTE, self.PAIRS))
        self.assertEqual(entries, [role._asdict() for role in self.EXPECTED])

    def test_default_text_listing_unchanged(self):
        code, stdout, stderr = self.run_cli(['--action-list-roles'], saml_data(AWS_ROLE_ATTRIBUTE, self.PAIRS))
        self.assertEqual(code, 0)
        self.assertEqual(stdout, self.EXPECTED_TEXT)
        self.assertEqual(stdout, '\n'.join(map(str, self.EXPECTED)) + '\n')
        self.assertIn('Authentication Success!', stderr)

    def test_export_flag_keeps_text_listing(self):
        code, stdout, _ = self.run_cli(['--action-list-roles', '-o', 'export'],
                                       saml_data(AWS_ROLE_ATTRIBUTE, self.PAIRS))
        self.assertEqual(code, 0)
        self.assertEqual(stdout, self.EXPECTED_TEXT)

    def test_empty_role_list(self):
        data = saml_data(AWS_ROLE_ATTRIBUTE, [])
        self.assertEqual(self.run_json(['--action-list-roles', '-o', 'json'], data), [])
        code, stdout, _ = self.run_cli(['--action-list-roles', '-o', 'json'], data)
        self.assertEqual((code, stdout), (0, '[]\n'))
        code, stdout, _ = self.run_cli(['--action-list-roles'], data)
        self.assertEqual((code, stdout), (0, '\n'))

    def test_non_ascii_role_names_are_escaped(self):
        pairs = ['arn:aws:iam::123456789012:saml-provider/okta,arn:aws:iam::123456789012:role/café-日本']
        code, stdout, _ = self.run_cli(['--action-list-roles', '-o', 'json'], saml_data(AWS_ROLE_ATTRIBUTE, pairs))
        self.assertEqual(code, 0)
        self.assertTrue(stdout.isascii())
        self.assertEqual(parse_listing(self, stdout)[0]['role'],
                         'arn:aws:iam::123456789012:role/café-日本')


class TestListRolesCliStoredOutputFormat(CliRunTestBase):
    """Stored output_format settings select credential output, not the role listing."""

    PAIRS = TestListRolesCliAws.PAIRS
    EXPECTED_TEXT = TestListRolesCliAws.EXPECTED_TEXT

    def test_config_output_format_json_keeps_text_listing(self):
        self.write_config('output_format = json\n')
        code, stdout, _ = self.run_cli(['--action-list-roles'], saml_data(AWS_ROLE_ATTRIBUTE, self.PAIRS))
        self.assertEqual((code, stdout), (0, self.EXPECTED_TEXT))

    def test_env_output_format_json_keeps_text_listing(self):
        self.write_config()
        code, stdout, _ = self.run_cli(['--action-list-roles'], saml_data(AWS_ROLE_ATTRIBUTE, self.PAIRS),
                                       environ={'GIMME_AWS_CREDS_OUTPUT_FORMAT': 'json'})
        self.assertEqual((code, stdout), (0, self.EXPECTED_TEXT))

    def test_json_flag_overrides_stored_settings(self):
        for stored in ('export', 'windows'):
            with self.subTest(stored=stored):
                self.write_config('output_format = {}\n'.format(stored))
                entries = self.run_json(['--action-list-roles', '-o', 'json'],
                                        saml_data(AWS_ROLE_ATTRIBUTE, self.PAIRS),
                                        environ={'GIMME_AWS_CREDS_OUTPUT_FORMAT': stored})
                self.assertEqual(len(entries), 2)

    def test_json_flag_without_listing_keeps_credential_output(self):
        self.write_config()
        record = {'shared_credentials_file': self.aws_credentials, 'profile': {'name': 'role'},
                  'role': {'arn': 'arn:aws:iam::123456789012:role/Admin'},
                  'credentials': {'credentials_type': 'aws', 'aws_access_key_id': 'synthetic-key-id'}}
        env = {'HOME': self.home, 'AWS_SHARED_CREDENTIALS_FILE': self.aws_credentials}
        creds = GimmeAWSCreds(ui=ui.CLIUserInterface(environ=env, argv=['gimme-aws-creds', '-o', 'json']))
        creds.set_okta_platform('identity_engine')
        out = io.StringIO()
        with patch.object(GimmeAWSCreds, 'aws_roles', new_callable=PropertyMock,
                          side_effect=AssertionError('roles must not be listed')), \
                patch.object(GimmeAWSCreds, 'iter_selected_aws_credentials', return_value=iter([record])), \
                patch.object(GimmeAWSCreds, 'write_credentials_from_data',
                             side_effect=AssertionError('-o json must not write files')), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            creds.run()
        self.assertEqual(out.getvalue(), json.dumps(record) + '\n')


class TestListRolesCliAwsResolved(CliRunTestBase):
    """Friendly names from the AWS sign-in page (alias resolution on)."""

    PAIRS = [
        'arn:aws:iam::987654321987:saml-provider/OKTA-IDP,arn:aws:iam::987654321987:role/testrole3',
        'arn:aws:iam::987654321987:saml-provider/OKTA-IDP,arn:aws:iam::987654321987:role/testrole4',
        'arn:aws:iam::987654321987:saml-provider/OKTA-IDP,arn:aws:iam::987654321987:role/testrole5',
        'arn:aws:iam::012345678901:saml-provider/OKTA-IDP,arn:aws:iam::012345678901:role/testrole1',
        'arn:aws:iam::012345678901:saml-provider/OKTA-IDP,arn:aws:iam::012345678901:role/testrole2',
    ]

    def setUp(self):
        super().setUp()
        self.write_config()

    def test_json_includes_friendly_names_in_resolver_order(self):
        data = saml_data(AWS_ROLE_ATTRIBUTE, self.PAIRS)
        with patch.object(AwsResolver, 'get_signinpage', return_value=read_fixture('aws_nextjs.html')) as page:
            entries = self.run_json(['--action-list-roles', '-o', 'json', '--resolve'], data)
        page.assert_called_once_with(data['SAMLResponse'], data['TargetUrl'])
        account1 = 'Account: testaccount1 (012345678901)'
        account2 = 'Account: 987654321987'
        self.assertEqual(entries, [
            {'idp': 'arn:aws:iam::012345678901:saml-provider/OKTA-IDP',
             'role': 'arn:aws:iam::012345678901:role/testrole1',
             'friendly_account_name': account1, 'friendly_role_name': 'testrole1'},
            {'idp': 'arn:aws:iam::012345678901:saml-provider/OKTA-IDP',
             'role': 'arn:aws:iam::012345678901:role/testrole2',
             'friendly_account_name': account1, 'friendly_role_name': 'testrole2'},
            {'idp': 'arn:aws:iam::987654321987:saml-provider/OKTA-IDP',
             'role': 'arn:aws:iam::987654321987:role/testrole3',
             'friendly_account_name': account2, 'friendly_role_name': 'testrole3'},
            {'idp': 'arn:aws:iam::987654321987:saml-provider/OKTA-IDP',
             'role': 'arn:aws:iam::987654321987:role/testrole4',
             'friendly_account_name': account2, 'friendly_role_name': 'testrole4'},
            {'idp': 'arn:aws:iam::987654321987:saml-provider/OKTA-IDP',
             'role': 'arn:aws:iam::987654321987:role/testrole5',
             'friendly_account_name': account2, 'friendly_role_name': 'testrole5'},
        ])


class TestListRolesCliAlibabaCloud(CliRunTestBase):
    PAIRS = [
        'acs:ram::1234567890123456:role/admin,acs:ram::1234567890123456:saml-provider/okta',
        ' acs:ram::7654321098765432:role/ops/ReadOnly , acs:ram::7654321098765432:saml-provider/okta ',
        'acs:ram::example:role/no-account-id,acs:ram::example:saml-provider/okta',
    ]
    EXPECTED = [
        RoleSet(idp='acs:ram::1234567890123456:saml-provider/okta',
                role='acs:ram::1234567890123456:role/admin',
                friendly_account_name='Account: 1234567890123456', friendly_role_name='admin'),
        RoleSet(idp='acs:ram::7654321098765432:saml-provider/okta',
                role='acs:ram::7654321098765432:role/ops/ReadOnly',
                friendly_account_name='Account: 7654321098765432', friendly_role_name='ReadOnly'),
        RoleSet(idp='acs:ram::example:saml-provider/okta',
                role='acs:ram::example:role/no-account-id',
                friendly_account_name='', friendly_role_name='no-account-id'),
    ]

    def setUp(self):
        super().setUp()
        self.write_config('enable_alicloud = True\n')

    def test_json_listing(self):
        entries = self.run_json(['--action-list-roles', '-o', 'json'],
                                saml_data(ALIBABA_CLOUD_SAML_ROLE_ATTRIBUTE, self.PAIRS))
        self.assertEqual(entries, [role._asdict() for role in self.EXPECTED])

    def test_default_text_listing_unchanged(self):
        code, stdout, _ = self.run_cli(['--action-list-roles'],
                                       saml_data(ALIBABA_CLOUD_SAML_ROLE_ATTRIBUTE, self.PAIRS))
        self.assertEqual(code, 0)
        self.assertEqual(stdout, '\n'.join(map(str, self.EXPECTED)) + '\n')


if __name__ == '__main__':
    unittest.main()
