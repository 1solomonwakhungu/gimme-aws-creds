"""Tests for storing credentials records with write_credentials_from_data,
the write_aws_creds_from_data compatibility method and --action-store-json-creds.

All credentials are synthetic and every file lives in a temporary directory.
"""
import configparser
import copy
import io
import json
import os
import pathlib
import shutil
import stat
import tempfile
import unittest
from unittest.mock import Mock, PropertyMock, patch

from gimme_aws_creds import errors
from gimme_aws_creds.main import GimmeAWSCreds
from tests.user_interface_mock import MockUserInterface

AWS_ACCESS = 'synthetic-aws-access-key-id'
AWS_SECRET = 'synthetic-aws-secret-access-key'
AWS_TOKEN = 'synthetic-aws-session-token'
ALIBABA_ACCESS = 'synthetic-alibaba-access-key-id'
ALIBABA_SECRET = 'synthetic-alibaba-access-key-secret'
ALIBABA_TOKEN = 'synthetic-alibaba-security-token'
SECRET_VALUES = (AWS_ACCESS, AWS_SECRET, AWS_TOKEN, ALIBABA_ACCESS, ALIBABA_SECRET, ALIBABA_TOKEN)
EXPIRATION = '2030-01-01T00:00:00+00:00'


def legacy_aws_record(shared_credentials_file, profile_name='legacy-profile'):
    """A record as printed by ``gimme-aws-creds -o json`` before Alibaba Cloud
    support: no ``credentials_type`` field."""
    return {
        'shared_credentials_file': shared_credentials_file,
        'profile': {
            'name': profile_name,
            'derived_name': 'ReadOnly',
            'config_name': 'role',
        },
        'role': {
            'arn': 'arn:aws:iam::123456789012:role/ReadOnly',
            'name': 'arn:aws:iam::123456789012:role/ReadOnly',
            'friendly_name': 'ReadOnly',
            'friendly_account_name': 'Account: example (123456789012)',
        },
        'credentials': {
            'aws_access_key_id': AWS_ACCESS,
            'aws_secret_access_key': AWS_SECRET,
            'aws_session_token': AWS_TOKEN,
            'aws_security_token': AWS_TOKEN,
            'expiration': EXPIRATION,
        },
    }


def aws_record(shared_credentials_file, profile_name='aws-profile'):
    """A record as currently produced for AWS credentials."""
    record = legacy_aws_record(shared_credentials_file, profile_name)
    record['credentials']['credentials_type'] = 'aws'
    return record


def alibaba_record(shared_credentials_file, profile_name='alibaba-profile'):
    """A record as currently produced for Alibaba Cloud credentials."""
    return {
        'shared_credentials_file': shared_credentials_file,
        'profile': {
            'name': profile_name,
            'derived_name': 'ReadOnly',
            'config_name': 'role',
        },
        'role': {
            'arn': 'acs:ram::111122223333:role/ReadOnly',
            'name': 'acs:ram::111122223333:role/ReadOnly',
            'friendly_name': 'ReadOnly',
            'friendly_account_name': 'Account: example (111122223333)',
        },
        'credentials': {
            'access_key_id': ALIBABA_ACCESS,
            'access_key_secret': ALIBABA_SECRET,
            'security_token': ALIBABA_TOKEN,
            'expiration': EXPIRATION,
            'credentials_type': 'alibaba_cloud',
            'region_id': 'cn-shanghai',
        },
    }


class RecordingUserInterface(MockUserInterface):
    def __init__(self, environ=None):
        super().__init__(environ=environ)
        self.warnings = []
        self.messages = []

    def warning(self, message):
        self.warnings.append(message)

    def message(self, message):
        self.messages.append(message)


class CredentialsWriterTestCase(unittest.TestCase):
    def setUp(self):
        # Storing a record must not depend on the login configuration. Fail
        # instead of starting interactive first-run setup if it is loaded.
        config_guard = patch.object(GimmeAWSCreds, 'generate_config',
                                    side_effect=AssertionError('login configuration was loaded'))
        config_guard.start()
        self.addCleanup(config_guard.stop)
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.default_aws_file = os.path.join(self.tmp, 'default-aws', 'credentials')
        self.default_alibaba_file = os.path.join(self.tmp, 'default-aliyun', 'config.json')
        self.ui = RecordingUserInterface(environ={
            'AWS_SHARED_CREDENTIALS_FILE': self.default_aws_file,
            'ALIBABA_CLOUD_SHARED_CREDENTIALS_FILE': self.default_alibaba_file,
        })
        self.addCleanup(shutil.rmtree, self.ui.HOME, True)
        self.creds = GimmeAWSCreds(ui=self.ui)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)

    def login_provider(self, alicloud):
        """Simulate the Alibaba Cloud setting of the profile running the import."""
        return patch.object(GimmeAWSCreds, '_alicloud_enabled', return_value=alicloud)

    def mock_writers(self):
        aws_writer = Mock()
        alibaba_writer = Mock()
        self.creds._write_aws_credentials = aws_writer
        self.creds._write_alibaba_cloud_credentials = alibaba_writer
        return aws_writer, alibaba_writer

    @staticmethod
    def read_aws_file(path):
        config = configparser.RawConfigParser()
        with open(path) as handle:
            config.read_file(handle)
        return config

    @staticmethod
    def read_alibaba_file(path):
        with open(path) as handle:
            return json.load(handle)

    def assert_owner_only(self, path):
        if os.name != 'posix':
            return
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def assert_aws_profile(self, path, profile_name):
        config = self.read_aws_file(path)
        self.assertTrue(config.has_section(profile_name), config.sections())
        self.assertEqual(dict(config.items(profile_name)), {
            'aws_access_key_id': AWS_ACCESS,
            'aws_secret_access_key': AWS_SECRET,
            'aws_session_token': AWS_TOKEN,
            'aws_security_token': AWS_TOKEN,
            'x_security_token_expires': EXPIRATION,
        })
        self.assert_owner_only(path)

    def assert_alibaba_profile(self, path, profile_name):
        config = self.read_alibaba_file(path)
        self.assertEqual(config['current'], profile_name)
        matching = [p for p in config['profiles'] if p['name'] == profile_name]
        self.assertEqual(matching, [{
            'name': profile_name,
            'mode': 'StsToken',
            'access_key_id': ALIBABA_ACCESS,
            'access_key_secret': ALIBABA_SECRET,
            'sts_token': ALIBABA_TOKEN,
            'x_security_token_expires': EXPIRATION,
            'region_id': 'cn-shanghai',
            'language': 'en',
        }])
        self.assert_owner_only(path)


class TestWriteAwsCredsFromData(CredentialsWriterTestCase):
    """write_aws_creds_from_data(data, aws_config=None) keeps its original contract."""

    def test_python_api_example_writes_generated_record(self):
        destination = self.path('aws', 'credentials')
        data = aws_record(destination)
        data['profile']['name'] = 'okta-123456789012'

        self.creds.write_aws_creds_from_data(data)

        self.assert_aws_profile(destination, 'okta-123456789012')
        self.assertEqual(self.ui.warnings, [])

    def test_legacy_record_without_credentials_type(self):
        destination = self.path('aws', 'credentials')

        self.creds.write_aws_creds_from_data(legacy_aws_record(destination))

        self.assert_aws_profile(destination, 'legacy-profile')

    def test_aws_config_keyword_overrides_record_destination(self):
        record_destination = self.path('record', 'credentials')
        explicit_destination = self.path('explicit', 'credentials')

        self.creds.write_aws_creds_from_data(aws_record(record_destination), aws_config=explicit_destination)

        self.assert_aws_profile(explicit_destination, 'aws-profile')
        self.assertFalse(os.path.exists(record_destination))

    def test_aws_config_positional_argument(self):
        explicit_destination = self.path('explicit', 'credentials')

        self.creds.write_aws_creds_from_data(legacy_aws_record(self.path('record', 'credentials')),
                                             explicit_destination)

        self.assert_aws_profile(explicit_destination, 'legacy-profile')

    def test_empty_aws_config_uses_record_destination(self):
        record_destination = self.path('record', 'credentials')

        self.creds.write_aws_creds_from_data(aws_record(record_destination), aws_config='')

        self.assert_aws_profile(record_destination, 'aws-profile')

    def test_default_destination_without_record_destination(self):
        data = legacy_aws_record(None)
        del data['shared_credentials_file']

        self.creds.write_aws_creds_from_data(data)

        self.assert_aws_profile(self.default_aws_file, 'legacy-profile')
        self.assertFalse(os.path.exists(self.default_alibaba_file))

    def test_existing_profiles_are_preserved(self):
        destination = self.path('aws', 'credentials')
        os.makedirs(os.path.dirname(destination))
        with open(destination, 'w') as handle:
            handle.write('[existing]\naws_access_key_id = existing-synthetic-id\n')

        self.creds.write_aws_creds_from_data(aws_record(destination))

        config = self.read_aws_file(destination)
        self.assertEqual(config.get('existing', 'aws_access_key_id'), 'existing-synthetic-id')
        self.assert_aws_profile(destination, 'aws-profile')

    def test_rejects_alibaba_cloud_record(self):
        explicit_destination = self.path('explicit', 'credentials')
        data = alibaba_record(self.path('aliyun', 'config.json'))

        self.creds.write_aws_creds_from_data(data, aws_config=explicit_destination)

        self.assertFalse(os.path.exists(explicit_destination))
        self.assertFalse(os.path.exists(data['shared_credentials_file']))
        self.assertFalse(os.path.exists(self.default_alibaba_file))
        self.assertEqual(len(self.ui.warnings), 1)
        self.assertIn("got 'alibaba_cloud'", self.ui.warnings[0])
        self.assertIn('write_credentials_from_data', self.ui.warnings[0])

    def test_rejects_alibaba_cloud_record_with_mocked_writers(self):
        aws_writer, alibaba_writer = self.mock_writers()

        self.creds.write_aws_creds_from_data(alibaba_record(self.path('aliyun', 'config.json')))

        aws_writer.assert_not_called()
        alibaba_writer.assert_not_called()


class TestWriteCredentialsFromDataRoundTrip(CredentialsWriterTestCase):
    def test_typed_aws_record(self):
        destination = self.path('aws', 'credentials')

        self.creds.write_credentials_from_data(aws_record(destination))

        self.assert_aws_profile(destination, 'aws-profile')
        self.assertIn('Saving arn:aws:iam::123456789012:role/ReadOnly as aws-profile', self.ui.messages)

    def test_legacy_aws_record(self):
        destination = self.path('aws', 'credentials')

        self.creds.write_credentials_from_data(legacy_aws_record(destination))

        self.assert_aws_profile(destination, 'legacy-profile')
        self.assertEqual(self.ui.warnings, [])

    def test_alibaba_cloud_record(self):
        destination = self.path('aliyun', 'config.json')
        os.makedirs(os.path.dirname(destination))
        with open(destination, 'w') as handle:
            json.dump({'current': 'existing', 'profiles': [{'name': 'existing', 'mode': 'AK'}]}, handle)

        self.creds.write_credentials_from_data(alibaba_record(destination))

        self.assert_alibaba_profile(destination, 'alibaba-profile')
        self.assertIn({'name': 'existing', 'mode': 'AK'}, self.read_alibaba_file(destination)['profiles'])

    def test_credentials_file_overrides_record_destination(self):
        cases = (
            ('aws', aws_record, self.assert_aws_profile, 'aws-profile'),
            ('alibaba', alibaba_record, self.assert_alibaba_profile, 'alibaba-profile'),
        )
        for name, make_record, assert_profile, profile_name in cases:
            with self.subTest(provider=name):
                record_destination = self.path(name, 'record')
                explicit_destination = self.path(name, 'explicit')

                self.creds.write_credentials_from_data(make_record(record_destination),
                                                       credentials_file=explicit_destination)

                assert_profile(explicit_destination, profile_name)
                self.assertFalse(os.path.exists(record_destination))

    def test_path_like_credentials_file(self):
        destination = pathlib.Path(self.path('aws', 'credentials'))

        self.creds.write_credentials_from_data(aws_record(None), credentials_file=destination)

        self.assert_aws_profile(str(destination), 'aws-profile')

    def test_provider_default_destination_without_record_destination(self):
        aws_data = aws_record(None)
        del aws_data['shared_credentials_file']
        self.creds.write_credentials_from_data(aws_data)
        self.assert_aws_profile(self.default_aws_file, 'aws-profile')
        self.assertFalse(os.path.exists(self.default_alibaba_file))

        alibaba_data = alibaba_record(None)
        del alibaba_data['shared_credentials_file']
        self.creds.write_credentials_from_data(alibaba_data)
        self.assert_alibaba_profile(self.default_alibaba_file, 'alibaba-profile')
        self.assertEqual(self.read_aws_file(self.default_aws_file).sections(), ['aws-profile'])

    def test_record_type_decides_destination_regardless_of_login_provider(self):
        for alicloud in (False, True):
            with self.subTest(alicloud_enabled=alicloud), self.login_provider(alicloud):
                aws_destination = self.path(str(alicloud), 'aws-credentials')
                alibaba_destination = self.path(str(alicloud), 'aliyun-config.json')

                self.creds.write_credentials_from_data(aws_record(aws_destination))
                self.creds.write_credentials_from_data(alibaba_record(alibaba_destination))

                self.assert_aws_profile(aws_destination, 'aws-profile')
                self.assert_alibaba_profile(alibaba_destination, 'alibaba-profile')
        self.assertEqual(self.ui.warnings, [])


class TestWriteCredentialsFromDataDispatch(CredentialsWriterTestCase):
    def test_typed_records_dispatch_by_credentials_type(self):
        for alicloud in (False, True):
            with self.subTest(alicloud_enabled=alicloud), self.login_provider(alicloud):
                aws_writer, alibaba_writer = self.mock_writers()
                self.creds.write_credentials_from_data(aws_record('/synthetic/aws'))
                aws_writer.assert_called_once_with(
                    'aws-profile', AWS_ACCESS, AWS_SECRET, AWS_TOKEN, EXPIRATION,
                    credentials_file='/synthetic/aws')
                alibaba_writer.assert_not_called()

                aws_writer, alibaba_writer = self.mock_writers()
                self.creds.write_credentials_from_data(alibaba_record('/synthetic/aliyun'))
                alibaba_writer.assert_called_once_with(
                    'alibaba-profile', ALIBABA_ACCESS, ALIBABA_SECRET, ALIBABA_TOKEN, EXPIRATION, 'cn-shanghai',
                    credentials_file='/synthetic/aliyun')
                aws_writer.assert_not_called()

                aws_writer, alibaba_writer = self.mock_writers()
                self.creds.write_credentials_from_data(legacy_aws_record('/synthetic/legacy'))
                aws_writer.assert_called_once_with(
                    'legacy-profile', AWS_ACCESS, AWS_SECRET, AWS_TOKEN, EXPIRATION,
                    credentials_file='/synthetic/legacy')
                alibaba_writer.assert_not_called()
        self.assertEqual(self.ui.warnings, [])

    def test_writing_does_not_load_login_configuration(self):
        # setUp makes loading the login configuration raise.
        aws_writer, alibaba_writer = self.mock_writers()
        self.creds.write_credentials_from_data(aws_record('/synthetic/aws'))
        self.creds.write_credentials_from_data(alibaba_record('/synthetic/aliyun'))
        self.creds.write_credentials_from_data(legacy_aws_record('/synthetic/legacy'))
        self.creds.write_aws_creds_from_data(legacy_aws_record('/synthetic/legacy'))
        self.assertEqual(aws_writer.call_count, 3)
        self.assertEqual(alibaba_writer.call_count, 1)

    def test_extra_fields_of_typed_record_are_ignored(self):
        aws_writer, alibaba_writer = self.mock_writers()
        data = aws_record('/synthetic/aws')
        data['credentials']['region_id'] = 'cn-shanghai'

        self.creds.write_credentials_from_data(data)

        aws_writer.assert_called_once()
        alibaba_writer.assert_not_called()

    def test_role_that_is_not_a_dict_does_not_prevent_write(self):
        aws_writer, _ = self.mock_writers()
        data = aws_record('/synthetic/aws')
        data['role'] = 'not-a-dict'

        self.creds.write_credentials_from_data(data)

        aws_writer.assert_called_once()
        self.assertIn('Saving <no-arn> as aws-profile', self.ui.messages)


DELETE = object()


def rejected_records():
    """(description, record, expected warning fragment) for records that must not be written."""

    def with_credentials(make_record, **changes):
        record = make_record('/synthetic/destination')
        for key, value in changes.items():
            if value is DELETE:
                del record['credentials'][key]
            else:
                record['credentials'][key] = value
        return record

    untyped_alibaba = with_credentials(alibaba_record, credentials_type=DELETE)
    untyped_aws_with_region = with_credentials(legacy_aws_record, region_id='cn-shanghai')
    alibaba_with_aws_fields = with_credentials(aws_record, credentials_type='alibaba_cloud')
    aws_with_alibaba_fields = with_credentials(alibaba_record, credentials_type='aws', region_id=DELETE)
    missing_profile = aws_record('/synthetic/destination')
    del missing_profile['profile']['name']
    missing_credentials = legacy_aws_record('/synthetic/destination')
    del missing_credentials['credentials']
    bad_destination = aws_record('/synthetic/destination')
    bad_destination['shared_credentials_file'] = 42

    return (
        ('unknown credentials_type', with_credentials(aws_record, credentials_type='gcp'),
         'credentials_type is not supported'),
        ('credentials_type with different case', with_credentials(aws_record, credentials_type='AWS'),
         'credentials_type is not supported'),
        ('null credentials_type', with_credentials(aws_record, credentials_type=None),
         'credentials_type is not supported'),
        ('list credentials_type', with_credentials(aws_record, credentials_type=['aws']),
         'credentials_type is not supported'),
        ('secret-valued credentials_type', with_credentials(aws_record, credentials_type=AWS_SECRET),
         'credentials_type is not supported'),
        ('untyped Alibaba Cloud record', untyped_alibaba, 'credentials_type is not set'),
        ('untyped AWS record with Alibaba Cloud field', untyped_aws_with_region, 'region_id'),
        ('Alibaba Cloud record without region_id', with_credentials(alibaba_record, region_id=DELETE),
         'region_id is not set'),
        ('Alibaba Cloud record with empty region_id', with_credentials(alibaba_record, region_id=''),
         'region_id is not set'),
        ('Alibaba Cloud type with AWS fields', alibaba_with_aws_fields, 'access_key_id is not set'),
        ('AWS type with Alibaba Cloud fields', aws_with_alibaba_fields, 'aws_access_key_id is not set'),
        ('AWS record without expiration', with_credentials(aws_record, expiration=DELETE),
         'expiration is not set'),
        ('legacy AWS record without session token', with_credentials(legacy_aws_record, aws_session_token=DELETE),
         'aws_session_token is not set'),
        ('legacy AWS record with empty secret', with_credentials(legacy_aws_record, aws_secret_access_key=''),
         'aws_secret_access_key is not set'),
        ('record without credentials', missing_credentials, 'aws_access_key_id is not set'),
        ('record without profile name', missing_profile, 'name is not set'),
        ('record with non-path destination', bad_destination, 'destination is not a path: int'),
        ('credentials that are not a dict', {'profile': {'name': 'p'}, 'credentials': 'not-a-dict'},
         'credentials are not a dict'),
        ('record that is not a dict', ['not', 'a', 'record'], 'json line is not a dict'),
    )


class TestRejectedRecords(CredentialsWriterTestCase):
    def assert_rejected(self, write, record, fragment):
        self.ui.warnings.clear()
        self.ui.messages.clear()
        aws_writer, alibaba_writer = self.mock_writers()

        write(copy.deepcopy(record))

        aws_writer.assert_not_called()
        alibaba_writer.assert_not_called()
        self.assertTrue(any(fragment in warning for warning in self.ui.warnings), self.ui.warnings)
        self.assertFalse(any(message.startswith('Saving') for message in self.ui.messages))
        for warning in self.ui.warnings:
            for secret in SECRET_VALUES:
                self.assertNotIn(secret, warning)

    def test_generic_writer_rejects_invalid_records(self):
        for alicloud in (False, True):
            for description, record, fragment in rejected_records():
                with self.subTest(record=description, alicloud_enabled=alicloud), self.login_provider(alicloud):
                    self.assert_rejected(self.creds.write_credentials_from_data, record, fragment)

    def test_legacy_writer_rejects_invalid_records(self):
        for description, record, fragment in rejected_records():
            credentials = record.get('credentials') if isinstance(record, dict) else None
            if isinstance(credentials, dict) and credentials.get('credentials_type') == 'alibaba_cloud':
                # The AWS-only method reports the provider before checking Alibaba Cloud fields.
                fragment = "got 'alibaba_cloud'"
            with self.subTest(record=description):
                self.assert_rejected(self.creds.write_aws_creds_from_data, record, fragment)

    def test_rejected_records_leave_files_untouched(self):
        aws_destination = self.path('aws', 'credentials')
        alibaba_destination = self.path('aliyun', 'config.json')
        no_region = alibaba_record(alibaba_destination)
        del no_region['credentials']['region_id']
        unknown = aws_record(aws_destination)
        unknown['credentials']['credentials_type'] = 'gcp'

        self.creds.write_credentials_from_data(no_region)
        self.creds.write_credentials_from_data(unknown)
        self.creds.write_aws_creds_from_data(alibaba_record(alibaba_destination), aws_config=aws_destination)

        self.assertFalse(os.path.exists(aws_destination))
        self.assertFalse(os.path.exists(alibaba_destination))
        self.assertFalse(os.path.exists(self.default_aws_file))
        self.assertFalse(os.path.exists(self.default_alibaba_file))


class TestStoreJsonCreds(CredentialsWriterTestCase):
    def store(self, lines):
        config = Mock(action_store_json_creds=True)
        with patch.object(GimmeAWSCreds, 'config', new_callable=PropertyMock, return_value=config):
            with self.assertRaises(errors.GimmeAWSCredsExitSuccess):
                self.creds.handle_action_store_json_creds(stream=io.StringIO(''.join(lines)))

    def test_stream_stores_valid_records_and_skips_invalid_ones(self):
        aws_destination = self.path('aws', 'credentials')
        alibaba_destination = self.path('aliyun', 'config.json')
        unknown = aws_record(aws_destination, 'unknown-type')
        unknown['credentials']['credentials_type'] = 'gcp'
        no_region = alibaba_record(alibaba_destination, 'no-region')
        del no_region['credentials']['region_id']

        for alicloud in (False, True):
            with self.subTest(alicloud_enabled=alicloud), self.login_provider(alicloud):
                shutil.rmtree(os.path.dirname(aws_destination), ignore_errors=True)
                shutil.rmtree(os.path.dirname(alibaba_destination), ignore_errors=True)
                self.ui.warnings.clear()

                self.store([
                    'not json\n',
                    json.dumps(['not', 'a', 'record']) + '\n',
                    json.dumps(unknown) + '\n',
                    json.dumps(no_region) + '\n',
                    json.dumps(legacy_aws_record(aws_destination)) + '\n',
                    json.dumps(aws_record(aws_destination)) + '\n',
                    json.dumps(alibaba_record(alibaba_destination)),
                ])

                self.assertEqual(self.read_aws_file(aws_destination).sections(),
                                 ['legacy-profile', 'aws-profile'])
                self.assert_aws_profile(aws_destination, 'legacy-profile')
                self.assert_aws_profile(aws_destination, 'aws-profile')
                self.assertEqual([p['name'] for p in self.read_alibaba_file(alibaba_destination)['profiles']],
                                 ['alibaba-profile'])
                self.assert_alibaba_profile(alibaba_destination, 'alibaba-profile')
                self.assertEqual(len(self.ui.warnings), 4, self.ui.warnings)
                for warning in self.ui.warnings:
                    for secret in SECRET_VALUES:
                        self.assertNotIn(secret, warning)


if __name__ == '__main__':
    unittest.main()
