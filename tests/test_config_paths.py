"""Configuration discovery and first-write directory behavior."""
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from gimme_aws_creds.config import Config
from gimme_aws_creds.errors import GimmeAWSCredsError


class TestConfigPaths(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.legacy = self.home / '.okta_aws_login_config'
        self.xdg = self.home / '.config' / 'gimme-aws-creds' / 'config'

    def config(self, environ=None):
        ui = SimpleNamespace(HOME=str(self.home), environ=environ or {})
        return Config(ui, create_config=False)

    def create_file(self, path, contents='[DEFAULT]\nclient_id = synthetic\n'):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    @unittest.skipIf(os.name == 'nt', 'POSIX default')
    def test_new_installation_uses_xdg_without_creating_paths(self):
        config = self.config()
        self.assertEqual(config.OKTA_CONFIG, str(self.xdg))
        self.assertEqual(list(self.home.iterdir()), [])

    @unittest.skipIf(os.name == 'nt', 'POSIX default')
    def test_existing_xdg_file_is_read(self):
        self.create_file(self.xdg)
        self.assertEqual(self.config().get_config_dict()['client_id'], 'synthetic')

    def test_legacy_wins_when_both_exist(self):
        self.create_file(self.legacy, '[DEFAULT]\nclient_id = legacy\n')
        self.create_file(self.xdg)
        config = self.config()
        self.assertEqual(config.OKTA_CONFIG, str(self.legacy))
        self.assertEqual(config.get_config_dict()['client_id'], 'legacy')

    def test_explicit_override_wins_over_both(self):
        self.create_file(self.legacy)
        self.create_file(self.xdg)
        explicit = str(self.home / 'custom' / 'login')
        self.assertEqual(self.config({'OKTA_CONFIG': explicit}).OKTA_CONFIG, explicit)

    def test_explicit_relative_and_empty_overrides_remain_literal(self):
        for value in ('relative-config', ''):
            with self.subTest(value=value):
                self.assertEqual(self.config({'OKTA_CONFIG': value}).OKTA_CONFIG, value)

    @unittest.skipIf(os.name == 'nt', 'POSIX default')
    def test_absolute_xdg_override(self):
        root = str(self.home / 'other-config')
        self.assertEqual(self.config({'XDG_CONFIG_HOME': root}).OKTA_CONFIG,
                         os.path.join(root, 'gimme-aws-creds', 'config'))

    @unittest.skipIf(os.name == 'nt', 'POSIX default')
    def test_invalid_xdg_home_uses_default(self):
        for value in ('', 'relative', '~/config'):
            with self.subTest(value=value):
                self.assertEqual(self.config({'XDG_CONFIG_HOME': value}).OKTA_CONFIG,
                                 str(self.xdg))

    def test_windows_keeps_legacy_default(self):
        with patch('gimme_aws_creds.config.os.name', 'nt'):
            config = self.config({'XDG_CONFIG_HOME': str(self.home / 'other')})
        self.assertEqual(config.OKTA_CONFIG, str(self.legacy))

    def test_legacy_directory_is_not_silently_bypassed(self):
        self.legacy.mkdir()
        self.create_file(self.xdg)
        self.assertEqual(self.config().OKTA_CONFIG, str(self.legacy))

    @unittest.skipIf(os.name == 'nt', 'symlink permissions vary on Windows')
    def test_broken_legacy_symlink_is_not_silently_bypassed(self):
        self.legacy.symlink_to(self.home / 'missing')
        self.create_file(self.xdg)
        self.assertEqual(self.config().OKTA_CONFIG, str(self.legacy))

    @unittest.skipIf(os.name == 'nt', 'POSIX permissions')
    def test_unreadable_legacy_is_not_silently_bypassed(self):
        self.create_file(self.legacy)
        self.legacy.chmod(0)
        self.addCleanup(self.legacy.chmod, 0o600)
        self.create_file(self.xdg)
        self.assertEqual(self.config().OKTA_CONFIG, str(self.legacy))

    def test_nested_parent_created_only_on_write(self):
        destination = self.home / 'new' / 'nested' / 'login'
        config = self.config({'OKTA_CONFIG': str(destination)})
        self.assertFalse(destination.parent.exists())
        config.write_config_file({'client_id': 'synthetic'})
        self.assertEqual(config.get_config_dict()['client_id'], 'synthetic')
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(destination.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(destination.parent.parent.stat().st_mode), 0o700)

    @unittest.skipIf(os.name == 'nt', 'POSIX permissions')
    def test_existing_parent_permissions_preserved(self):
        parent = self.home / 'existing'
        parent.mkdir(mode=0o755)
        before = stat.S_IMODE(parent.stat().st_mode)
        self.config({'OKTA_CONFIG': str(parent / 'login')}).write_config_file({'client_id': 'synthetic'})
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), before)

    def test_parent_creation_failure_is_actionable(self):
        config = self.config({'OKTA_CONFIG': str(self.home / 'new' / 'login')})
        with patch('gimme_aws_creds.config.os.mkdir', side_effect=PermissionError(13, 'Permission denied')):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'Cannot write configuration file.*Permission denied'):
                config.write_config_file({'client_id': 'synthetic'})

    def test_file_in_parent_path_is_actionable(self):
        parent = self.home / 'not-a-directory'
        parent.write_text('existing data')
        config = self.config({'OKTA_CONFIG': str(parent / 'login')})
        with self.assertRaisesRegex(GimmeAWSCredsError, 'Cannot write configuration file'):
            config.write_config_file({'client_id': 'synthetic'})
        self.assertEqual(parent.read_text(), 'existing data')

    def test_named_profile_write_preserves_other_profiles(self):
        destination = self.home / 'nested' / 'login'
        self.create_file(destination, '[first]\nclient_id = original\n')
        config = self.config({'OKTA_CONFIG': str(destination)})
        config.conf_profile = 'second'
        config.write_config_file({'client_id': 'new'})
        self.assertEqual(config.get_config_dict()['client_id'], 'new')
        config.conf_profile = 'first'
        self.assertEqual(config.get_config_dict()['client_id'], 'original')

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink traversal')
    def test_existing_parent_after_symlink_dotdot_needs_no_creation(self):
        leaf = self.home / 'real' / 'leaf'
        leaf.mkdir(parents=True)
        destination = self.home / 'real' / 'dest' / 'config'
        self.create_file(destination)
        link = self.home / 'link'
        link.symlink_to(leaf, target_is_directory=True)
        path = str(link) + '/../dest/config'
        config = self.config({'OKTA_CONFIG': path})
        with patch('gimme_aws_creds.config.os.mkdir') as mkdir:
            config.write_config_file({'client_id': 'updated'})
        mkdir.assert_not_called()
        self.assertIn('updated', destination.read_text())
        self.assertFalse((self.home / 'dest').exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink traversal')
    def test_missing_parent_after_symlink_dotdot_uses_actual_destination(self):
        leaf = self.home / 'real' / 'leaf'
        leaf.mkdir(parents=True)
        link = self.home / 'link'
        link.symlink_to(leaf, target_is_directory=True)
        for name in ('explicit', 'xdg'):
            with self.subTest(location=name):
                root = str(link) + '/../' + name
                environ = ({'OKTA_CONFIG': root + '/config'} if name == 'explicit'
                           else {'XDG_CONFIG_HOME': root})
                config = self.config(environ)
                config.write_config_file({'client_id': 'synthetic'})
                destination = self.home / 'real' / name
                if name == 'xdg':
                    destination = destination / 'gimme-aws-creds'
                self.assertTrue((destination / 'config').is_file())
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
                self.assertFalse((self.home / name).exists())

    def test_relative_parent_creation_terminates_at_current_directory(self):
        previous = os.getcwd()
        try:
            os.chdir(self.home)
            self.config({'OKTA_CONFIG': 'nested/config'}).write_config_file({'client_id': 'synthetic'})
            self.assertTrue((self.home / 'nested' / 'config').is_file())
        finally:
            os.chdir(previous)
