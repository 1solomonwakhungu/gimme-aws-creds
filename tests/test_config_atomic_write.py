"""Tests for atomic, owner-only writes of the Okta configuration file."""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gimme_aws_creds.config import Config
from gimme_aws_creds.errors import GimmeAWSCredsError
from tests.user_interface_mock import MockUserInterface

POSIX = os.name != 'nt'
IS_ROOT = POSIX and os.geteuid() == 0


def file_mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class RecordingUserInterface(MockUserInterface):
    def __init__(self, home, environ=None):
        super().__init__(environ=environ)
        os.rmdir(self.HOME)
        self.HOME = home
        self.warnings = []

    def warning(self, message):
        self.warnings.append(message)


class AtomicConfigWriteTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='gac-atomic-')
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.path = self.home / 'okta_config'
        self.ui = None

    def config(self, path=None):
        self.ui = RecordingUserInterface(str(self.home), {'OKTA_CONFIG': str(path or self.path)})
        return Config(gac_ui=self.ui, create_config=False)

    def write(self, value='synthetic', path=None):
        config = self.config(path)
        config.write_config_file({'client_id': value})
        return config

    def leftovers(self, directory=None):
        return [p.name for p in (directory or self.home).iterdir() if p.name.endswith('.tmp')]

    def with_umask(self, mask):
        previous = os.umask(mask)
        self.addCleanup(os.umask, previous)

    @unittest.skipUnless(POSIX, 'POSIX permissions')
    def test_new_file_is_0600_under_any_umask(self):
        for mask in (0o000, 0o022, 0o077):
            with self.subTest(umask=oct(mask)):
                previous = os.umask(mask)
                try:
                    if self.path.exists():
                        self.path.unlink()
                    self.write()
                finally:
                    os.umask(previous)
                self.assertEqual(file_mode(self.path), 0o600)
                self.assertEqual(self.ui.warnings, [])

    @unittest.skipUnless(POSIX, 'POSIX permissions')
    def test_broad_existing_mode_is_repaired_with_warning(self):
        for mask in (0o000, 0o022, 0o077):
            for broad in (0o644, 0o666, 0o640, 0o604, 0o777):
                with self.subTest(umask=oct(mask), mode=oct(broad)):
                    self.path.write_text('[DEFAULT]\nclient_id = old\n')
                    os.chmod(self.path, broad)
                    previous = os.umask(mask)
                    try:
                        self.write()
                    finally:
                        os.umask(previous)
                    self.assertEqual(file_mode(self.path), 0o600)
                    self.assertEqual(len(self.ui.warnings), 1)
                    self.assertIn('{:04o}'.format(broad), self.ui.warnings[0])

    @unittest.skipUnless(POSIX, 'POSIX permissions')
    def test_secure_mode_is_kept_without_warning(self):
        self.path.write_text('')
        os.chmod(self.path, 0o600)
        self.with_umask(0o000)
        self.write()
        self.assertEqual(file_mode(self.path), 0o600)
        self.assertEqual(self.ui.warnings, [])

    @unittest.skipUnless(POSIX and not IS_ROOT, 'POSIX permissions as non-root')
    def test_read_only_file_is_not_made_writable(self):
        self.path.write_text('[DEFAULT]\nclient_id = old\n')
        os.chmod(self.path, 0o400)
        self.addCleanup(os.chmod, self.path, 0o600)
        with self.assertRaisesRegex(GimmeAWSCredsError, 'read-only'):
            self.write()
        self.assertEqual(file_mode(self.path), 0o400)
        self.assertIn('old', self.path.read_text())
        self.assertEqual(self.leftovers(), [])

    def test_content_round_trips_and_other_profiles_are_kept(self):
        self.path.write_text('[other]\nclient_id = kept\n')
        config = self.write('new')
        self.assertEqual(config.get_config_dict()['client_id'], 'new')
        config.conf_profile = 'other'
        self.assertEqual(config.get_config_dict()['client_id'], 'kept')
        self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX, 'inode semantics')
    def test_existing_file_is_replaced_not_rewritten_in_place(self):
        self.path.write_text('')
        hard_link = self.home / 'hard_link'
        os.link(self.path, hard_link)
        self.write()
        self.assertNotEqual(os.stat(self.path).st_ino, os.stat(hard_link).st_ino)
        self.assertEqual(hard_link.read_text(), '')

    def test_interrupted_write_keeps_original_and_cleans_up(self):
        original = '[DEFAULT]\nclient_id = original\n'
        for failure in (KeyboardInterrupt(), OSError(28, 'No space left on device')):
            for target in ('gimme_aws_creds.config.os.fsync', 'gimme_aws_creds.config.os.replace'):
                with self.subTest(failure=type(failure).__name__, at=target):
                    self.path.write_text(original)
                    # OSError is reported as a configuration error; interrupts propagate.
                    expected = KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else GimmeAWSCredsError
                    with patch(target, side_effect=failure):
                        with self.assertRaises(expected):
                            self.write('partial')
                    self.assertEqual(self.path.read_text(), original)
                    self.assertEqual(self.leftovers(), [])

    def test_new_file_not_created_when_interrupted(self):
        with patch('gimme_aws_creds.config.os.replace', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.write()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_planted_temp_symlink_is_not_followed(self):
        victim = self.home / 'victim'
        victim.write_text('victim data')
        planted = self.home / '.okta_config.0000000000000000.tmp'
        planted.symlink_to(victim)
        with patch('gimme_aws_creds.config.secrets.token_hex', return_value='0000000000000000'):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'File exists'):
                self.write()
        self.assertEqual(victim.read_text(), 'victim data')
        self.assertTrue(planted.is_symlink())
        self.assertFalse(self.path.exists())

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_own_symlink_updates_regular_target_atomically(self):
        real_dir = self.home / 'dotfiles'
        real_dir.mkdir()
        real = real_dir / 'okta'
        real.write_text('[DEFAULT]\nclient_id = old\n')
        os.chmod(real, 0o644)
        self.path.symlink_to(real)
        self.write('new')
        self.assertTrue(self.path.is_symlink())
        self.assertIn('new', real.read_text())
        self.assertEqual(file_mode(real), 0o600)
        self.assertEqual(self.leftovers(real_dir), [])

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_relative_symlink_resolves_against_link_directory(self):
        (self.home / 'sub').mkdir()
        real = self.home / 'sub' / 'real'
        real.write_text('')
        link = self.home / 'sub' / 'link'
        link.symlink_to('real')
        self.write('new', path=link)
        self.assertTrue(link.is_symlink())
        self.assertIn('new', real.read_text())

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_unsafe_symlinks_are_refused(self):
        directory = self.home / 'a_directory'
        directory.mkdir()
        cases = {
            'dangling': self.home / 'missing',
            'directory': directory,
            'loop': self.path,
        }
        for label, destination in cases.items():
            with self.subTest(case=label):
                if self.path.is_symlink():
                    self.path.unlink()
                self.path.symlink_to(destination)
                with self.assertRaisesRegex(GimmeAWSCredsError, 'Refusing to follow'):
                    self.write()
                self.assertTrue(self.path.is_symlink())
                self.assertFalse((self.home / 'missing').exists())
                self.assertEqual(list(directory.iterdir()), [])
                self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX and not IS_ROOT, 'POSIX ownership as non-root')
    def test_symlink_owned_by_another_user_is_refused(self):
        victim = self.home / 'victim'
        victim.write_text('[victim]\n')
        self.path.symlink_to(victim)
        real_euid = os.geteuid()
        with patch('gimme_aws_creds.config.os.geteuid', return_value=real_euid + 1):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'owned by another user'):
                self.write()
        self.assertEqual(victim.read_text(), '[victim]\n')

    def test_non_regular_destination_is_refused(self):
        self.path.mkdir()
        with self.assertRaisesRegex(GimmeAWSCredsError, 'not a regular file'):
            self.write()
        self.assertEqual(list(self.path.iterdir()), [])
        self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX, 'POSIX ownership')
    def test_owner_and_group_are_preserved(self):
        self.path.write_text('')
        real = os.stat(self.path)
        fake = os.stat_result((real.st_mode, real.st_ino, real.st_dev, real.st_nlink,
                               real.st_uid, real.st_gid + 1, real.st_size,
                               real.st_atime, real.st_mtime, real.st_ctime))
        config = self.config()
        with patch('gimme_aws_creds.config.os.fchown') as fchown:
            fd = os.open(self.home / 'probe', os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                config._preserve_ownership(fd, fake, str(self.path))
            finally:
                os.close(fd)
        fchown.assert_called_once_with(fd, real.st_uid, real.st_gid + 1)

    @unittest.skipUnless(POSIX, 'POSIX ownership')
    def test_foreign_owner_is_not_silently_replaced(self):
        original = '[DEFAULT]\nclient_id = original\n'
        self.path.write_text(original)
        real = os.stat(self.path)
        foreign = os.stat_result((real.st_mode, real.st_ino, real.st_dev, real.st_nlink,
                                  real.st_uid + 1, real.st_gid, real.st_size,
                                  real.st_atime, real.st_mtime, real.st_ctime))
        real_lstat = os.lstat

        def fake_lstat(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            return foreign if os.fspath(path) == str(self.path) else result

        with patch('gimme_aws_creds.config.os.lstat', side_effect=fake_lstat), \
                patch('gimme_aws_creds.config.os.fchown', side_effect=PermissionError(1, 'denied')):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'owned by another user'):
                self.write()
        self.assertEqual(self.path.read_text(), original)
        self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX, 'POSIX symlink traversal')
    def test_symlink_parent_dotdot_follows_filesystem_semantics(self):
        leaf = self.home / 'real' / 'leaf'
        leaf.mkdir(parents=True)
        (self.home / 'real' / 'dest').mkdir()
        (self.home / 'dest').mkdir()
        link = self.home / 'link'
        link.symlink_to(leaf, target_is_directory=True)
        self.write('physical', path=str(link) + '/../dest/config')
        self.assertIn('physical', (self.home / 'real' / 'dest' / 'config').read_text())
        self.assertEqual(file_mode(self.home / 'real' / 'dest' / 'config'), 0o600)
        self.assertEqual(list((self.home / 'dest').iterdir()), [])

    def test_relative_path_is_written_in_current_directory(self):
        previous = os.getcwd()
        os.chdir(self.home)
        self.addCleanup(os.chdir, previous)
        self.write('relative', path='relative_config')
        self.assertIn('relative', (self.home / 'relative_config').read_text())
        self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX, 'POSIX permissions')
    def test_missing_parent_is_created_before_private_write(self):
        path = self.home / 'missing' / 'config'
        self.write('nested', path=path)
        self.assertEqual(file_mode(path.parent), 0o700)
        self.assertEqual(file_mode(path), 0o600)
        self.assertIn('nested', path.read_text())

    def test_windows_path_skips_posix_mode_and_ownership_calls(self):
        config = self.config()
        with patch('gimme_aws_creds.config.os.name', 'nt'), \
                patch('gimme_aws_creds.config.os.fchmod', create=True) as fchmod, \
                patch('gimme_aws_creds.config.os.fchown', create=True) as fchown:
            config.write_config_file({'client_id': 'windows'})
        fchmod.assert_not_called()
        fchown.assert_not_called()
        self.assertEqual(config.get_config_dict()['client_id'], 'windows')
        self.assertEqual(self.leftovers(), [])


if __name__ == '__main__':
    unittest.main()
