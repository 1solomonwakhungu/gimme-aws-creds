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

    def fake_ownership(self, uid_offset=0, gid_offset=0):
        """Report the config file as owned by another uid/gid (no real chown)."""
        real_lstat = os.lstat
        target = self.path

        def fake_lstat(path, *args, **kwargs):
            result = real_lstat(path, *args, **kwargs)
            name = os.fspath(path)
            if name == str(target) or (kwargs.get('dir_fd') is not None and name == target.name):
                fields = list(result)
                fields[4] += uid_offset
                fields[5] += gid_offset
                return os.stat_result(fields)
            return result

        return patch('gimme_aws_creds.config.os.lstat', side_effect=fake_lstat)

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

    def temp_entries(self, directory):
        return [p for p in directory.iterdir() if p.name.endswith('.tmp')]

    @unittest.skipUnless(POSIX, 'POSIX directory descriptors')
    def test_parent_directory_swap_cannot_redirect_write(self):
        # Another process renames the parent away and recreates it with its
        # own file under the temporary name just before the rename.
        live = self.home / 'live'
        live.mkdir()
        path = live / 'config'
        path.write_text('[DEFAULT]\nclient_id = old\n')
        os.chmod(path, 0o600)
        parked = self.home / 'parked'
        real_replace = os.replace

        def swap_parent(src, dst, *args, **kwargs):
            live.rename(parked)
            live.mkdir()
            planted = live / os.path.basename(src)
            planted.write_text('[DEFAULT]\nclient_id = attacker\n')
            os.chmod(planted, 0o644)
            return real_replace(src, dst, *args, **kwargs)

        with patch('gimme_aws_creds.config.os.replace', side_effect=swap_parent):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'moved or replaced'):
                self.write('new', path=path)
        self.assertFalse(path.exists())
        self.assertIn('new', (parked / 'config').read_text())
        self.assertEqual(file_mode(parked / 'config'), 0o600)
        self.assertEqual(self.temp_entries(parked), [])

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_temp_entry_swapped_before_rename_is_refused(self):
        original = '[DEFAULT]\nclient_id = original\n'
        self.path.write_text(original)
        os.chmod(self.path, 0o600)
        victim = self.home / 'victim'
        victim.write_text('victim data')
        real_fsync = os.fsync
        planted = []

        def swap_temp(fd):
            real_fsync(fd)
            if not planted:
                (entry,) = self.temp_entries(self.home)
                entry.unlink()
                entry.symlink_to(victim)
                planted.append(entry)

        with patch('gimme_aws_creds.config.os.fsync', side_effect=swap_temp):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'temporary file was replaced'):
                self.write('new')
        self.assertFalse(self.path.is_symlink())
        self.assertEqual(self.path.read_text(), original)
        self.assertEqual(victim.read_text(), 'victim data')
        # Someone else's entry is not ours to delete.
        self.assertTrue(planted[0].is_symlink())

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_temp_entry_swapped_at_rename_is_reported(self):
        # Publication cannot be prevented here; the write must not succeed.
        self.path.write_text('[DEFAULT]\nclient_id = original\n')
        os.chmod(self.path, 0o600)
        victim = self.home / 'victim'
        victim.write_text('victim data')
        real_replace = os.replace

        def swap_temp(src, dst, *args, **kwargs):
            entry = self.home / os.path.basename(src)
            entry.unlink()
            entry.symlink_to(victim)
            return real_replace(src, dst, *args, **kwargs)

        with patch('gimme_aws_creds.config.os.replace', side_effect=swap_temp):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'changed by another process'):
                self.write('new')
        self.assertEqual(victim.read_text(), 'victim data')

    def final_link_fixture(self):
        intended = self.home / 'intended'
        intended.write_text('[DEFAULT]\nclient_id = old\n')
        unexpected = self.home / 'unexpected'
        unexpected.write_text('[DEFAULT]\nclient_id = untouched\n')
        self.path.symlink_to(intended)
        return intended, unexpected

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_final_symlink_replaced_after_check_is_refused(self):
        intended, unexpected = self.final_link_fixture()
        real_readlink = os.readlink
        swapped = []

        def swap_link(path, *args, **kwargs):
            if not swapped:
                self.path.unlink()
                self.path.symlink_to(unexpected)
                swapped.append(True)
            return real_readlink(path, *args, **kwargs)

        with patch('gimme_aws_creds.config.os.readlink', side_effect=swap_link):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'Refusing to follow.*changed'):
                self.write('new')
        self.assertIn('old', intended.read_text())
        self.assertIn('untouched', unexpected.read_text())
        self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_final_symlink_swapped_out_and_back_is_refused(self):
        # The checked link is moved aside during readlink and then restored.
        intended, unexpected = self.final_link_fixture()
        aside = self.home / 'aside'
        real_readlink = os.readlink
        swapped = []

        def swap_and_restore(path, *args, **kwargs):
            if swapped:
                return real_readlink(path, *args, **kwargs)
            swapped.append(True)
            os.rename(self.path, aside)
            self.path.symlink_to(unexpected)
            try:
                return real_readlink(path, *args, **kwargs)
            finally:
                os.replace(aside, self.path)

        with patch('gimme_aws_creds.config.os.readlink', side_effect=swap_and_restore):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'Refusing to follow.*changed'):
                self.write('new')
        self.assertIn('old', intended.read_text())
        self.assertIn('untouched', unexpected.read_text())

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_symlink_chain_is_followed_when_every_link_is_trusted(self):
        (self.home / 'dir').mkdir()
        real = self.home / 'dir' / 'real'
        real.write_text('')
        (self.home / 'dir' / 'middle').symlink_to('real')
        self.path.symlink_to(Path('dir') / 'middle')
        self.write('chained')
        self.assertTrue(self.path.is_symlink())
        self.assertIn('chained', real.read_text())
        self.assertEqual(file_mode(real), 0o600)

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
        with self.fake_ownership(uid_offset=1), \
                patch('gimme_aws_creds.config.os.fchown', side_effect=PermissionError(1, 'denied')) as fchown:
            with self.assertRaisesRegex(GimmeAWSCredsError, 'owned by another user'):
                self.write()
        fchown.assert_called_once()
        self.assertEqual(self.path.read_text(), original)
        self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX, 'POSIX ownership')
    def test_group_that_cannot_be_kept_refuses_replacement(self):
        # Same owner, but the file's group is one the owner may not assign.
        original = '[DEFAULT]\nclient_id = original\n'
        self.path.write_text(original)
        os.chmod(self.path, 0o600)
        gid = os.stat(self.path).st_gid
        with self.fake_ownership(gid_offset=12345), \
                patch('gimme_aws_creds.config.os.fchown', side_effect=PermissionError(1, 'denied')) as fchown:
            with self.assertRaisesRegex(GimmeAWSCredsError, 'group .* cannot be kept'):
                self.write('new')
        fchown.assert_called_once()
        self.assertEqual(self.path.read_text(), original)
        self.assertEqual(os.stat(self.path).st_gid, gid)
        self.assertEqual(self.leftovers(), [])

    def test_long_valid_file_name_can_be_rewritten(self):
        path = self.home / ('n' * 240)
        try:
            path.write_text('[DEFAULT]\nclient_id = old\n')
        except OSError as exc:
            self.skipTest('filesystem rejects a 240-character name: {}'.format(exc))
        self.write('new', path=path)
        self.assertIn('new', path.read_text())
        if POSIX:
            self.assertEqual(file_mode(path), 0o600)
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
