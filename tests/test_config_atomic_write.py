"""Tests for atomic, owner-only writes of the Okta configuration file."""
import contextlib
import ctypes
import errno
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gimme_aws_creds import config as config_module
from gimme_aws_creds.config import Config
from gimme_aws_creds.errors import GimmeAWSCredsError
from tests.user_interface_mock import MockUserInterface

POSIX = os.name != 'nt'
IS_ROOT = POSIX and os.geteuid() == 0
# The fixed name of the file inside the writer's private staging directory.
STAGED_FILE_NAME = 'config'


def file_mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class DirectoryDescriptorCapabilityTest(unittest.TestCase):
    def test_stat_support_covers_lstat_on_older_python(self):
        supported = {os.open, os.stat, os.readlink, os.rename,
                     os.unlink, os.mkdir, os.rmdir}
        with patch.object(os, 'supports_dir_fd', supported), \
                patch.object(os, 'supports_fd', {os.listdir}):
            self.assertTrue(config_module._directory_descriptors_supported())
            for required in supported:
                with self.subTest(required=required.__name__):
                    with patch.object(os, 'supports_dir_fd', supported - {required}):
                        self.assertFalse(config_module._directory_descriptors_supported())
            with patch.object(os, 'supports_fd', set()):
                self.assertFalse(config_module._directory_descriptors_supported())

    @unittest.skipUnless(POSIX, 'POSIX directory descriptors')
    def test_lstat_relative_to_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample'
            path.touch()
            fd = os.open(directory, os.O_RDONLY)
            try:
                self.assertEqual(os.lstat('sample', dir_fd=fd).st_ino, path.stat().st_ino)
            finally:
                os.close(fd)


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
                    self.assertNotIn(str(self.path), self.ui.warnings[0])

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

    @unittest.skipUnless(POSIX, 'POSIX directory descriptors')
    def test_failure_while_checking_staging_directory_cleans_up(self):
        original = '[DEFAULT]\nclient_id = original\n'
        real_mkdir = os.mkdir
        calls = []
        for failure in (KeyboardInterrupt(), OSError(5, 'Input/output error')):
            def after_mkdir(*args, **kwargs):
                # The directory exists, but the call is interrupted on return.
                real_mkdir(*args, **kwargs)
                if kwargs.get('dir_fd') is not None:  # only the staging directory
                    calls.append(args[0])
                    raise failure

            for target, effect in (('gimme_aws_creds.config.os.listdir', failure),
                                   ('gimme_aws_creds.config.os.mkdir', after_mkdir)):
                with self.subTest(failure=type(failure).__name__, at=target):
                    self.path.write_text(original)
                    expected = KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else GimmeAWSCredsError
                    with patch(target, side_effect=effect):
                        with self.assertRaises(expected):
                            self.write('partial')
                    self.assertEqual(self.path.read_text(), original)
                    self.assertEqual(self.leftovers(), [])
        self.assertEqual(len(calls), 2)

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

    def staging_entry(self, directory):
        (entry,) = self.temp_entries(directory)
        return entry

    def plant(self, entry, kind, victim):
        """Put an attacker entry of ``kind`` at ``entry`` (synthetic bytes)."""
        if kind == 'regular':
            entry.write_text('[DEFAULT]\nclient_id = ATTACKER\n')
            os.chmod(entry, 0o644)
        elif kind == 'symlink':
            entry.symlink_to(victim)
        else:
            entry.mkdir()
            (entry / STAGED_FILE_NAME).write_text('[DEFAULT]\nclient_id = ATTACKER\n')
            os.chmod(entry / STAGED_FILE_NAME, 0o644)

    @unittest.skipUnless(POSIX, 'POSIX directory descriptors')
    def test_parent_directory_swap_cannot_redirect_write(self):
        # Another process renames the parent away and recreates it with its
        # own entry under the staging name just before the rename.
        live = self.home / 'live'
        live.mkdir()
        path = live / 'config'
        path.write_text('[DEFAULT]\nclient_id = old\n')
        os.chmod(path, 0o600)
        parked = self.home / 'parked'
        real_replace = os.replace
        planted = []

        def swap_parent(src, dst, *args, **kwargs):
            live.rename(parked)
            live.mkdir()
            entry = live / self.staging_entry(parked).name
            self.plant(entry, 'directory', None)
            planted.append(entry)
            return real_replace(src, dst, *args, **kwargs)

        with patch('gimme_aws_creds.config.os.replace', side_effect=swap_parent):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'moved or replaced'):
                self.write('new', path=path)
        self.assertFalse(path.exists())
        self.assertIn('new', (parked / 'config').read_text())
        self.assertEqual(file_mode(parked / 'config'), 0o600)
        self.assertEqual(self.temp_entries(parked), [])
        # The attacker's entry is neither published nor removed.
        self.assertIn('ATTACKER', (planted[0] / STAGED_FILE_NAME).read_text())

    @unittest.skipUnless(POSIX, 'POSIX directory descriptors')
    def test_public_staging_entry_swapped_at_rename_is_never_published(self):
        # Defence in depth: the destination directory must be private to this
        # user (or root), so only the same user could do this. The staging
        # directory's name is moved away and a 0644 file, a symlink or a
        # directory is planted in its place immediately before the rename.
        # The rename must still publish exactly the file written here.
        for kind in ('regular', 'symlink', 'directory'):
            with self.subTest(planted=kind):
                home = self.home / kind
                home.mkdir()
                path = home / 'config'
                path.write_text('[DEFAULT]\nclient_id = original\n')
                os.chmod(path, 0o600)
                victim = home / 'victim'
                victim.write_text('victim data')
                moved = home / 'moved'
                real_replace = os.replace
                at_commit = {}

                def swap(src, dst, *args, **kwargs):
                    entry = self.staging_entry(home)
                    os.rename(entry, moved)
                    self.plant(entry, kind, victim)
                    result = real_replace(src, dst, *args, **kwargs)
                    # Observe the writer's own rename before any later check.
                    at_commit.update(link=path.is_symlink(), text=path.read_text(),
                                     mode=file_mode(path))
                    return result

                outcome = None
                with patch('gimme_aws_creds.config.os.replace', side_effect=swap):
                    try:
                        self.write('new', path=path)
                    except GimmeAWSCredsError as exc:
                        outcome = exc
                # What the writer's own rename published, whatever it reports.
                self.assertFalse(at_commit['link'], outcome)
                self.assertNotIn('ATTACKER', at_commit['text'])
                self.assertNotIn('victim', at_commit['text'])
                self.assertIn('new', at_commit['text'])
                self.assertEqual(at_commit['mode'], 0o600)
                self.assertIsNone(outcome)
                self.assertFalse(path.is_symlink())
                self.assertIn('new', path.read_text())
                self.assertEqual(victim.read_text(), 'victim data')
                # The moved staging directory is now empty; the planted entry is
                # someone else's and is left alone.
                self.assertEqual(list(moved.iterdir()), [])
                self.assertTrue(os.path.lexists(self.staging_entry(home)))

    @unittest.skipUnless(POSIX, 'POSIX directory descriptors')
    def test_substituted_staging_directory_is_refused(self):
        # The staging directory is replaced between mkdir() and open(). In a
        # private destination directory only the same user or root can do
        # that; even so, only directories private to this user and empty are
        # used, and what was planted is left alone.
        original = '[DEFAULT]\nclient_id = original\n'
        decoy = self.home / 'decoy'
        real_mkdir = os.mkdir
        real_euid = os.geteuid()
        cases = ('symlink', 'regular', 'group_writable', 'not_empty', 'foreign_owner')
        for kind in cases:
            with self.subTest(planted=kind):
                self.path.write_text(original)
                os.chmod(self.path, 0o600)
                if decoy.exists():
                    for child in decoy.iterdir():
                        child.unlink()
                    decoy.rmdir()
                decoy.mkdir(mode=0o700)

                substituted = []

                def substitute(entry, *args, **kwargs):
                    real_mkdir(entry, *args, **kwargs)
                    if kwargs.get('dir_fd') is None:
                        return  # not the writer's staging directory
                    substituted.append(entry)
                    staged = self.home / entry
                    staged.rmdir()
                    if kind == 'symlink':
                        staged.symlink_to(decoy, target_is_directory=True)
                    elif kind == 'regular':
                        staged.write_text('[DEFAULT]\nclient_id = ATTACKER\n')
                    else:
                        real_mkdir(staged, 0o700)
                        if kind == 'group_writable':
                            os.chmod(staged, 0o770)
                        elif kind == 'not_empty':
                            (staged / 'planted').write_text('ATTACKER')

                # 'foreign_owner': the planted directory belongs to this test's
                # uid, so once it is planted the writer is told it runs as
                # another uid instead.
                def euid():
                    if kind == 'foreign_owner' and substituted:
                        return real_euid + 1
                    return real_euid

                with patch('gimme_aws_creds.config.os.mkdir', side_effect=substitute), \
                        patch('gimme_aws_creds.config.os.geteuid', side_effect=euid):
                    with self.assertRaisesRegex(GimmeAWSCredsError, 'staging directory .* replaced'):
                        self.write('new')
                self.assertFalse(self.path.is_symlink())
                self.assertEqual(self.path.read_text(), original)
                self.assertEqual(file_mode(self.path), 0o600)
                self.assertEqual(list(decoy.iterdir()), [])
                for entry in self.temp_entries(self.home):
                    if entry.is_dir() and not entry.is_symlink():
                        for child in entry.iterdir():
                            child.unlink()
                        entry.rmdir()
                    else:
                        entry.unlink()

    @unittest.skipUnless(POSIX, 'POSIX directory descriptors')
    def test_staged_file_is_written_and_renamed_through_private_directory_fd(self):
        real_open = os.open
        real_replace = os.replace
        for mask in (0o000, 0o022, 0o077, 0o277):
            with self.subTest(umask=oct(mask)):
                staged = []
                renamed = []

                def record_open(entry, flags, *args, dir_fd=None, **kwargs):
                    if flags & os.O_CREAT:
                        directory = os.fstat(dir_fd) if dir_fd is not None else None
                        contents = os.listdir(dir_fd) if dir_fd is not None else None
                        staged.append((entry, dir_fd, directory, contents))
                    return real_open(entry, flags, *args, dir_fd=dir_fd, **kwargs)

                def record_replace(src, dst, *args, **kwargs):
                    renamed.append((src, kwargs.get('src_dir_fd'), os.fstat(kwargs['src_dir_fd'])))
                    return real_replace(src, dst, *args, **kwargs)

                previous = os.umask(mask)
                try:
                    with patch('gimme_aws_creds.config.os.open', side_effect=record_open), \
                            patch('gimme_aws_creds.config.os.replace', side_effect=record_replace):
                        self.write('new')
                finally:
                    os.umask(previous)
                self.assertEqual(Config._STAGED_FILE_NAME, STAGED_FILE_NAME)
                ((entry, dir_fd, directory, contents),) = staged
                self.assertEqual(entry, STAGED_FILE_NAME)
                self.assertIsNotNone(dir_fd)
                self.assertTrue(stat.S_ISDIR(directory.st_mode))
                self.assertEqual(directory.st_uid, os.geteuid())
                self.assertEqual(stat.S_IMODE(directory.st_mode), 0o700)
                self.assertEqual(contents, [])
                ((src, src_dir_fd, src_directory),) = renamed
                self.assertEqual(src, STAGED_FILE_NAME)
                self.assertEqual((src_directory.st_dev, src_directory.st_ino),
                                 (directory.st_dev, directory.st_ino))
                self.assertIn('new', self.path.read_text())
                self.assertEqual(file_mode(self.path), 0o600)
                self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX, 'POSIX')
    def test_posix_without_directory_descriptors_is_refused(self):
        original = '[DEFAULT]\nclient_id = original\n'
        self.path.write_text(original)
        with patch('gimme_aws_creds.config._DIR_FD_SUPPORTED', False):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'cannot open directories safely'):
                self.write('new')
        self.assertEqual(self.path.read_text(), original)
        self.assertEqual(self.leftovers(), [])

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_same_user_change_inside_staging_directory_is_refused_before_rename(self):
        # Outside the threat boundary: only this user (or root) can change the
        # private staging directory. A change made before the final check is
        # still refused; one made during the rename cannot be prevented.
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
                entry = self.staging_entry(self.home) / STAGED_FILE_NAME
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

    def shared_link_fixture(self, mode=0o777):
        """A config symlink in a directory other users can change.

        Its intended and unexpected targets are in the private home.
        """
        intended = self.home / 'intended'
        intended.write_text('[DEFAULT]\nclient_id = old\n')
        unexpected = self.home / 'unexpected'
        unexpected.write_text('[DEFAULT]\nclient_id = untouched\n')
        for target in (intended, unexpected):
            os.chmod(target, 0o600)
        shared = self.home / 'shared'
        shared.mkdir()
        os.chmod(shared, mode)
        link = shared / 'config'
        link.symlink_to(intended)
        return shared, link, intended, unexpected

    def assert_link_refused_unread(self, link, intended, unexpected, schedule):
        """The write is refused before the link is read; nothing changes."""
        with patch('gimme_aws_creds.config.os.readlink', side_effect=schedule) as readlink:
            with self.assertRaisesRegex(
                    GimmeAWSCredsError,
                    'Refusing to follow configuration symlink .*: the directory .*shared '
                    'that contains it is writable by other users'):
                self.write('new', path=link)
        readlink.assert_not_called()
        self.assertEqual(os.readlink(link), str(intended))
        self.assertIn('old', intended.read_text())
        self.assertIn('untouched', unexpected.read_text())
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(self.leftovers(link.parent), [])

    @unittest.skipUnless(POSIX and not IS_ROOT, 'POSIX symlinks as non-root')
    def test_link_in_shared_directory_is_refused_before_it_can_be_replaced(self):
        for mode in (0o777, 0o1777, 0o770, 0o722):
            with self.subTest(mode=oct(mode)):
                shared, link, intended, unexpected = self.shared_link_fixture(mode)
                real_readlink = os.readlink

                def replace_link(path, *args, **kwargs):
                    link.unlink()
                    link.symlink_to(unexpected)
                    return real_readlink(path, *args, **kwargs)

                self.assert_link_refused_unread(link, intended, unexpected, replace_link)
                os.chmod(shared, 0o700)
                shutil.rmtree(shared)
                (self.home / 'intended').unlink()
                (self.home / 'unexpected').unlink()

    @unittest.skipUnless(POSIX and not IS_ROOT, 'POSIX symlinks as non-root')
    def test_link_swapped_out_and_back_in_shared_directory_is_refused(self):
        # Moving the checked link aside during readlink and restoring it can
        # leave its inode and ctime unchanged (seen on Linux tmpfs), so the
        # directory itself must rule the swap out before the link is read.
        shared, link, intended, unexpected = self.shared_link_fixture()
        aside = shared / 'aside'
        real_readlink = os.readlink

        def swap_and_restore(path, *args, **kwargs):
            os.rename(link, aside)
            link.symlink_to(unexpected)
            try:
                return real_readlink(path, *args, **kwargs)
            finally:
                os.replace(aside, link)

        self.assert_link_refused_unread(link, intended, unexpected, swap_and_restore)

    @unittest.skipUnless(POSIX and not IS_ROOT, 'POSIX symlinks as non-root')
    def test_chain_through_link_in_shared_directory_is_refused_at_that_link(self):
        # The first link is in the private home; the second is not.
        shared, middle, intended, unexpected = self.shared_link_fixture()
        self.path.symlink_to(middle)
        real_readlink = os.readlink
        read = []

        def record(path, *args, **kwargs):
            read.append(path)
            return real_readlink(path, *args, **kwargs)

        with patch('gimme_aws_creds.config.os.readlink', side_effect=record):
            with self.assertRaisesRegex(
                    GimmeAWSCredsError, 'the directory .*shared that contains it is writable'):
                self.write('new')
        self.assertEqual(read, [self.path.name])
        self.assertIn('old', intended.read_text())
        self.assertIn('untouched', unexpected.read_text())
        self.assertEqual(os.readlink(middle), str(intended))

    @unittest.skipUnless(POSIX, 'POSIX symlinks')
    def test_link_in_read_only_shared_directory_is_followed(self):
        shared, link, intended, unexpected = self.shared_link_fixture(0o755)
        self.write('new', path=link)
        self.assertTrue(link.is_symlink())
        self.assertIn('new', intended.read_text())
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


DARWIN = sys.platform == 'darwin'
# An ordinary inheritable ACL entry giving everyone the directory rights an
# attacker needs to replace entries: list, add_file, search, add_subdirectory
# and delete_child (named read, write, execute, append, delete_child in text).
EVERYONE_INHERITABLE = (
    b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:'
    b'allow,file_inherit,directory_inherit:read,write,execute,append,delete_child\n')
# The same entry, inherit-only: it gives nobody access to the directory it
# is set on, but new children inherit it as an ordinary (effective) entry.
EVERYONE_INHERIT_ONLY = (
    b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:'
    b'allow,file_inherit,directory_inherit,only_inherit:read,write,execute,append,delete_child\n')
# The same rights set directly (not inherited) on one directory.
EVERYONE_EXPLICIT = (
    b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:'
    b'allow:read,write,execute,append,delete_child\n')


class DarwinAcl:
    """Test-side access to real macOS extended ACLs of test-owned files."""
    TYPE_EXTENDED = 0x00000100

    def __init__(self):
        lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        lib.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        lib.acl_get_fd_np.restype = ctypes.c_void_p
        lib.acl_set_fd_np.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.acl_set_fd_np.restype = ctypes.c_int
        lib.acl_from_text.argtypes = [ctypes.c_char_p]
        lib.acl_from_text.restype = ctypes.c_void_p
        lib.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        lib.acl_to_text.restype = ctypes.c_void_p
        lib.acl_free.argtypes = [ctypes.c_void_p]
        self.lib = lib

    def set(self, fd, text):
        acl = self.lib.acl_from_text(text)
        if not acl:
            raise OSError(ctypes.get_errno(), 'acl_from_text')
        try:
            if self.lib.acl_set_fd_np(fd, acl, self.TYPE_EXTENDED) != 0:
                raise OSError(ctypes.get_errno(), 'acl_set_fd_np')
        finally:
            self.lib.acl_free(acl)

    def set_path(self, path, text):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            self.set(fd, text)
        finally:
            os.close(fd)

    def text(self, fd):
        """The ACL of ``fd`` as text, or '' if it has none."""
        ctypes.set_errno(0)
        acl = self.lib.acl_get_fd_np(fd, self.TYPE_EXTENDED)
        if not acl:
            if ctypes.get_errno() == errno.ENOENT:
                return ''
            raise OSError(ctypes.get_errno(), 'acl_get_fd_np')
        try:
            text = self.lib.acl_to_text(acl, None)
            try:
                return ctypes.string_at(text).decode()
            finally:
                self.lib.acl_free(text)
        finally:
            self.lib.acl_free(acl)

    def text_path(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            return self.text(fd)
        finally:
            os.close(fd)

    def everyone_may_replace_entries(self, fd):
        """Whether the ACL lets every user add and delete entries in directory ``fd``.

        These are the rights a lower-privileged user would use; the process
        running the test holds them anyway as the owner, so this decides
        whether the simulated attacker's action would be permitted.
        """
        for line in self.text(fd).splitlines()[1:]:
            fields = line.split(':')
            flags = fields[4].split(',')
            # Inherit-only entries do not apply to the directory they are on.
            if fields[2] == 'everyone' and flags[0] == 'allow' and 'only_inherit' not in flags:
                rights = fields[5].split(',')
                if {'write', 'execute', 'delete_child'} <= set(rights):
                    return True
        return False


@unittest.skipUnless(POSIX and not IS_ROOT, 'POSIX staging as non-root')
class StagingAclTest(unittest.TestCase):
    """Access granted by ACLs inherited by the staging directory."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='gac-acl-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.acl = DarwinAcl() if DARWIN else None

    def inheriting_home(self, name):
        """A private test-owned directory whose new children inherit an ACL.

        The entry is inherit-only, so it does not apply to the directory
        itself, which stays a supported destination; the staging directory
        inherits it as an entry that gives every user its rights.
        """
        home = self.root / name
        home.mkdir(mode=0o700)
        self.acl.set_path(home, EVERYONE_INHERIT_ONLY)
        self.assertFalse(self.acl.everyone_may_replace_entries(self.acl_fd(home)))
        # Remove the ACL before the temporary directory is cleaned up.
        self.addCleanup(self.clear_acls, home)
        return home

    def acl_fd(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        return fd

    def clear_acls(self, top):
        if not top.exists():
            return
        for path in [top, *top.rglob('*')]:
            if not path.is_symlink():
                self.acl.set_path(path, b'!#acl 1\n')

    def write(self, path, value='new'):
        ui = RecordingUserInterface(str(path.parent), {'OKTA_CONFIG': str(path)})
        Config(gac_ui=ui, create_config=False).write_config_file({'client_id': value})

    def destination(self, home):
        path = home / 'config'
        path.write_text('[DEFAULT]\nclient_id = original\n')
        os.chmod(path, 0o600)
        victim = home / 'victim'
        victim.write_text('victim data')
        return path, victim

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_inherited_acl_cannot_substitute_the_staged_file(self):
        # A real inherited ACL on the staging directory. The attacker opens
        # the new staging directory as soon as it exists (the ACL lets every
        # user search it) and keeps that descriptor. Immediately before the
        # writer's rename it replaces the staged file through the descriptor,
        # with a 0644 file or a symlink, if the directory's ACL at that moment
        # gives every user the rights to do so.
        for kind in ('regular', 'symlink'):
            with self.subTest(planted=kind):
                home = self.inheriting_home(kind)
                parent_acl = self.acl.text_path(home)
                path, victim = self.destination(home)
                real_mkdir, real_replace = os.mkdir, os.replace
                attacker = {}
                at_commit = {}

                def mkdir(entry, *args, **kwargs):
                    real_mkdir(entry, *args, **kwargs)
                    if kwargs.get('dir_fd') is not None:
                        attacker['fd'] = os.open(entry, os.O_RDONLY | os.O_DIRECTORY,
                                                 dir_fd=kwargs['dir_fd'])
                        self.addCleanup(os.close, attacker['fd'])
                        attacker['acl_at_open'] = self.acl.text(attacker['fd'])

                def replace(src, dst, *args, **kwargs):
                    fd = attacker['fd']
                    stage = kwargs['src_dir_fd']
                    at_commit.update(
                        stage_acl=self.acl.text(stage),
                        stage_mode=stat.S_IMODE(os.fstat(stage).st_mode),
                        same_directory=os.path.samestat(os.fstat(fd), os.fstat(stage)))
                    staged = os.open(src, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=stage)
                    at_commit.update(file_acl=self.acl.text(staged),
                                     file_mode=stat.S_IMODE(os.fstat(staged).st_mode))
                    os.close(staged)
                    attacker['permitted'] = self.acl.everyone_may_replace_entries(fd)
                    if attacker['permitted']:
                        os.unlink(src, dir_fd=fd)
                        if kind == 'symlink':
                            os.symlink(str(victim), src, dir_fd=fd)
                        else:
                            planted = os.open(src, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644,
                                              dir_fd=fd)
                            os.write(planted, b'[DEFAULT]\nclient_id = ATTACKER\n')
                            os.close(planted)
                    result = real_replace(src, dst, *args, **kwargs)
                    at_commit.update(link=path.is_symlink(), text=path.read_text(),
                                     mode=stat.S_IMODE(os.lstat(path).st_mode))
                    return result

                outcome = None
                with patch('gimme_aws_creds.config.os.mkdir', side_effect=mkdir), \
                        patch('gimme_aws_creds.config.os.replace', side_effect=replace):
                    try:
                        self.write(path)
                    except GimmeAWSCredsError as exc:
                        outcome = exc
                # The fixture really was inherited by the new staging directory.
                self.assertIn('everyone', attacker['acl_at_open'])
                self.assertIn('inherited', attacker['acl_at_open'])
                self.assertTrue(at_commit['same_directory'])
                # What the writer's own rename published, before later checks.
                self.assertFalse(at_commit['link'], outcome)
                self.assertNotIn('ATTACKER', at_commit['text'])
                self.assertNotIn('victim', at_commit['text'])
                self.assertIn('new', at_commit['text'])
                self.assertEqual(at_commit['mode'], 0o600)
                # Nobody but the owner had access to the directory or the file.
                self.assertEqual(at_commit['stage_acl'], '')
                self.assertEqual(at_commit['stage_mode'], 0o700)
                self.assertEqual(at_commit['file_acl'], '')
                self.assertEqual(at_commit['file_mode'], 0o600)
                self.assertFalse(attacker['permitted'])
                self.assertIsNone(outcome)
                self.assertIn('new', path.read_text())
                self.assertEqual(victim.read_text(), 'victim data')
                self.assertEqual(self.acl.text_path(path), '')
                # The destination directory's own ACL is left as it was.
                self.assertEqual(self.acl.text_path(home), parent_acl)
                self.assertEqual([p.name for p in home.iterdir() if p.name.endswith('.tmp')], [])

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_secret_is_written_only_once_the_staged_file_is_private(self):
        home = self.inheriting_home('privacy')
        path, _ = self.destination(home)
        real_fsync = os.fsync
        seen = []

        def fsync(fd):
            # The data has been written to the staged file at this point.
            if stat.S_ISREG(os.fstat(fd).st_mode):
                seen.append((self.acl.text(fd), stat.S_IMODE(os.fstat(fd).st_mode)))
            return real_fsync(fd)

        with patch('gimme_aws_creds.config.os.fsync', side_effect=fsync):
            self.write(path, 'secret')
        self.assertEqual(seen, [('', 0o600)])
        self.assertIn('secret', path.read_text())

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_entries_added_before_the_acl_is_removed_are_refused(self):
        # While the inherited ACL is still in place, every user may add
        # entries. Anything added before it is removed must be found.
        for kind in ('regular', 'symlink', 'directory'):
            with self.subTest(planted=kind):
                home = self.inheriting_home('window-' + kind)
                path, victim = self.destination(home)
                real_clear = config_module._DarwinACL.clear
                planted = []

                def clear(api, fd):
                    self.assertTrue(self.acl.everyone_may_replace_entries(fd))
                    entry = STAGED_FILE_NAME
                    if kind == 'regular':
                        handle = os.open(entry, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644,
                                         dir_fd=fd)
                        os.write(handle, b'ATTACKER')
                        os.close(handle)
                    elif kind == 'symlink':
                        os.symlink(str(victim), entry, dir_fd=fd)
                    else:
                        os.mkdir(entry, 0o777, dir_fd=fd)
                    planted.append(kind)
                    return real_clear(api, fd)

                with patch.object(config_module._DarwinACL, 'clear', autospec=True,
                                  side_effect=clear):
                    with self.assertRaisesRegex(GimmeAWSCredsError, 'staging directory .* replaced'):
                        self.write(path)
                self.assertEqual(planted, [kind])
                self.assertFalse(path.is_symlink())
                self.assertEqual(path.read_text(), '[DEFAULT]\nclient_id = original\n')
                self.assertEqual(victim.read_text(), 'victim data')

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_directory_with_explicit_acl_entries_is_refused_and_left_alone(self):
        # Only a directory put in place of the new one can have entries that
        # were not inherited; its ACL must not be changed.
        home = self.root / 'explicit'
        home.mkdir(mode=0o700)
        path, _ = self.destination(home)
        self.addCleanup(self.clear_acls, home)
        real_mkdir = os.mkdir
        made = []

        def mkdir(entry, *args, **kwargs):
            real_mkdir(entry, *args, **kwargs)
            if kwargs.get('dir_fd') is not None:
                fd = os.open(entry, os.O_RDONLY | os.O_DIRECTORY, dir_fd=kwargs['dir_fd'])
                try:
                    self.acl.set(fd, EVERYONE_EXPLICIT)
                finally:
                    os.close(fd)
                made.append(home / entry)

        with patch('gimme_aws_creds.config.os.mkdir', side_effect=mkdir):
            with self.assertRaisesRegex(GimmeAWSCredsError, 'staging directory .* replaced'):
                self.write(path)
        (stage,) = made
        text = self.acl.text_path(stage)
        self.assertIn('everyone', text)
        self.assertNotIn('inherited', text)
        self.assertEqual(path.read_text(), '[DEFAULT]\nclient_id = original\n')

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_acl_that_cannot_be_removed_is_refused(self):
        def fail(api, fd):
            raise OSError(errno.EPERM, os.strerror(errno.EPERM))

        for name, effect, message in (
                ('fails', fail, os.strerror(errno.EPERM)),
                ('ignored', lambda api, fd: None, 'still present')):
            with self.subTest(clear=name):
                home = self.inheriting_home('stuck-' + name)
                path, _ = self.destination(home)
                with patch.object(config_module._DarwinACL, 'clear', autospec=True,
                                  side_effect=effect):
                    with self.assertRaisesRegex(GimmeAWSCredsError, 'cannot remove the access '
                                                'control list .*' + message):
                        self.write(path)
                self.assertEqual(path.read_text(), '[DEFAULT]\nclient_id = original\n')
                self.assertEqual([p.name for p in home.iterdir() if p.name.endswith('.tmp')], [])

    def test_platform_whose_acls_cannot_be_checked_is_refused(self):
        home = self.root / 'unsupported'
        home.mkdir(mode=0o700)
        path, _ = self.destination(home)
        for policy in (None, 'darwin'):
            with self.subTest(policy=policy):
                ui = RecordingUserInterface(str(home), {'OKTA_CONFIG': str(path)})
                config = Config(gac_ui=ui, create_config=False)
                # 'darwin': libSystem's ACL functions could not be loaded.
                with patch('gimme_aws_creds.config._ACL_POLICY', policy), \
                        patch('gimme_aws_creds.config._darwin_acl_api', return_value=None), \
                        patch('gimme_aws_creds.config.os.mkdir') as mkdir:
                    with self.assertRaisesRegex(GimmeAWSCredsError,
                                                'access control lists cannot be checked'):
                        config.write_config_file({'client_id': 'new'})
                mkdir.assert_not_called()
                self.assertEqual(path.read_text(), '[DEFAULT]\nclient_id = original\n')

    def test_linux_refuses_nfs4_acls_and_unreadable_acls(self):
        home = self.root / 'linux'
        home.mkdir(mode=0o700)
        path, _ = self.destination(home)
        checked = []

        def no_acl(fd, name):
            checked.append((stat.S_IFMT(os.fstat(fd).st_mode), name))
            raise OSError(errno.ENODATA, 'No data available')

        def io_error(fd, name):
            raise OSError(errno.EIO, os.strerror(errno.EIO))

        home_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, home_fd)

        def on_staging_only(effect):
            # The destination directory has no NFSv4 ACL; the staging
            # directory or file has ``effect``.
            def getxattr(fd, name):
                if os.path.samestat(os.fstat(fd), os.fstat(home_fd)):
                    raise OSError(errno.ENODATA, 'No data available')
                return effect(fd, name)
            return getxattr

        nfs4 = lambda fd, name: b'\0\0\0\1'
        for name, effect, error, before_mkdir in (
                ('none', no_acl, None, False),
                ('nfs4', on_staging_only(nfs4), 'NFSv4', False),
                ('unreadable', on_staging_only(io_error), os.strerror(errno.EIO), False),
                ('destination nfs4', nfs4, 'its directory .* access control list that may '
                 'let other users', True),
                ('destination unreadable', io_error, 'its directory .* cannot be checked .*'
                 + os.strerror(errno.EIO), True)):
            with self.subTest(acl=name):
                real_mkdir = os.mkdir
                with patch('gimme_aws_creds.config._ACL_POLICY', 'linux'), \
                        patch.object(config_module.os, 'getxattr', create=True,
                                     side_effect=effect), \
                        patch('gimme_aws_creds.config.os.mkdir', side_effect=real_mkdir) as mkdir:
                    if error is None:
                        self.write(path, 'linux')
                    else:
                        with self.assertRaisesRegex(GimmeAWSCredsError, error):
                            self.write(path, 'refused')
                staging = [c for c in mkdir.call_args_list if c.kwargs.get('dir_fd') is not None]
                self.assertEqual(len(staging), 0 if before_mkdir else 1)
                self.assertIn('linux', path.read_text())
                self.assertEqual([p.name for p in home.iterdir() if p.name.endswith('.tmp')], [])
        # The destination directory before anything is created, then the
        # staging directory, the staged file before it is written, and both
        # again before the rename.
        self.assertEqual(checked, [(stat.S_IFDIR, 'system.nfs4_acl'),
                                   (stat.S_IFDIR, 'system.nfs4_acl'),
                                   (stat.S_IFREG, 'system.nfs4_acl'),
                                   (stat.S_IFDIR, 'system.nfs4_acl'),
                                   (stat.S_IFREG, 'system.nfs4_acl')])

# ACL entries that let other users change the entries of the directory they
# are set on, and entries that do not.
UNTRUSTED_DIRECTORY_ACLS = {
    'inheritable': EVERYONE_INHERITABLE,
    'explicit': EVERYONE_EXPLICIT,
    'add_file': b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:write\n',
    'add_subdirectory': b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:append\n',
    'delete_child': b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:delete_child\n',
    'writesecurity': b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:writesecurity\n',
    'chown': b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:chown\n',
}
TRUSTED_DIRECTORY_ACLS = {
    'deny': b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:delete\n',
    'read_only': b'!#acl 1\ngroup:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:allow:read,execute\n',
    'inherit_only': EVERYONE_INHERIT_ONLY,
}
ORIGINAL = '[DEFAULT]\nclient_id = OLD_SYNTHETIC\n'


@unittest.skipUnless(POSIX and not IS_ROOT, 'POSIX staging as non-root')
class DestinationDirectoryTrustTest(unittest.TestCase):
    """The destination directory must be one only this user or root can change."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='gac-trust-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.acl = DarwinAcl() if DARWIN else None

    def directory(self, name, mode=0o700, acl=None):
        """A destination directory with a config file and an unrelated empty directory."""
        home = self.root / name
        home.mkdir()
        os.chmod(home, mode)
        self.addCleanup(self.restore, home)
        path = home / 'config'
        path.write_text(ORIGINAL)
        os.chmod(path, 0o600)
        unrelated = home / 'unrelated-existing'
        unrelated.mkdir(mode=0o700)
        if acl is not None:
            self.acl.set_path(home, acl)
        return home, path, unrelated

    def restore(self, home):
        if not home.exists():
            return
        os.chmod(home, 0o700)
        if self.acl is not None:
            for entry in [home, *home.rglob('*')]:
                if not entry.is_symlink():
                    self.acl.set_path(entry, b'!#acl 1\n')

    def snapshot(self, home, unrelated):
        """Everything a refused write must leave unchanged."""
        result = {
            'entries': sorted(p.name for p in home.iterdir()),
            'home_mode': stat.S_IMODE(os.stat(home).st_mode),
            'config': (home / 'config').read_text(),
            'config_mode': file_mode(home / 'config'),
        }
        if unrelated.exists():
            st = os.stat(unrelated)
            result.update(unrelated_identity=(st.st_dev, st.st_ino),
                          unrelated_mode=stat.S_IMODE(st.st_mode),
                          unrelated_entries=os.listdir(unrelated))
        if self.acl is not None:
            result['home_acl'] = self.acl.text_path(home)
            if unrelated.exists():
                result['unrelated_acl'] = self.acl.text_path(unrelated)
        return result

    @staticmethod
    def config_for(path):
        # Built before any os patch: the mock user interface makes a
        # temporary directory of its own.
        ui = RecordingUserInterface(str(path.parent), {'OKTA_CONFIG': str(path)})
        return Config(gac_ui=ui, create_config=False)

    def write(self, path, value='NEW_SYNTHETIC', config=None):
        (config or self.config_for(path)).write_config_file({'client_id': value})

    def assert_refused_before_mkdir(self, path, message):
        config = self.config_for(path)
        real_mkdir = os.mkdir
        with patch('gimme_aws_creds.config.os.mkdir', side_effect=real_mkdir) as spy:
            with self.assertRaisesRegex(GimmeAWSCredsError, message):
                self.write(path, config=config)
        spy.assert_not_called()

    def test_directory_writable_by_others_is_refused_before_anything_is_created(self):
        # Shared and world-writable directories are not a supported location,
        # sticky or not: a lower-privileged user could rename entries in them.
        for mode in (0o770, 0o730, 0o720, 0o707, 0o702, 0o777, 0o1777, 0o3777):
            with self.subTest(mode=oct(mode)):
                home, path, unrelated = self.directory('mode-{:o}'.format(mode), mode)
                before = self.snapshot(home, unrelated)
                self.assert_refused_before_mkdir(path, 'its directory .* is writable by other users')
                self.assertEqual(self.snapshot(home, unrelated), before)

    def test_private_and_read_only_shared_directories_are_accepted(self):
        for mode in (0o700, 0o750, 0o755, 0o711):
            with self.subTest(mode=oct(mode)):
                home, path, _ = self.directory('ok-{:o}'.format(mode), mode)
                self.write(path)
                self.assertIn('NEW_SYNTHETIC', path.read_text())
                self.assertEqual(file_mode(path), 0o600)
                self.assertEqual(stat.S_IMODE(os.stat(home).st_mode), mode)
                self.assertEqual([p.name for p in home.iterdir() if p.name.endswith('.tmp')], [])

    def test_directory_owned_by_another_user_is_refused(self):
        home, path, unrelated = self.directory('foreign')
        before = self.snapshot(home, unrelated)
        with patch('gimme_aws_creds.config.os.geteuid', return_value=os.geteuid() + 1):
            self.assert_refused_before_mkdir(path, 'its directory .* is owned by another user')
        self.assertEqual(self.snapshot(home, unrelated), before)

    def test_directory_owned_by_root_or_this_user_is_trusted(self):
        home, path, _ = self.directory('owners')
        config = Config(gac_ui=RecordingUserInterface(str(home), {'OKTA_CONFIG': str(path)}),
                        create_config=False)
        fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        real = os.fstat(fd)
        for owner in (os.geteuid(), 0):
            with self.subTest(owner=owner):
                fields = list(real)
                fields[4] = owner
                with patch('gimme_aws_creds.config.os.fstat', return_value=os.stat_result(fields)):
                    config._require_trusted_directory(str(path), (str(home), fd))

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_directory_acl_letting_others_change_entries_is_refused_and_left_alone(self):
        for name, text in UNTRUSTED_DIRECTORY_ACLS.items():
            with self.subTest(acl=name):
                home, path, unrelated = self.directory('acl-' + name, acl=text)
                before = self.snapshot(home, unrelated)
                self.assert_refused_before_mkdir(
                    path, 'its directory .* access control list that may let other users')
                self.assertEqual(self.snapshot(home, unrelated), before)
                self.assertIn('everyone', before['home_acl'])

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_link_in_directory_whose_acl_lets_others_change_entries_is_not_read(self):
        target_home, target, _ = self.directory('link-target')
        for name, text in UNTRUSTED_DIRECTORY_ACLS.items():
            with self.subTest(acl=name):
                home, _, unrelated = self.directory('link-acl-' + name, acl=text)
                link = home / 'link'
                link.symlink_to(target)
                before = self.snapshot(home, unrelated)
                config = self.config_for(link)
                with patch('gimme_aws_creds.config.os.readlink') as readlink:
                    with self.assertRaisesRegex(
                            GimmeAWSCredsError, 'Refusing to follow configuration symlink .*: '
                            'the directory .* access control list that may let other users'):
                        self.write(link, config=config)
                readlink.assert_not_called()
                self.assertEqual(self.snapshot(home, unrelated), before)
                self.assertEqual(target.read_text(), ORIGINAL)

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_directory_acl_without_those_rights_is_accepted_and_left_alone(self):
        for name, text in TRUSTED_DIRECTORY_ACLS.items():
            with self.subTest(acl=name):
                home, path, _ = self.directory('ok-acl-' + name, acl=text)
                acl = self.acl.text_path(home)
                self.write(path)
                self.assertIn('NEW_SYNTHETIC', path.read_text())
                self.assertEqual(self.acl.text_path(home), acl)
                self.assertEqual(self.acl.text_path(path), '')
                self.assertEqual([p.name for p in home.iterdir() if p.name.endswith('.tmp')], [])

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_directory_acl_that_cannot_be_read_is_refused(self):
        home, path, unrelated = self.directory('acl-unreadable', acl=EVERYONE_INHERIT_ONLY)
        before = self.snapshot(home, unrelated)
        lib = config_module._darwin_acl_api()._lib
        for name, broken in (('acl_get_fd_np', lambda fd, kind: None),
                             ('acl_get_entry', lambda acl, which, entry: -1)):
            with self.subTest(failing=name):
                real = getattr(lib, name)

                def fail(*args, broken=broken):
                    ctypes.set_errno(errno.EIO)
                    return broken(*args)

                with patch.object(lib, name, side_effect=fail):
                    self.assert_refused_before_mkdir(
                        path, 'its directory .* cannot be checked .*' + os.strerror(errno.EIO))
                self.assertIs(getattr(lib, name), real)
                self.assertEqual(self.snapshot(home, unrelated), before)

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_staging_substitution_schedules_cannot_touch_an_existing_directory(self):
        # The four schedules of the independent ACL review. The destination
        # directory carries an ordinary inheritable everyone entry, which
        # also lets every user rename entries in it; at the mkdir() boundary
        # the adversary renames the new staging directory aside and an
        # existing empty directory of this user into its place. Writes into
        # that directory are now refused before anything is created, so the
        # existing directory keeps its name, inode, mode, contents and ACL.
        for case in ('inherited_success', 'restore_after_clear', 'inherited_clear_error',
                     'explicit_read_error', 'destination_acl_read_error'):
            with self.subTest(schedule=case):
                home, path, unrelated = self.directory('schedule-' + case,
                                                       acl=EVERYONE_INHERITABLE)
                self.assertTrue(self.acl.everyone_may_replace_entries(
                    self.pinned(home)))
                if case == 'explicit_read_error':
                    self.acl.set_path(unrelated, EVERYONE_EXPLICIT)
                pinned = self.pinned(unrelated)
                before = self.snapshot(home, unrelated)
                inode = os.fstat(pinned).st_ino
                adversary = []
                real_mkdir = os.mkdir
                real_clear = config_module._DarwinACL.clear

                def mkdir(entry, *args, **kwargs):
                    real_mkdir(entry, *args, **kwargs)
                    if kwargs.get('dir_fd') is not None:
                        # Namespace operations only: no chmod, chown or ACL edits.
                        os.rename(entry, 'original-stage', src_dir_fd=kwargs['dir_fd'],
                                  dst_dir_fd=kwargs['dir_fd'])
                        os.rename(unrelated.name, entry, src_dir_fd=kwargs['dir_fd'],
                                  dst_dir_fd=kwargs['dir_fd'])
                        adversary.append(entry)

                def clear_and_restore(api, fd):
                    real_clear(api, fd)
                    os.rename(home / adversary[0], unrelated)
                    os.rename(home / 'original-stage', home / adversary[0])

                patches = [patch('gimme_aws_creds.config.os.mkdir', side_effect=mkdir)]
                if case == 'restore_after_clear':
                    patches.append(patch.object(config_module._DarwinACL, 'clear', autospec=True,
                                                side_effect=clear_and_restore))
                elif case == 'inherited_clear_error':
                    patches.append(patch.object(config_module._DarwinACL, 'clear',
                                                side_effect=OSError(errno.EPERM, 'injected')))
                elif case == 'explicit_read_error':
                    patches.append(patch.object(config_module._DarwinACL, 'entries',
                                                side_effect=OSError(errno.EIO, 'injected')))
                elif case == 'destination_acl_read_error':
                    patches.append(patch.object(config_module._DarwinACL, 'may_change_entries',
                                                side_effect=OSError(errno.EIO, 'injected')))
                config = self.config_for(path)
                with contextlib.ExitStack() as stack:
                    spies = [stack.enter_context(p) for p in patches]
                    with self.assertRaisesRegex(GimmeAWSCredsError, 'its directory '):
                        self.write(path, config=config)
                spies[0].assert_not_called()
                self.assertEqual(adversary, [])
                self.assertEqual(self.snapshot(home, unrelated), before)
                self.assertTrue(unrelated.is_dir())
                self.assertEqual(os.stat(unrelated).st_ino, inode)
                self.assertEqual(self.acl.text(pinned), before['unrelated_acl'])
                self.assertEqual(path.read_text(), ORIGINAL)

    def pinned(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        return fd

    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_failure_in_a_trusted_directory_removes_only_the_new_staging_directory(self):
        # In a private directory whose new children inherit an everyone
        # entry, nobody else can rename entries, so the staging directory is
        # the one mkdir() made. An ACL read or clear failure removes it and
        # nothing else; an existing directory with an explicit ACL is untouched.
        cases = (('read', 'entries', OSError(errno.EIO, 'injected read failure')),
                 ('clear', 'clear', OSError(errno.EPERM, 'injected clear failure')))
        for name, method, error in cases:
            with self.subTest(failing=name):
                home, path, unrelated = self.directory('trusted-' + name,
                                                       acl=EVERYONE_INHERIT_ONLY)
                self.acl.set_path(unrelated, EVERYONE_EXPLICIT)
                self.assertFalse(self.acl.everyone_may_replace_entries(self.pinned(home)))
                before = self.snapshot(home, unrelated)
                real_mkdir = os.mkdir
                made = []

                def mkdir(entry, *args, **kwargs):
                    real_mkdir(entry, *args, **kwargs)
                    if kwargs.get('dir_fd') is not None:
                        made.append(os.stat(entry, dir_fd=kwargs['dir_fd']))

                config = self.config_for(path)
                with patch('gimme_aws_creds.config.os.mkdir', side_effect=mkdir), \
                        patch.object(config_module._DarwinACL, method, side_effect=error):
                    with self.assertRaisesRegex(GimmeAWSCredsError, 'staging directory .*'
                                                + error.strerror):
                        self.write(path, config=config)
                self.assertEqual(len(made), 1)
                self.assertEqual(self.snapshot(home, unrelated), before)


class DarwinAclIteratorTest(unittest.TestCase):
    @unittest.skipUnless(DARWIN, 'macOS extended ACLs')
    def test_iterator_errors_are_not_mistaken_for_the_end_of_the_acl(self):
        api = config_module._darwin_acl_api()
        temp = tempfile.TemporaryDirectory(prefix='gac-iter-')
        self.addCleanup(temp.cleanup)
        acl = DarwinAcl()
        directory = Path(temp.name) / 'd'
        directory.mkdir(mode=0o700)
        acl.set_path(directory, EVERYONE_EXPLICIT)
        self.addCleanup(acl.set_path, directory, b'!#acl 1\n')
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.assertEqual(api.entries(fd), [False])
        self.assertTrue(api.may_change_entries(fd))

        def fail(*args):
            ctypes.set_errno(errno.EIO)
            return -1

        with patch.object(api._lib, 'acl_get_entry', side_effect=fail):
            for check in (api.entries, api.may_change_entries):
                with self.assertRaises(OSError) as raised:
                    check(fd)
                self.assertEqual(raised.exception.errno, errno.EIO)


if __name__ == '__main__':
    unittest.main()
