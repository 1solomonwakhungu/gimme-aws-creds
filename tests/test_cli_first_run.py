"""Entry-point checks for running gimme-aws-creds before it is configured.

Each test starts the command-line script in a separate, isolated interpreter
with an empty temporary home directory, no configuration file, a minimal
environment and a closed standard input. A small bootstrap installs tripwires
before the program is imported: network access, file writes, process or
browser launches and credential backend lookups end the process immediately
with GUARD_EXIT_CODE, so a regression fails the test instead of reaching a
real service or the user's keychain. Writes to the operating system null device
are allowed because dependencies use it to discard diagnostics.
"""
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from pathlib import Path

from gimme_aws_creds import version

PROJECT_ROOT = Path(__file__).absolute().parent.parent
SOURCE_SCRIPT = PROJECT_ROOT / 'bin' / 'gimme-aws-creds'
INSTALLED_SCRIPT = Path(sysconfig.get_path('scripts')) / 'gimme-aws-creds'
GUARD_EXIT_CODE = 86
TIMEOUT_SECONDS = 60

# Usage: python -I -B -c BOOTSTRAP <source root or ""> <script> [args...]
BOOTSTRAP = r'''
import os
import runpy
import sys

import keyring
from keyring.backends import null

GUARD_EXIT_CODE = 86
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC
# socket.bind is not listed: urllib3 binds a loopback socket at import time to
# detect IPv6 support.
NETWORK_EVENTS = {
    "socket.connect", "socket.getaddrinfo", "socket.gethostbyaddr",
    "socket.gethostbyname", "socket.getnameinfo", "socket.sendmsg", "socket.sendto",
}
BLOCKED_EVENTS = {
    "os.exec", "os.fork", "os.forkpty", "os.link", "os.mkdir", "os.posix_spawn",
    "os.remove", "os.rename", "os.rmdir", "os.spawn", "os.startfile", "os.symlink",
    "os.system", "os.truncate", "subprocess.Popen", "webbrowser.open",
}


def trip(reason):
    try:
        sys.stderr.write("GUARD TRIPPED: " + reason + "\n")
        sys.stderr.flush()
    finally:
        os._exit(GUARD_EXIT_CODE)


def audit(event, args):
    if event in NETWORK_EVENTS:
        trip("network access (" + event + ")")
    elif event == "open":
        path, mode, flags = args
        # Dependencies may discard diagnostics without creating a file.
        if path == os.devnull:
            return
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & WRITE_FLAGS):
            trip("file write (" + repr(path) + ")")
    elif event in BLOCKED_EVENTS:
        trip(event)


class TripwireKeyring(null.Keyring):
    def get_password(self, service, username):
        trip("credential backend read")

    def set_password(self, service, username, password):
        trip("credential backend write")

    def delete_password(self, service, username):
        trip("credential backend delete")

    def get_credential(self, service, username):
        trip("credential backend read")


keyring.set_keyring(TripwireKeyring())
sys.addaudithook(audit)

source_root, script = sys.argv[1], sys.argv[2]
if source_root:
    sys.path.insert(0, source_root)
sys.argv = [script] + sys.argv[3:]
runpy.run_path(script, run_name="__main__")
'''


class IsolatedEntryPointMixin:
    """Runs a script through BOOTSTRAP; subclasses set script and source_root."""

    script = None
    source_root = None

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='gimme-aws-creds-first-run-'))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.home = self.root / 'home'
        self.home.mkdir()
        (self.root / 'tmp').mkdir()
        self.env = {
            'HOME': str(self.home),
            'USERPROFILE': str(self.home),
            'TMPDIR': str(self.root / 'tmp'),
            'TEMP': str(self.root / 'tmp'),
            'TMP': str(self.root / 'tmp'),
            'PYTHON_KEYRING_BACKEND': 'keyring.backends.null.Keyring',
        }
        for name in ('PATH', 'SYSTEMROOT'):
            if name in os.environ:
                self.env[name] = os.environ[name]

    def run_cli(self, *args):
        command = [
            sys.executable, '-I', '-B', '-c', BOOTSTRAP,
            str(self.source_root or ''), str(self.script), *args,
        ]
        return subprocess.run(
            command,
            cwd=str(self.root),
            env=self.env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )

    def snapshot(self):
        return sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*'))

    def assert_no_guard_tripped(self, result):
        self.assertNotEqual(result.returncode, GUARD_EXIT_CODE, result.stderr)
        self.assertNotIn('GUARD TRIPPED', result.stderr)


class TestEntryPointGuards(IsolatedEntryPointMixin, unittest.TestCase):
    """The tripwires must stop the operations the entry-point tests rely on
    them to detect."""

    PROBES = (
        ('network', 'import socket\nsocket.getaddrinfo("localhost", 443)\n'),
        ('credential backend', 'import keyring\nkeyring.get_password("gimme-aws-creds", "probe")\n'),
        ('file write', 'open("probe-output.txt", "w").close()\n'),
        ('null-named regular file', 'open("null", "w").close()\n'),
    )

    def test_null_device_writes_are_allowed(self):
        self.script = self.root / 'probe.py'
        self.script.write_text(
            'import os\n'
            'with open(os.devnull, "w") as sink:\n'
            '    sink.write("discarded")\n'
            'fd = os.open(os.devnull, os.O_WRONLY)\n'
            'os.write(fd, b"discarded")\n'
            'os.close(fd)\n')
        before = self.snapshot()
        result = self.run_cli()
        self.assert_no_guard_tripped(result)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

    def test_guards_stop_forbidden_operations(self):
        self.script = self.root / 'probe.py'
        for name, code in self.PROBES:
            with self.subTest(guard=name):
                self.script.write_text(code)
                before = self.snapshot()
                result = self.run_cli()
                self.assertEqual(result.returncode, GUARD_EXIT_CODE, result.stderr)
                self.assertIn('GUARD TRIPPED', result.stderr)
                self.assertEqual(self.snapshot(), before)


class FirstRunEntryPointMixin(IsolatedEntryPointMixin):
    """Checks shared by the source and installed entry points."""

    def assert_exits_before_configuration(self, *args):
        before = self.snapshot()
        result = self.run_cli(*args)
        self.assert_no_guard_tripped(result)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('first-time configuration', result.stderr)
        self.assertEqual(self.snapshot(), before, 'no files may be created')
        return result

    def test_help_exits_without_configuration(self):
        result = self.assert_exits_before_configuration('--help')
        self.assertIn('usage: gimme-aws-creds', result.stdout)
        self.assertIn('--action-configure', result.stdout)

    def test_version_exits_without_configuration(self):
        result = self.assert_exits_before_configuration('--version')
        self.assert_version_output(result.stdout)

    def assert_version_output(self, output):
        self.assertRegex(output, r'^gimme-aws-creds \d+\.\d+\.\d+')


class TestSourceEntryPointFirstRun(FirstRunEntryPointMixin, unittest.TestCase):
    """Runs bin/gimme-aws-creds against the package in this source tree."""

    script = SOURCE_SCRIPT
    source_root = PROJECT_ROOT

    def assert_version_output(self, output):
        self.assertEqual(output.strip(), 'gimme-aws-creds {}'.format(version))

    def test_no_arguments_still_start_first_time_configuration(self):
        before = self.snapshot()
        result = self.run_cli()
        self.assert_no_guard_tripped(result)
        self.assertIn('starting first-time configuration', result.stderr)
        self.assertIn('Okta URL for your organization', result.stderr)
        # Standard input is closed, so the wizard stops before writing anything.
        self.assertEqual(self.snapshot(), before)

    def test_configured_profile_listing_still_works(self):
        config_path = self.home / '.okta_aws_login_config'
        contents = '[DEFAULT]\nokta_org_url = https://example.invalid\ngimme_creds_server = appurl\n'
        config_path.write_text(contents)
        before = self.snapshot()
        result = self.run_cli('--action-list-profiles')
        self.assert_no_guard_tripped(result)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('okta_org_url = https://example.invalid', result.stdout)
        self.assertEqual(config_path.read_text(), contents)
        self.assertEqual(self.snapshot(), before)


@unittest.skipUnless(INSTALLED_SCRIPT.is_file(),
                     'gimme-aws-creds is not installed for this interpreter')
class TestInstalledEntryPointFirstRun(FirstRunEntryPointMixin, unittest.TestCase):
    """Runs the script installed for this interpreter against the installed
    package; the source tree is not on the subprocess path."""

    script = INSTALLED_SCRIPT


if __name__ == '__main__':
    unittest.main()
