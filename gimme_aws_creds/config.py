"""
Copyright 2016-present Nike, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and* limitations under the License.*
"""
import argparse
import configparser
import contextlib
import errno
import io
import os
import secrets
import stat
import sys

import requests
from urllib.parse import urlparse

from . import errors, ui, version
from .common import user_agent

# Whether the config writer can pin directories with descriptors. os.replace()
# and os.rename() share renameat(), but only os.rename is listed in
# supports_dir_fd, so test that rather than os.replace.
def _directory_descriptors_supported():
    # lstat delegates to stat on older Python versions and may be absent
    # from supports_dir_fd even though its dir_fd argument is supported.
    return (
        {os.open, os.stat, os.readlink, os.rename, os.unlink, os.mkdir, os.rmdir}
        <= os.supports_dir_fd and os.listdir in os.supports_fd)


_DIR_FD_SUPPORTED = _directory_descriptors_supported()

# How the config writer keeps access granted by access control lists (ACLs)
# off its staging directory; see Config._write_private_config.
if sys.platform == 'darwin':
    _ACL_POLICY = 'darwin'
elif sys.platform.startswith('linux'):
    _ACL_POLICY = 'linux'
else:
    _ACL_POLICY = None


class _DarwinACL:
    """Extended ACLs of open files, through the acl(3) functions in libSystem."""
    _TYPE_EXTENDED = 0x00000100
    _FIRST_ENTRY = 0
    _NEXT_ENTRY = -1
    _EXTENDED_ALLOW = 1
    _EXTENDED_DENY = 2
    _ENTRY_INHERITED = 1 << 4
    _ENTRY_ONLY_INHERIT = 1 << 8
    # Directory rights that let a principal add, remove or rename entries
    # (ACL_ADD_FILE, ACL_ADD_SUBDIRECTORY, ACL_DELETE_CHILD) or give itself
    # those rights (ACL_WRITE_SECURITY, ACL_CHANGE_OWNER).
    _CHANGE_ENTRIES = (1 << 2) | (1 << 5) | (1 << 6) | (1 << 12) | (1 << 13)

    def __init__(self):
        import ctypes
        self._ctypes = ctypes
        lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        pointer, integer = ctypes.c_void_p, ctypes.c_int
        for name, restype, argtypes in (
                ('acl_get_fd_np', pointer, [integer, integer]),
                ('acl_set_fd_np', integer, [integer, pointer, integer]),
                ('acl_init', pointer, [integer]),
                ('acl_get_entry', integer, [pointer, integer, ctypes.POINTER(pointer)]),
                ('acl_get_tag_type', integer, [pointer, ctypes.POINTER(integer)]),
                ('acl_get_permset_mask_np', integer, [pointer, ctypes.POINTER(ctypes.c_uint64)]),
                ('acl_get_flagset_np', integer, [pointer, ctypes.POINTER(pointer)]),
                ('acl_get_flag_np', integer, [pointer, integer]),
                ('acl_free', integer, [pointer])):
            function = getattr(lib, name)
            function.restype = restype
            function.argtypes = argtypes
        self._lib = lib

    def _error(self):
        code = self._ctypes.get_errno() or errno.EIO
        return OSError(code, os.strerror(code))

    def _each_entry(self, fd):
        """Yield the ACL entries of ``fd``; none if it has no extended ACL."""
        ctypes, lib = self._ctypes, self._lib
        ctypes.set_errno(0)
        acl = lib.acl_get_fd_np(fd, self._TYPE_EXTENDED)
        if not acl:
            if ctypes.get_errno() == errno.ENOENT:
                return  # the file has no extended ACL
            raise self._error()
        try:
            entry = ctypes.c_void_p()
            which = self._FIRST_ENTRY
            while True:
                ctypes.set_errno(0)
                if lib.acl_get_entry(acl, which, ctypes.byref(entry)) != 0:
                    # acl_get_entry() fails with EINVAL after the last entry.
                    if ctypes.get_errno() == errno.EINVAL:
                        return
                    raise self._error()
                which = self._NEXT_ENTRY
                yield entry
        finally:
            lib.acl_free(acl)

    def _has_flag(self, entry, flag):
        ctypes, lib = self._ctypes, self._lib
        flagset = ctypes.c_void_p()
        if lib.acl_get_flagset_np(entry, ctypes.byref(flagset)) != 0:
            raise self._error()
        value = lib.acl_get_flag_np(flagset, flag)
        if value < 0:
            raise self._error()
        return bool(value)

    def entries(self, fd):
        """Return one flag per ACL entry of ``fd``: whether it was inherited."""
        with contextlib.closing(self._each_entry(fd)) as each:
            return [self._has_flag(entry, self._ENTRY_INHERITED) for entry in each]

    def may_change_entries(self, fd):
        """Whether an ACL entry of directory ``fd`` lets anyone change its entries.

        Allow entries that apply to the directory itself and grant a right in
        _CHANGE_ENTRIES count, whoever they name; so does an entry of an
        unknown kind. Deny entries and inherit-only entries do not.
        """
        ctypes, lib = self._ctypes, self._lib
        with contextlib.closing(self._each_entry(fd)) as each:
            for entry in each:
                tag = ctypes.c_int()
                if lib.acl_get_tag_type(entry, ctypes.byref(tag)) != 0:
                    raise self._error()
                if tag.value == self._EXTENDED_DENY:
                    continue
                if tag.value != self._EXTENDED_ALLOW:
                    return True
                if self._has_flag(entry, self._ENTRY_ONLY_INHERIT):
                    continue
                rights = ctypes.c_uint64()
                if lib.acl_get_permset_mask_np(entry, ctypes.byref(rights)) != 0:
                    raise self._error()
                if rights.value & self._CHANGE_ENTRIES:
                    return True
        return False

    def clear(self, fd):
        """Replace the extended ACL of ``fd`` with an empty one."""
        acl = self._lib.acl_init(0)
        if not acl:
            raise self._error()
        try:
            if self._lib.acl_set_fd_np(fd, acl, self._TYPE_EXTENDED) != 0:
                raise self._error()
        finally:
            self._lib.acl_free(acl)


_darwin_acl = None


def _darwin_acl_api():
    """Return the shared _DarwinACL, or None if libSystem does not provide it."""
    global _darwin_acl
    if _darwin_acl is None:
        try:
            _darwin_acl = _DarwinACL()
        except (ImportError, OSError, AttributeError):
            return None
    return _darwin_acl


class Config:
    """
       The Config Class gets the CLI arguments, writes out the okta config file,
       gets and returns username and password and the Okta API key.

       A lot of this code is modified from https://github.com/nimbusscale/okta_aws_login
       under the MIT license.
    """

    def __init__(self, gac_ui, create_config=True, alicloud_sdk_available=False):
        """
        :type gac_ui: ui.UserInterface
        :type create_config: bool
        :type alicloud_sdk_available: bool
        """
        self._alicloud_sdk_available = alicloud_sdk_available
        self.ui = gac_ui
        self.FILE_ROOT = self.ui.HOME
        self.OKTA_CONFIG = self._resolve_config_path()
        # Tracking for `--debug` output: how each config value was determined.
        # See log_resolved_configuration().
        self._cli_args_provided = {}
        self._env_used_in_init = {}
        self._inheritance_chain = []
        self._profile_value_sources = {}
        if self.ui.environ.get('OKTA_CONFIG') is not None:
            self._env_used_in_init['OKTA_CONFIG'] = {
                'sets': 'config file path',
                'value': self.ui.environ.get('OKTA_CONFIG'),
            }
        self.disable_keychain = False
        self.open_browser = False
        self.action_register_device = False
        self.username = None
        self.api_key = None
        self.conf_profile = 'DEFAULT'
        self.verify_ssl_certs = True
        self.app_url = None
        self.resolve = False
        self.mfa_code = None
        self.remember_device = False
        self.aws_default_duration = 3600
        self.device_token = None
        self.action_configure = False
        self.action_list_profiles = False
        self.action_list_roles = False
        self.action_store_json_creds = False
        self.action_setup_fido_authenticator = False
        self.action_output_format = False
        self.output_format = 'export'
        self.force_classic = False
        self.debug = False
        self.enable_alicloud = False
        self.roles = []

        if self.ui.environ.get("OKTA_USERNAME") is not None:
            self.username = self.ui.environ.get("OKTA_USERNAME")
            self._env_used_in_init['OKTA_USERNAME'] = {
                'sets': 'config.username',
                'value': self.username,
            }

        if self.ui.environ.get("OKTA_API_KEY") is not None:
            self.api_key = self.ui.environ.get("OKTA_API_KEY")
            self._env_used_in_init['OKTA_API_KEY'] = {
                'sets': 'config.api_key',
                'value': self.api_key,
            }

        if create_config and not os.path.isfile(self.OKTA_CONFIG):
            # Validate the command line before prompting, so that --help,
            # --version and invalid arguments exit without starting the
            # first-time configuration wizard. get_args() applies the values.
            self._build_arg_parser().parse_args(self.ui.args)
            self.ui.notify('No gimme-aws-creds configuration file found, starting first-time configuration...')
            self.update_config_file()

    def _resolve_config_path(self):
        """Preserve explicit and legacy locations before choosing an XDG path."""
        if 'OKTA_CONFIG' in self.ui.environ:
            return self.ui.environ['OKTA_CONFIG']

        legacy = os.path.join(self.FILE_ROOT, '.okta_aws_login_config')
        # Keep an existing legacy path authoritative, including a broken symlink
        # or directory, rather than silently selecting another login identity.
        if os.name == 'nt' or os.path.lexists(legacy):
            return legacy

        config_home = self.ui.environ.get('XDG_CONFIG_HOME', '')
        if not config_home or not os.path.isabs(config_home):
            config_home = os.path.join(self.FILE_ROOT, '.config')
        return os.path.join(config_home, 'gimme-aws-creds', 'config')

    @staticmethod
    def _create_config_parent(path):
        """Create missing parents privately without changing existing modes."""
        # Keep '..' intact: the filesystem resolves symlinks before it, just
        # as open() will when writing the original configuration path.
        parent = os.path.dirname(path) or os.curdir
        missing = []
        while True:
            try:
                os.stat(parent)
            except FileNotFoundError:
                ancestor = os.path.dirname(parent) or os.curdir
                if ancestor == parent:
                    raise
                missing.append(parent)
                parent = ancestor
            else:
                break
        for directory in reversed(missing):
            try:
                os.mkdir(directory, mode=0o700)
            except FileExistsError:
                if not os.path.isdir(directory):
                    raise

    def _build_arg_parser(self):
        """Build the CLI argument parser"""
        parser = argparse.ArgumentParser(
            description="Gets a STS token to use for AWS or Alibaba Cloud CLI based on a SAML assertion from Okta"
        )
        parser.add_argument(
            '--username', '-u',
            help="The username to use when logging into Okta. The username can "
                 "also be set via the OKTA_USERNAME env variable. If not provided "
                 "you will be prompted to enter a username."
        )
        parser.add_argument(
            '--action-configure', '--configure', '-c',
            action='store_true',
            help="If set, will prompt user for configuration parameters and then exit."
        )
        parser.add_argument(
            '--action-register-device',
            '--register-device',
            '--register_device',
            action='store_true',
            help='Download a device token from Okta and add it to the configuration file.'
        )
        parser.add_argument(
            '--output-format', '-o',
            choices=['export', 'json'],
            help='Output credentials as either list of shell exports or lines of structured JSON.'
        )
        parser.add_argument(
            '--profile', '-p',
            help='If set, the specified configuration profile will be used instead of the default.'
        )
        parser.add_argument(
            '--roles',
            help='If set, the specified role will be used instead of the aws_rolename in the profile, '
                 'can be specified as a comma separated list, '
                 'can be regex in format /<pattern>/. '
                 'for example: arn:aws:iam::123456789012:role/Admin,/:210987654321:/ '
                 'would match both account 123456789012 by ARN and 210987654321 by regexp'
        )
        parser.add_argument(
            '--resolve', '-r',
            action='store_true',
            help='If set, perfom alias resolution.'
        )
        parser.add_argument(
            '--insecure', '-k',
            action='store_true',
            help='Allow connections to SSL sites without cert verification.'
        )
        parser.add_argument(
            '--mfa-code',
            help="The MFA verification code to be used with SMS or TOTP authentication methods. "
                 "If not provided you will be prompted to enter an MFA verification code. "
                 "Can be read from OKTA_MFA_CODE environment variable"
        )
        parser.add_argument(
            '--remember-device', '-m',
            action='store_true',
            help="The MFA device will be remembered by Okta service for a limited time, "
                 "otherwise, you will be prompted for it every time."
        )
        parser.add_argument(
            '--version', action='version',
            version='%(prog)s {}'.format(version),
            help='gimme-aws-creds version')
        parser.add_argument(
            '--action-list-profiles', '--list-profiles', action='store_true',
            help='List all the profiles under .okta_aws_login_config')
        parser.add_argument(
            '--action-list-roles', action='store_true',
            help='List all the roles in the selected profile')
        parser.add_argument(
            '--action-store-json-creds', action='store_true',
            help='Read credentials from stdin (in json format) and store them in ~/.aws/credentials file')
        parser.add_argument(
            '--action-setup-fido-authenticator', action='store_true',
            help='Sets up a new FIDO WebAuthn authenticator in Okta'
        )
        parser.add_argument(
            '--open-browser', action='store_true',
            help='Automatically open a webbrowser for device authorization (Okta Identity Engine only)'
        )
        parser.add_argument(
            '--disable-keychain', action='store_true',
            help="Disable the use of the system keychain to store the user's password"
        )
        parser.add_argument(
            '--force-classic', action='store_true',
            help='Force the use of the Okta Classic login process (Okta Identity Engine only)'
        )
        parser.add_argument(
            '--aws-cred-profile',
            help="If set, overrides the cred_profile setting from the config file and the "
                 "GIMME_AWS_CREDS_CRED_PROFILE environment variable."
        )
        parser.add_argument(
            '--debug', action='store_true',
            help='Enable debug logging to show API request and response data'
        )
        parser.add_argument(
            '--enable-alicloud', action='store_true',
            help='Request openid, okta.apps.sso, and interclient_access on OIE device authorization '
                 '(Alibaba Cloud / Native-to-Web SSO alongside AWS Web SSO). '
                 'Requires optional dependencies: pip install "gimme-aws-creds[alicloud]". '
                 'Can also be set per-profile as enable_alicloud in the config file.'
        )
        return parser

    def get_args(self):
        """Get the CLI args"""
        parser = self._build_arg_parser()
        args = parser.parse_args(self.ui.args)

        # Track which CLI flags were explicitly provided (i.e. differ from
        # argparse defaults). Used by --debug output to show how each value
        # was determined.
        for action in parser._actions:
            if action.dest in ('help', 'version'):
                continue
            if not hasattr(args, action.dest):
                continue
            parsed_value = getattr(args, action.dest)
            if parsed_value != action.default:
                self._cli_args_provided[action.dest] = parsed_value

        self.action_configure = args.action_configure
        self.action_list_profiles = args.action_list_profiles
        self.action_list_roles = args.action_list_roles
        self.action_store_json_creds = args.action_store_json_creds
        self.action_register_device = args.action_register_device
        self.action_setup_fido_authenticator = args.action_setup_fido_authenticator
        self.open_browser = args.open_browser
        self.disable_keychain = args.disable_keychain
        self.force_classic = args.force_classic
        self.debug = args.debug
        self.enable_alicloud = args.enable_alicloud

        if args.insecure is True:
            ui.default.warning("Warning: SSL certificate validation is disabled!")
            self.verify_ssl_certs = False
        else:
            self.verify_ssl_certs = True

        if args.username is not None:
            self.username = args.username
        if args.mfa_code is not None:
            self.mfa_code = args.mfa_code
        if args.remember_device:
            self.remember_device = True
        if args.resolve is True:
            self.resolve = True
        if args.output_format is not None:
            self.action_output_format = args.output_format
            self.output_format = args.output_format
        if args.roles is not None:
            self.roles = [role.strip() for role in args.roles.split(',') if role.strip()]
        self.cred_profile = args.aws_cred_profile
        self.conf_profile = args.profile or 'DEFAULT'

    def _handle_config(self, config, profile_config, include_inherits = True, profile_name=None):
        # Track this profile in the inheritance chain (most-derived first).
        if profile_name is not None and profile_name not in self._inheritance_chain:
            self._inheritance_chain.append(profile_name)

        # Capture keys directly defined in this profile (before merging parents)
        # so we can correctly stamp child overrides over parent values.
        raw_keys_in_profile = [k for k in profile_config.keys() if k != 'inherits']

        # Convert True/False strings to booleans
        for key in profile_config:
            if profile_config[key] == 'True':
                profile_config[key] = True
            elif profile_config[key] == 'False':
                profile_config[key] = False

        if "inherits" in profile_config.keys() and include_inherits:
            self.ui.message("Using inherited config: " + profile_config["inherits"])
            if profile_config["inherits"] not in config:
                raise errors.GimmeAWSCredsError(self.conf_profile + " inherits from " + profile_config["inherits"] + ", but could not find " + profile_config["inherits"])
            parent_name = profile_config["inherits"]
            profile_config = {
                **self._handle_config(config, dict(config[parent_name]), profile_name=parent_name),
                **profile_config,
            }
            del profile_config["inherits"]

        # Stamp this profile's directly-defined keys, overriding parent stamps
        # for keys the child explicitly defines.
        if profile_name is not None:
            for key in raw_keys_in_profile:
                if key in profile_config:
                    self._profile_value_sources[key] = profile_name

        # Empty string in force_classic should be handled as True - this makes sure that migrating from Classic to OIE is seamless
        if profile_config.get('force_classic') == '' or profile_config.get('force_classic') is None:
            profile_config['force_classic'] = True

        return profile_config

    def get_config_dict(self, include_inherits = True):
        """returns the conf dict from the okta config file"""
        # Check to see if config file exists, if not complain and exit
        # If config file does exist return config dict from file
        if os.path.isfile(self.OKTA_CONFIG):
            config = configparser.ConfigParser()
            config.read(self.OKTA_CONFIG)

            try:
                profile_config = dict(config[self.conf_profile])
                self.fail_if_profile_not_found(profile_config, self.conf_profile, config.default_section)
                return self._handle_config(config, profile_config, include_inherits, profile_name=self.conf_profile)
            except KeyError:
                if self.action_configure:
                    return {}
                raise errors.GimmeAWSCredsError(
                    'Configuration profile not found! Use the --action-configure flag to generate the profile.')
        raise errors.GimmeAWSCredsError('Configuration file not found! Use the --action-configure flag to generate file.')

    def update_config_file(self):
        """
           Prompts user for config details for the okta_aws_login tool.
           Either updates existing config file or creates new one.
           Config Options:
                okta_org_url = Okta URL
                gimme_creds_server = URL of the gimme-creds-server or 'internal' for local processing or 'appurl' when app url available
                client_id = OAuth Client ID - used for the gimme-creds-server in Okta classic and user authentication in Okta Identity Engine
                okta_auth_server = Server ID for the OAuth authorization server used by gimme-creds-server
                write_aws_creds = Option to write creds to ~/.aws/credentials
                cred_profile = Use DEFAULT or Role-based name as the profile in ~/.aws/credentials
                aws_appname = (optional) Okta App Name (AWS or Alibaba Cloud)
                aws_rolename =  (optional) AWS or Alibaba Cloud Role ARN to assume
                okta_username = Okta username
                aws_default_duration = Default AWS or Alibaba Cloud session duration in seconds (default: 3600)
                preferred_mfa_type = (optional, Okta Classic only) Select this MFA device type automatically
                preferred_mfa_factor_id = (optional, Okta Classic only) Pin a specific Okta factor by id (overrides preferred_mfa_type when matched)
                include_path - (optional) includes the full role path to the role name for profile
                enable_keychain = (optional, Okta Classic only) enable the use of the system keychain to store the user's password
                enable_alicloud = (optional, OIE only) y/n - use Native-to-Web SSO scope for Alibaba Cloud RAM
                alicloud_saml_url = (optional, Alibaba Cloud only) explicit SAML SSO URL for the Alibaba Cloud app in Okta; falls back to the app link if not set
                alicloud_region = (optional, Alibaba Cloud only) Alibaba Cloud STS region used for AssumeRoleWithSAML (default: cn-hangzhou)

        """
        config = configparser.ConfigParser()
        if self.action_configure:
            self.conf_profile = self._get_conf_profile_name(self.conf_profile)

        defaults = {
            'okta_org_url': '',
            'okta_auth_server': '',
            'client_id': '',
            'gimme_creds_server': 'appurl',
            'aws_appname': '',
            'aws_rolename': ','.join(self.roles),
            'write_aws_creds': '',
            'cred_profile': 'role',
            'okta_username': '',
            'app_url': '',
            'resolve_aws_alias': 'n',
            'include_path': 'n',
            'preferred_mfa_type': '',
            'preferred_mfa_factor_id': '',
            'remember_device': 'n',
            'aws_default_duration': '3600',
            'output_format': 'export',
            'force_classic': '',
            'open_browser': '',
            'enable_alicloud': 'n',
            'alicloud_saml_url': '',
            'alicloud_region': 'cn-hangzhou',
            'enable_keychain': 'y'
        }

        # See if a config file already exists.
        # If so, use current values as defaults
        if os.path.isfile(self.OKTA_CONFIG):
            config.read(self.OKTA_CONFIG)

            if self.conf_profile in config:
                profile = config[self.conf_profile]

                for default in defaults:
                    defaults[default] = profile.get(default, defaults[default])

        # Prompt user for config details and store in config_dict
        config_dict = defaults
        config_dict['okta_org_url'] = self._get_org_url_entry(defaults['okta_org_url'])
        client_id_set = False

        # Options specific to OIE domains
        if self._okta_platform == 'identity_engine':
            config_dict['force_classic'] = self._get_force_classic(defaults['force_classic'])
            if config_dict['force_classic'] is False:
                config_dict['open_browser'] = self._get_open_browser(defaults['open_browser'])
                config_dict['client_id'] = self._get_client_id_entry(defaults['client_id'])
                config_dict['okta_auth_server'] = self._get_auth_server_entry(defaults['okta_auth_server'])
                client_id_set = True

            # Options specific to Alibaba Cloud
            if self._alicloud_sdk_available:
                config_dict['enable_alicloud'] = self._get_enable_alicloud(defaults['enable_alicloud'])
                self.enable_alicloud = config_dict['enable_alicloud']
                if config_dict['enable_alicloud'] is True:
                    config_dict['alicloud_saml_url'] = self._get_alicloud_saml_url(defaults['alicloud_saml_url'])
                    config_dict['alicloud_region'] = self._get_alicloud_region(defaults['alicloud_region'])

        # These options are only used in the Classic authentication flow
        if self._okta_platform == 'classic' or config_dict['force_classic'] is True:
            config_dict['okta_username'] = self._get_okta_username(defaults['okta_username'])
            config_dict['enable_keychain'] = self._get_enable_keychain(defaults['enable_keychain'])
            config_dict['preferred_mfa_type'] = self._get_preferred_mfa_type(defaults['preferred_mfa_type'])
            config_dict['remember_device'] = self._get_remember_device(defaults['remember_device'])

        # The rest of the options are used in both OIE and Classic
        config_dict['gimme_creds_server'] = self._get_gimme_creds_server_entry(defaults['gimme_creds_server'])
        if config_dict['gimme_creds_server'] == 'appurl':
            config_dict['app_url'] = self._get_appurl_entry(defaults['app_url'])
        elif config_dict['gimme_creds_server'] != 'internal':
            if client_id_set is False:
                config_dict['client_id'] = self._get_client_id_entry(defaults['client_id'])
                config_dict['okta_auth_server'] = self._get_auth_server_entry(defaults['okta_auth_server'])
        config_dict['write_aws_creds'] = self._get_write_aws_creds(defaults['write_aws_creds'])
        config_dict['include_path'] = self._get_include_path(defaults['include_path'])
        config_dict['aws_rolename'] = self._get_aws_rolename(defaults['aws_rolename'])
        config_dict['resolve_aws_alias'] = self._get_resolve_aws_alias(defaults['resolve_aws_alias'])
        config_dict['aws_default_duration'] = self._get_aws_default_duration(defaults['aws_default_duration'])
        if config_dict['gimme_creds_server'] != 'appurl':
            config_dict['aws_appname'] = self._get_aws_appname(defaults['aws_appname'])

        config_dict["output_format"] = ''
        if not config_dict["write_aws_creds"]:
            config_dict['output_format'] = self._get_output_format(defaults['output_format'])

        # If write_aws_creds is True get the profile name
        if config_dict['write_aws_creds'] is True:
            config_dict['cred_profile'] = self._get_cred_profile(defaults['cred_profile'])
        else:
            config_dict['cred_profile'] = defaults['cred_profile']

        self.write_config_file(config_dict)

    def write_config_file(self, config_dict):
        config = configparser.ConfigParser()
        config.read(self.OKTA_CONFIG)
        config[self.conf_profile] = config_dict

        buffer = io.StringIO()
        config.write(buffer)
        # Create directories only when configuration is explicitly written.
        try:
            self._create_config_parent(self.OKTA_CONFIG)
            self._write_private_config(self.OKTA_CONFIG, buffer.getvalue())
        except OSError as exc:
            raise errors.GimmeAWSCredsError(
                'Cannot write configuration file {}: {}'.format(self.OKTA_CONFIG, exc.strerror)
            ) from exc

    # Owner read/write only: the config can hold an Okta device token.
    _CONFIG_FILE_MODE = 0o600
    # Symlinks followed from the configuration path before giving up (ELOOP).
    _MAX_CONFIG_SYMLINKS = 40
    # Destination characters kept in the temporary name; the rest of the name
    # is fixed-length, so a valid destination name always fits.
    _TEMP_NAME_PREFIX = 32

    def _write_private_config(self, path, data):
        """Atomically create or replace ``path`` with owner-only permissions.

        The data is written to a file with a fixed name inside a new staging
        directory, which is created next to the destination with mode 0700,
        opened once, and checked to be an empty directory owned by the current
        user with no group or other permissions. The file is created with
        O_EXCL and O_NOFOLLOW and mode 0600, flushed to disk and renamed over
        the destination relative to the staging directory's descriptor.
        Readers see either the old or the new file, never a partial one. An
        error raised before the rename leaves the original untouched and
        removes the staged file and directory; a crash can leave them behind.

        * Group/other permission bits on an existing file are removed (with a
          warning); owner bits are kept, so a rewrite never widens the mode.
          A file that is not owner-writable is refused, as open() would.
        * The existing owner and group are kept. If either cannot be kept
          (only root may give a file away, and only a member may assign a
          group), the write is refused rather than changing ownership.
        * If the path is a symlink, the regular file it points to is replaced,
          provided every link followed is owned by the current user or root
          and is in a directory that is trusted in the same way as the
          destination directory (see below). That is checked through the
          directory's pinned descriptor before the link is read, so no other
          user can swap the link for another while it is read; links in any
          other directory, such as a shared or sticky one, are refused
          without being read. Dangling links, links owned by other users and
          links to anything other than a regular file are refused. A symlink to a directory
          earlier in the path, followed by '..', resolves as the kernel does;
          the path is never normalized lexically.

        Threat model (POSIX). Every directory involved is opened once and
        later operations are relative to those descriptors, so renaming or
        replacing a parent directory cannot redirect the write.

        The directory that will hold the file (after following symlinks) must
        be owned by the current user or root, have no group or other write
        bit, and have no ACL entry that lets anyone add, remove or rename its
        entries or change its ACL or owner. Otherwise the write is refused
        before anything is created, and nothing in that directory, including
        its ACL, is changed. A shared or world-writable directory (even with
        the sticky bit) is therefore not a supported configuration location;
        the default and XDG locations are private directories.

        Within such a directory only this user and root can put an entry
        under a name, so the staging directory this process creates cannot
        be swapped for another directory, and the file renamed into place is
        always the one this process wrote. Cleanup removes only the staging
        directory and file this process created, checked by identity first.
        A staging directory that is not a directory, not owned by the
        current user, not private or not empty when checked (which only the
        same user or root could cause) is refused and left alone.

        ACLs. A new directory can inherit ACL entries from its parent that
        grant other users access its 0700 mode does not show, so the staging
        directory's ACL is dealt with before it is checked and used:

        * macOS: the extended ACL is read and removed through the directory's
          descriptor (acl_get_fd_np/acl_set_fd_np) and read again to confirm
          it is gone. Permissions are checked on every operation, so users it
          named lose access at once, even through descriptors they opened
          earlier; entries they created or a move of the directory meanwhile
          are refused by the checks that follow. A directory with entries that
          were not inherited is not the one just made, so it is refused and
          its ACL left alone. ACLs of the destination and its directories are
          only read, never changed; inherit-only entries of the destination
          directory, which do not apply to it, are what the staging directory
          can inherit.
        * Linux: POSIX.1e ACL entries for named users and groups are limited
          by the ACL mask, which is the group mode bits: without the group
          write bit nobody they name can change the destination directory,
          and the staging directory's group bits are zero. NFSv4 ACLs
          (system.nfs4_acl) are not limited that way and are refused on
          either directory.
        * Other POSIX systems: refused, as their ACLs cannot be checked.

        The staged file's mode and ACL are checked before anything is written
        to it, and the directory and file again before the rename.

        Not covered: processes running as the same user or as root, which can
        change anything this process can; network filesystems whose server
        grants access the local modes and ACLs do not show; and filesystems
        that do not enforce POSIX ownership and modes. Another user who can
        write to a directory earlier in the path can still change what the path resolves to
        before it is opened, so success means the new file was published
        where the path pointed when it was resolved. The
        write fails, after publishing, if the published file or a pinned
        directory no longer matches. POSIX systems without the descriptor
        functions this needs are refused rather than written insecurely.

        Windows: directory descriptors are not available, so the path is
        resolved by name and none of the guarantees above are claimed. The
        staging directory and file inherit the ACL of the destination
        directory (by default the user profile, which is private) and
        ``os.chmod`` only toggles the read-only flag, so POSIX modes and
        ownership are not enforced there.
        """
        posix = os.name != 'nt'
        if posix and not _DIR_FD_SUPPORTED:
            raise errors.GimmeAWSCredsError(
                'Refusing to write configuration file {}: this platform cannot open '
                'directories safely'.format(path))
        if posix:
            self._require_acl_support(path)
        pinned = posix
        opened = []
        try:
            directory, name, existing = self._locate_config_target(path, posix, pinned, opened)
            if posix:
                self._require_trusted_directory(path, directory)
            self._replace_config(path, directory, name, existing, data, posix, opened)
        finally:
            for _, fd in opened:
                os.close(fd)

    @staticmethod
    def _at(directory, name):
        """Return the path and dir_fd arguments for ``name`` in ``directory``."""
        directory_path, fd = directory
        if fd is None:
            return os.path.join(directory_path, name), None
        return name, fd

    @staticmethod
    def _open_directory(directory_path, entry, dir_fd, pinned, opened):
        """Open a directory once, resolving it as open() would.

        ``directory_path`` names the directory in messages and later checks;
        ``entry`` is opened relative to ``dir_fd``.
        """
        if not pinned:
            return directory_path, None
        flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0)
        fd = os.open(entry, flags, dir_fd=dir_fd)
        opened.append((directory_path, fd))
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), directory_path)
        return directory_path, fd

    def _locate_config_target(self, path, posix, pinned, opened):
        """Find the directory and name to replace, following trusted symlinks.

        Returns ``(directory, name, existing)`` where ``existing`` is the
        lstat result of the current file, or None if there is none yet.
        """
        directory_path, name = os.path.split(path)
        if not name:
            raise errors.GimmeAWSCredsError(
                'Cannot write configuration file {}: not a file path'.format(path))
        directory_path = directory_path or os.curdir
        directory = self._open_directory(directory_path, directory_path, None, pinned, opened)

        def refuse_link(reason):
            return errors.GimmeAWSCredsError(
                'Refusing to follow configuration symlink {}: {}'.format(path, reason))

        followed = 0
        while True:
            entry, dir_fd = self._at(directory, name)
            try:
                link = os.lstat(entry, dir_fd=dir_fd)
            except FileNotFoundError as exc:
                if followed:
                    raise refuse_link(exc.strerror) from exc
                return directory, name, None
            if not stat.S_ISLNK(link.st_mode):
                if stat.S_ISREG(link.st_mode):
                    return directory, name, link
                if followed:
                    raise refuse_link('target is not a regular file')
                raise errors.GimmeAWSCredsError(
                    'Refusing to replace configuration file {}: not a regular file'.format(path))
            if followed >= self._MAX_CONFIG_SYMLINKS:
                raise refuse_link(os.strerror(errno.ELOOP))
            if posix:
                if link.st_uid not in (os.geteuid(), 0):
                    raise refuse_link('owned by another user')
                # Only a directory whose entries no other user can change
                # guarantees that the link read below is the one just
                # checked: elsewhere it could be moved aside, replaced and
                # restored with nothing in its metadata to show it.
                problem = self._directory_trust_problem(directory[1])
                if problem:
                    raise refuse_link('the directory {} that contains it {}'.format(
                        directory[0], problem))
            target = os.readlink(entry, dir_fd=dir_fd)
            followed += 1

            target_directory, name = os.path.split(target)
            if name in ('', os.curdir, os.pardir):
                raise refuse_link('target is not a regular file')
            if target_directory:
                display = os.path.join(directory[0], target_directory)
                try:
                    directory = self._open_directory(
                        display, target_directory, directory[1], pinned, opened)
                except OSError as exc:
                    raise refuse_link(exc.strerror) from exc

    # Name of the file inside the private staging directory. It is fixed:
    # nobody else can create entries there.
    _STAGED_FILE_NAME = 'config'

    def _replace_config(self, path, directory, name, existing, data, posix, opened):
        """Write ``data`` in a private staging directory and rename it to ``name``."""
        mode = self._CONFIG_FILE_MODE
        if existing is not None and posix:
            current = stat.S_IMODE(existing.st_mode)
            mode = current & self._CONFIG_FILE_MODE
            if not mode & stat.S_IWUSR and os.geteuid() != 0:
                raise errors.GimmeAWSCredsError(
                    'Refusing to replace configuration file {}: it is read-only'.format(path))
            if current & ~self._CONFIG_FILE_MODE:
                self.ui.warning(
                    'Configuration file had permissions {:04o}; restricting them to {:04o}.'.format(
                        current, mode))

        stage_name = '.{}.{}.tmp'.format(name[:self._TEMP_NAME_PREFIX], secrets.token_hex(8))
        stage = None
        try:
            stage = self._create_staging_directory(path, directory, stage_name, posix)
            self._publish_staged(path, directory, name, stage, existing, mode, data, posix, opened)
        finally:
            if stage is not None:
                self._remove_staging_directory(directory, stage_name, stage)

    def _create_staging_directory(self, path, directory, stage_name, posix):
        """Create the private staging directory and return it pinned.

        Returns ``(display_path, fd)``; ``fd`` is None on Windows.
        """
        entry, dir_fd = self._at(directory, stage_name)
        display = os.path.join(directory[0], stage_name)
        try:
            os.mkdir(entry, 0o700, dir_fd=dir_fd)
        except FileExistsError:
            raise  # the name belongs to someone else
        except BaseException:
            # mkdir() may have succeeded before an interrupt was delivered.
            self._discard_new_staging_directory(entry, dir_fd, None)
            raise
        if not posix:
            return display, None

        def refuse():
            return errors.GimmeAWSCredsError(
                'Refusing to write configuration file {}: its staging directory {} was '
                'replaced by another process'.format(path, display))

        flags = (os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | os.O_NOFOLLOW
                 | getattr(os, 'O_CLOEXEC', 0))
        fd = None
        ours = False
        try:
            try:
                fd = os.open(entry, flags, dir_fd=dir_fd)
            except OSError as exc:
                # A symlink or non-directory now has the name we created.
                if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.ENOENT):
                    raise refuse() from exc
                raise

            def private_and_empty():
                st = os.fstat(fd)
                return (stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
                        and not stat.S_IMODE(st.st_mode) & 0o077 and not os.listdir(fd))

            # Only this user and root can add or rename entries in the
            # destination directory (_require_trusted_directory), so the
            # name mkdir() just created refers to that directory or, if an
            # inherited ACL let someone move it out, to nothing; nobody else
            # can put another directory there. These checks guard against the
            # same user or root, which are outside the threat model: mkdir()
            # made it 0700 (less any umask bits), so group/other bits,
            # another owner or existing entries mean this is not that
            # directory, and it is left alone.
            if not private_and_empty():
                raise refuse()
            ours = True
            if not self._drop_inherited_acl(path, display, fd):
                # A new directory only has inherited ACL entries.
                ours = False
                raise refuse()
            # Until the inherited ACL was removed, the principals it named
            # could add entries here or move the directory out of the
            # destination directory; they no longer can, and anything they
            # did is caught now.
            if not private_and_empty() or not self._is_same_file(entry, dir_fd, os.fstat(fd)):
                raise refuse()
            if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
                # The umask removed owner bits this process needs.
                os.fchmod(fd, 0o700)
        except errors.GimmeAWSCredsError:
            if ours:
                # Our empty directory, checked by identity before removal.
                self._discard_new_staging_directory(entry, dir_fd, fd)
            elif fd is not None:
                # Whatever is there now is not ours to remove.
                os.close(fd)
            raise
        except BaseException:
            # Failed or interrupted while checking the directory just made.
            self._discard_new_staging_directory(entry, dir_fd, fd)
            raise
        return display, fd

    def _require_trusted_directory(self, path, directory):
        """Refuse a destination directory whose entries other users can change.

        Only its owner, if that is this user or root, may add, remove or
        rename its entries: no group or other write bit, and no ACL entry
        that grants those rights or the right to change the ACL or owner.
        Nothing is created or changed before this check passes.
        """
        directory_path, fd = directory
        problem = self._directory_trust_problem(fd)
        if problem:
            raise errors.GimmeAWSCredsError(
                'Refusing to write configuration file {}: its directory {} {}'.format(
                    path, directory_path, problem))

    def _directory_trust_problem(self, fd):
        """Say why users other than this one and root may change entries of ``fd``.

        Returns None for a trusted directory. The directory is only read.
        """
        st = os.fstat(fd)
        if st.st_uid not in (os.geteuid(), 0):
            return 'is owned by another user'
        if stat.S_IMODE(st.st_mode) & 0o022:
            return 'is writable by other users (remove that with chmod go-w)'
        try:
            if _ACL_POLICY == 'darwin':
                shared = _darwin_acl_api().may_change_entries(fd)
            else:
                # POSIX.1e ACLs: the group bits, checked above, are the mask
                # that limits every named user and group entry. NFSv4 ACLs
                # are not limited by the mode.
                shared = self._has_nfs4_acl(fd)
        except OSError as exc:
            return 'has an access control list that cannot be checked ({})'.format(exc.strerror)
        if shared:
            return 'has an access control list that may let other users add or remove entries'
        return None

    def _require_acl_support(self, path):
        """Refuse platforms where ACLs on the staging directory cannot be ruled out."""
        if _ACL_POLICY == 'darwin' and _darwin_acl_api() is not None:
            return
        if _ACL_POLICY == 'linux':
            return
        raise errors.GimmeAWSCredsError(
            'Refusing to write configuration file {}: access control lists cannot be '
            'checked on this platform'.format(path))

    @staticmethod
    def _has_nfs4_acl(fd):
        """Whether ``fd`` has an NFSv4 ACL, which Linux file modes do not limit."""
        try:
            os.getxattr(fd, 'system.nfs4_acl')
        except OSError as exc:
            if exc.errno in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
                return False
            raise
        return True

    def _acl_may_grant_access(self, fd):
        """Whether an ACL may give others access to ``fd`` despite an owner-only mode."""
        if _ACL_POLICY == 'darwin':
            return bool(_darwin_acl_api().entries(fd))
        # POSIX.1e ACLs: the group mode bits are the ACL mask, which limits
        # every named user and group entry; callers require them to be zero.
        return self._has_nfs4_acl(fd)

    def _drop_inherited_acl(self, path, display, fd):
        """Remove the ACL the new staging directory inherited from its parent.

        Returns False, changing nothing, if the directory has ACL entries that
        were not inherited; raises if the ACL cannot be removed.
        """
        def failed(reason):
            return errors.GimmeAWSCredsError(
                'Refusing to write configuration file {}: cannot remove the access control '
                'list its staging directory {} inherited ({})'.format(path, display, reason))

        if _ACL_POLICY != 'darwin':
            # Linux: POSIX.1e ACLs are bounded by the 0700 mode; refuse the
            # NFSv4 ACLs that are not.
            try:
                if self._has_nfs4_acl(fd):
                    raise failed('NFSv4 ACLs are not limited by file modes')
            except OSError as exc:
                raise failed(exc.strerror) from exc
            return True
        acl = _darwin_acl_api()
        try:
            inherited = acl.entries(fd)
            if not all(inherited):
                return False
            if inherited:
                acl.clear(fd)
                if acl.entries(fd):
                    raise failed('it is still present')
        except OSError as exc:
            raise failed(exc.strerror) from exc
        return True

    def _require_private(self, path, fd):
        """Refuse to go on if others can reach ``fd`` through its mode or an ACL."""
        if stat.S_IMODE(os.fstat(fd).st_mode) & 0o077 or self._acl_may_grant_access(fd):
            raise errors.GimmeAWSCredsError(
                'Refusing to write configuration file {}: its staging area became accessible '
                'to other users'.format(path))

    @staticmethod
    def _discard_new_staging_directory(entry, dir_fd, fd):
        """Best-effort removal of a staging directory that was never used."""
        try:
            current = os.lstat(entry, dir_fd=dir_fd)
            if fd is not None:
                pinned = os.fstat(fd)
                ours = (current.st_dev, current.st_ino) == (pinned.st_dev, pinned.st_ino)
            elif os.name != 'nt':
                ours = stat.S_ISDIR(current.st_mode) and current.st_uid == os.geteuid()
            else:
                ours = stat.S_ISDIR(current.st_mode)
            if ours:
                os.rmdir(entry, dir_fd=dir_fd)
        except OSError:
            pass
        finally:
            if fd is not None:
                os.close(fd)

    def _remove_staging_directory(self, directory, stage_name, stage):
        """Remove the staging directory if its name still refers to it."""
        _, stage_fd = stage
        entry, dir_fd = self._at(directory, stage_name)
        try:
            if stage_fd is None or self._is_same_file(entry, dir_fd, os.fstat(stage_fd)):
                os.rmdir(entry, dir_fd=dir_fd)
        except OSError:
            pass
        finally:
            if stage_fd is not None:
                os.close(stage_fd)

    def _publish_staged(self, path, directory, name, stage, existing, mode, data, posix, opened):
        """Write the staged file and rename it over the destination."""
        temp_entry, temp_dir_fd = self._at(stage, self._STAGED_FILE_NAME)
        target_entry, target_dir_fd = self._at(directory, name)
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
        handle = os.fdopen(os.open(temp_entry, flags, self._CONFIG_FILE_MODE, dir_fd=temp_dir_fd), 'w')
        written = os.fstat(handle.fileno())
        committed = False
        try:
            if posix:
                if existing is not None:
                    self._preserve_ownership(handle.fileno(), existing, path)
                # Apply the mode explicitly: open() is subject to umask.
                os.fchmod(handle.fileno(), mode)
                # Nothing is written until the file is known to be private.
                self._require_private(path, handle.fileno())
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            if not posix:
                # Windows does not allow renaming this file while it is open.
                handle.close()
            # Only the same user or root can reach inside the staging directory,
            # whose inherited ACL was removed; this catches such a change made
            # before the rename, not during it.
            if posix:
                self._require_private(path, temp_dir_fd)
                self._require_private(path, handle.fileno())
            if posix and not self._is_same_file(temp_entry, temp_dir_fd, written):
                raise errors.GimmeAWSCredsError(
                    'Refusing to replace configuration file {}: the temporary file was '
                    'replaced by another process'.format(path))
            os.replace(temp_entry, target_entry, src_dir_fd=temp_dir_fd, dst_dir_fd=target_dir_fd)
            committed = True
            if posix:
                self._fsync_directory(directory)
                self._verify_published(path, target_entry, target_dir_fd, written, opened)
        except BaseException:
            if not committed:
                self._remove_if_same_file(temp_entry, temp_dir_fd, written)
            raise
        finally:
            handle.close()

    @staticmethod
    def _is_same_file(entry, dir_fd, expected):
        try:
            current = os.lstat(entry, dir_fd=dir_fd)
        except OSError:
            return False
        return (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino)

    def _remove_if_same_file(self, entry, dir_fd, expected):
        """Remove the temporary file, but never an entry someone put in its place."""
        if self._is_same_file(entry, dir_fd, expected):
            try:
                os.unlink(entry, dir_fd=dir_fd)
            except OSError:
                pass

    def _verify_published(self, path, entry, dir_fd, written, opened):
        """Fail if the rename did not publish our file where ``path`` points."""
        if not self._is_same_file(entry, dir_fd, written):
            raise errors.GimmeAWSCredsError(
                'Configuration file {} was changed by another process while it was '
                'being written; check its contents'.format(path))
        for directory_path, fd in opened:
            try:
                now = os.stat(directory_path)
            except OSError:
                now = None
            pinned = os.fstat(fd)
            if now is None or (now.st_dev, now.st_ino) != (pinned.st_dev, pinned.st_ino):
                raise errors.GimmeAWSCredsError(
                    'Configuration directory {} was moved or replaced while {} was being '
                    'written; the new configuration is in the original directory'.format(
                        directory_path, path))

    @staticmethod
    def _preserve_ownership(fd, existing, target):
        """Give the replacement file the owner and group of the original."""
        created = os.fstat(fd)
        if (created.st_uid, created.st_gid) == (existing.st_uid, existing.st_gid):
            return
        try:
            os.fchown(fd, existing.st_uid, existing.st_gid)
        except PermissionError as exc:
            if created.st_uid != existing.st_uid:
                reason = 'it is owned by another user'
            else:
                reason = 'its group (gid {}) cannot be kept'.format(existing.st_gid)
            raise errors.GimmeAWSCredsError(
                'Refusing to replace configuration file {}: {}'.format(target, reason)) from exc

    @staticmethod
    def _fsync_directory(directory):
        """Persist the rename; not every filesystem supports this."""
        directory_path, fd = directory
        if fd is not None:
            try:
                os.fsync(fd)
            except OSError:
                pass
            return
        try:
            fd = os.open(directory_path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _get_org_url_entry(self, default_entry):
        """ Get and validate okta_org_url """
        ui.default.info("Enter the Okta URL for your organization. This is https://something.okta[preview].com")
        okta_org_url_valid = False
        okta_org_url = default_entry

        while okta_org_url_valid is False:
            okta_org_url = self._get_user_input("Okta URL for your organization", default_entry).strip('/')

            # Validate that the URL given is an Okta domain and what the platform is
            url_parse_results = urlparse(okta_org_url)
            if url_parse_results.scheme == "https":
                try:
                    response = requests.get(
                        okta_org_url + '/.well-known/okta-organization',
                        headers={
                            'Accept': 'application/json',
                            'User-Agent': user_agent()
                        },
                        timeout=30
                    )

                    response_data = response.json()

                    if response.status_code == 200:
                        if response_data['pipeline'] == 'v1':
                            self._okta_platform = 'classic'
                            okta_org_url_valid = True
                            ui.default.notify("Okta Classic domain detected")
                        elif response_data['pipeline'] == 'idx':
                            self._okta_platform = 'identity_engine'
                            okta_org_url_valid = True
                            ui.default.notify("Okta Identity Engine domain detected")
                        else:
                            ui.default.error('Unknown Okta platform type: {}'.format(response_data['pipeline']))
                    else:
                        response.raise_for_status()
                except Exception as err:
                    ui.default.error('{} is not a valid Okta domain'.format(okta_org_url))
            else:
                ui.default.error("Okta organization URL must be HTTPS URL")

        self._okta_org_url = okta_org_url

        return okta_org_url

    def _get_auth_server_entry(self, default_entry):
        """ Get and validate okta_auth_server """
        ui.default.message(
            "Enter the OAuth authorization server for the gimme-creds-server. If you do not know this value, contact your Okta admin")

        okta_auth_server = self._get_user_input("Authorization server", default_entry)
        self._okta_auth_server = okta_auth_server

        return okta_auth_server
    
    def _get_enable_keychain(self, default_entry):
        """ enable the use of the system keychain to store the user's password """

        while True:
            try:
                return self._get_user_input_yes_no("Use the system keychain to store the user's password? (y/n)", default_entry)
            except ValueError:
                ui.default.warning("Enable keychain must be either y or n.")

    def _get_client_id_entry(self, default_entry):
        """ Get and validate client_id """
        ui.default.message(
            "Enter the OAuth Client ID for the gimme-aws-creds. This value is REQUIRED for Okta Identity Engine domains. If you do not know this value, contact your Okta admin")

        client_id = self._get_user_input("Client ID", default_entry)
        self._client_id = client_id

        return client_id

    def _get_appurl_entry(self, default_entry):
        """ Get and validate app_url """
        ui.default.message(
            "Enter the application link. This is {}/home/amazon_aws/<app_id>/something".format(self._okta_org_url))
        okta_app_url_valid = False
        app_url = default_entry

        while okta_app_url_valid is False:
            app_url = self._get_user_input("Application url", default_entry)
            url_parse_results = urlparse(app_url)
            okta_org_parse = urlparse(self._okta_org_url)
            if url_parse_results.scheme == "https" and url_parse_results.hostname == okta_org_parse.hostname:
                okta_app_url_valid = True
            else:
                ui.default.warning(
                    "Okta organization URL must be HTTPS URL for {}".format(self._okta_org_url))

        self._app_url = app_url

        return app_url

    def _get_gimme_creds_server_entry(self, default_entry):
        """ Get gimme_creds_server """
        ui.default.message("Enter the URL for the gimme-creds-server, 'appurl' for an Okta Application URL or 'internal' for handling Okta APIs locally.")
        gimme_creds_server_valid = False
        gimme_creds_server = default_entry

        while gimme_creds_server_valid is False:
            gimme_creds_server = self._get_user_input(
                "URL for gimme-creds-server", default_entry)
            if gimme_creds_server == "internal":
                gimme_creds_server_valid = True
            elif gimme_creds_server == "appurl":
                gimme_creds_server_valid = True
            else:
                url_parse_results = urlparse(gimme_creds_server)

                if url_parse_results.scheme == "https":
                    gimme_creds_server_valid = True
                else:
                    ui.default.warning("The gimme-creds-server must be a HTTPS URL")

        return gimme_creds_server

    def _get_write_aws_creds(self, default_entry):
        """ Option to write to the ~/.aws/credentials, ~/.aliyun/config.json, or to stdout"""

        if self.enable_alicloud:
            ui.default.message(
                "Do you want to write the temporary Alibaba Cloud credentials to ~/.aliyun/config.json?"
                "\nIf no, the credentials will be written to stdout."
                "\nPlease answer y or n.")
        else:
            ui.default.message(
                "Do you want to write the temporary AWS credentials to ~/.aws/credentials?"
                "\nIf no, the credentials will be written to stdout."
                "\nPlease answer y or n.")

        while True:
            try:
                return self._get_user_input_yes_no("Write to Credentials file", default_entry)
            except ValueError:
                ui.default.warning("Write to Credentials file must be either y or n.")

    def _get_include_path(self, default_entry):
        """ Option to include path from rolename """

        ui.default.message(
            "Do you want to include the full role path to the role name in credential profile name?"
            "\nPlease answer y or n.")

        while True:
            try:
                return self._get_user_input_yes_no("Include Path", default_entry)
            except ValueError:
                ui.default.warning("Include Path must be either y or n.")

    def _get_resolve_aws_alias(self, default_entry):
        """ Option to resolve account id to alias """
        ui.default.message(
            "Do you want to resolve account id to an alias ?"
            "\nPlease answer y or n.")
        while True:
            try:
                return self._get_user_input_yes_no("Resolve account alias", default_entry)
            except ValueError:
                ui.default.warning("Resolve account alias must be either y or n.")

    def _get_cred_profile(self, default_entry):
        """sets the aws credential profile name"""
        ui.default.message(
            "The credential profile defines which profile is used to store the temp credentials.\n"
            "If set to 'role' then a new profile will be created matching the role name assumed by the user.\n"
            "If set to 'acc' then a new profile will be created matching the account number.\n"
            "If set to 'acc-role' then a new profile will be created matching the role name assumed by the user, but prefixed with account number to avoid collisions.\n"
            "If set to 'default' then the temp creds will be stored in the default profile\n"
            "If set to any other value, the name of the profile will match that value."
        )

        cred_profile = self._get_user_input(
            "Credential Profile", default_entry)

        if cred_profile.lower() in ['default', 'role', 'acc', 'acc-role']:
            cred_profile = cred_profile.lower()

        return cred_profile

    def _get_aws_appname(self, default_entry):
        """ Get Okta App name (AWS or Alibaba Cloud) """
        ui.default.message(
            "Enter the Okta App Name (AWS or Alibaba Cloud)."
            "\nThis is optional, you can select the App when you run the CLI.")
        aws_appname = self._get_user_input("App Name", default_entry)
        return aws_appname

    def _get_aws_rolename(self, default_entry):
        """ Get the Role ARN (AWS or Alibaba Cloud)"""
        ui.default.message(
            "Enter the ARN for the role you want credentials for. 'all' will retrieve all roles."
            "\nThis is optional, you can select the role when you run the CLI.")
        aws_rolename = self._get_user_input("Role ARN", default_entry)
        return aws_rolename

    def _get_conf_profile_name(self, default_entry):
        """Get and validate configuration profile name. [Optional]"""
        ui.default.message(
            "If you'd like to assign the Okta configuration to a specific profile\n"
            "instead of to the default profile, specify the name of the profile.\n"
            "This is optional.")
        conf_profile = self._get_user_input(
            "Okta Configuration Profile Name", default_entry)
        return conf_profile

    def _get_okta_username(self, default_entry):
        """Get and validate okta username. [Optional]"""
        ui.default.message(
            "If you'd like to set your okta username in the config file, specify the username.\n"
            "This is optional.")
        okta_username = self._get_user_input(
            "Okta User Name", default_entry)
        return okta_username

    def _get_aws_default_duration(self, default_entry):
        """Get and validate the aws default session duration. [Optional]"""
        ui.default.message(
            "If you'd like to set the default session duration, specify it (in seconds).\n"
            "This is optional and defaults to 3600 seconds.")
        aws_default_duration = self._get_user_input(
            "Default Session Duration (in seconds)", default_entry)
        return aws_default_duration

    def _get_preferred_mfa_type(self, default_entry):
        """Get the user's preferred MFA device [Optional]"""
        ui.default.message(
            "If you'd like to set a preferred device type to use for MFA, enter it here.\n"
            "This is optional. valid devices types:\n"
            """
            - push - Okta Verify App push or DUO push (depends on okta supplied provider type)
            - token:software:totp - OTP using the Okta Verify App
            - token:hardware - OTP using hardware like Yubikey
            - call - OTP via Voice call
            - sms - OTP via SMS message
            - email - OTP via email message
            - web - DUO uses localhost webbrowser to support push|call|passcode
            - passcode - DUO uses `OKTA_MFA_CODE` or `--mfa-code` if set, or prompts user for passcode(OTP).
            """
        )
        okta_username = self._get_user_input(
            "Preferred MFA Device Type", default_entry)
        return okta_username

    def _get_output_format(self, default_entry):
        """Get the user's preferred output format [Optional]"""
        ui.default.message("Set the tools' output format:[export, json, windows]")
        output_format = None
        while output_format not in ('export', 'json', 'windows'):
            output_format = self._get_user_input(
                "Preferred output format", default_entry)
        return output_format

    def _get_remember_device(self, default_entry):
        """Option to remember the MFA device"""
        ui.default.message(
            "Do you want the MFA device be remembered?\n"
            "Please answer y or n.")
        while True:
            try:
                return self._get_user_input_yes_no(
                    "Remember device", default_entry)
            except ValueError:
                ui.default.warning("Remember the MFA device must be either y or n.")

    def _get_force_classic(self, default_entry):
        """Option to force the Okta Classic login process"""
        ui.default.message(
            "Do you want to force the Okta Classic login flow? (Okta Identity Engine domains only)\n"
            "Please answer y or n.")
        while True:
            try:
                return self._get_user_input_yes_no(
                    "Force classic login flow", default_entry)
            except ValueError:
                ui.default.warning("Force Classic login flow must be either y or n.")

    def _get_open_browser(self, default_entry):
        """Option to automatically open the default browser for OIE authentication"""
        ui.default.message(
            "Do you want to automatically open the default browser for authentication? (Okta Identity Engine domains only)\n"
            "Please answer y or n.")
        while True:
            try:
                return self._get_user_input_yes_no(
                    "Open default browser automatically", default_entry)
            except ValueError:
                ui.default.warning("Open browser must be either y or n.")

    def _get_enable_alicloud(self, default_entry):
        """Option to request interclient_access scope for Alibaba Cloud SSO (OIE only)."""
        ui.default.message(
            "Enable Alibaba Cloud support? This profile will be used to authenticate with Alibaba Cloud instead of AWS."
            "\nPlease answer y or n.")
        while True:
            try:
                return self._get_user_input_yes_no(
                    "Enable Alibaba Cloud support", default_entry)
            except ValueError:
                ui.default.warning("Enable Alibaba Cloud must be either y or n.")

    def _get_alicloud_saml_url(self, default_entry):
        """Get the Alibaba Cloud SAML SSO URL"""
        ui.default.message(
            "Enter the Alibaba Cloud SAML SSO URL."
            "\nContact your Okta admin to get the SAML SSO URL.")
        alicloud_saml_url = self._get_user_input("Alibaba Cloud SAML SSO URL", default_entry)
        return alicloud_saml_url

    def _get_alicloud_region(self, default_entry):
        """Get the Alibaba Cloud STS region used for AssumeRoleWithSAML."""
        ui.default.message(
            "Enter the Alibaba Cloud STS region used for AssumeRoleWithSAML "
            "(e.g. cn-hangzhou, ap-southeast-1).")
        if not default_entry:
            default_entry = 'cn-hangzhou'
        alicloud_region = self._get_user_input("Alibaba Cloud STS region", default_entry)
        return alicloud_region

    def _get_user_input(self, message, default=None):
        """formats message to include default and then prompts user for input
        via keyboard with message. Returns user's input or if user doesn't
        enter input will return the default."""
        if default and default != '':
            prompt_message = message + " [{}]: ".format(default)
        else:
            prompt_message = message + ': '

        # print the prompt with print() rather than input() as input prompts on stderr
        user_input = self.ui.input(prompt_message)
        if user_input:
            return user_input
        return default

    def _get_user_input_yes_no(self, message, default=None):
        """works like _get_user_input, but either: return bool or
        raises ValueError"""
        if isinstance(default, str):
            default = default.lower()

        if default in ('y', 'true', True):
            default = 'y'
        else:
            default = 'n'

        answer = self._get_user_input(message, default=default)
        answer = answer.lower()

        if answer == 'y':
            return True
        if answer == 'n':
            return False

        raise ValueError('Invalid answer: %s' % answer)

    def log_resolved_configuration(self, conf_dict, env_overrides_applied=None,
                                   cli_overrides_applied=None):
        """Emit the resolved configuration (and how each value was determined)
        via the debug logger. Intended to be called when --debug is enabled.

        :param conf_dict: the merged profile config dictionary used at runtime
        :param env_overrides_applied: dict of {conf_key: env_var_name} for env
            variables that overrode profile values (from main.py envvar_list)
        :param cli_overrides_applied: dict of {conf_key: cli_flag_name} for
            CLI flags that overrode profile values (e.g. --aws-cred-profile)
        """
        import logging
        from .debug_formatter import format_resolved_configuration

        logger = logging.getLogger('gimme_aws_creds')
        output = format_resolved_configuration(
            config=self,
            conf_dict=conf_dict or {},
            env_overrides_applied=env_overrides_applied or {},
            cli_overrides_applied=cli_overrides_applied or {},
        )
        logger.debug(output)

    def clean_up(self):
        """ clean up secret stuff"""
        del self.username
        del self.api_key

    def fail_if_profile_not_found(self, profile_config, conf_profile, default_section):
        """
        When a users profile does not have a profile named 'DEFAULT' configparser fails to throw
        an exception. This will raise an exception that handles this case and provide better messaging
        to the user why the failure occurred.
        Ensure that whichever profile is set as the default exists in the end users okta config
        """
        if not profile_config and conf_profile == default_section:
            raise errors.GimmeAWSCredsError(
                'DEFAULT profile is missing! This is profile is required when not using --profile')
