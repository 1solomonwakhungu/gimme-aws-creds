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
import logging
import math
import reprlib
import time
import webbrowser
from urllib.parse import parse_qs
import jwt
import requests

from . import errors
from .common import user_agent, parse_saml_form, create_http_session, OktaHttpMixin, okta_token_exchange

logger = logging.getLogger(__name__)


class DeviceAuthorizationSlowDown(requests.exceptions.HTTPError):
    """The token endpoint answered ``slow_down`` (RFC 8628 section 3.5).

    This subclasses HTTPError because a ``slow_down`` response used to surface
    as an HTTPError, so existing handlers keep catching it.
    """


class _DeviceTokenAdapter(requests.adapters.BaseAdapter):
    """Let the polling loop own retries without changing other token grants."""

    def __init__(self, default_adapter):
        self._default_adapter = default_adapter
        self._polling_adapter = requests.adapters.HTTPAdapter(max_retries=0)

    def send(self, request, **kwargs):
        adapter = self._default_adapter
        content_type = request.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
        if request.method == 'POST' and content_type == 'application/x-www-form-urlencoded':
            try:
                body = request.body.decode('ascii') if isinstance(request.body, bytes) else request.body
                fields = parse_qs(body) if isinstance(body, str) else {}
            except (UnicodeError, ValueError):
                fields = {}
            if fields.get('grant_type') == ['urn:ietf:params:oauth:grant-type:device_code']:
                adapter = self._polling_adapter
        return adapter.send(request, **kwargs)

    def close(self):
        # The session still owns the default adapter under its original prefix.
        self._polling_adapter.close()


def _positive_seconds(value):
    """Return ``value`` as a finite, positive number of seconds, or None.

    Accepts numbers and numeric strings. Rejects booleans, other types, NaN,
    infinities, zero and negative values.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return None
    elif not isinstance(value, (int, float)):
        return None
    try:
        seconds = float(value)
    except OverflowError:
        return None
    if not math.isfinite(seconds) or seconds <= 0:
        return None
    return value


def _format_seconds(seconds):
    seconds = float(seconds)
    return str(int(seconds)) if seconds.is_integer() else str(seconds)


class OktaIdentityEngine(OktaHttpMixin):
    """
       The Okta Client Class performs the necessary API
       calls to an Okta Identity Engine domain to get temporary AWS credentials.
    """

    HTTP_TIMEOUT = 30  # Timeout in seconds for HTTP requests
    DEVICE_FLOW_TIMEOUT = 120  # Overall limit in seconds for device authorization polling
    DEVICE_FLOW_DEFAULT_INTERVAL = 5  # RFC 8628 section 3.2: polling interval when the server sends none
    DEVICE_FLOW_SLOW_DOWN_INCREMENT = 5  # RFC 8628 section 3.5: seconds added to the interval per slow_down

    def __init__(self, gac_ui, okta_org_url, client_id, verify_ssl_certs=True, device_token=None, device_flow_timeout=None, debug=False, device_flow_scope='openid okta.apps.sso'):
        """
        :type gac_ui: ui.UserInterface
        :param okta_org_url: Base URL string for Okta IDP.
        :param client_id: Client ID that will be used for user auth
        :param verify_ssl_certs: Enable/disable SSL verification
        :param device_flow_timeout: Overall limit in seconds for device authorization polling (default: 120)
        :param device_flow_scope: OAuth scope for device authorization (default: Web SSO / AWS flow)
        :param debug: Enable debug logging for API requests/responses
        """
        self.ui = gac_ui
        self._okta_org_url = okta_org_url
        self._client_id = client_id
        self._verify_ssl_certs = verify_ssl_certs
        self._debug = debug
        self._device_flow_scope = device_flow_scope
        
        self._use_oauth_access_token = False
        self._use_oauth_id_token = False
        self._oauth_access_token = None
        self._oauth_id_token = None
        if device_flow_timeout is None:
            device_flow_timeout = self.DEVICE_FLOW_TIMEOUT
        self._device_flow_timeout = _positive_seconds(device_flow_timeout)
        if self._device_flow_timeout is None:
            raise errors.GimmeAWSCredsError(
                "device_flow_timeout must be a positive number of seconds, got {}".format(
                    reprlib.repr(device_flow_timeout)), 2)

        self._http_client = create_http_session(
            verify_ssl=verify_ssl_certs, debug=debug)
        self._http_client.cookies = requests.cookies.RequestsCookieJar()
        token_url = self._okta_org_url + '/oauth2/v1/token'
        self._http_client.mount(
            token_url, _DeviceTokenAdapter(self._http_client.get_adapter(token_url)))
    
    def use_oauth_access_token(self, val=True):
        self._use_oauth_access_token = val

    def use_oauth_id_token(self, val=True):
        self._use_oauth_id_token = val

    def auth_session(self, **kwargs):
        """ Authenticate the user and return the Okta Identity and access token"""
        login_response = self._start_device_flow()
        # The polling deadline is measured from receipt of the device authorization response.
        authorization_received_at = self._monotonic()

        # Safe access to nested response data
        if 'apiResponse' not in login_response or 'verification_uri_complete' not in login_response['apiResponse']:
            raise errors.GimmeAWSCredsError("Invalid response from device authorization flow", 2)
        
        if 'open_browser' not in kwargs:
            open_browser = False
        else:
            open_browser = kwargs['open_browser']

        if open_browser:
            self.ui.info("The system web browser will open the following URL to begin Okta device authorization:")
            webbrowser.open(login_response['apiResponse']['verification_uri_complete'])
        else:
            self.ui.info("Open the following URL to begin Okta device authorization:")
        self.ui.info("")
        self.ui.info(login_response['apiResponse']['verification_uri_complete'])
        self.ui.info("")

        if 'device_code' not in login_response['apiResponse']:
            raise errors.GimmeAWSCredsError("Device code missing from authorization response", 2)
        
        interval, expires_in = self._device_flow_timing(login_response['apiResponse'])
        token_response = self._poll_for_user_tokens(
            login_response['apiResponse']['device_code'], interval, expires_in, authorization_received_at)

        # Safe access to token response fields
        if 'access_token' not in token_response:
            raise errors.GimmeAWSCredsError("Access token missing from token response", 2)
            
        at_data = jwt.decode(token_response['access_token'], options={"verify_signature": False})
        
        return {
            'username': at_data['sub'],
            'access_token': token_response['access_token'],
            'id_token': token_response.get('id_token', ''),
            'scope': token_response.get('scope', '')
        }

    def _start_device_flow(self):
        response = self._http_client.post(
            self._okta_org_url + '/oauth2/v1/device/authorize',
            headers=self._get_headers(),
            data={'scope': self._device_flow_scope, 'client_id': self._client_id },
            verify=self._verify_ssl_certs,
            timeout=self.HTTP_TIMEOUT
        )

        # Safe JSON parsing with error handling
        try:
            response_data = response.json()
        except ValueError as e:
            raise errors.GimmeAWSCredsError(
                "Invalid JSON response from device authorization endpoint: {}".format(str(e)), 2)

        if response.status_code == 200:
            func_result = {'apiResponse': response_data}
            return func_result
        elif response.status_code == 401:
            raise errors.GimmeAWSCredsError(
                f"LOGIN ERROR: The client_id ({self._client_id}) is not authorized to use the Device Authorization flow.\n"
                "Do you want to try classic mode? Run with --force-classic", 2)
        else:
            response.raise_for_status()
    
    def _device_flow_timing(self, device_response):
        """Read the polling interval and device code lifetime from a device authorization response.

        Returns ``(interval, expires_in)``. A missing interval uses the RFC 8628 default of
        five seconds; an invalid one uses the default and prints a warning. A missing or
        invalid ``expires_in`` returns None, which leaves the configured timeout in charge.
        """
        raw_interval = device_response.get('interval')
        interval = _positive_seconds(raw_interval)
        if interval is None:
            if raw_interval is not None:
                self.ui.warning(
                    "Ignoring invalid device authorization interval {} from Okta; "
                    "waiting {} seconds between token requests".format(
                        reprlib.repr(raw_interval), self.DEVICE_FLOW_DEFAULT_INTERVAL))
            interval = self.DEVICE_FLOW_DEFAULT_INTERVAL

        raw_expires_in = device_response.get('expires_in')
        expires_in = _positive_seconds(raw_expires_in)
        if expires_in is None and raw_expires_in is not None:
            self.ui.warning(
                "Ignoring invalid device code lifetime (expires_in) {} from Okta; "
                "using the {} second device authorization timeout".format(
                    reprlib.repr(raw_expires_in), _format_seconds(self._device_flow_timeout)))
        return interval, expires_in

    def _poll_for_user_tokens(self, device_code, interval, expires_in, started_at):
        """Poll the token endpoint until device authorization finishes (RFC 8628 section 3.5).

        The first token request is sent immediately. Each later request waits at least
        ``interval`` seconds after the previous response. A ``slow_down`` response adds
        five seconds to the interval and a request timeout doubles it; both changes last
        for the rest of the flow. Terminal OAuth errors such as ``access_denied``,
        ``expired_token`` and ``invalid_client`` end polling immediately.

        Polling stops at the earlier of the configured timeout and the server's
        ``expires_in``, both counted on a monotonic clock from ``started_at``. Time spent
        waiting for HTTP responses counts toward that limit. No request starts at or
        after the deadline, and each request's timeout is capped at the time remaining.
        requests applies that timeout to connecting and to each socket read, not to the
        whole response or DNS resolution. An in-flight request can exceed the deadline;
        a token it returns is still used.
        """
        limited_by_expiry = expires_in is not None and expires_in < self._device_flow_timeout
        budget = expires_in if limited_by_expiry else self._device_flow_timeout
        deadline = started_at + budget
        next_poll_at = started_at

        while True:
            now = self._monotonic()
            if next_poll_at > now:
                if next_poll_at >= deadline:
                    break
                self._sleep(next_poll_at - now)
                now = self._monotonic()
            remaining = deadline - now
            if remaining <= 0:
                break

            try:
                token_response = self._get_user_tokens(device_code, timeout=min(self.HTTP_TIMEOUT, remaining))
            except DeviceAuthorizationSlowDown:
                interval += self.DEVICE_FLOW_SLOW_DOWN_INCREMENT
                logger.debug("Token endpoint returned slow_down; polling interval is now %s seconds", interval)
            except requests.exceptions.Timeout:
                interval *= 2
                logger.debug("Token request timed out; polling interval is now %s seconds", interval)
            else:
                if token_response is not None:
                    return token_response
            next_poll_at = self._monotonic() + interval

        if limited_by_expiry:
            raise errors.GimmeAWSCredsError(
                "The device code expired after {} seconds before authorization was completed. "
                "Run the command again to get a new code".format(_format_seconds(budget)), 2)
        raise errors.GimmeAWSCredsError(
            "Timeout waiting for device authorization ({} seconds)".format(_format_seconds(budget)), 2)

    def _get_user_tokens(self, device_code, timeout=None):
        """Send one device flow token request.

        Returns the token response on success and None while authorization is pending.
        Raises DeviceAuthorizationSlowDown (an HTTPError) when the server asks the client
        to poll less often, GimmeAWSCredsError for other OAuth errors such as
        ``access_denied``, ``expired_token`` or ``invalid_client``, and HTTPError for
        other HTTP failures. ``timeout`` defaults to HTTP_TIMEOUT.
        """
        response = self._http_client.post(
            self._okta_org_url + '/oauth2/v1/token',
            headers=self._get_headers(),
            data={'client_id':self._client_id, 'device_code': device_code, 'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'},
            verify=self._verify_ssl_certs,
            timeout=self.HTTP_TIMEOUT if timeout is None else timeout,
            allow_redirects=False,
        )

        # Safe JSON parsing with error handling
        try:
            response_data = response.json()
        except ValueError as e:
            raise errors.GimmeAWSCredsError(
                "Invalid JSON response from token endpoint: {}".format(str(e)), 2)

        if response.status_code == 200:
            self._oauth_access_token = response_data.get('access_token')
            self._oauth_id_token = response_data.get('id_token')
            return response_data

        error = response_data.get('error') if isinstance(response_data, dict) else None
        if response.status_code == 400 and error == 'authorization_pending':
            return None
        if response.status_code == 400 and error == 'slow_down':
            raise DeviceAuthorizationSlowDown(
                "Token endpoint asked the client to slow down", response=response)
        if isinstance(error, str) and error:
            raise errors.GimmeAWSCredsError(self._device_flow_error_message(error, response_data), 2)
        response.raise_for_status()
        raise errors.GimmeAWSCredsError(
            "Unexpected HTTP {} response from token endpoint".format(response.status_code), 2)

    def _device_flow_error_message(self, error, response_data):
        if error == 'access_denied':
            message = "Device authorization was denied"
        elif error == 'expired_token':
            message = ("The device code expired before authorization was completed. "
                       "Run the command again to get a new code")
        elif error in ('invalid_client', 'unauthorized_client'):
            message = "The token endpoint rejected client_id ({}): {}".format(self._client_id, error)
        else:
            message = "Device authorization failed: {}".format(error)
        description = response_data.get('error_description')
        if isinstance(description, str) and description:
            message += " ({})".format(description)
        return message

    @staticmethod
    def _monotonic():
        return time.monotonic()

    @staticmethod
    def _sleep(seconds):
        time.sleep(seconds)

    def _web_sso_token_exchange(self, app_id, access_token, id_token):
        return okta_token_exchange(
            self._http_client, self._okta_org_url, self._client_id,
            app_id, access_token, id_token,
            requested_token_type='urn:okta:oauth:token-type:web_sso_token',
            verify_ssl=self._verify_ssl_certs, timeout=self.HTTP_TIMEOUT,
        )

    def get_saml_response(self, url, auth_session):

        # extract the ID from the app link
        app_id = url.split('/')[-2]

        web_sso_token = self._web_sso_token_exchange(app_id, auth_session['access_token'], auth_session['id_token'])

        # Get the SAML response with the Web SSO token
        response = self._http_client.get(
            '{}/login/token/sso?token={}'.format(self._okta_org_url, web_sso_token['access_token']),
            headers=self._get_headers(),
            timeout=self.HTTP_TIMEOUT
        )

        if response.status_code == 200:
            saml_response, relay_state, form_action = parse_saml_form(response.text)

            if saml_response is None:
                from bs4 import BeautifulSoup
                saml_soup = BeautifulSoup(response.text, "html.parser")
                saml_error = 'Did not receive SAML Response after successful authentication [' + url + ']'
                if saml_soup.find(class_='error-content') is not None:
                    saml_error += '\n' + saml_soup.find(class_='error-content').get_text()

                raise errors.GimmeAWSCredsError(saml_error, 2)

        else:
            response.raise_for_status()
        return {'SAMLResponse': saml_response, 'RelayState': relay_state, 'TargetUrl': form_action}

    @staticmethod
    def _get_headers():
        """sets the default headers"""
        return {
            'User-Agent': user_agent(),
            'Accept': 'application/json',
        }
