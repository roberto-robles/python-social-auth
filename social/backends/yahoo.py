"""
Yahoo OpenId and OAuth1 backends, docs at:
    http://psa.matiasaguirre.net/docs/backends/yahoo.html
"""
from social.backends.open_id import OpenIdAuth
from social.backends.oauth import BaseOAuth1
from social.utils import url_add_parameters, parse_qs
import json
import time
import uuid

class YahooOpenId(OpenIdAuth):
    """Yahoo OpenID authentication backend"""
    name = 'yahoo'
    URL = 'http://me.yahoo.com'


class YahooOAuth(BaseOAuth1):
    """Yahoo OAuth authentication backend"""
    name = 'yahoo-oauth'
    ID_KEY = 'guid'
    AUTHORIZATION_URL = 'https://api.login.yahoo.com/oauth/v2/request_auth'
    REQUEST_TOKEN_URL = \
        'https://api.login.yahoo.com/oauth/v2/get_request_token'
    ACCESS_TOKEN_URL = 'https://api.login.yahoo.com/oauth/v2/get_token'
    REFRESH_TOKEN_URL = ACCESS_TOKEN_URL
    REFRESH_TOKEN_METHOD = 'GET'
    EXTRA_DATA = [
        ('guid', 'id'),
        ('access_token', 'access_token'),
        ('expires', 'expires'),
        ('refresh_token', 'refresh_token', True), # added for testing
        ('expires_in', 'expires'), #added for testing
    ]

    def get_user_details(self, response):
        """Return user details from Yahoo Profile"""
        fname = response.get('givenName')
        lname = response.get('familyName')
        emails = [email for email in response.get('emails', [])
                        if email.get('handle')]
        emails.sort(key=lambda e: e.get('primary', False))
        return {'username': response.get('nickname'),
                'email': emails[0]['handle'] if emails else '',
                'fullname': '{0} {1}'.format(fname, lname),
                'first_name': fname,
                'last_name': lname}

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = 'http://social.yahooapis.com/v1/user/{0}/profile?format=json'
        return self.get_json(
            url.format(self._get_guid(access_token)),
            auth=self.oauth_auth(access_token)
        )['profile']

    def _get_guid(self, access_token):
        """
            Beause you have to provide GUID for every API request
            it's also returned during one of OAuth calls
        """
        return self.get_json(
            'http://social.yahooapis.com/v1/me/guid?format=json',
            auth=self.oauth_auth(access_token)
        )['guid']['value']

    def refresh_token_params(self, token, *args, **kwargs):
        client_id, client_secret = self.get_key_and_secret()
        signed = self.oauth_auth(token)
        return {

            'oauth_nonce': str(uuid.uuid4()),
            'oauth_consumer_key' : client_id,
            'oauth_signature_method' : 'plaintext',
            'oauth_signature' : '%s&%s' % (client_secret, token['oauth_token_secret']),# + '%26',
            'oauth_version' : '1.0',
            'oauth_token' : token['oauth_token'],
            'oauth_timestamp': time.time() + 600,
            'oauth_session_handle': token['oauth_session_handle']
        }

    def process_refresh_token_response(self, response, *args, **kwargs):
        return  {'access_token': parse_qs(response)}

    def refresh_token(self, token, *args, **kwargs):
        params = self.refresh_token_params(token, *args, **kwargs)
        url = self.REFRESH_TOKEN_URL or self.ACCESS_TOKEN_URL
        method = self.REFRESH_TOKEN_METHOD
        key = 'params' if method == 'GET' else 'data'
        request_args = {'headers': self.auth_headers(),
                        'method': method,
                        key: params}
        request = self.request(url, **request_args)
        return process_refresh_token_response(request.content)

    def auth_headers(self):
        return {'Content-Type': 'application/json'}
