from rauth import OAuth1Service, OAuth2Service
from flask import current_app, url_for, request, redirect, session, json
from xml.dom.minidom import parseString


class OAuthSignIn(object):
    providers = None

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'][provider_name]
        self.consumer_id = credentials['id']
        self.consumer_secret = credentials['secret']

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('oauth_callback', provider=self.provider_name, _external=True)

    @classmethod
    def get_provider(self, provider_name):
        if self.providers is None:
            self.providers = {}
            for provider_class in self.__subclasses__():
                provider = provider_class()
                self.providers[provider.provider_name] = provider
        return self.providers[provider_name]


class FacebookSignIn(OAuthSignIn):
    def __init__(self):
        super(FacebookSignIn, self).__init__('facebook')
        self.service = OAuth2Service(
            name='facebook',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://graph.facebook.com/v2.8/oauth/authorize',
            access_token_url='https://graph.facebook.com/v2.8/oauth/access_token',
            base_url='https://graph.facebook.com/v2.8/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='email',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()},
            decoder=json.loads
        )
        me = oauth_session.get('me?fields=id,email,name').json()
        # Can get various picture sizes by passing type of large, small, normal or square - square is the default
        social_id = '{}${}'.format(self.service.name, me['id'])
        name = me['name']
        email = me['email']
        profile_image_url = self.service.base_url + "/{}/picture?type=square".format(me['id'])
        return social_id, name, email, profile_image_url


class TwitterSignIn(OAuthSignIn):
    def __init__(self):
        super(TwitterSignIn, self).__init__('twitter')
        self.service = OAuth1Service(
            name='twitter',
            consumer_key=self.consumer_id,
            consumer_secret=self.consumer_secret,
            request_token_url='https://api.twitter.com/oauth/request_token',
            authorize_url='https://api.twitter.com/oauth/authorize',
            access_token_url='https://api.twitter.com/oauth/access_token',
            base_url='https://api.twitter.com/1.1/'
        )

    def authorize(self):
        request_token = self.service.get_request_token(
            params={'oauth_callback': self.get_callback_url()}
        )
        session['request_token'] = request_token
        return redirect(self.service.get_authorize_url(request_token[0]))

    def callback(self):
        request_token = session.pop('request_token')
        if 'oauth_verifier' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            request_token[0],
            request_token[1],
            data={'oauth_verifier': request.args['oauth_verifier']}
        )
        me = oauth_session.get('account/verify_credentials.json').json()
        social_id = '{}${}'.format(self.service.name, me['id'])
        name = me['screen_name']
        email = None # Twitter does not provide email
        profile_image_url = me['profile_image_url']
        return social_id, name, email, profile_image_url  


class GoogleSignIn(OAuthSignIn):
    # https://accounts.google.com/.well-known/openid-configuration
    def __init__(self):
        super(GoogleSignIn, self).__init__('google')
        self.service = OAuth2Service(
            name='google',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
            access_token_url='https://www.googleapis.com/oauth2/v4/token',
            base_url='https://www.googleapis.com/oauth2/v3/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='email',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()},
            decoder=json.loads
        )
        me = oauth_session.get('userinfo').json()
        social_id = '{}${}'.format(self.service.name, me['sub'])
        name = me['name']
        email = me['email']
        profile_image_url = me['picture']
        return social_id, name, email, profile_image_url


class LinkedInSignIn(OAuthSignIn):
    # https://accounts.google.com/.well-known/openid-configuration
    def __init__(self):
        super(LinkedInSignIn, self).__init__('linkedin')
        self.service = OAuth2Service(
            name='linkedin',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://www.linkedin.com/oauth/v2/authorization',
            access_token_url='https://www.linkedin.com/oauth/v2/accessToken',
            base_url='https://api.linkedin.com/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='r_basicprofile r_emailaddress',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()},
            decoder=json.loads
        )
        
        me = parseString(oauth_session.get('v1/people/~:(id,first-name,last-name,picture-url,email-address)').text)
        social_id = '{}${}'.format(self.service.name, me.getElementsByTagName("id")[0].lastChild.data)
        name = '{} {}'.format(me.getElementsByTagName("first-name")[0].lastChild.data,
                              me.getElementsByTagName("last-name")[0].lastChild.data)
        email = me.getElementsByTagName("email-address")[0].lastChild.data
        profile_image_url = me.getElementsByTagName("picture-url")[0].lastChild.data
        return social_id, name, email, profile_image_url
