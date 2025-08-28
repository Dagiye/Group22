from authlib.integrations.requests_client import OAuth2Session

class OIDCAuth:
    def __init__(self, client_id: str, client_secret: str, authorize_url: str, token_url: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = OAuth2Session(client_id, client_secret, redirect_uri=redirect_uri)
        self.authorize_url = authorize_url
        self.token_url = token_url

    def fetch_token(self, code: str):
        return self.session.fetch_token(self.token_url, code=code)
