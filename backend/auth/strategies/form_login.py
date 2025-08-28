import requests

class FormLogin:
    def __init__(self, login_url: str, username_field: str, password_field: str, csrf_field: str = None):
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.csrf_field = csrf_field
        self.session = requests.Session()

    def login(self, username: str, password: str, csrf_token: str = None) -> bool:
        payload = {
            self.username_field: username,
            self.password_field: password
        }
        if self.csrf_field and csrf_token:
            payload[self.csrf_field] = csrf_token
        response = self.session.post(self.login_url, data=payload)
        return response.ok and "logout" in response.text.lower()
