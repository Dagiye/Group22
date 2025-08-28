import requests
from requests.auth import HTTPDigestAuth

class BasicDigestAuth:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def request(self, url: str):
        response = requests.get(url, auth=HTTPDigestAuth(self.username, self.password))
        return response
