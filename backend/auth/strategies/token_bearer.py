import requests

class BearerTokenAuth:
    def __init__(self, token: str):
        self.token = token

    def request(self, url: str, method: str = "GET"):
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.request(method, url, headers=headers)
        return response
