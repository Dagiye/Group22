import requests

class GraphQLAuthScanner:
    """
    Tests GraphQL endpoints for authorization flaws,
    such as accessing restricted queries or mutations
    without proper permissions.
    """
    def __init__(self, endpoint_url: str, headers: dict = None, timeout: int = 10):
        self.endpoint_url = endpoint_url
        self.headers = headers or {}
        self.timeout = timeout

    def test_endpoint(self, query: str):
        try:
            response = requests.post(
                self.endpoint_url,
                json={"query": query},
                headers=self.headers,
                timeout=self.timeout
            )
            return {
                "query": query,
                "status_code": response.status_code,
                "response": response.text
            }
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
