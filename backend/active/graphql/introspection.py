import requests

class GraphQLIntrospectionScanner:
    """
    Detects GraphQL endpoints and performs introspection
    to enumerate types, queries, and mutations.
    """
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            types {
                name
                kind
                fields {
                    name
                }
            }
        }
    }
    """

    def __init__(self, endpoint_url: str, timeout: int = 10):
        self.endpoint_url = endpoint_url
        self.timeout = timeout

    def scan(self):
        try:
            response = requests.post(
                self.endpoint_url,
                json={"query": self.INTROSPECTION_QUERY},
                timeout=self.timeout
            )
            if response.status_code == 200 and "__schema" in response.text:
                return {
                    "introspection": True,
                    "data": response.json()
                }
            else:
                return {"introspection": False}
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
