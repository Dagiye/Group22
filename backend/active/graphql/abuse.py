import requests

class GraphQLAbuseScanner:
    """
    Attempts to abuse GraphQL endpoints, such as
    expensive queries (DoS), enumeration of sensitive data,
    or mass data extraction.
    """
    def __init__(self, endpoint_url: str, timeout: int = 10):
        self.endpoint_url = endpoint_url
        self.timeout = timeout

    def expensive_query(self, query: str):
        try:
            response = requests.post(
                self.endpoint_url,
                json={"query": query},
                timeout=self.timeout
            )
            return {
                "query": query,
                "status_code": response.status_code,
                "response": response.text
            }
        except requests.exceptions.RequestException as e:
            return {"error": str(e)}
