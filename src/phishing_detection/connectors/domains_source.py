import requests


class OpenPhishClient:
    def __init__(self, base_url: str = "https://openphish.com"):
        self._base_url = base_url

    def get_urls(self) -> list[str]:
        response = requests.get(f"{self._base_url}/feed.txt", timeout=60)
        response.raise_for_status()

        return response.text.splitlines()
