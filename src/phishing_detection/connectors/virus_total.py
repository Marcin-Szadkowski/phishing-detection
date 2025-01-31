import vt

from phishing_detection import settings


class VirusTotalClient:
    def __init__(self, api_key: str = settings.VIRUS_TOTAL_API_KEY):
        self.api_key = api_key
        self._client = vt.Client(api_key)

    def get_url_report(self, url: str):
        url_id = vt.url_id(url)
        return self._client.get_object(f"/urls/{url_id}")
