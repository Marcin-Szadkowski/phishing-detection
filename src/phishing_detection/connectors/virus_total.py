import vt

from phishing_detection import settings
from phishing_detection.domain.models import VirusTotalUrlReport


class VirusTotalClient:
    def __init__(self, api_key: str = settings.VIRUS_TOTAL_API_KEY):
        self.api_key = api_key
        self._client = vt.Client(api_key)

    def get_url_report(self, url: str) -> VirusTotalUrlReport:
        """
        https://docs.virustotal.com/reference/url-object

        """
        url_id = vt.url_id(url)

        report = self._client.get_object(f"/urls/{url_id}")

        return VirusTotalUrlReport(
            harmless=report.last_analysis_stats["harmless"],
            malicious=report.last_analysis_stats["malicious"],
            suspicious=report.last_analysis_stats["suspicious"],
            timeout=report.last_analysis_stats["timeout"],
            undetected=report.last_analysis_stats["undetected"],
        )
