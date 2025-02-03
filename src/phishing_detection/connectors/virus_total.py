from logging import getLogger

import vt

from phishing_detection import settings
from phishing_detection.domain.models import VirusTotalUrlReport

logger = getLogger(__name__)


class VirusTotalClient:
    def __init__(self, api_key: str = settings.VIRUS_TOTAL_API_KEY):
        self._api_key = api_key

    async def get_url_report(self, url: str) -> VirusTotalUrlReport | None:
        """
        https://docs.virustotal.com/reference/url-object

        """
        url_id = vt.url_id(url)

        try:
            report = await vt.Client(self._api_key).get_object_async(f"/urls/{url_id}")
        except vt.APIError:
            logger.error(
                "Error while fetching URL report from VirusTotal", exc_info=True
            )
            return None

        return VirusTotalUrlReport(
            harmless=report.last_analysis_stats["harmless"],
            malicious=report.last_analysis_stats["malicious"],
            suspicious=report.last_analysis_stats["suspicious"],
            timeout=report.last_analysis_stats["timeout"],
            undetected=report.last_analysis_stats["undetected"],
        )
