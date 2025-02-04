from __future__ import annotations

from logging import getLogger

import requests

from phishing_detection import settings
from phishing_detection.domain.models import DataSource

logger = getLogger(__name__)


def get_for_source(source_type: DataSource) -> OpenPhishClient | PhishStatsClient:
    if source_type is DataSource.OPEN_PHISH:
        return OpenPhishClient()
    if source_type is DataSource.PHISH_STATS:
        return PhishStatsClient()

    raise NotImplementedError(f"Client for {source_type.value} is not implemented")


class OpenPhishClient:
    def __init__(self, base_url: str = settings.OPEN_PHISH_BASE_URL):
        self._base_url = base_url

    def get_urls(self) -> list[str]:
        logger.info("Fetching URLs from OpenPhish")

        response = requests.get(f"{self._base_url}/feed.txt", timeout=60)
        response.raise_for_status()

        return response.text.splitlines()


class PhishStatsClient:
    """
    # https://phishstats.info/#apidoc

    """

    def __init__(self, base_url: str = settings.PHISH_STATS_BASE_URL):
        self._base_url = base_url

    def get_urls(self, count: int = 100) -> list[str]:
        # 100 records is the maximum allowed
        logger.info("Fetching URLs from PhishStats")

        params = {
            "_size": count,
            "_sort": "-date",
        }
        response = requests.get(f"{self._base_url}/phishing", params=params, timeout=60)
        response.raise_for_status()

        return [record["url"] for record in response.json()]
