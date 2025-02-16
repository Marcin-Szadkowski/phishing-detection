from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TypedDict


class DataSource(Enum):
    OPEN_PHISH = "OPEN_PHISH"
    PHISH_STATS = "PHISH_STATS"


class IDetectionMechanism(ABC):
    @abstractmethod
    async def check_url(self, url: str) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError


class IAnalysisReport(ABC):
    @abstractmethod
    def save_as_csv(self, path: str):
        raise NotImplementedError

    @abstractmethod
    def read_from_csv(self, path: str):
        raise NotImplementedError

    @abstractmethod
    def get_stats(self) -> dict[str, float]:
        raise NotImplementedError


@dataclass
class VirusTotalUrlReport:
    harmless: int
    malicious: int
    suspicious: int
    timeout: int
    undetected: int


class VirusTotalPhishingPolicy:
    @staticmethod
    def is_phishing(report: VirusTotalUrlReport | None) -> bool:
        # TODO this actually needs VirusTotal insights
        if report is None:
            return False

        return report.malicious >= 3


class VirusTotalDetectionMechanism(IDetectionMechanism):
    def __init__(self, client):
        self._client = client

    async def check_url(self, url: str) -> bool:
        report = await self._client.get_url_report(url)
        return VirusTotalPhishingPolicy.is_phishing(report)

    @property
    def name(self) -> str:
        return "VIRUS_TOTAL"


class GoogleSafeBrowsingV4DetectionMechanism(IDetectionMechanism):
    def __init__(self, client):
        self._client = client

    async def check_url(self, url: str) -> bool:
        response = await self._client.get_threat_matches(url)
        return response is not None

    @property
    def name(self) -> str:
        return "GOOGLE_SAFE_BROWSING_V4"


class GoogleSafeBrowsingV5DetectionMechanism(IDetectionMechanism):
    def __init__(self, client):
        self._client = client

    async def check_url(self, url: str) -> bool:
        response = await self._client.search_url(url)
        return response is not None

    @property
    def name(self) -> str:
        return "GOOGLE_SAFE_BROWSING_V5"


@dataclass(frozen=True)
class WebsiteResponse:
    class ResponseError(Enum):
        UNSPECIFIED = "UNSPECIFIED"
        CONNECTION_ERROR = "CONNECTION_ERROR"
        REDIRECTED_WITHOUT_LOCATION = "REDIRECTED_WITHOUT_LOCATION"
        REDIRECTED_WITH_LOCATION = "REDIRECTED_WITH_LOCATION"

    status_code: int | None = None
    error: ResponseError | None = None


class WebsiteStatusPolicy:
    @staticmethod
    def is_up(response: WebsiteResponse) -> bool:
        if response.error:
            # Or consider as down?
            if response.error is WebsiteResponse.ResponseError.REDIRECTED_WITH_LOCATION:
                return True
            return False
        return response.status_code == 200


@dataclass(frozen=True)
class WebsiteStatusReport:
    url: str
    is_up: bool

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "url": self.url,
            "is_up": self.is_up,
        }


@dataclass(frozen=True)
class WebsitePhishingReport:
    url: str
    status_by_mechanism: dict[str, bool]

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "url": self.url,
            **{
                mechanism: status
                for mechanism, status in self.status_by_mechanism.items()
            },
        }


class CombinedPhishingReport(TypedDict):
    detection_mechanism: str
    is_phishing: bool
