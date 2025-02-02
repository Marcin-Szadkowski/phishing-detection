from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TypedDict

# class DetectionMechanismTypes(Enum):
#     VIRUS_TOTAL = "VIRUS_TOTAL"
#     GOOGLE_SAFE_BROWSING_API = "GOOGLE_SAFE_BROWSING_API"


class IDetectionMechanism(ABC):
    @abstractmethod
    def check_url(self, url: str) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
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
    def is_phishing(report: VirusTotalUrlReport) -> bool:
        return report.malicious >= 3


class VirusTotalDetectionMechanism(IDetectionMechanism):
    def __init__(self, client):
        self._client = client

    def check_url(self, url: str) -> bool:
        report = self._client.get_url_report(url)
        return VirusTotalPhishingPolicy.is_phishing(report)

    @property
    def name(self) -> str:
        return "VIRUS_TOTAL"


class GoogleSafeBrowsingV4DetectionMechanism(IDetectionMechanism):
    def __init__(self, client):
        self._client = client

    def check_url(self, url: str) -> bool:
        response = self._client.get_threat_matches(url)
        return response is not None

    @property
    def name(self) -> str:
        return "GOOGLE_SAFE_BROWSING_V4"


class GoogleSafeBrowsingV5DetectionMechanism(IDetectionMechanism):
    def __init__(self, client):
        self._client = client

    def check_url(self, url: str) -> bool:
        response = self._client.search_url(url)
        return response is not None

    @property
    def name(self) -> str:
        return "GOOGLE_SAFE_BROWSING_V5"

class CombinedPhishingReport(TypedDict):
    detection_mechanism: str
    is_phishing: bool
