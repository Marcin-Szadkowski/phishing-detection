from logging import getLogger

import pandas as pd

from phishing_detection.domain.models import IAnalysisReport

logger = getLogger(__name__)


class AnalysisReport(IAnalysisReport):
    def __init__(self, urls: list):
        self._report = pd.DataFrame([{"url": url} for url in urls])

    def merge_results(self, objects: list) -> None:
        new_data = pd.DataFrame([obj.to_dict() for obj in objects])

        self._report = pd.merge(self._report, new_data, on="url", how="left")

    def read_from_csv(self, path: str) -> None:
        self._report = pd.read_csv(path)

    def save_as_csv(self, path: str) -> None:
        logger.info(f"Saving report to {path}")
        self._report.to_csv(path, index=False)

    def get_stats(self) -> dict[str, int]:
        return self._report.mean(numeric_only=True).to_dict()
