import asyncio
from functools import partial
from itertools import chain, islice
from logging import getLogger
from typing import Callable, Iterable

from more_itertools import chunked

from phishing_detection import settings
from phishing_detection.connectors.domains_source import OpenPhishClient
from phishing_detection.connectors.google_safe_browsing import (
    GoogleSafeBrowsingClientV4,
    GoogleSafeBrowsingClientV5,
)
from phishing_detection.connectors.virus_total import VirusTotalClient
from phishing_detection.connectors.website_status import WebsiteStatusClient
from phishing_detection.domain import services
from phishing_detection.domain.models import (
    GoogleSafeBrowsingV4DetectionMechanism,
    GoogleSafeBrowsingV5DetectionMechanism,
    VirusTotalDetectionMechanism,
    WebsiteStatusReport,
)

logger = getLogger(__name__)


BATCH_PROCESSING_SIZE = 5


def batch(iterable, size):
    source_iter = iter(iterable)
    while True:
        try:
            batch_iter = islice(source_iter, size)
            yield chain([next(batch_iter)], batch_iter)
        except StopIteration:
            return


async def process_async(tasks: Iterable[Callable]):
    asyncio_tasks = []

    for task in tasks:
        asyncio_tasks.append(asyncio.create_task(task()))

    logger.info("Waiting for async tasks to finish...")
    results = await asyncio.gather(*asyncio_tasks)

    return results


def run_analysis_task(assess_status: bool = False, detect_phishing: bool = False):
    urls_to_check = OpenPhishClient().get_urls()[:20]

    logger.info(f"Found URLs to check. Count: {len(urls_to_check)}")

    website_statuses, phishing_statuses = [], []

    if assess_status:
        website_statuses = _assess_website_status(urls_to_check)

    if detect_phishing:
        phishing_statuses = _detect_phishing(urls_to_check)

    return website_statuses + phishing_statuses


def _assess_website_status(urls_to_check: list[str]):
    all_results: list[WebsiteStatusReport] = []

    for urls_batch in chunked(urls_to_check, BATCH_PROCESSING_SIZE):
        tasks = []
        for url in urls_batch:
            task = partial(services.check_website_status, url, WebsiteStatusClient())
            tasks.append(task)

        results = asyncio.run(process_async(tasks))
        all_results.extend(results)

    return all_results


def _detect_phishing(urls_to_check: list[str]):
    all_results = []
    detection_mechanisms = [
        VirusTotalDetectionMechanism(
            client=VirusTotalClient(api_key=settings.VIRUS_TOTAL_API_KEY)
        ),
        GoogleSafeBrowsingV4DetectionMechanism(
            client=GoogleSafeBrowsingClientV4(
                base_url=settings.SAVE_BROWSING_API_BASE_URL,
                api_key=settings.SAFE_BROWSING_API_KEY,
            )
        ),
        GoogleSafeBrowsingV5DetectionMechanism(
            client=GoogleSafeBrowsingClientV5(
                base_url=settings.SAVE_BROWSING_API_BASE_URL,
                api_key=settings.SAFE_BROWSING_API_KEY,
            )
        ),
    ]

    for urls_batch in chunked(urls_to_check, BATCH_PROCESSING_SIZE):
        tasks = []
        for url in urls_batch:
            task = partial(services.check_phishing, url, detection_mechanisms)
            tasks.append(task)

        results = asyncio.run(process_async(tasks))
        all_results.extend(results)

    return all_results
