import logging

from phishing_detection.connectors.website_status import WebsiteStatusClient
from phishing_detection.domain.models import (
    IDetectionMechanism,
    WebsitePhishingReport,
    WebsiteStatusPolicy,
    WebsiteStatusReport,
)

logger = logging.getLogger(__name__)


async def check_phishing(
    url: str,
    detection_mechanisms: list[IDetectionMechanism],
) -> WebsitePhishingReport:
    report = WebsitePhishingReport(url=url, status_by_mechanism={})

    for detection_mechanism in detection_mechanisms:
        result = await detection_mechanism.check_url(url)
        logger.info(
            f"Detection mechanism: {detection_mechanism.name}. "
            f"URL: {url} - Is phishing: {result}"
        )
        report.status_by_mechanism[detection_mechanism.name] = result

    return report


async def check_website_status(
    url: str,
    client: WebsiteStatusClient,
) -> WebsiteStatusReport:
    response = await client.get_status(url)

    return WebsiteStatusReport(url=url, is_up=WebsiteStatusPolicy.is_up(response))
