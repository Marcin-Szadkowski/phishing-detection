import logging

from phishing_detection.connectors.website_status import WebsiteStatusClient
from phishing_detection.domain.models import (
    IDetectionMechanism,
    WebsiteStatusPolicy,
)

logger = logging.getLogger(__name__)


async def check_url(
    url: str,
    detection_mechanisms: list[IDetectionMechanism],
) -> dict[str, bool]:
    report = {}

    for detection_mechanism in detection_mechanisms:
        result = await detection_mechanism.check_url(url)
        logger.info(
            f"Detection mechanism: {detection_mechanism.name}. "
            f"URL: {url} - Is phishing: {result}"
        )
        report[detection_mechanism.name] = result

    return report


async def check_website_status(
    url: str,
    client: WebsiteStatusClient,
) -> bool:
    response = await client.get_status(url)

    return WebsiteStatusPolicy.is_up(response)
