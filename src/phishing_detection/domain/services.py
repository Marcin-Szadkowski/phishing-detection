import logging
from ssl import SSLCertVerificationError

import requests
import urllib3
from urllib3.exceptions import NameResolutionError

from phishing_detection.domain.models import IDetectionMechanism

# TODO for each detection mechanism, try to detect if the URL is phishing or not

# TODO assess website status. Check if the website is up or down

# TODO analyze results for a minimum of 100 URLs. Compare Detection Mechanisms. Which one is the most effective?

logger = logging.getLogger(__name__)


def check_url(
    url: str,
    detection_mechanisms: list[IDetectionMechanism],
) -> dict[str, bool]:
    report = {}

    for detection_mechanism in detection_mechanisms:
        is_phishing = detection_mechanism.check_url(url)
        logger.info(
            f"Detection mechanism: {detection_mechanism.name} - URL: {url} - Is phishing: {is_phishing}"
        )

        report[detection_mechanism.name] = is_phishing

    return report


def check_website_status(
    url: str,
) -> bool:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        response = requests.head(url, verify=False, timeout=60)
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Error checking website {url} status: {e}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking website {url} status: {e}")
        return False
    else:
        logger.info(f"Got response from HEAD request to {url}. Response: {response.status_code}")
        if response.status_code == 302:
            new_location = response.headers["Location"]
            if new_location:
                logger.info(f"Redirected to {new_location}")
                return True

        return response.status_code == 200


if __name__ == "__main__":
    check_website_status("https://p3650.com/ ")
