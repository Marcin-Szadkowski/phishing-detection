import ssl
from logging import getLogger

import aiohttp

from phishing_detection.domain.models import WebsiteResponse

logger = getLogger(__name__)


class WebsiteStatusClient:
    @staticmethod
    async def get_status(url: str) -> WebsiteResponse:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, ssl=ssl_context, timeout=60) as response:
                    logger.info(
                        f"Got response from HEAD request to {url}. "
                        f"Response: {response.status}"
                    )

                    if response.status == 302:
                        new_location = response.headers.get("Location")
                        if new_location:
                            logger.info(f"Redirected to {new_location}")
                            return WebsiteResponse(
                                status_code=response.status,
                                error=WebsiteResponse.ResponseError.REDIRECTED_WITH_LOCATION,  # noqa
                            )
                        else:
                            return WebsiteResponse(
                                status_code=response.status,
                                error=WebsiteResponse.ResponseError.REDIRECTED_WITHOUT_LOCATION,  # noqa
                            )

                    return WebsiteResponse(status_code=response.status, error=None)

        except aiohttp.ClientConnectionError as e:
            logger.error(f"Error checking website {url} status: {e}")
            return WebsiteResponse(
                status_code=None,
                error=WebsiteResponse.ResponseError.CONNECTION_ERROR,
            )
        except aiohttp.ClientError as e:
            logger.error(f"Error checking website {url} status: {e}")
            return WebsiteResponse(
                status_code=None,
                error=WebsiteResponse.ResponseError.UNSPECIFIED,
            )
