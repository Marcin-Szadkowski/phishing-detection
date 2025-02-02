import asyncio
from functools import partial
from itertools import chain, islice

import typer

from phishing_detection.connectors.domains_source import OpenPhishClient
from phishing_detection.connectors.website_status import WebsiteStatusClient

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

import logging

from phishing_detection import settings
from phishing_detection.connectors.google_safe_browsing import (
    GoogleSafeBrowsingClientV4,
    GoogleSafeBrowsingClientV5,
)
from phishing_detection.connectors.virus_total import VirusTotalClient
from phishing_detection.domain import services
from phishing_detection.domain.models import (
    GoogleSafeBrowsingV4DetectionMechanism,
    GoogleSafeBrowsingV5DetectionMechanism,
    VirusTotalDetectionMechanism,
)

logging.basicConfig(format="%(levelname)s - %(name)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

app = typer.Typer()


def batch(iterable, size):
    source_iter = iter(iterable)
    while True:
        try:
            batch_iter = islice(source_iter, size)
            yield chain([next(batch_iter)], batch_iter)
        except StopIteration:
            return


@app.command()
def check_url(url: str):
    typer.echo(f"Checking URL: {url}...")

    check_url_callable = partial(
        services.check_url,
        url,
        detection_mechanisms=[
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
        ],
    )

    report = asyncio.run(check_url_callable())
    typer.echo(report)


@app.command()
def check_website_status(url: str):
    typer.echo("Checking website status...")

    is_up = asyncio.run(
        services.check_website_status(url, client=WebsiteStatusClient())
    )

    if is_up:
        typer.echo("The website is up!")
    else:
        typer.echo("The website is down!")


@app.command()
def check_all_website_statuses():
    typer.echo("Checking all URLs...")

    async def run_multiple_tasks(tasks):
        results = await asyncio.gather(*tasks)
        return results

    urls = OpenPhishClient(base_url=settings.OPEN_PHISH_BASE_URL).get_urls()

    for batch_urls in batch(urls, 50):
        tasks = [
            services.check_website_status(url, client=WebsiteStatusClient())
            for url in batch_urls
        ]
        results = asyncio.run(run_multiple_tasks(tasks))
        typer.echo(results)


@app.command()
def hello():
    typer.echo("Hello World!")


if __name__ == "__main__":
    app()
