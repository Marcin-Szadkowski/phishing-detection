import asyncio
from functools import partial

import typer

from phishing_detection.connectors.website_status import WebsiteStatusClient

try:
    from dotenv import load_dotenv  # type: ignore

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
    DataSource,
    GoogleSafeBrowsingV4DetectionMechanism,
    GoogleSafeBrowsingV5DetectionMechanism,
    VirusTotalDetectionMechanism,
)
from phishing_detection.tasks import run_analysis_task

logging.basicConfig(format="%(levelname)s - %(name)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

app = typer.Typer()


@app.command()
def check_phishing(url: str):
    typer.echo(f"Checking URL: {url}...")

    check_url_callable = partial(
        services.check_phishing,
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
def run_analysis(
    output_path: str = typer.Argument(
        default="analysis_report.csv", help="Pass .csv format"
    ),
    data_source: str = typer.Argument(
        default="OPEN_PHISH", help="Data source: OPEN_PHISH or PHISH_STATS"
    ),
    assess_status: bool = False,
    check_phishing: bool = False,
):
    try:
        DataSource(data_source)
    except ValueError:
        typer.echo("Invalid data source")
        raise typer.Exit(code=1)

    report = run_analysis_task(DataSource(data_source), assess_status, check_phishing)

    report.save_as_csv(output_path)

    typer.echo(report.get_stats())


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


if __name__ == "__main__":
    app()
