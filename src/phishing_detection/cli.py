import typer
from dotenv import load_dotenv

from phishing_detection.connectors.domains_source import OpenPhishClient

load_dotenv()

from phishing_detection import settings
from phishing_detection.connectors.virus_total import VirusTotalClient
from phishing_detection.connectors.google_safe_browsing import GoogleSafeBrowsingClientV4, GoogleSafeBrowsingClientV5
from phishing_detection.domain import services
from phishing_detection.domain.models import VirusTotalDetectionMechanism, GoogleSafeBrowsingV4DetectionMechanism, \
    GoogleSafeBrowsingV5DetectionMechanism
import logging

logging.basicConfig(format='%(levelname)s - %(name)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

app = typer.Typer()


@app.command()
def check_url(url: str):
    typer.echo(f"Checking URL: {url}...")

    report = services.check_url(
        url,
        detection_mechanisms=[
            VirusTotalDetectionMechanism(
                client=VirusTotalClient(api_key=settings.VIRUS_TOTAL_API_KEY)
            ),
            GoogleSafeBrowsingV4DetectionMechanism(
                client=GoogleSafeBrowsingClientV4(base_url=settings.SAVE_BROWSING_API_BASE_URL, api_key=settings.SAFE_BROWSING_API_KEY)
            ),
            GoogleSafeBrowsingV5DetectionMechanism(
                client=GoogleSafeBrowsingClientV5(base_url=settings.SAVE_BROWSING_API_BASE_URL, api_key=settings.SAFE_BROWSING_API_KEY)
            )
        ],
    )
    typer.echo(report)


@app.command()
def check_website_status(url: str):
    typer.echo("Checking website status...")

    is_up = services.check_website_status(url)

    if is_up:
        typer.echo("The website is up!")
    else:
        typer.echo("The website is down!")


@app.command()
def check_all_urls():
    typer.echo("Checking all URLs...")

    urls = OpenPhishClient(base_url=settings.OPEN_PHISH_BASE_URL).get_urls()

    # urls = [
    #     "https://p3650.com/", # NameResoulutionError
    #     "https://outlookoffice365.xyz/", # SSLCertVerificationError
    # ]
    for url in urls:
        is_up = services.check_website_status(url)


@app.command()
def hello():
    typer.echo("Hello World!")


if __name__ == "__main__":
    app()
