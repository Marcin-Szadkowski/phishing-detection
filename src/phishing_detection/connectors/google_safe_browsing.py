import base64
import hashlib
import ipaddress
import re
import time
import urllib.parse

import aiohttp
import idna
from charset_normalizer.md import getLogger
from google.protobuf.json_format import MessageToDict
from playwright.sync_api import sync_playwright

from phishing_detection import settings
from phishing_detection.connectors import safe_browsing_response_pb2

logger = getLogger(__name__)


def canonical_form(url: str) -> str:
    """
    Canonicalizes a given URL according to Google Safe Browsing rules.
    """
    parsed_url = urllib.parse.urlparse(url)
    path = parsed_url.path if parsed_url.path else "/"

    url = re.sub(r"[\t\r\n]", "", url)

    url = url.split("#")[0]

    while "%" in url:
        url = urllib.parse.unquote(url)

    hostname = parsed_url.hostname or ""

    try:
        hostname = idna.encode(hostname).decode()
    except idna.IDNAError:
        # If conversion fails, keep original hostname
        pass

    # Normalize hostname
    hostname = hostname.lower()
    hostname = re.sub(r"\.+", ".", hostname).strip(".")

    try:
        ip = ipaddress.ip_address(hostname)
        if isinstance(ip, ipaddress.IPv4Address):
            hostname = ip.exploded
        elif isinstance(ip, ipaddress.IPv6Address):
            hostname = ip.compressed
            if hostname.startswith("::ffff:") or hostname.startswith("64:ff9b::"):
                hostname = str(ip.ipv4_mapped) if ip.ipv4_mapped else hostname
    except ValueError:
        # Not an IP, leave hostname as is
        pass

    path = re.sub(r"/\./", "/", path)
    while "/../" in path:
        path = re.sub(r"/[^/]+/\.\./", "/", path)
    path = re.sub(r"/+", "/", path)

    canonical_url = f"{hostname}{path}"

    def percent_escape(match):
        return f"%{ord(match.group(0)):02X}"

    canonical_url = re.sub(r"[\x00-\x20\x7F-\xFF#%]", percent_escape, canonical_url)

    return canonical_url


def full_hash(url: str) -> bytes:
    canonical_url = canonical_form(url)
    sha256_hash = hashlib.sha256(canonical_url.encode("utf-8"))
    return sha256_hash.digest()


def encode_to_base64(hash_value: bytes) -> str:
    # google expects not urlsafe encoding
    return base64.b64encode(hash_value).decode("utf-8")


def open_chrome_with_protection_mode(url: str, enhanced: bool = False):
    with sync_playwright() as p:
        args = []
        # This works
        # the option is set but actually it doesn't work
        args.append("--no-sandbox")

        if enhanced:
            args.append("--safebrowsing-enable-enhanced-protection")

        browser = p.chromium.launch(headless=False, args=args, channel="chrome")

        context = browser.new_context()

        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded")

        time.sleep(10000)


class PlatformType:
    PLATFORM_TYPE_UNSPECIFIED = "PLATFORM_TYPE_UNSPECIFIED"
    WINDOWS = "WINDOWS"
    LINUX = "LINUX"
    ANDROID = "ANDROID"
    OSX = "OSX"
    IOS = "IOS"
    ANY_PLATFORM = "ANY_PLATFORM"
    ALL_PLATFORMS = "ALL_PLATFORMS"
    CHROME = "CHROME"


class ThreatType:
    """
    https://developers.google.com/safe-browsing/reference/rest/v4/ThreatType
    """

    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"


class GoogleSafeBrowsingClientV4:
    def __init__(
        self,
        base_url: str = settings.SAVE_BROWSING_API_BASE_URL,
        api_key: str = settings.SAFE_BROWSING_API_KEY,
    ):
        self._base_url = f"{base_url}/v4"
        self._api_key = api_key

    async def get_threat_matches(self, url: str):
        body = {
            "client": {
                "clientId": "phishing_detection_v1",
                "clientVersion": "1.5.2",
            },
            "threatInfo": {
                "threatTypes": [ThreatType.SOCIAL_ENGINEERING],
                "platformTypes": [PlatformType.ANY_PLATFORM],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url},
                ],
            },
        }

        logger.info("Calling Google Safe Browsing API v4")

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._base_url}/threatMatches:find?key={self._api_key}",
                json=body,
                timeout=60,
            ) as response:
                response.raise_for_status()
                response_json = await response.json()

        return response_json.get("matches")


class GoogleSafeBrowsingClientV5:
    def __init__(
        self,
        base_url: str = settings.SAVE_BROWSING_API_BASE_URL,
        api_key: str = settings.SAFE_BROWSING_API_KEY,
    ):
        self._base_url = f"{base_url}/v5"
        self._api_key = api_key

    async def search_url(self, url: str):
        canonical_url = canonical_form(url)
        url_full_hash = full_hash(canonical_url)
        first_4_bytes = url_full_hash[:4]

        url_truncated_hash = encode_to_base64(first_4_bytes).rstrip("=")
        url_full_hash_encoded = encode_to_base64(url_full_hash)

        response = await self.search_prefixes(url_truncated_hash)

        for _full_hash in response.get("fullHashes", []):
            if _full_hash["fullHash"] == url_full_hash_encoded:
                for _details in _full_hash["fullHashDetails"]:
                    if _details["threatType"] == "SOCIAL_ENGINEERING":
                        return _full_hash

        return None

    async def search_prefixes(self, prefix: str):
        params = {"key": self._api_key, "hashPrefixes": prefix}

        logger.info("Calling Google Safe Browsing API for prefix search")

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._base_url}/hashes:search", params=params, timeout=60
            ) as response:
                response.raise_for_status()
                response_content = await response.read()

        safe_browsing_response = safe_browsing_response_pb2.SafeBrowsingResponse()
        safe_browsing_response.ParseFromString(response_content)
        return MessageToDict(safe_browsing_response)
