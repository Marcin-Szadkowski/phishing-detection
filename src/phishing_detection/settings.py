import os

_HERE = os.path.abspath(os.path.dirname(__file__))
_ROOT = os.path.join(
    _HERE,
    "..",
)

CHROME_PROFILE_PATH = os.path.join(_ROOT, "data", "playwright_chrome_profile")

VIRUS_TOTAL_API_KEY = os.getenv("VIRUS_TOTAL_API_KEY", "")

OPEN_PHISH_BASE_URL = os.getenv("OPEN_PHISH_BASE_URL", "")

PHISH_STATS_BASE_URL = os.getenv("PHISH_STATS_BASE_URL", "")

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "")
SAVE_BROWSING_API_BASE_URL = os.getenv("SAVE_BROWSING_API_BASE_URL", "")

PLAYWRIGHT_WS_URL = os.getenv("PLAYWRIGHT_WS_URL", "")
