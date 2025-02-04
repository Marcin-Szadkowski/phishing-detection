"""
This is a playground script to test the Enhanced Security Mode of Chrome

"""

import os
import time

from playwright.sync_api import sync_playwright

from phishing_detection import settings

_HERE = os.path.abspath(os.path.dirname(__file__))
_ROOT = os.path.join(
    _HERE,
    "..",
)

# These were reported by Safe Browsing v4 API
URLS_TO_TEST = [
    "http://asdun.top/",
    "http://client-verify-now-your-id2.vercel.app/",
    "https://meu-buscar.com/?i=xX./expire/./expire/",
    "http://spandan-maharana.github.io/Netflix-Clone",
    "http://sales101.online/canada",
    "http://mgc-token-migration-debug.netlify.app/",
    "http://help-fb-recovery.github.io/notification",
    "http://laserbyyas.com.au/double/PDF",
    "https://mostafaislam78.github.io/Facebook-Log-In-Page/index.html",
    "http://saurabhshrikhande.github.io/HTML-CSS1-1Netflix",
    "http://asakoohki.github.io/NetflixCloneWebsite",
    "http://sumit-1803.github.io/FacebookClone",
    "http://hrick-08.github.io/Fake-login",
    "http://chegeian.github.io/Netflix-",
    "https://urlz.fr/tYIS",
    "http://ajaygangwar123.github.io/Netflix-Clone-",
    "http://fedbolifij.duckdns.org/en/",
    "http://ieysmzuonq.duckdns.org/en/",
    "http://ocuvrifbbb.duckdns.org/en/",
    "https://khalisdesisoghat.com/p/Sites/index.html",
    "https://smtah888.com/",
    "http://microupdateportal.github.io/myaccount",
    "https://broadband-100478.weeblysite.com/",
    "https://nft-claimr15.vercel.app/",
    "http://you4-alert.com/",
    "http://uxcurrentjhfduxux.weebly.com/",
    "http://mygov-authsec.com/",
    "https://rdakhmax.serv00.net/RDGDESDZRFSYJNOI/index.php?FGDD=1#HDHKJDJDSSJDSJKJDSJDSDJJDSHYKJHGFG",
    "http://ebay.myprofiles.cyou/profile/fRoFbGEwZ9ccU5H8",
    "https://mfacebook.com.vn/kQ6oezxII3gPoYdtzv561a?v",
    "http://tiktok.jp5ybn1.top/",
    "https://metumskloign.webflow.io/",
    "http://www.login-pionex.com/",
    "https://att.daftpage.com/",
    "https://loginbnp.netlify.app/",
    "https://cancelocomprbanlombuias.firebaseapp.com/",
    "https://cancelocomprbanlombuias.web.app/",
    "https://fjaqwi83jfrtwnvgnzx7.web.app/",
    "https://fjaqwi83jfrtwnvgnzx7.firebaseapp.com/",
    "http://carwrapsfl.com/backup/usps_fees/Next-Step",
    "http://help-fb-recovery-center.github.io/notification",
    "http://buiano007.github.io/-NetflixClone",
    "http://www.t5j1gz.top/",
    "http://repentancetv.org/web/",
    "https://iunjeakqw.com/",
    "https://blackyselva1997.github.io/FB-SingUp-Page-DOM-Mini-Project/signup/index.html",
    "http://espacio-logistico.com/js/img/auth/sign",
    "http://tess.bagibagisaldogopay.biz.id/",
    "https://totalmundos.com/kk/newcodingLinkedin/",
    "https://nnenjonzhtx.pages.dev/smart89/",
    "http://verified-badge-service-use-info.vercel.app/",
    "http://att-e573ce.webflow.io/",
    "https://apply-free-verified-badge-official-ten.vercel.app/",
    "https://anzinternetbanking.vercel.app/",
    "https://on-line4tik.com/",
    "https://tkonline-shopping7.com/",
    "https://uptodatebuzmaincentrevowsebcserver.weebly.com/",
    "http://t.n9z9a8b.com/",
    "http://www.sms22.com/images/flog/delivery/tracking.php",
    "http://www.zetalube.co.kr/images/chol/cn900/",
    "https://4redundant.wixstudio.com/att84894894/",
]


def is_page_blocked(page):
    try:
        if page.locator("text=Dangerous site").is_visible():
            return True
    except Exception:
        pass
    return False


def test_enhanced_security_mode():
    chrome_profile = settings.CHROME_PROFILE_PATH
    assert os.path.exists(chrome_profile)

    urls_to_test = URLS_TO_TEST

    with sync_playwright() as p:
        browser = p.chromium.launch_persistent_context(
            chrome_profile,
            headless=False,
            args=[
                "--safebrowsing-enable-enhanced-protection",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        page = browser.new_page()

        results = {}

        for url in urls_to_test:
            try:
                print(f"Testing {url} in Enhanced Security Mode mode...")
                page.goto(url, timeout=15000)
                time.sleep(3)

                blocked = is_page_blocked(page)
                results[url] = "Blocked" if blocked else "Not Blocked"

            except Exception as e:
                results[url] = f"Error: {str(e)}"

        browser.close()

    print(results)
