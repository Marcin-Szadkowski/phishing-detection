# phishing-detection
A comprehensive Python script that automates the detection and analysis of phishing websites using multiple data sources and detection engines.

# CLI usage
```bash

```
TODO:
after installation run `playwright install` to install the browser

### The goal
As in input we have some domains reported as phishing. The goal is to discover if they are really phishing domains.

# TODO 
Q: How to check DNS filter for phishing domains?
Try to get Phishtank database https://phishtank.org/developer_info.php

Q: Does VirusTotal provide 0-1 score for phishing domains? Pay attention to vendors

Q: Comparing Google Safe Browsing v4 and v5 API:
All results found by v5 are also found by v4, but v4 has more results.

Q: What is Google Enhanced Safe Browsing?

`ulr_blocked_in_my_browser=https://page-support-case-review-center.dpi68s8j63ukb.amplifyapp.com/`

https://blog.chromium.org/2024/02/optimizing-safe-browsing-checks-in.html

# Chromium sandboxing
https://github.com/microsoft/playwright/issues/1977
https://chromium.googlesource.com/chromium/src/+/master/docs/design/sandbox_faq.md