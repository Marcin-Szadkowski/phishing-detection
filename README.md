# phishing-detection
A comprehensive Python script that automates the detection and analysis of phishing websites using multiple data sources and detection engines.


### What's done
- Implemented 2 data sources ([phishstats.info](https://phishstats.info/#apidoc) and OpenPhish)
- Implemented detection by VirusTotal API v3
- Implemented detection by Google Safe Browsing API v4 and v5 (although they should return the same results)
- Implemented website status assessment
- Implemented CLI

### What's left
- Get that Playwright setup working

### Why two versions of Google Safe Browsing API are implemented?
My first approach was to implement v4 API and I assumed that Enhanced mode uses v5 API. However, this is probably not 
true and different results are observed due to not extensive prefixes search.

According to the [description](https://support.google.com/chrome/answer/9890866#zippy=%2Cenhanced-protection%2Cstandard-protection)
the feasible way to compare Standard & Enhanced modes is to rely on Playwright or other tool. 

### Playwright with our without Enhanced Chrome Safe Browsing mode
The issue is that configuration is not working as expected. Browser (in the UI) shows that option is enabled, but
no websites are blocked. We can see that `Safe Browsing` directory is empty which leads to the conclusion that
the Safe Browsing client is not syncing with the server. Maybe logging in is required. 

# Usage
Check [pyprojectl.toml](pyproject.toml) for supported Python versions.

To install package in development environment run:

```bash
  pip install -e .[dev]
```

Or install exact versions of dependencies:

```bash
  pip install -e . --no-deps
  pip install -r requirements.txt
```

See [settings.py](src/phishing_detection/settings.py) for necessary ENV variables. Provided that you installed
the package with `dev` dependencies you can create `.env`. The variables defined in `.evn` will be loaded at entry point
(`cli`). 


### CLI
See available commands by running:
```bash
  phishing-deteciton --help
```

See available options for a command by running:
```bash
  phishing-detection <command> --help
```

For example to run full analysis using [phishstats.info](https://phishstats.info/#apidoc) as a data source
```bash
  phishing-detection run-analysis phish_stats_analysis.csv PHISH_STATS --assess-status --check-phishing
```