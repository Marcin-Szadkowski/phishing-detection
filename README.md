# phishing-detection
A comprehensive Python script that automates the detection and analysis of phishing websites using multiple data sources and detection engines.

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
