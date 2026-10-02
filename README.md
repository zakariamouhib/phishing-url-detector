# Phishing URL Detector

Python tool that scores URLs for phishing indicators.

> **Disclaimer:** Educational purposes only. The tool only analyzes the
> URL text, it never visits the website. The sample URLs are fake and use
> reserved domains (example.com, example.net, example.org) and reserved
> documentation IP addresses.

## Features

- Analyzes URLs with simple, explainable rules
- Gives a score and a verdict: SAFE, SUSPICIOUS or PHISHING
- Shows the reasons behind every score
- Analyzes a single URL or a whole file
- Saves the report to a file
- No external dependencies (standard library only)

## Requirements

- Python 3.8+

## Usage

    python detector.py
    python detector.py -u "http://192.0.2.45/login/verify-account"
    python detector.py -f sample_urls.txt
    python detector.py -o report.txt

## Options

| Option | Description | Default |
|--------|-------------|---------|
| -u, --url | Analyze a single URL | - |
| -f, --file | File with one URL per line | sample_urls.txt |
| -o, --output | Save the report to a file | - |

## Detection rules

| Indicator | Points |
|-----------|--------|
| IP address instead of a domain name | +3 |
| Contains `@` in the URL | +3 |
| Not using HTTPS | +1 |
| Suspicious keywords (login, verify, secure...) | +1 each, max +3 |
| Too many subdomains | +2 |
| Many hyphens in the domain | +1 |

Verdict: score 4 or more = PHISHING, 2 or 3 = SUSPICIOUS, below 2 = SAFE.

## Example output

    [SAFE] (score 0) https://www.google.com/search?q=python
    [PHISHING] (score 7) http://192.0.2.45/login/verify-account
        - IP address instead of a domain name (+3)
        - Not using HTTPS (+1)
        - Suspicious keywords: login, verify, account (+3)

## What I learned

- Parsing URLs with `urllib.parse`
- Regular expressions (`re`)
- Building a rule-based scoring system
- Building a CLI with `argparse`
- Basics of phishing detection for SOC analysts

## Limitations

This is a simple rule-based detector. It can produce false positives and
false negatives, and it does not check domain age, reputation or page content.

## Roadmap

- [ ] Detect typosquatting (ex: paypa1 vs paypal)
- [ ] Check against a list of known brand names
- [ ] Export report as CSV or JSON

## License

MIT
