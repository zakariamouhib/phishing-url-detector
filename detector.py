import re
import argparse
from urllib.parse import urlparse

KEYWORDS = ["login", "verify", "secure", "update", "account",
            "password", "confirm", "signin", "bank"]

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def analyze(url):
    score = 0
    reasons = []

    parsed = urlparse(url)
    host = parsed.hostname or ""
    is_ip = bool(IP_PATTERN.match(host))

    if is_ip:
        score += 3
        reasons.append("IP address instead of a domain name (+3)")

    if "@" in url:
        score += 3
        reasons.append("Contains '@' (hides the real domain) (+3)")

    if parsed.scheme != "https":
        score += 1
        reasons.append("Not using HTTPS (+1)")

    found = [k for k in KEYWORDS if k in url.lower()]
    if found:
        points = min(len(found), 3)
        score += points
        reasons.append(f"Suspicious keywords: {', '.join(found)} (+{points})")

    if not is_ip and host.count(".") >= 3:
        score += 2
        reasons.append("Too many subdomains (+2)")

    if host.count("-") >= 2:
        score += 1
        reasons.append("Many hyphens in the domain (+1)")

    if score >= 4:
        verdict = "PHISHING"
    elif score >= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return score, verdict, reasons


def main():
    parser = argparse.ArgumentParser(
        description="Score URLs for phishing indicators (educational use only). "
                    "The tool only analyzes the URL text, it never visits the site."
    )
    parser.add_argument("-u", "--url",
                        help="Analyze a single URL")
    parser.add_argument("-f", "--file", default="sample_urls.txt",
                        help="File with one URL per line (default: sample_urls.txt)")
    parser.add_argument("-o", "--output",
                        help="Save the report to a file (ex: report.txt)")
    args = parser.parse_args()

    if args.url:
        urls = [args.url]
    else:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: file '{args.file}' not found.")
            return

    lines = []
    for url in urls:
        score, verdict, reasons = analyze(url)
        lines.append(f"[{verdict}] (score {score}) {url}")
        for reason in reasons:
            lines.append(f"    - {reason}")

    for line in lines:
        print(line)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"\nReport saved to {args.output}")


if __name__ == "__main__":
    main()