#!/usr/bin/env python3
"""
Automated Web Scanner
---------------------
Audits websites for missing/weak HTTP security headers and CORS
misconfigurations, then prints a summary and saves a JSON report.

Only scan websites you own or have written permission to test.
"""

import argparse
import json
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests

TIMEOUT = 10
USER_AGENT = "AutomatedWebScanner/1.0 (educational project)"
TEST_ORIGIN = "https://evil.example.com"

# header name -> (severity if missing, why it matters)
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HIGH", "Forces HTTPS; prevents SSL-stripping attacks."),
    "Content-Security-Policy": ("HIGH", "Restricts content sources; mitigates XSS."),
    "X-Frame-Options": ("MEDIUM", "Prevents clickjacking via iframes."),
    "X-Content-Type-Options": ("MEDIUM", "Stops MIME-type sniffing (should be 'nosniff')."),
    "Referrer-Policy": ("LOW", "Controls how much referrer info is leaked."),
    "Permissions-Policy": ("LOW", "Limits access to browser features (camera, mic, etc.)."),
}

# headers that leak technology details
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def normalize_url(url):
    url = url.strip()
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


def fetch(url, origin=None):
    headers = {"User-Agent": USER_AGENT}
    if origin is not None:
        headers["Origin"] = origin
    return requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)


def check_security_headers(resp):
    findings = []
    for name, (severity, why) in SECURITY_HEADERS.items():
        value = resp.headers.get(name)
        if value is None:
            findings.append({"check": name, "severity": severity,
                             "issue": "Header missing", "detail": why})
            continue
        if name == "X-Content-Type-Options" and value.lower() != "nosniff":
            findings.append({"check": name, "severity": "MEDIUM",
                             "issue": f"Weak value: {value}", "detail": why})
        if name == "Strict-Transport-Security":
            try:
                max_age = int(value.split("max-age=")[1].split(";")[0])
                if max_age < 15552000:  # ~180 days
                    findings.append({"check": name, "severity": "LOW",
                                     "issue": f"max-age too short ({max_age}s)",
                                     "detail": "Use at least 6 months."})
            except (IndexError, ValueError):
                findings.append({"check": name, "severity": "MEDIUM",
                                 "issue": "max-age not found", "detail": why})
        if name == "Content-Security-Policy" and "unsafe-inline" in value:
            findings.append({"check": name, "severity": "MEDIUM",
                             "issue": "Uses 'unsafe-inline'", "detail": "Weakens XSS protection."})
    for name in LEAKY_HEADERS:
        if name in resp.headers:
            findings.append({"check": name, "severity": "INFO",
                             "issue": f"Discloses: {resp.headers[name]}",
                             "detail": "Hide technology/version details."})
    return findings


def check_cors(url):
    findings = []
    for label, origin in (("arbitrary origin", TEST_ORIGIN), ("null origin", "null")):
        try:
            resp = fetch(url, origin=origin)
        except requests.RequestException as exc:
            findings.append({"check": "CORS", "severity": "INFO",
                             "issue": f"CORS test failed: {exc}", "detail": ""})
            continue
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao is None:
            continue
        if acao == "*" and acac == "true":
            findings.append({"check": "CORS", "severity": "HIGH",
                             "issue": "Wildcard origin with credentials allowed",
                             "detail": "Invalid/dangerous combination."})
        elif acao == origin and acac == "true":
            findings.append({"check": "CORS", "severity": "HIGH",
                             "issue": f"Reflects {label} with credentials",
                             "detail": "Any site can read authenticated responses."})
        elif acao == origin:
            findings.append({"check": "CORS", "severity": "MEDIUM",
                             "issue": f"Reflects {label} in Access-Control-Allow-Origin",
                             "detail": "Origin is not validated against an allow-list."})
        elif acao == "*":
            findings.append({"check": "CORS", "severity": "LOW",
                             "issue": "Wildcard Access-Control-Allow-Origin",
                             "detail": "Fine for public data, risky otherwise."})
    return findings


def scan(url):
    url = normalize_url(url)
    result = {"url": url, "scanned_at": datetime.now().isoformat(timespec="seconds"),
              "status": None, "findings": [], "error": None}
    try:
        resp = fetch(url)
    except requests.RequestException as exc:
        result["error"] = str(exc)
        return result
    result["status"] = resp.status_code
    result["findings"] += check_security_headers(resp)
    result["findings"] += check_cors(url)
    return result


def print_result(result):
    print("=" * 70)
    print(f"Target : {result['url']}")
    if result["error"]:
        print(f"ERROR  : {result['error']}")
        return
    print(f"Status : {result['status']}")
    if not result["findings"]:
        print("No issues found.")
        return
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    for f in sorted(result["findings"], key=lambda x: order[x["severity"]]):
        print(f"  [{f['severity']:<6}] {f['check']}: {f['issue']}")


def main():
    parser = argparse.ArgumentParser(description="Automated Web Scanner: security headers and CORS audit")
    parser.add_argument("urls", nargs="*", help="URL(s) to scan")
    parser.add_argument("-f", "--file", help="text file with one URL per line")
    parser.add_argument("-o", "--output", default="scan_report.json", help="JSON report path")
    args = parser.parse_args()

    targets = list(args.urls)
    if args.file:
        with open(args.file) as fh:
            targets += [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    if not targets:
        parser.print_help()
        sys.exit(1)

    results = [scan(t) for t in targets]
    for r in results:
        print_result(r)

    with open(args.output, "w") as fh:
        json.dump(results, fh, indent=2)
    print("=" * 70)
    print(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
