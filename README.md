# Automated Web Scanner

A Python script that audits websites for **missing or weak HTTP security headers** and **CORS misconfigurations**, then prints a severity-ranked summary and saves a JSON report.

> **Legal notice:** Only scan websites you own or have explicit permission to test.

## Features

- Checks 6 key security headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- Detects weak values (short HSTS max-age, `unsafe-inline` in CSP, wrong `nosniff`)
- Flags information-leaking headers (`Server`, `X-Powered-By`, `X-AspNet-Version`)
- Tests CORS by sending an untrusted `Origin` and a `null` origin, and detects:
  - Wildcard `*` with credentials
  - Reflected origins (with or without credentials)
  - Plain wildcard origins
- Scans one URL, many URLs, or a list from a file
- Severity levels: HIGH, MEDIUM, LOW, INFO
- Exports results to JSON

## Requirements

- Python 3.8+
- `requests` library

## Installation

```bash
git clone <your-repo-url>
cd <project-folder>
pip install -r requirements.txt
```

## Usage

Scan a single site:

```bash
python web_scanner.py https://example.com
```

Scan several sites:

```bash
python web_scanner.py https://example.com https://example.org
```

Scan from a file (one URL per line, `#` for comments) and choose the report name:

```bash
python web_scanner.py -f urls.txt -o my_report.json
```

## Sample Output

```
======================================================================
Target : https://example.com
Status : 200
  [HIGH  ] Strict-Transport-Security: Header missing
  [HIGH  ] Content-Security-Policy: Header missing
  [MEDIUM] X-Frame-Options: Header missing
  [LOW   ] Referrer-Policy: Header missing
  [INFO  ] Server: Discloses: nginx
======================================================================
Report saved to scan_report.json
```

## How It Works

1. Sends a normal GET request and inspects response headers against a security checklist.
2. Sends two more GET requests with a fake `Origin` header and checks how the server answers in `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials`.
3. Collects findings, ranks them by severity, prints them, and writes a JSON report.

## Project Files

| File | Purpose |
|---|---|
| `web_scanner.py` | Main scanner program |
| `requirements.txt` | Python dependencies |
| `README.md` | Project documentation |
| Report | Full project report |

## Limitations

- Passive checks only: it does not exploit anything or crawl links
- Tests only the URL given (not every page)
- Does not test CORS preflight (`OPTIONS`) behaviour

## Future Improvements

- Crawl multiple pages per site
- Preflight (`OPTIONS`) testing
- HTML report output
- Cookie flag checks (`Secure`, `HttpOnly`, `SameSite`)
