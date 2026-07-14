# wctfsv

Web CTF Solver - All-in-One Web Penetration Testing Tool for Kali Linux.

Created by **op-h** - https://github.com/op-h/wctfcv

## Features

- **SQLi** - Error-based, UNION, blind, time-based SQL injection detection + data dump
- **XSS** - 70+ payloads, filter bypass, DOM sink detection, CSP analysis
- **Brute** - Multi-threaded directory/file brute-force
- **Subdomains** - DNS brute-force + crt.sh certificate transparency
- **Headers** - Security header audit + technology detection
- **Source** - Comments, hidden fields, forms, emails, API keys, JS analysis
- **Cookies** - Security flags, entropy analysis, manipulation payloads
- **All** - Run every module in one shot

## Requirements

- Kali Linux (or any Debian-based distro)
- Python 3.10+

## Install

```bash
git clone https://github.com/op-h/wctfcv.git
cd wctfcv
chmod +x install.sh
./install.sh
```

## Usage

```bash
# SQL Injection scan + dump tables
wctfsv sqli -u "http://target.com/page?id=1" --dump

# XSS scan
wctfsv xss -u "http://target.com/search?q=test" -p q

# Generate XSS payloads
wctfsv xss -u "http://target.com" -p input --payloads

# Directory brute-force
wctfsv brute -u "http://target.com" --threads 20

# Subdomain enumeration
wctfsv subdomains -d target.com --crtsh

# Header analysis
wctfsv headers -u "http://target.com"

# Source code review
wctfsv source -u "http://target.com"

# Cookie analysis + manipulation
wctfsv cookies -u "http://target.com" --payloads --cookie-name session

# Run all modules
wctfsv all -u "http://target.com" --threads 20 -j results.json
```

## Help

```bash
wctfsv --help           # Global help with all modules
wctfsv sqli --help      # SQLi module examples
wctfsv xss --help       # XSS module examples
wctfsv brute --help     # Brute-force examples
wctfsv all --help       # Run-all examples
```

## Auth & Headers

```bash
# With Bearer token
wctfsv sqli -u "http://target.com/api?id=1" -H "Authorization: Bearer eyJ..."

# With cookies
wctfsv brute -u "http://target.com" -H "Cookie: session=abc123"

# POST data
wctfsv sqli -u "http://target.com/login" -d "user=admin" -d "pass=123" --dump
```

## Disclaimer

For educational and CTF purposes only. Use responsibly and only on systems you have permission to test.
