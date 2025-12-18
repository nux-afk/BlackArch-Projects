# Malware Triage Bot (Static Analysis)

## Project Overview
This is a basic Python-based automated triage tool I made to accelerate the initial assessment of suspicious binaries. It is meant to mimic the "Level 1" analysis workflow used in SOC environments by programmatically extracting Indicators of Compromise (IOCs) and file metadata without executing the payload.

## Features
* **Cryptographic Fingerprinting:** Grabs MD5 and SHA256 hashes for Threat Intelligence correlation (VirusTotal/MalwareBazaar).
* **PE Header Analysis:** Parses Windows Portable Executable headers to identify compile timestamps and section entropy (detecting potential packing/obfuscation).
* **IOC Extraction:** Scrapes the binary for hardcoded IPv4 addresses and URLs using regex filtering to identify Command & Control (C2) infrastructure.

## Usage
```bash
python3 triage_bot.py <path_to_suspicious_file>
```
## Technical Skills Demonstrated

    Language: Python 3

    Libraries: pefile, re, hashlib

    Concepts: Static Analysis, Windows PE Structure, IOC Hunting, Regex
