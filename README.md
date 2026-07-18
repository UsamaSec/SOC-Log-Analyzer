# SOC Log Analyzer

A Python script that parses Windows Security Event Log data (Event ID 4625 — failed logon) and flags source IPs showing brute-force patterns, replicating core SIEM detection logic outside of a SIEM platform.

## Why This Project

Built as a follow-up to my [Home-SOC-Lab](https://github.com/usamabhatti3492/Home-SOC-Lab) project, where I detected a brute-force attack using Splunk's search interface. This script reimplements that same detection logic in Python — grouping failed login events by source IP and flagging suspicious activity — to demonstrate the underlying mechanics a SIEM automates, and basic security scripting/automation skills.

## Tools Used
Python 3 · csv (standard library) · Kali Linux

## What It Does
1. Reads exported Windows Security Event Log data (CSV)
2. Groups failed login attempts (Event ID 4625) by source IP
3. Flags any IP with 5+ failed attempts as suspicious
4. Outputs a report showing attempt count, first seen, and last seen per IP

## How to Run
```bash
python3 log_analyzer.py
```
By default, it reads `sample-data/failed_logins.csv`. To use your own data, export failed logon events from Splunk (or any SIEM) as CSV and update the file path in the script.

## Sample Output

![Script output flagging a suspicious IP](screenshots/script-output.png)

## Data Source
Sample data in `/sample-data` was generated from the brute-force attack simulated in my [Home-SOC-Lab](https://github.com/usamabhatti3492/Home-SOC-Lab) project.

## What I Learned
[Fill in once built — e.g., working with Python's csv module, structuring detection logic, handling real-world messy field names from Splunk exports]

## Next Steps
[Optional — e.g., add command-line arguments for custom thresholds, export results to CSV instead of just printing]
