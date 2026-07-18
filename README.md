# SOC Log Analyzer

A Python script that parses Windows Security Event Log data (Event ID 4625 — failed logon) and flags source IPs showing brute-force patterns, replicating core SIEM detection logic outside of a SIEM platform.

## Why This Project

Built as a follow-up to my [Home-SOC-Lab](https://github.com/UsamaSec/Home-SOC-Lab) project, where I detected a brute-force attack using Splunk's search interface. This script reimplements that same detection logic in Python, grouping failed login events by source IP and flagging suspicious activity — to demonstrate the underlying mechanics a SIEM automates, and basic security scripting/automation skills.

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

<img width="740" height="436" alt="image" src="https://github.com/user-attachments/assets/34c963cd-8325-4a12-8a67-eb213ee25cf3" />



## Data Source
Sample data in `/sample-data` was generated from the brute-force attack simulated in my [Home-SOC-Lab](https://github.com/UsamaSec/Home-SOC-Lab) project.

## What I Learned
Learned that real-world log data rarely matches assumptions, Splunk's actual 
CSV export used different field names than expected (Source_Network_Address, 
not a generic "src_ip"), requiring me to inspect the raw data before the script 
would run correctly. Also reinforced how a simple counting/grouping approach 
in plain Python can replicate core SIEM detection logic, and how noisy 
real data (background/legitimate traffic mixed with attack traffic) needs 
to be correctly filtered rather than assumed clean.

## Next Steps
Add command-line arguments to make the threshold and input file configurable, 
and add an option to export flagged results to a CSV report instead of just 
printing to terminal.
