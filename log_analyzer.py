# log_analyzer.py
# Reads a CSV of failed login attempts (Windows Event ID 4625)
# and counts how many times each IP address tried to log in.
# Any IP with 5 or more failed attempts gets flagged as suspicious.

import csv

# how many failed attempts before we call it suspicious
THRESHOLD = 5

# path to the exported log data
CSV_FILE = "sample-data/failed_logins.csv"

# this will store data like: {"192.168.56.20": {"count": 3, "first": "...", "last": "..."}}
ip_data = {}

# try to open the file - if it's missing, show a clear message instead of a crash
try:
    with open(CSV_FILE, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            ip = row["Source_Network_Address"]
            time = row["_time"]

            # if we haven't seen this IP before, add it to our dictionary
            if ip not in ip_data:
                ip_data[ip] = {"count": 0, "first": time, "last": time}

            # increase the count for this IP
            ip_data[ip]["count"] = ip_data[ip]["count"] + 1

            # update first seen time if this event is earlier
            if time < ip_data[ip]["first"]:
                ip_data[ip]["first"] = time

            # update last seen time if this event is later
            if time > ip_data[ip]["last"]:
                ip_data[ip]["last"] = time

except FileNotFoundError:
    print(f"Could not find {CSV_FILE}. Make sure the CSV export is in the sample-data folder.")
    exit()

# now print out the results
print("IP Address       Attempts   First Seen              Last Seen               Flag")
print("--------------------------------------------------------------------------------")

suspicious_count = 0
total_events = 0

for ip in ip_data:
    count = ip_data[ip]["count"]
    first = ip_data[ip]["first"]
    last = ip_data[ip]["last"]
    total_events = total_events + count

    # decide if this IP looks suspicious
    if count >= THRESHOLD:
        flag = "SUSPICIOUS"
        suspicious_count = suspicious_count + 1
    else:
        flag = ""

    print(ip, count, first, last, flag)

# print a short summary at the end
print("--------------------------------------------------------------------------------")
print(f"Total events processed: {total_events}")
print(f"Unique IP addresses: {len(ip_data)}")
print(f"Suspicious IPs flagged (>= {THRESHOLD} attempts): {suspicious_count}")
