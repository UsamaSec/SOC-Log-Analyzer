# log_analyzer.py
# Reads a CSV of failed login attempts (Windows Event ID 4625)
# and counts how many times each IP address tried to log in.
# Any IP with 5 or more failed attempts gets flagged as suspicious.

import csv

# how many failed attempts before we call it suspicious
THRESHOLD = 5

# this will store data like: {"192.168.56.20": {"count": 3, "first": "...", "last": "..."}}
ip_data = {}

# open the CSV file and read it row by row
with open("sample-data/failed_logins.csv", newline="", encoding="utf-8") as file:
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

# now print out the results
print("IP Address       Attempts   First Seen              Last Seen               Flag")
print("--------------------------------------------------------------------------------")

for ip in ip_data:
    count = ip_data[ip]["count"]
    first = ip_data[ip]["first"]
    last = ip_data[ip]["last"]

    # decide if this IP looks suspicious
    if count >= THRESHOLD:
        flag = "SUSPICIOUS"
    else:
        flag = ""

    print(ip, count, first, last, flag)
