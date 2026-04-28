import re

log_file = "../data/sample_log.txt"

suspicious = ["/give", "/op", "/gamemode"]

print("=== BlockWatch Scan Started ===\n")

with open(log_file, "r") as file:
    lines = file.readlines()

for line in lines:
    print("LOG:", line.strip())

    for command in suspicious:
        if command in line:
            print("ALERT: Suspicious command detected ->", command)

print("\n=== Scan Complete ===")
