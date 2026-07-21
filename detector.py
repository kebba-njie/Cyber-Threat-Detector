from collections import Counter
from datetime import datetime

print("=" * 40)
print("      CYBER THREAT DETECTOR")
print("=" * 40)

# Read security logs
with open("sample_logs.txt", "r") as file:
    logs = file.readlines()

print("\nScanning security logs...\n")

# Create threat report file
report = open("threat_report.txt", "w")

report.write("=" * 40 + "\n")
report.write("       CYBER THREAT REPORT\n")
report.write("=" * 40 + "\n")
report.write("Generated: " + str(datetime.now()) + "\n\n")


# Count security events
event_count = Counter(log.strip() for log in logs)


# Threat Detection Rules

for event, count in event_count.items():

    if "LOGIN_FAILED" in event and count >= 5:
        print("[WARNING] Possible Brute Force Attack Detected")
        print("Event:", event)
        print("Failed Attempts:", count)
        print()

        report.write("Threat: Brute Force Attack\n")
        report.write("Event: " + event + "\n")
        report.write("Risk Level: HIGH\n")
        report.write("Evidence: " + str(count) + " failed login attempts\n\n")


    elif "PORT_SCAN" in event and count >= 3:
        print("[ALERT] Possible Port Scanning Detected")
        print("Event:", event)
        print("Scan Attempts:", count)
        print()

        report.write("Threat: Port Scanning\n")
        report.write("Event: " + event + "\n")
        report.write("Risk Level: MEDIUM\n")
        report.write("Evidence: " + str(count) + " scan attempts\n\n")


    elif "DOS_ATTACK" in event and count >= 5:
        print("[CRITICAL] Possible DoS Attack Detected")
        print("Event:", event)
        print("Requests:", count)
        print()

        report.write("Threat: DoS Attack\n")
        report.write("Event: " + event + "\n")
        report.write("Risk Level: CRITICAL\n")
        report.write("Evidence: " + str(count) + " attack requests\n\n")


report.write("Security Scan Completed.\n")

report.close()

print("Security Scan Complete!")
print("Threat report created successfully!")