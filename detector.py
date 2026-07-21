from collections import Counter

print("=" * 40)
print("      CYBER THREAT DETECTOR")
print("=" * 40)

# Read security logs
with open("sample_logs.txt", "r") as file:
    logs = file.readlines()


print("\nScanning security logs...\n")


# Count each type of event
event_count = Counter(log.strip() for log in logs)


# Threat Detection Rules

for event, count in event_count.items():

    if "LOGIN_FAILED" in event and count >= 5:
        print("[WARNING] Possible Brute Force Attack Detected")
        print("Event:", event)
        print("Failed Attempts:", count)
        print()


    elif "PORT_SCAN" in event and count >= 3:
        print("[ALERT] Possible Port Scanning Detected")
        print("Event:", event)
        print("Scan Attempts:", count)
        print()


    elif "DOS_ATTACK" in event and count >= 5:
        print("[CRITICAL] Possible DoS Attack Detected")
        print("Event:", event)
        print("Requests:", count)
        print()


print("Security Scan Complete!")