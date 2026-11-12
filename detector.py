from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import ipaddress


# Project file locations
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "sample_logs.txt"
REPORT_FILE = BASE_DIR / "threat_report.txt"


def display_banner():
    print("=" * 45)
    print("          CYBER THREAT DETECTOR")
    print("=" * 45)


def read_logs():
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        return file.readlines()


def extract_ip(event):
    for word in event.split():
        candidate = word.strip("[](),;")

        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue

    return None


def classify_ip_risk(activity):

    if activity["DOS_ATTACK"] >= 5:
        return "CRITICAL RISK"

    elif activity["LOGIN_FAILED"] >= 5:
        return "HIGH RISK"

    elif activity["PORT_SCAN"] >= 3:
        return "MEDIUM RISK"

    else:
        return "LOW RISK"


def analyze_logs(logs):
    events = [log.strip() for log in logs if log.strip()]

    ip_activity = defaultdict(Counter)
    threats = []

    for event in events:
        ip_address = extract_ip(event)

        if not ip_address:
            continue

        if "LOGIN_FAILED" in event:
            ip_activity[ip_address]["LOGIN_FAILED"] += 1

        elif "PORT_SCAN" in event:
            ip_activity[ip_address]["PORT_SCAN"] += 1

        elif "DOS_ATTACK" in event:
            ip_activity[ip_address]["DOS_ATTACK"] += 1

        else:
            ip_activity[ip_address]["OTHER"] += 1

    ip_risks = {}

    for ip_address, activity in ip_activity.items():

        risk = classify_ip_risk(activity)
        ip_risks[ip_address] = risk

        if activity["LOGIN_FAILED"] >= 5:
            threats.append({
                "name": "Brute Force Attack",
                "severity": "HIGH",
                "ip": ip_address,
                "evidence": (
                    f"{activity['LOGIN_FAILED']} failed login attempts"
                )
            })

        if activity["PORT_SCAN"] >= 3:
            threats.append({
                "name": "Port Scanning",
                "severity": "MEDIUM",
                "ip": ip_address,
                "evidence": (
                    f"{activity['PORT_SCAN']} scanning attempts"
                )
            })

        if activity["DOS_ATTACK"] >= 5:
            threats.append({
                "name": "Denial of Service Attack",
                "severity": "CRITICAL",
                "ip": ip_address,
                "evidence": (
                    f"{activity['DOS_ATTACK']} attack requests"
                )
            })

    return threats, len(events), ip_activity, ip_risks


def display_ip_activity(ip_activity, ip_risks):

    print("IP ADDRESS ACTIVITY")
    print("-" * 45)

    if not ip_activity:
        print("No valid IP addresses found.")
        return

    for ip_address, activity in ip_activity.items():
        total = sum(activity.values())

        print(f"IP Address: {ip_address}")
        print(f"Total Events: {total}")

        for event_type, count in activity.items():
            print(f"{event_type}: {count}")

        print("Risk Classification:", ip_risks[ip_address])
        print("-" * 45)


def display_threats(threats):

    print("\nDETECTED SECURITY THREATS")
    print("-" * 45)

    if not threats:
        print("No suspicious activities detected.")
        return

    for threat in threats:
        print(f"[{threat['severity']}] {threat['name']}")
        print("IP Address:", threat["ip"])
        print("Evidence:", threat["evidence"])
        print("-" * 45)


def generate_report(threats, total_events, ip_activity, ip_risks):

    with open(REPORT_FILE, "w", encoding="utf-8") as report:

        report.write("=" * 45 + "\n")
        report.write("          CYBER THREAT REPORT\n")
        report.write("=" * 45 + "\n")
        report.write(f"Generated: {datetime.now()}\n")
        report.write(f"Total Events Analyzed: {total_events}\n\n")

        report.write("IP ADDRESS ACTIVITY AND RISK CLASSIFICATION\n")
        report.write("-" * 45 + "\n")

        for ip_address, activity in ip_activity.items():
            report.write(f"\nIP Address: {ip_address}\n")
            report.write(f"Total Events: {sum(activity.values())}\n")

            for event_type, count in activity.items():
                report.write(f"{event_type}: {count}\n")

            report.write(
                f"Risk Classification: {ip_risks[ip_address]}\n"
            )

        report.write("\nDETECTED SECURITY THREATS\n")
        report.write("-" * 45 + "\n")

        if not threats:
            report.write("No suspicious activities detected.\n")

        for threat in threats:
            report.write(f"\nThreat: {threat['name']}\n")
            report.write(f"Severity: {threat['severity']}\n")
            report.write(f"IP Address: {threat['ip']}\n")
            report.write(f"Evidence: {threat['evidence']}\n")

        report.write("\nSecurity Scan Completed.\n")


def main():

    display_banner()

    print("\nScanning security logs...\n")

    try:
        logs = read_logs()

    except FileNotFoundError:
        print("Error: sample_logs.txt was not found.")
        return

    threats, total_events, ip_activity, ip_risks = analyze_logs(logs)

    display_ip_activity(ip_activity, ip_risks)
    display_threats(threats)

    generate_report(threats, total_events, ip_activity, ip_risks)

    print("\nSecurity Scan Completed!")
    print("Total Events Analyzed:", total_events)
    print("Threat Report Generated Successfully!")


if __name__ == "__main__":
    main()