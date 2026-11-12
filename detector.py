from collections import Counter
from datetime import datetime
from pathlib import Path


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


def analyze_logs(logs):
    events = [log.strip() for log in logs if log.strip()]
    event_counts = Counter(events)

    threats = []

    for event, count in event_counts.items():

        if "LOGIN_FAILED" in event and count >= 5:
            threats.append({
                "name": "Brute Force Attack",
                "severity": "HIGH",
                "event": event,
                "evidence": f"{count} failed login attempts"
            })

        elif "PORT_SCAN" in event and count >= 3:
            threats.append({
                "name": "Port Scanning",
                "severity": "MEDIUM",
                "event": event,
                "evidence": f"{count} scanning attempts"
            })

        elif "DOS_ATTACK" in event and count >= 5:
            threats.append({
                "name": "Denial of Service Attack",
                "severity": "CRITICAL",
                "event": event,
                "evidence": f"{count} attack requests"
            })

    return threats, len(events)


def display_threats(threats):

    if not threats:
        print("No suspicious activities detected.")
        return

    for threat in threats:
        print(f"[{threat['severity']}] {threat['name']}")
        print("Event:", threat["event"])
        print("Evidence:", threat["evidence"])
        print("-" * 45)


def generate_report(threats, total_events):

    with open(REPORT_FILE, "w", encoding="utf-8") as report:

        report.write("=" * 45 + "\n")
        report.write("          CYBER THREAT REPORT\n")
        report.write("=" * 45 + "\n")
        report.write(f"Generated: {datetime.now()}\n")
        report.write(f"Total Events Analyzed: {total_events}\n\n")

        if not threats:
            report.write("No suspicious activities detected.\n")

        for threat in threats:
            report.write(f"Threat: {threat['name']}\n")
            report.write(f"Severity: {threat['severity']}\n")
            report.write(f"Event: {threat['event']}\n")
            report.write(f"Evidence: {threat['evidence']}\n")
            report.write("-" * 45 + "\n")

        report.write("\nSecurity Scan Completed.\n")


def main():

    display_banner()

    print("\nScanning security logs...\n")

    try:
        logs = read_logs()

    except FileNotFoundError:
        print("Error: sample_logs.txt was not found.")
        return

    threats, total_events = analyze_logs(logs)

    display_threats(threats)

    generate_report(threats, total_events)

    print("\nSecurity Scan Completed!")
    print("Total Events Analyzed:", total_events)
    print("Threat Report Generated Successfully!")


if __name__ == "__main__":
    main()