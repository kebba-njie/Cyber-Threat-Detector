from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import ipaddress


# Project file locations
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "sample_logs.txt"
REPORT_FILE = BASE_DIR / "threat_report.txt"

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

VALID_EVENT_TYPES = {
    "LOGIN_FAILED",
    "LOGIN_SUCCESS",
    "PORT_SCAN",
    "DOS_ATTACK"
}
# Configurable threat detection thresholds
DETECTION_THRESHOLDS = {
    "BRUTE_FORCE": 5,
    "PORT_SCAN": 3,
    "DOS_ATTACK": 5
}


def display_banner():
    print("=" * 45)
    print("          CYBER THREAT DETECTOR")
    print("=" * 45)


def read_logs():

    valid_logs = []
    invalid_logs = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            line = line.strip()

            if not line:
                continue

            parts = line.split()

            if len(parts) < 4:
                invalid_logs.append(
                    f"Line {line_number}: Incomplete log entry"
                )
                continue

            timestamp = extract_timestamp(line)

            if timestamp is None:
                invalid_logs.append(
                    f"Line {line_number}: Invalid timestamp"
                )
                continue

            ip_address = extract_ip(line)

            if ip_address is None:
                invalid_logs.append(
                    f"Line {line_number}: Invalid IP address"
                )
                continue

            event_type = parts[2]

            if event_type not in VALID_EVENT_TYPES:
                invalid_logs.append(
                    f"Line {line_number}: Unknown event type ({event_type})"
                )
                continue

            valid_logs.append(line)

    return valid_logs, invalid_logs


def extract_timestamp(event):

    try:
        timestamp_text = " ".join(event.split()[:2])

        return datetime.strptime(
            timestamp_text,
            TIMESTAMP_FORMAT
        )

    except ValueError:
        return None


def extract_ip(event):

    for word in event.split():

        candidate = word.strip("[](),;")

        try:
            return str(ipaddress.ip_address(candidate))

        except ValueError:
            continue

    return None


def classify_ip_risk(activity):

    if activity["DOS_ATTACK"] >= DETECTION_THRESHOLDS["DOS_ATTACK"]:
        return "CRITICAL RISK"

    elif activity["LOGIN_FAILED"] >= DETECTION_THRESHOLDS["BRUTE_FORCE"]:
        return "HIGH RISK"

    elif activity["PORT_SCAN"] >= DETECTION_THRESHOLDS["PORT_SCAN"]:
        return "MEDIUM RISK"

    else:
        return "LOW RISK"


def build_event_timeline(logs):

    timeline = []

    for event in logs:

        event = event.strip()

        if not event:
            continue

        timestamp = extract_timestamp(event)

        if timestamp is not None:

            event_description = " ".join(event.split()[2:])

            timeline.append({
                "timestamp": timestamp,
                "event": event_description
            })

    timeline.sort(key=lambda item: item["timestamp"])

    return timeline


def analyze_logs(logs):

    ip_activity = defaultdict(Counter)
    threats = []

    events = [
        event.strip()
        for event in logs
        if event.strip()
    ]

    for event in events:

        ip_address = extract_ip(event)

        if not ip_address:
            continue

        event_parts = event.split()
        event_type = event_parts[2]

        ip_activity[ip_address][event_type] += 1

    for ip_address, activity in ip_activity.items():

        # Brute force detection
        if activity["LOGIN_FAILED"] >= DETECTION_THRESHOLDS["BRUTE_FORCE"]:

            threats.append({
                "type": "Brute Force Attack",
                "ip": ip_address,
                "severity": "HIGH",
                "evidence": (
                    f'{activity["LOGIN_FAILED"]} failed login attempts'
                )
            })

        # Port scanning detection
        if activity["PORT_SCAN"] >= DETECTION_THRESHOLDS["PORT_SCAN"]:

            threats.append({
                "type": "Port Scanning",
                "ip": ip_address,
                "severity": "MEDIUM",
                "evidence": (
                    f'{activity["PORT_SCAN"]} scanning attempts'
                )
            })

        # Denial of Service detection
        if activity["DOS_ATTACK"] >= DETECTION_THRESHOLDS["DOS_ATTACK"]:

            threats.append({
                "type": "Denial of Service Attack",
                "ip": ip_address,
                "severity": "CRITICAL",
                "evidence": (
                    f'{activity["DOS_ATTACK"]} attack requests'
                )
            })

    ip_risks = {
        ip_address: classify_ip_risk(activity)
        for ip_address, activity in ip_activity.items()
    }

    return threats, len(events), ip_activity, ip_risks

def display_event_timeline(timeline):

    print("\nSECURITY EVENT TIMELINE")
    print("-" * 45)

    if not timeline:
        print("No timestamped events found.")
        return

    for item in timeline:

        timestamp = item["timestamp"].strftime(TIMESTAMP_FORMAT)

        print(f"{timestamp} - {item['event']}")

    print("-" * 45)

    print(
        "Earliest Event:",
        timeline[0]["timestamp"].strftime(TIMESTAMP_FORMAT)
    )

    print(
        "Latest Event:",
        timeline[-1]["timestamp"].strftime(TIMESTAMP_FORMAT)
    )


def display_ip_activity(ip_activity, ip_risks):

    print("\nIP ADDRESS ACTIVITY")
    print("-" * 45)

    for ip_address, activity in ip_activity.items():

        print(f"\nIP Address: {ip_address}")

        for event_type, count in activity.items():
            print(f"{event_type}: {count}")

        print(f"Risk Level: {ip_risks[ip_address]}")

    print("-" * 45)


def display_threats(threats):

    print("\nDETECTED SECURITY THREATS")
    print("-" * 45)

    if not threats:
        print("No suspicious activity detected.")
        return

    for threat in threats:

        print(f'[{threat["severity"]}] {threat["type"]}')
        print(f'IP Address: {threat["ip"]}')
        print(f'Evidence: {threat["evidence"]}')
        print("-" * 45)
def generate_report(
    threats,
    total_events,
    ip_activity,
    ip_risks,
    timeline,
    invalid_logs
):

    with open(REPORT_FILE, "w", encoding="utf-8") as report:

        report.write("CYBER THREAT DETECTOR REPORT\n")
        report.write("=" * 45 + "\n\n")

        report.write(f"Valid Events Analyzed: {total_events}\n")
        report.write(f"Invalid Events Rejected: {len(invalid_logs)}\n\n")

        # Invalid log entries
        report.write("LOG VALIDATION RESULTS\n")
        report.write("-" * 45 + "\n")

        if not invalid_logs:
            report.write("All log entries passed validation.\n")

        else:
            for error in invalid_logs:
                report.write(error + "\n")

        # IP activity report
        report.write("\n\nIP ADDRESS ACTIVITY\n")
        report.write("-" * 45 + "\n")

        for ip_address, activity in ip_activity.items():

            report.write(f"\nIP Address: {ip_address}\n")
            report.write(f"Total Events: {sum(activity.values())}\n")

            for event_type, count in activity.items():

                report.write(f"{event_type}: {count}\n")

            report.write(
                f"Risk Classification: {ip_risks[ip_address]}\n"
            )

        # Event timeline report
        report.write("\n\nSECURITY EVENT TIMELINE\n")
        report.write("-" * 45 + "\n")

        for item in timeline:

            timestamp = item["timestamp"].strftime(TIMESTAMP_FORMAT)

            report.write(
                f"{timestamp} - {item['event']}\n"
            )

        # Threat report
        report.write("\n\nDETECTED SECURITY THREATS\n")
        report.write("-" * 45 + "\n")

        if not threats:
            report.write("No suspicious activity detected.\n")

        for threat in threats:

            report.write(
                f'\n[{threat["severity"]}] {threat["type"]}\n'
            )

            report.write(f'IP Address: {threat["ip"]}\n')
            report.write(f'Evidence: {threat["evidence"]}\n')

    print("\nThreat Report Generated Successfully!")


def main():

    display_banner()

    print("\nScanning security logs...")

    try:
        logs, invalid_logs = read_logs()

    except FileNotFoundError:
        print("Error: sample_logs.txt was not found.")
        return

    except (OSError, UnicodeDecodeError) as error:
        print(f"Error reading security logs: {error}")
        return

    print(f"\nValid Log Entries: {len(logs)}")
    print(f"Invalid Log Entries: {len(invalid_logs)}")

    # Display rejected entries
    if invalid_logs:

        print("\nINVALID LOG ENTRIES")
        print("-" * 45)

        for error in invalid_logs:
            print(error)

    threats, total_events, ip_activity, ip_risks = analyze_logs(logs)

    timeline = build_event_timeline(logs)

    display_ip_activity(ip_activity, ip_risks)

    display_event_timeline(timeline)

    display_threats(threats)

    print("\nSecurity Scan Completed!")
    print(f"Total Valid Events Analyzed: {total_events}")
    print(f"Total Invalid Events Rejected: {len(invalid_logs)}")

    generate_report(
        threats,
        total_events,
        ip_activity,
        ip_risks,
        timeline,
        invalid_logs
    )


if __name__ == "__main__":
    main()