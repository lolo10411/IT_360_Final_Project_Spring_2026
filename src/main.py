import os
import hashlib
import argparse
import csv
from datetime import datetime

try:
    from ai_chatgpt_analyzer import analyze_with_chatgpt
except ImportError:
    analyze_with_chatgpt = None


SUSPICIOUS_COMMANDS = [
    "/give",
    "/op",
    "/deop",
    "/gamemode",
    "/tp",
    "/kill",
    "/ban",
    "/pardon"
]


def calculate_file_hash(file_path):
    """
    Calculates a SHA-256 hash for the evidence file.
    This supports forensic integrity by allowing investigators
    to verify that the evidence file was not changed after collection.
    """
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


def classify_risk(command):
    """
    Assigns a basic risk level to suspicious Minecraft commands.
    """
    high_risk_commands = ["/op", "/deop", "/ban", "/pardon"]
    medium_risk_commands = ["/give", "/gamemode", "/tp", "/kill"]

    if command in high_risk_commands:
        return "High"
    elif command in medium_risk_commands:
        return "Medium"
    else:
        return "Low"


def scan_log_file(log_path):
    """
    Scans a Minecraft server log file for suspicious administrative commands.
    Returns a list of flagged events.
    """
    flagged_events = []

    with open(log_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            clean_line = line.strip()

            for command in SUSPICIOUS_COMMANDS:
                if command in clean_line:
                    flagged_events.append({
                        "line_number": line_number,
                        "command": command,
                        "risk": classify_risk(command),
                        "log_entry": clean_line
                    })

    return flagged_events


def generate_report(flagged_events, evidence_file, evidence_hash, output_path):
    """
    Generates a text report containing suspicious events found in the log file.
    """
    with open(output_path, "w", encoding="utf-8") as report:
        report.write("BlockWatch Suspicious Activity Report\n")
        report.write("=" * 45 + "\n\n")

        report.write(f"Report Generated: {datetime.now()}\n")
        report.write(f"Evidence File: {evidence_file}\n")
        report.write(f"Evidence SHA-256: {evidence_hash}\n\n")

        report.write("Summary\n")
        report.write("-" * 20 + "\n")
        report.write(f"Total suspicious events detected: {len(flagged_events)}\n\n")
        command_counts = count_commands(flagged_events)

        report.write("Command Summary\n")
        report.write("-" * 20 + "\n")

        for command, count in command_counts.items():
            report.write(f"{command}: {count}\n")

        report.write("\n")

        if not flagged_events:
            report.write("No suspicious events were detected.\n")
            return

        report.write("Flagged Events\n")
        report.write("-" * 20 + "\n\n")

        for event in flagged_events:
            report.write(f"Line Number: {event['line_number']}\n")
            report.write(f"Command Detected: {event['command']}\n")
            report.write(f"Risk Level: {event['risk']}\n")
            report.write(f"Log Entry: {event['log_entry']}\n")

            if analyze_with_chatgpt:
                ai_result = analyze_with_chatgpt(event["log_entry"])
                report.write("\nAI-Assisted Analysis:\n")
                report.write(ai_result + "\n")

            report.write("-" * 45 + "\n")

def generate_csv_timeline(flagged_events, output_path):
    """
    Generates a CSV timeline of flagged suspicious events.
    """
    with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["line_number", "command", "risk", "log_entry"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        for event in flagged_events:
            writer.writerow({
                "line_number": event["line_number"],
                "command": event["command"],
                "risk": event["risk"],
                "log_entry": event["log_entry"]
            })
            
def count_commands(flagged_events):
    """
    Counts how many times each suspicious command appears.
    """
    command_counts = {}

    for event in flagged_events:
        command = event["command"]
        command_counts[command] = command_counts.get(command, 0) + 1

    return command_counts
    
def main():
    parser = argparse.ArgumentParser(description="BlockWatch Minecraft Insider Threat Scanner")
    parser.add_argument(
        "--log",
        default="data/sample_log.txt",
        help="Path to the Minecraft server log file to analyze"
    )
    parser.add_argument(
        "--output",
        default="output",
        help="Directory where generated reports will be saved"
    )
    args = parser.parse_args()

    log_path = args.log
    output_dir = args.output
    output_report = os.path.join(output_dir, "suspicious_activity_report.txt")
    output_csv = os.path.join(output_dir, "timeline.csv")

    print("=== BlockWatch Minecraft Insider Threat Scanner ===\n")

    if not os.path.exists(log_path):
        print(f"Error: Log file not found: {log_path}")
        return

    os.makedirs(output_dir, exist_ok=True)

    print(f"Scanning evidence file: {log_path}")

    evidence_hash = calculate_file_hash(log_path)
    print(f"Evidence SHA-256: {evidence_hash}\n")

    flagged_events = scan_log_file(log_path)

    print(f"Suspicious events detected: {len(flagged_events)}\n")

    for event in flagged_events:
        print(f"Line {event['line_number']} | {event['risk']} Risk | {event['command']}")
        print(f"Log Entry: {event['log_entry']}")
        print("-" * 50)

    generate_report(flagged_events, log_path, evidence_hash, output_report)
    generate_csv_timeline(flagged_events, output_csv)
    print(f"CSV timeline generated: {output_csv}")

    print(f"\nReport generated: {output_report}")
    print("\n=== Scan Complete ===")


if __name__ == "__main__":
    main()
