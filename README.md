# BlockWatch: Minecraft Insider Threat Forensics Tool

## Team Members
- Logan Carmody
- Abhi Jannu

## Project Overview

BlockWatch is a digital forensics tool designed to investigate potential insider threat activity on a Minecraft server. The tool treats a Minecraft server as an application system and applies digital forensics concepts such as log analysis, evidence integrity, suspicious activity detection, timeline reconstruction, and AI-assisted triage.

Minecraft servers can experience incidents that resemble real-world security events, including unauthorized administrative actions, privilege abuse, item inflation, griefing, suspicious user behavior, and misuse of operator permissions. These incidents may not always come from an external attacker; they can also be caused by a trusted user with operator or administrator privileges.

BlockWatch helps investigators review Minecraft server logs in a repeatable and organized way by identifying suspicious administrative activity, assigning risk levels, calculating evidence hashes, generating structured reports, and optionally using AI to explain suspicious events.

---

## Problem Statement

Manual review of Minecraft server logs can be slow, inconsistent, and easy to overlook important evidence. In an insider threat scenario, suspicious activity may appear as normal administrator behavior unless commands, timestamps, actors, and timelines are reviewed carefully.

This project addresses that problem by automating the review of Minecraft server logs and highlighting events that may indicate privileged access abuse. The tool supports forensic investigation by preserving evidence integrity through SHA-256 hashing and producing clear reports of suspicious activity.

---

## Features

BlockWatch currently includes the following features:

- Parses Minecraft server log files from a selected path
- Detects suspicious slash commands and real Minecraft server log phrases
- Assigns risk levels to flagged events
- Extracts timestamps from log entries
- Extracts actors/users from suspicious events
- Calculates SHA-256 hashes for evidence integrity
- Generates a suspicious activity report
- Generates a CSV timeline of flagged events
- Reconstructs an incident timeline
- Includes optional ChatGPT/OpenAI-assisted forensic analysis
- Runs with or without AI using the `--no-ai` option
- Can scan a Minecraft server’s `latest.log` directly without copying it into the project folder

---

## Suspicious Activity Detected

BlockWatch currently flags both slash-command style entries and real Minecraft log phrases.

### Slash Commands

- `/give`
- `/op`
- `/deop`
- `/gamemode`
- `/tp`
- `/kill`
- `/ban`
- `/pardon`
- `/whitelist`
- `/kick`

### Real Minecraft Log Phrases

- `Gave`
- `Set own game mode`
- `Set game mode`
- `Teleported`
- `server operator`
- `no longer a server operator`
- `Banned`
- `Unbanned`
- `Kicked`
- `Whitelist`

These commands and phrases were selected because they can represent administrative misuse, privilege escalation, unauthorized item generation, forced movement, or moderation abuse.

---

## AI-Assisted Forensic Analysis

BlockWatch includes an optional AI-assisted analysis module using the OpenAI API. When an API key is provided, suspicious Minecraft log entries can be sent to ChatGPT for a concise forensic explanation.

The AI-assisted analysis can provide:

- A risk interpretation
- An explanation of why the event may matter in an insider threat investigation
- Recommended follow-up evidence to review

The tool still works without an API key. If no API key is configured, BlockWatch skips AI analysis safely and continues generating the report.

**Important:** Do not commit a real API key to GitHub.

---

## Evidence Sources

The tool primarily analyzes Minecraft server log data.

Sample evidence is stored in:

```text
data/sample_log.txt
```

A copied real Minecraft server log used for testing may be stored as:

```text
data/real_latest.log.log
```

A real Minecraft server log can also be scanned directly from its original server folder. For example:

```text
C:\Users\YourName\Desktop\minecraft_test_server\logs\latest.log
```

Possible evidence sources include:

- `logs/latest.log`
- archived Minecraft server logs
- `ops.json`
- `whitelist.json`
- `server.properties`
- plugin logs such as Essentials, LuckPerms, or CoreProtect

For this project demo, BlockWatch can analyze both sample logs and real Minecraft server logs generated from a local Java server.

---

## Setup Instructions

### 1. Clone the repository

```bash
git clone <repository-url>
cd IT_360_Final_Project_Spring_2026
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

On Windows, this can also be run as:

```powershell
py -m pip install -r requirements.txt
```

### 3. Optional AI setup

To use OpenAI/ChatGPT analysis, set the API key as an environment variable.

PowerShell:

```powershell
$env:OPENAI_API_KEY="your_api_key_here"
```

Do not commit a real API key to GitHub.

A template is provided in:

```text
.env.example
```

---

## How to Run

### Run with the sample log and no AI

```powershell
py src/main.py --log data/sample_log.txt --output sample_test --no-ai
```

### Run with the sample log and AI enabled

First set the API key:

```powershell
$env:OPENAI_API_KEY="your_api_key_here"
```

Then run:

```powershell
py src/main.py --log data/sample_log.txt --output ai_test
```

### Run against a copied real Minecraft log

```powershell
py src/main.py --log data/real_latest.log.log --output real_log_test --no-ai
```

### Run against the Minecraft server’s latest.log directly

This command scans the Minecraft server’s `latest.log` file directly without copying it into the project folder:

```powershell
py src/main.py --log "$env:USERPROFILE\Desktop\minecraft_test_server\logs\latest.log" --output server_log_scan --no-ai
```

### Run with a custom output folder

```powershell
py src/main.py --log data/sample_log.txt --output custom_output --no-ai
```

---

## Output Files

BlockWatch generates output files in the selected output folder.

Main report:

```text
suspicious_activity_report.txt
```

CSV timeline:

```text
timeline.csv
```

The suspicious activity report includes:

- Report generation timestamp
- Evidence file path
- SHA-256 evidence hash
- Total suspicious events detected
- Command summary
- Risk summary
- Incident timeline
- Line numbers
- Timestamps
- Actors/users
- Commands or phrases detected
- Risk levels
- Original log entries
- Optional AI-assisted analysis

---

## Example Output

Example console output:

```text
=== BlockWatch Minecraft Insider Threat Scanner ===

Scanning evidence file: data/real_latest.log.log
Evidence SHA-256: b0cce1ec5e27048ac0a02f2034ae3915ea519edf5ada1d0ced7996d190d74ad1

Suspicious events detected: 9

Line 30 | 18:11:26 | Medium Risk | Gave
Actor: lolo10411
Log Entry: [18:11:26] [Server thread/INFO]: [lolo10411: Gave 5 [Diamond] to lolo10411]
```

---

## Repository Structure

```text
src/
  main.py
  ai_chatgpt_analyzer.py

data/
  sample_log.txt
  real_latest.log.log

docs/
  final_report.pdf
  report_draft.md
  test_results.md
  screenshots/

scripts/
  scan_latest_log.ps1

README.md
requirements.txt
.gitignore
.env.example
LICENSE
```

---

## Methodology

BlockWatch follows a basic forensic workflow:

1. **Evidence Identification**
   - Locate the Minecraft server log file to be reviewed.

2. **Evidence Integrity**
   - Calculate a SHA-256 hash of the log file before analysis.

3. **Log Parsing**
   - Read the log file line by line.
   - Detect suspicious slash commands and real Minecraft log phrases.

4. **Event Extraction**
   - Extract timestamps, actors, detected commands, risk levels, and original log entries.

5. **Risk Classification**
   - Assign basic risk levels based on the type of suspicious action detected.

6. **Timeline Reconstruction**
   - Reconstruct an incident timeline from suspicious log activity.

7. **AI-Assisted Analysis**
   - Optionally send flagged events to the OpenAI API for forensic-style explanation.

8. **Reporting**
   - Generate a structured text report and CSV timeline for review.

---

## Testing Plan

The tool was tested using both a sample Minecraft log and a real Minecraft server log generated from a local Java server.

Test cases include:

- Normal player join and leave events
- Suspicious `/give` command usage
- Gamemode changes
- Operator privilege changes
- Teleportation events
- Ban and unban events
- Report generation
- CSV timeline generation
- Evidence hashing
- Optional AI-assisted analysis

The project is considered successful if the tool correctly identifies suspicious activity, generates readable reports, exports a CSV timeline, and preserves the original evidence log.

---

## Ethical and Legal Considerations

This tool is designed only for authorized forensic analysis of Minecraft servers or systems that the investigator owns or has permission to examine.

BlockWatch does not attempt to deanonymize users, perform intrusive scanning, or access systems without permission. Evidence handling follows basic forensic principles by preserving the original log file and using hashing to support integrity verification.

---

## Current Project Status

Completed:

- Repository initialized
- Source code folder created
- Sample Minecraft log data added
- Real Minecraft log testing performed
- Suspicious command and real Minecraft phrase detection implemented
- Evidence hashing added
- Risk classification added
- Timestamp and actor extraction added
- CSV timeline export added
- Incident timeline reconstruction added
- Optional AI analysis module added
- README documentation updated

In progress:

- Final written report
- Screenshots for documentation
- Video presentation

---

## Video Presentation

Video link will be added before final submission.
