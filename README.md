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
