# BlockWatch: Minecraft Insider Threat Forensics Tool

## Team Members
- Logan Carmody
- Abhi Jannu

## Project Overview

BlockWatch is a digital forensics tool designed to investigate potential insider threat activity on a Minecraft server. The tool treats a Minecraft server as an application system and applies digital forensics concepts such as log analysis, evidence integrity, suspicious activity detection, and AI-assisted triage.

Minecraft servers can experience incidents that resemble real-world security events, including unauthorized administrative actions, privilege abuse, item inflation, griefing, and suspicious user behavior. These incidents may not always come from an external attacker; they can also be caused by a trusted user with operator or administrator privileges.

BlockWatch helps investigators review Minecraft server logs in a more repeatable and organized way by identifying suspicious administrative commands, assigning risk levels, calculating evidence hashes, and generating a structured investigation report.

---

## Problem Statement

Manual review of Minecraft server logs can be slow, inconsistent, and easy to overlook important evidence. In an insider threat scenario, the activity may appear as normal administrator behavior unless commands and timelines are reviewed carefully.

This project addresses that problem by automating the review of Minecraft server logs and highlighting events that may indicate privileged access abuse. The tool supports forensic investigation by preserving evidence integrity through SHA-256 hashing and producing a clear report of suspicious activity.

---

## Features

BlockWatch currently includes the following features:

- Parses Minecraft server log files
- Detects suspicious administrative commands
- Assigns basic risk levels to flagged events
- Calculates SHA-256 hashes for evidence integrity
- Generates a suspicious activity report
- Includes optional ChatGPT/OpenAI-assisted forensic analysis
- Uses sample Minecraft evidence logs for testing and demonstration

---

## Suspicious Commands Detected

BlockWatch currently flags the following Minecraft commands:

- `/give`
- `/op`
- `/deop`
- `/gamemode`
- `/tp`
- `/kill`
- `/ban`
- `/pardon`

These commands were selected because they can represent possible administrative misuse, privilege escalation, unauthorized item generation, forced movement, or moderation abuse.

---

## AI-Assisted Forensic Analysis

BlockWatch includes an optional AI-assisted analysis module using the OpenAI API. When an API key is provided, suspicious Minecraft log entries can be sent to ChatGPT for a concise forensic explanation.

The AI-assisted analysis can provide:

- A risk interpretation
- An explanation of why the event may matter in an insider threat investigation
- Recommended follow-up evidence to review

The tool still works without an API key. If no API key is configured, BlockWatch skips the AI analysis safely and continues generating the report.

**Important:** Do not commit a real API key to GitHub.

---

## Evidence Sources

The tool primarily analyzes Minecraft server log data, including sample evidence stored in:

```text
data/sample_log.txt
