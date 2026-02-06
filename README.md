# Project Proposal: Minecraft Insider Threat Forensics Tool

## Team Members
- Logan Carmody
- Abhi Jannu

## Project Title
**BlockWatch: A Digital Forensics Tool for Investigating Insider Threat Activity on a Minecraft Server**

## Summary
This project develops a digital forensics tool that investigates potential **insider threat / privileged access abuse** on a Minecraft server. The tool treats the Minecraft server as an application system and applies digital forensics principles to collect, preserve, and analyze evidence. It focuses on identifying suspicious administrative activity (ex: `/give`, `/gamemode`, `/op`) by parsing server logs, extracting timelines, and producing structured reports.

## Problem Statement
Minecraft servers can experience incidents that resemble real-world security events: unauthorized changes, item inflation, griefing, and service disruption. These events may not come from an external attacker; they can be caused by a trusted user (OP/admin) abusing privileges. Manual log review is slow and inconsistent, which can lead to missed evidence or weak conclusions. A repeatable automated approach improves speed, consistency, and defensibility.

## Goals & Objectives
By the end of the project, the tool will:

- Automate collection of key server artifacts (logs + config)
- Preserve evidence integrity using hashes and a collection manifest
- Parse logs to extract player/admin activity and command execution
- Reconstruct a timeline of relevant events
- Flag high-risk administrative actions and generate summaries
- Output both human-readable and structured reports (TXT/CSV/JSON)

## Scope
### In Scope
- Offline analysis of Minecraft server folders/logs (post-incident investigation)
- Log parsing and event extraction:
  - player joins/leaves
  - UUID ↔ username mapping (when present)
  - command usage related to privileged actions
- Evidence packaging:
  - copy evidence to an output directory
  - generate hash manifest and collection metadata
- Reporting:
  - timeline report
  - per-admin summary (counts, top commands, activity windows)
  - flagged “high-risk” events list

### Out of Scope (to keep the project realistic)
- Live packet capture or network IDS
- Mod/plugin development
- Real-time detection/alerting (this is forensic, not monitoring)
- Attempting to attribute real-world identity from IPs

## Evidence Sources
The tool will primarily use:
- `logs/latest.log` and archived logs in `logs/`
- `ops.json`, `whitelist.json`, `server.properties` (if present)
Optional (if time permits):
- plugin logs (ex: Essentials, LuckPerms, CoreProtect)

## Approach / Methodology
1. **Requirements & design**
   - Identify high-value events and privileged commands
   - Define output formats and directory structure

2. **Evidence collection**
   - Copy relevant artifacts into an `evidence/` output folder
   - Compute hashes (SHA-256) for integrity
   - Record collection metadata (time, host, tool version)

3. **Parsing & normalization**
   - Parse log files and extract structured events:
     - timestamp
     - actor (player/admin)
     - event type (login, command, etc.)
     - details (command string, target, etc.)

4. **Analysis**
   - Reconstruct a chronological timeline
   - Flag “high-risk” actions (example: `/op`, `/give`, `/gamemode`)
   - Summarize per-admin behavior (counts, spikes, off-hours activity)

5. **Reporting**
   - Generate:
     - `timeline.csv` (or `.json`)
     - `admin_summary.txt`
     - `flagged_events.txt`
     - `hash_manifest.txt`

## Planned Features
### Required Features (Minimum Viable Product)
- Collect logs/config into an output folder
- Create SHA-256 hash manifest
- Parse logs and output a timeline
- Identify and report high-risk admin commands

### Stretch Goals (if time permits)
- Risk scoring (weighted actions + off-hours access)
- Player-centric view (filter timeline by actor)
- Simple “incident window” detection (clusters of suspicious activity)

## Deliverables
- Source code in this repository
- A written report describing:
  - design decisions
  - evidence sources
  - parsing logic
  - findings from a test dataset
  - limitations and future work
- Example outputs (sample timeline + reports)
- Presentation slide(s) summarizing the project (if required by the course)

## Testing Plan
- Create or use a sample server log set containing:
  - normal player activity
  - at least one admin misuse scenario (excessive `/give`, `/gamemode`, `/op`)
- Validate:
  - timeline ordering is correct
  - flagged commands appear correctly
  - hash manifest matches collected files

## Ethical / Legal Considerations
- The tool is designed for authorized forensic analysis of systems the investigator owns or has permission to examine.
- It does not attempt to deanonymize users or perform intrusive scanning.
- Evidence handling will follow best practices: analysis on copies, hashing for integrity, and clear documentation.

## Tools / Tech
- Bash or Python (final implementation depends on course expectations)
- Standard utilities for hashing and file handling
- Optional: Python `re` for parsing + CSV/JSON output

## Project Timeline (Example)
- Week 1: finalize requirements + repo structure
- Week 2: implement evidence collection + hashing
- Week 3: implement log parser + timeline output
- Week 4: implement admin summaries + flagged events
- Week 5: testing + documentation + final report

## Success Criteria
The project is successful if the tool can ingest a server log folder and reliably produce:
1) an evidence package with hashes, and  
2) a timeline + suspicious admin activity report that supports an incident investigation.

