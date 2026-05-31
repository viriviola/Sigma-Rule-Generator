# Sigma Rule Generator

![Python](https://img.shields.io/badge/Python-3.7+-blue)
![Sigma](https://img.shields.io/badge/Sigma-Detection%20Rules-red)
![MITRE ATT%26CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)
![Detection Engineering](https://img.shields.io/badge/Detection-Engineering-green)
![License](https://img.shields.io/badge/License-Educational-lightgrey)

Convert threat intelligence reports into production-ready Sigma detection rules, SOC investigation runbooks, and MITRE ATT&CK coverage maps.

This project bridges the gap between **Threat Intelligence**, **Detection Engineering**, **SOC Operations**, and **Adversary Analysis** by automating the creation of detection content from identified attacker techniques.

---

## Overview

Threat reports often contain valuable information about attacker tactics, techniques, and procedures (TTPs), but transforming those findings into actionable detections is usually a manual and time-consuming process.

This project automates that workflow by allowing analysts to define techniques extracted from threat reports and automatically generate:

* Sigma detection rules
* SOC investigation runbooks
* MITRE ATT&CK coverage visualizations

The result is faster detection development and improved operational readiness.

---

## The Problem It Solves

| Traditional Workflow                | With Sigma Rule Generator        |
| ----------------------------------- | -------------------------------- |
| Manually write Sigma rules          | Auto-generated Sigma rules       |
| Create analyst investigation guides | Auto-generated runbooks          |
| Build MITRE coverage documentation  | Auto-generated ATT&CK map        |
| Hours of repetitive work            | Minutes of review and validation |

For a threat report containing multiple techniques, the tool significantly reduces the effort required to operationalize intelligence.

---

## Features

### Sigma Rule Generation

Automatically generates Sigma-compatible detection rules based on:

* MITRE ATT&CK technique IDs
* Detection logic
* Adversary behavior
* Command-line indicators

Generated rules can be adapted for:

* Splunk
* Elastic Security
* Microsoft Sentinel
* QRadar
* Other Sigma-compatible platforms

---

### SOC Runbook Generation

Creates analyst-ready investigation guides including:

* Alert description
* Investigation steps
* False positive considerations
* Containment recommendations

This helps SOC teams standardize incident response procedures.

---

### MITRE ATT&CK Coverage Mapping

Generates an HTML visualization showing:

* Technique coverage
* ATT&CK tactics
* Detection mappings
* Coverage statistics

This provides a quick overview of detection engineering coverage.

---

### Threat Intelligence Operationalization

Transforms intelligence reports into:

```text
Threat Report
      │
      ▼
Technique Extraction
      │
      ▼
Detection Content Generation
      │
 ┌────┼────┐
 ▼    ▼    ▼
Sigma  SOC  MITRE
Rules Runbook Map
```

---

## Project Structure

```text
sigma-rule-generator/
│
├── generate.py
│
├── templates/
│   └── mitre_map.html
│
├── rules/
│   └── *.yml
│
├── output/
│   ├── soc_runbook.md
│   └── mitre_map.html
│
└── README.md
```

### File Descriptions

| File                     | Purpose                                  |
| ------------------------ | ---------------------------------------- |
| generate.py              | Main detection content generation script |
| templates/mitre_map.html | MITRE ATT&CK visualization template      |
| rules/                   | Generated Sigma detection rules          |
| output/soc_runbook.md    | Generated analyst investigation guide    |
| output/mitre_map.html    | Generated ATT&CK coverage visualization  |
| README.md                | Project documentation                    |

---

## Skills Demonstrated

| Domain                | Demonstrated Capability                     |
| --------------------- | ------------------------------------------- |
| Threat Intelligence   | TTP extraction from threat reports          |
| Detection Engineering | Sigma rule creation                         |
| MITRE ATT&CK          | Technique mapping and coverage analysis     |
| SOC Operations        | Investigation runbook generation            |
| Adversary Analysis    | Technique identification and classification |
| Security Automation   | Automated content generation                |

---

## Installation

### Prerequisites

* Python 3.7 or higher

No third-party dependencies are required.

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/sigma-rule-generator.git
cd sigma-rule-generator
```

---

## Usage

### Step 1: Define Techniques

Open `generate.py` and edit the `TECHNIQUES` list:

```python
TECHNIQUES = [
    {
        "name": "PowerShell with Encoded Commands",
        "mitre_id": "T1059.001",
        "tactic": "Execution",
        "what_to_detect": "powershell.exe with -EncodedCommand flag",
        "command": "powershell.exe -EncodedCommand <base64>"
    }
]
```

---

### Step 2: Generate Detection Content

Run the script:

```bash
python generate.py
```

---

### Step 3: Review Outputs

Generated files include:

```text
rules/
├── rule_powershell.yml
├── rule_wmi.yml
└── ...

output/
├── soc_runbook.md
└── mitre_map.html
```

---

## Output Files

### Sigma Detection Rules

Generated YAML rules contain:

* Detection logic
* Log source information
* ATT&CK references
* Severity levels
* Detection conditions

Example:

```yaml
title: Detection: PowerShell with Encoded Commands
status: experimental
description: Detects powershell.exe with -EncodedCommand flag
level: high
```

---

### SOC Investigation Runbook

Generated runbooks provide:

* Alert context
* Investigation procedures
* Validation steps
* False positive guidance
* Containment recommendations

---

### MITRE ATT&CK Coverage Map

The generated HTML dashboard displays:

* Technique coverage
* ATT&CK tactic breakdown
* Detection mappings
* Coverage metrics

---

## Example Techniques

The project currently supports techniques such as:

| Technique                   | MITRE ID  | Tactic           |
| --------------------------- | --------- | ---------------- |
| PowerShell Encoded Commands | T1059.001 | Execution        |
| PowerShell Download Cradle  | T1059.001 | Execution        |
| WMI Lateral Movement        | T1047     | Lateral Movement |
| WMI Event Subscription      | T1546.003 | Persistence      |
| Scheduled Tasks             | T1053.005 | Persistence      |
| BITSAdmin Download          | T1197     | Defense Evasion  |
| Rundll32 Execution          | T1218.011 | Defense Evasion  |

---

## Dashboard Preview

Add screenshots here:

```markdown
![MITRE Coverage Map](screenshots/mitre_map.png)
```

---

## Future Enhancements

Potential improvements include:

* Additional Sigma rule templates
* Elastic EQL support
* Splunk SPL generation
* Sigma rule validation pipeline
* MISP integration
* STIX/TAXII support
* CI/CD rule testing
* Automated ATT&CK Navigator export

---

## Learning Outcomes

This project demonstrates practical experience with:

* Threat Intelligence Analysis
* Detection Engineering
* MITRE ATT&CK Framework
* SOC Operations
* Adversary Behavior Analysis
* Security Automation

---

## Author

**Alaka Parida**

Built to demonstrate a multidisciplinary cybersecurity role combining:

* Threat Intelligence
* Detection Engineering
* SOC Operations
* Adversary Analysis

---

## License

This project is intended for educational, research, and portfolio purposes.
