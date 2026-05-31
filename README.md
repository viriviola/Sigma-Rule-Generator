# Sigma Rule Generator

Convert threat report techniques into production-ready Sigma detection rules.

## What This Does

1. You read a hacker threat report
2. You list the attack techniques
3. This script creates detection rules automatically

## Files Created

- `rules/` - Sigma rules for your SIEM
- `output/soc_runbook.md` - Instructions for SOC analysts
- `output/mitre_map.html` - MITRE ATT&CK visualization

## How to Use

1. Edit `TECHNIQUES` in `sigma_generator.py`
2. Run `python sigma_generator.py`
3. Import `rules/*.yml` into your SIEM

## Example Output

The script creates rules like this:

```yaml
title: Detection: PowerShell with Encoded Commands
detection:
  selection:
    Image|endswith: "\powershell.exe"
    CommandLine|contains: "-EncodedCommand"
  condition: selection
level: high