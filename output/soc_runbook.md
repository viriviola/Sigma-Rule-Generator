# SOC Runbook

## Techniques

- PowerShell with Encoded Commands (T1059.001): powershell.exe with -EncodedCommand flag
- WMI Lateral Movement (T1047): wmiprvse.exe spawning cmd.exe
- Scheduled Tasks for Persistence (T1053.005): schtasks.exe creating new tasks
- PowerShell Download Cradle (T1059.001): powershell.exe with Invoke-Expression and DownloadString
- WMI Event Subscription (T1546.003): Register-WmiEvent or __FilterToConsumerBinding
- BITSAdmin Download (T1197): bitsadmin.exe /transfer /download
- Rundll32 Execution (T1218.011): rundll32.exe executing .dll or .cpl files
