# Alert 1: PsExec Lateral Movement
Write-Host "=== Alert 1: PsExec Lateral Movement ==="
$b1 = @{
    alert_name = "PsExec Remote Service Installation"
    description = "PsExec.exe detected installing PSEXESVC on remote host DC-PROD-01. Source user admin_jsmith executed from IT-WORKSTATION-07. Multiple lateral movement attempts to 3 domain controllers detected within 5 minutes."
    severity = "critical"
    hostname = "DC-PROD-01"
    username = "admin_jsmith"
    source_ip = "10.10.5.22"
    dest_ip = "10.10.1.5"
    mitre_technique = "T1570"
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:5000/ingest" -Method POST -Body $b1 -ContentType "application/json" | ConvertTo-Json
Start-Sleep -Seconds 2

# Alert 2: Ransomware File Encryption
Write-Host "=== Alert 2: Ransomware File Encryption ==="
$b2 = @{
    alert_name = "Mass File Extension Change Detected"
    description = "Over 500 files renamed with .encrypted extension in shared drive \\FILESERV01\finance within 2 minutes. Process svchost.exe spawned unusual child process that is iterating through directories."
    severity = "critical"
    hostname = "FILESERV01"
    username = "svc_backup"
    source_ip = "10.10.3.100"
    mitre_technique = "T1486"
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:5000/ingest" -Method POST -Body $b2 -ContentType "application/json" | ConvertTo-Json
Start-Sleep -Seconds 2

# Alert 3: Suspicious OAuth Token
Write-Host "=== Alert 3: Suspicious OAuth Token ==="
$b3 = @{
    alert_name = "Unusual OAuth Token Grant"
    description = "OAuth application 'DataSync Pro' granted admin consent for Mail.ReadWrite and Files.ReadWrite.All permissions. Consent granted by user from IP geolocated to unusual country. Application registered 2 hours ago."
    severity = "high"
    hostname = "AZURE-AD"
    username = "cfo_williams"
    source_ip = "185.156.73.44"
    mitre_technique = "T1550.001"
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:5000/ingest" -Method POST -Body $b3 -ContentType "application/json" | ConvertTo-Json
Start-Sleep -Seconds 2

# Alert 4: Benign Scheduled Backup
Write-Host "=== Alert 4: Benign Scheduled Backup ==="
$b4 = @{
    alert_name = "Large Data Transfer to External Storage"
    description = "Veeam backup agent transferring 250GB to Azure Blob Storage. Transfer matches weekly backup schedule defined in IT-POLICY-2024-03. All data encrypted with AES-256."
    severity = "low"
    hostname = "BACKUP-SRV-01"
    username = "svc_veeam"
    source_ip = "10.10.2.50"
    dest_ip = "52.239.228.100"
    mitre_technique = "T1567"
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:5000/ingest" -Method POST -Body $b4 -ContentType "application/json" | ConvertTo-Json
Start-Sleep -Seconds 2

# Alert 5: Supply Chain Attack
Write-Host "=== Alert 5: Supply Chain Attack ==="
$b5 = @{
    alert_name = "NPM Package with Post-Install Script Anomaly"
    description = "Developer workstation installed npm package 'event-stream-utils' which triggered post-install script downloading binary from pastebin.com. Package was added to project dependencies 1 hour ago by unknown contributor."
    severity = "high"
    hostname = "DEV-LAPTOP-14"
    username = "dev_sarah"
    source_ip = "10.10.6.88"
    dest_ip = "104.20.67.143"
    mitre_technique = "T1195.002"
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:5000/ingest" -Method POST -Body $b5 -ContentType "application/json" | ConvertTo-Json

Write-Host "`n=== All 5 alerts sent! ==="
