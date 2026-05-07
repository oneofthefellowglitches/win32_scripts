<#
.SYNOPSIS
Collect AD health data: DC info, replication summary, FSMO roles, recent critical events. Produces CSV and HTML outputs and supports email.

.PARAMETER OutputFolder
  Folder to write reports. Default: .\AD-HealthReport-<date>\

.PARAMETER DaysEventWindow
  How many days back to collect critical/warning events. Default 1.

.PARAMETER MailTo
  Optional comma-separated recipients to email HTML report.

.PARAMETER DryRun
  If set, the script will list actions it would perform without calling repadmin/dcdiag.

.EXAMPLE
.\AD-HealthCheck.ps1 -OutputFolder C:\Reports\ADHealth -MailTo 'ops@example.com' -DaysEventWindow 2

Gather DC metadata with Get-ADDomainController.
Query FSMO holders via Get-ADForest/Get-ADDomain.
Run repadmin /replsummary and dcdiag -q for replication and diagnostics (parsed lightly).
Pull recent critical/warning events from Directory Service, System, DNS Server logs on each DC.
Export CSVs and a readable HTML report; optionally email the HTML.
Use DryRun for safe testing; schedule via Task Scheduler and integrate return codes into monitoring.

If event queries fail for a remote DC, verify WinRM/remote Event Log permissions and firewall; test with Get-WinEvent -ComputerName manually and ensure you can access Event Logs remotely.
#>

param(
    [string]$OutputFolder = ".\AD-HealthReport-$(Get-Date -Format yyyyMMdd-HHmmss)",
    [int]$DaysEventWindow = 1,
    [string]$MailTo = "",
    [switch]$DryRun,
    [switch]$VerboseLog
)

Set-StrictMode -Version Latest
Import-Module ActiveDirectory -ErrorAction Stop

function Log { param($m) if ($VerboseLog) { Write-Output "$(Get-Date -Format s) $m" } }

# Ensure output folder
if (-not $DryRun) { New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null } else { Log "DRYRUN: Would create folder $OutputFolder" }

# 1) Domain Controllers list
Log "Gathering domain controllers..."
$dcProps = @('Name','HostName','Site','OperatingSystem','OperatingSystemVersion','IsGlobalCatalog','IPv4Address')
$dcList = if ($DryRun) {
    Write-Output "DRYRUN: Would run Get-ADDomainController -Filter * -Properties $($dcProps -join ',')"
    @()
} else {
    Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object $dcProps
}

# 2) FSMO role holders
Log "Getting FSMO role holders..."
$fsmo = if ($DryRun) {
    @{ SchemaMaster = 'DRYRUN'; DomainNamingMaster='DRYRUN'; PDCEmulator='DRYRUN'; RIDMaster='DRYRUN'; InfrastructureMaster='DRYRUN' }
} else {
    $forest = Get-ADForest -ErrorAction Stop
    [ordered]@{
        SchemaMaster = $forest.SchemaMaster
        DomainNamingMaster = $forest.DomainNamingMaster
        PDCEmulator = (Get-ADDomain).PDCEmulator
        RIDMaster = (Get-ADDomain).RIDMaster
        InfrastructureMaster = (Get-ADDomain).InfrastructureMaster
    }
}

# 3) Replication summary (using repadmin /replsummary)
Log "Collecting replication summary..."
$repSummaryRaw = if ($DryRun) {
    "DRYRUN: repadmin /replsummary"
} else {
    & repadmin /replsummary 2>&1
}
# parse minimal info: failed exchanges count per DC (simple parse)
$repSummary = @()
if (-not $DryRun) {
    foreach ($line in $repSummaryRaw) {
        if ($line -match '^\s*(\d+)\s+Waiting\s+for\s+acknowledgement') { continue }
        if ($line -match '^Replication failures:\s+(\d+)') { $repSummary += [pscustomobject]@{ Metric='ReplicationFailures'; Value=[int]$matches[1] } }
    }
}

# 4) DCDiag run (optional brief)
Log "Running dcdiag -q (quick) on local machine (or remote if desired)..."
$dcdiagOutput = if ($DryRun) {
    "DRYRUN: dcdiag -q"
} else {
    & dcdiag -q 2>&1
}

# 5) Recent critical/warning events from AD-related channels on each DC
Log "Gathering recent critical/warning events from DCs..."
$events = @()
if (-not $DryRun) {
    $cutoff = (Get-Date).AddDays(-$DaysEventWindow)
    foreach ($dc in (Get-ADDomainController -Filter * -ErrorAction Stop)) {
        try {
            # Query System, Directory Service, and DNS Server logs for errors/warnings
            $logs = @('Directory Service','System','DNS Server')
            foreach ($log in $logs) {
                $found = Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{LogName=$log; Level=@(1,2,3); StartTime=$cutoff} -ErrorAction SilentlyContinue
                foreach ($e in $found) {
                    $events += [pscustomobject]@{
                        TimeCreated = $e.TimeCreated
                        Machine = $dc.HostName
                        LogName = $log
                        Id = $e.Id
                        LevelDisplayName = $e.LevelDisplayName
                        Message = ($e.Message -replace "`r`n","\n")
                    }
                }
            }
        } catch {
            Log "Warning: Failed to query events from $($dc.HostName): $($_.Exception.Message)"
        }
    }
} else {
    Log "DRYRUN: Would query event logs on each DC for Level 1-3 since $DaysEventWindow day(s) ago"
}

# 6) Build concise summary object
$summary = [ordered]@{
    ReportGenerated = (Get-Date).ToString("s")
    Domain = if (-not $DryRun) { (Get-ADDomain).DNSRoot } else { 'DRYRUN' }
    DCCount = if (-not $DryRun) { (Get-ADDomainController -Filter *).Count } else { 'DRYRUN' }
    ReplicationFailures = if ($repSummary) { ($repSummary | Where-Object {$_.Metric -eq 'ReplicationFailures'}).Value } else { 'Unknown/DRYRUN' }
    FSMO = $fsmo
    DCDiagSnippet = if ($DryRun) { $dcdiagOutput } else { ($dcdiagOutput | Select-Object -First 50) -join "`n" }
}

# 7) Export CSVs and HTML summary
$timestamp = Get-Date -Format yyyyMMdd-HHmmss
$dcCsv = Join-Path $OutputFolder "DCs-$timestamp.csv"
$eventsCsv = Join-Path $OutputFolder "Events-$timestamp.csv"
$summaryCsv = Join-Path $OutputFolder "Summary-$timestamp.csv"
$htmlReport = Join-Path $OutputFolder "AD-Health-$timestamp.html"

if ($DryRun) {
    Log "DRYRUN: Would export DC list to $dcCsv, events to $eventsCsv, summary to $summaryCsv and HTML to $htmlReport"
} else {
    $dcList | Export-Csv -Path $dcCsv -NoTypeInformation -Encoding UTF8
    $events | Export-Csv -Path $eventsCsv -NoTypeInformation -Encoding UTF8
    # Flatten summary into single-row CSV
    $summary | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $OutputFolder "Summary-$timestamp.json") -Encoding UTF8
    # Build simple HTML
    $html = @"
<html>
<head><title>AD Health Report - $timestamp</title></head>
<body>
<h1>AD Health Report</h1>
<p>Generated: $($summary.ReportGenerated)</p>
<h2>Domain summary</h2>
<ul>
<li>Domain: $($summary.Domain)</li>
<li>Domain Controllers: $($summary.DCCount)</li>
<li>Replication failures: $($summary.ReplicationFailures)</li>
</ul>
<h2>FSMO role holders</h2>
<ul>
<li>SchemaMaster: $($summary.FSMO.SchemaMaster)</li>
<li>DomainNamingMaster: $($summary.FSMO.DomainNamingMaster)</li>
<li>PDCEmulator: $($summary.FSMO.PDCEmulator)</li>
<li>RIDMaster: $($summary.FSMO.RIDMaster)</li>
<li>InfrastructureMaster: $($summary.FSMO.InfrastructureMaster)</li>
</ul>
<h2>Recent critical/warning events (last $DaysEventWindow day(s))</h2>
<table border='1' cellpadding='4' cellspacing='0'>
<tr><th>Time</th><th>Machine</th><th>Log</th><th>Id</th><th>Level</th><th>Message</th></tr>
"@

    foreach ($e in $events | Sort-Object TimeCreated -Descending | Select-Object -First 200) {
        $msg = [System.Web.HttpUtility]::HtmlEncode($e.Message)
        $html += "<tr><td>$($e.TimeCreated)</td><td>$($e.Machine)</td><td>$($e.LogName)</td><td>$($e.Id)</td><td>$($e.LevelDisplayName)</td><td><pre style='white-space:pre-wrap;'>$msg</pre></td></tr>`n"
    }

    $html += "</table></body></html>"
    $html | Out-File -FilePath $htmlReport -Encoding UTF8

    Log "Reports written: $dcCsv, $eventsCsv, $htmlReport"
}

# 8) Email report
if ($MailTo -and -not $DryRun) {
    try {
        $smtp = "localhost" # change as needed
        $subject = "AD Health Report - $timestamp"
        $body = "AD Health Report generated at $($summary.ReportGenerated). See attached HTML."
        Send-MailMessage -To $MailTo -From "ad-health@domain.local" -SmtpServer $smtp -Subject $subject -Body $body -Attachments $htmlReport -ErrorAction Stop
        Log "Emailed report to $MailTo"
    } catch {
        Log "Failed to send email: $($_.Exception.Message)"
    }
} elseif ($MailTo -and $DryRun) {
    Log "DRYRUN: Would send report to $MailTo (SMTP server configured in script)"
}

if (-not $DryRun) {
    if ($repSummaryRaw -match 'FAILED|error|fail') { exit 2 } else { exit 0 }
} else {
    exit 0
}
