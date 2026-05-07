<#
.SYNOPSIS
Find inactive AD user accounts and optionally disable them.

.PARAMETER DaysIdle
  Accounts idle for this many days or more are reported/acted on. Default 90.

.PARAMETER OU
  Optional distinguishedName or LDAP path to scope the search.

.PARAMETER Disable
  If present the script will disable found accounts (safe: respects DryRun).

.PARAMETER DryRun
  Show planned actions without making changes.

.PARAMETER OutputCsv
  Path to write results CSV.

.EXAMPLE
.\Find-Disable-IdleAccounts.ps1 -DaysIdle 120 -OU "OU=Employees,DC=contoso,DC=com" -OutputCsv .\idle.csv -DryRun


Gather users (optionally scoped by OU) and read lastLogonTimestamp/lastLogon/whenCreated.
Compute idle period and mark accounts idle if last activity is older than threshold or absent.
By default, generate a report; if -Disable is set and not -DryRun, disable accounts and record actions.
Export a CSV with planned actions, results, and errors for auditing.

If lastLogonTimestamp appears stale, trigger and check replication (repadmin /showrepl) and query multiple DCs for lastLogon to confirm true inactivity
#>

param(
    [int]$DaysIdle = 90,
    [string]$OU = '',
    [switch]$Disable,
    [switch]$DryRun,
    [string]$OutputCsv = ".\idle-accounts.csv",
    [switch]$VerboseLog
)

Import-Module ActiveDirectory -ErrorAction Stop
Set-StrictMode -Version Latest

function Write-Log { param($m,$level='INFO') if ($VerboseLog -or $level -ne 'DEBUG') { "$((Get-Date).ToString('s')) [$level] $m" } }

# Convert days to DateTime threshold
$thresholdDate = (Get-Date).AddDays(-$DaysIdle)
Write-Log "Searching for user accounts not logged on since $thresholdDate (or never logged on)."

# LDAP filter: userAccountControl excludes disabled/system accounts; search enabled and disabled to report both but filter out special accounts
$filter = '(&(objectCategory=person)(objectClass=user))'

$searchParams = @{
    Filter = $filter
    Properties = @('SamAccountName','DistinguishedName','DisplayName','lastLogonTimestamp','lastLogon','whenCreated','mail','Enabled')
    ErrorAction = 'Stop'
    ResultSetSize = $null
}
if ($OU -and $OU.Trim()) { $searchParams.SearchBase = $OU }

$allUsers = Get-ADUser @searchParams

$results = foreach ($u in $allUsers) {
    # Normalize last logon using lastLogonTimestamp (replicated) and lastLogon (per-DC) fallback
    $lastLogonTS = if ($u.lastLogonTimestamp) { [DateTime]::FromFileTime($u.lastLogonTimestamp) } else { $null }
    $lastLogon = if ($u.lastLogon) { [DateTime]::FromFileTime($u.lastLogon) } else { $null }

    # Choose the latest meaningful logon
    $lastActivity = @($lastLogonTS,$lastLogon) | Where-Object { $_ -ne $null } | Sort-Object -Descending | Select-Object -First 1

    # If no logon entries, use whenCreated as fallback (treat as never logged on)
    $whenCreated = $u.whenCreated
    if (-not $lastActivity -and $whenCreated) { $lastActivity = $whenCreated }

    # Determine idle days
    $idleDays = if ($lastActivity) { (New-TimeSpan -Start $lastActivity -End (Get-Date)).Days } else { $null }

    # Decide if considered idle
    $isIdle = $false
    if ($lastActivity) {
        if ($lastActivity -lt $thresholdDate) { $isIdle = $true }
    } else {
        # no activity recorded => treat as idle
        $isIdle = $true
    }

    if ($isIdle) {
        [pscustomobject]@{
            Timestamp         = (Get-Date).ToString("s")
            SamAccountName    = $u.SamAccountName
            DisplayName       = $u.DisplayName
            DistinguishedName = $u.DistinguishedName
            Mail              = $u.mail
            Enabled           = $u.Enabled
            LastActivity      = ($lastActivity -as [string])
            IdleDays          = ($idleDays -as [string])
            ActionPlanned     = (if ($Disable) { 'Disable' } else { 'ReportOnly' })
            ActionResult      = ''
            ErrorMessage      = ''
        }
    }
}

if (-not $results) {
    Write-Log "No idle accounts found matching criteria." 'INFO'
    $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    exit 0
}

# Act on results if requested
foreach ($r in $results) {
    try {
        if ($Disable) {
            if ($DryRun) {
                Write-Log "DRY RUN: Would disable $($r.SamAccountName) (IdleDays: $($r.IdleDays))"
                $r.ActionResult = 'DryRun - Skipped'
            } else {
                Disable-ADAccount -Identity $r.SamAccountName -ErrorAction Stop
                $r.ActionResult = 'Disabled'
                Write-Log "Disabled $($r.SamAccountName)" 'INFO'
            }
        } else {
            $r.ActionResult = 'Reported'
        }
    } catch {
        $r.ActionResult = 'Failed'
        $r.ErrorMessage = $_.Exception.Message
        Write-Log "ERROR acting on $($r.SamAccountName): $($r.ErrorMessage)" 'ERROR'
    }
}

# Export CSV
$results | Select-Object Timestamp,SamAccountName,DisplayName,DistinguishedName,Mail,Enabled,LastActivity,IdleDays,ActionPlanned,ActionResult,ErrorMessage |
    Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Log "Done. Results exported to $OutputCsv" 'INFO'
