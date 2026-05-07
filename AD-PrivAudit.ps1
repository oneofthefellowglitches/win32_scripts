<#
.SYNOPSIS
Audit and optionally remediate privileged AD group membership.

.PARAMETER PrivGroups
  Comma-separated group names to audit (default common privileged groups).

.PARAMETER AllowListCsv
  CSV with SamAccountName column listing allowed privileged accounts.

.PARAMETER OutputCsv
  Path for output CSV.

.PARAMETER Enforce
  If present, remove members not in allowlist (requires rights). Use with caution.

.PARAMETER DryRun
  Show planned removals without making changes.

.PARAMETER VerboseLog
  More output.

If Remove-ADGroupMember fails with “Insufficient access”, run the script using an account in Domain Admins or with delegated rights, and verify no nested group with protected membership or recycle-bin/replication latency blocking changes
#>

param(
    [string]$PrivGroups = "Domain Admins,Enterprise Admins,Schema Admins,Administrators",
    [string]$AllowListCsv = ".\AllowList.csv",
    [string]$OutputCsv = ".\PrivilegedMembers.csv",
    [switch]$Enforce,
    [switch]$DryRun,
    [switch]$VerboseLog
)

Import-Module ActiveDirectory -ErrorAction Stop
Set-StrictMode -Version Latest
function Log { param($m) if ($VerboseLog) { Write-Output "$(Get-Date -Format s) $m" } }

# Load allowlist
$allowed = @()
if (Test-Path $AllowListCsv) {
    try {
        $allowed = Import-Csv -Path $AllowListCsv | ForEach-Object { $_.SamAccountName.Trim().ToLower() } | Where-Object { $_ -ne '' } | Sort-Object -Unique
        Log "Loaded allowlist with $($allowed.Count) entries"
    } catch {
        Throw "Failed to read allowlist: $($_.Exception.Message)"
    }
} else {
    Log "AllowList not found; treating allowlist as empty (no one allowed)" 
}

# Prepare group list
$groupNames = $PrivGroups -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

$results = @()

foreach ($gname in $groupNames) {
    try {
        $group = Get-ADGroup -Identity $gname -ErrorAction Stop
    } catch {
        Log "Group not found: $gname"
        continue
    }

    # Get recursive members: returns users and groups; filter users
    $members = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }

    foreach ($m in $members) {
        # resolve SamAccountName and DN
        $user = Get-ADUser -Identity $m.SamAccountName -Properties SamAccountName,DistinguishedName -ErrorAction SilentlyContinue
        $sam = if ($user) { $user.SamAccountName } else { $m.SamAccountName }
        $dn  = if ($user) { $user.DistinguishedName } else { $m.DistinguishedName }

        $isAllowed = ($allowed -contains $sam.ToLower())
        $res = [pscustomobject]@{
            Group = $gname
            MemberSamAccountName = $sam
            MemberDistinguishedName = $dn
            Allowed = $isAllowed
            ActionPlanned = if ($isAllowed) { 'None' } else { if ($Enforce) { 'Remove' } else { 'ReportOnly' } }
            ActionResult = ''
            Error = ''
        }

        # If enforcement requested and member not allowed, remove
        if ($Enforce -and -not $isAllowed) {
            if ($DryRun) {
                Log "DRYRUN: Would remove $sam from $gname"
                $res.ActionResult = 'DryRun - NotRemoved'
            } else {
                try {
                    Remove-ADGroupMember -Identity $group.DistinguishedName -Members $sam -Confirm:$false -ErrorAction Stop
                    Log "Removed $sam from $gname"
                    $res.ActionResult = 'Removed'
                } catch {
                    $res.ActionResult = 'Failed'
                    $res.Error = $_.Exception.Message
                    Log "Failed to remove $sam from $gname: $($res.Error)"
                }
            }
        } else {
            $res.ActionResult = 'NoAction'
        }

        $results += $res
    }

    # If no direct users found, record empty note
    if ($members.Count -eq 0) {
        $results += [pscustomobject]@{
            Group = $gname
            MemberSamAccountName = ''
            MemberDistinguishedName = ''
            Allowed = $false
            ActionPlanned = 'None'
            ActionResult = 'NoMembers'
            Error = ''
        }
    }
}

# Export results
$results | Select-Object Group,MemberSamAccountName,MemberDistinguishedName,Allowed,ActionPlanned,ActionResult,Error |
    Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Output "Audit complete. Results exported to $OutputCsv"
if ($Enforce -and -not $DryRun) { Write-Output "Enforcement run completed." }
if ($Enforce -and $DryRun) { Write-Output "Enforcement dry-run completed; no changes made." }
