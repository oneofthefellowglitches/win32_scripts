<#
.SYNOPSIS
Reconcile AD group membership from CSV.

CSV format: GroupName, Members
Members = semicolon-separated list of SamAccountName or user principal names.

.PARAMETER InputCsv
  Path to CSV mapping groups to desired members.

.PARAMETER DryRun
  Show planned adds/removes without making changes.

.PARAMETER OutputCsv
  Path to write reconciliation results.

.PARAMETER SkipRemove
  If set, script will only add missing members, not remove extras.

If Add-ADGroupMember or Remove-ADGroupMember errors with "Some specified accounts do not exist", 
verify whether names are SamAccountName vs UPN and test Resolve with Get-ADUser; log unmapped names separately for manual review.
#>

param(
    [string]$InputCsv = ".\group-membership.csv",
    [switch]$DryRun,
    [string]$OutputCsv = ".\reconcile-results.csv",
    [switch]$SkipRemove,
    [switch]$VerboseLog
)

Import-Module ActiveDirectory -ErrorAction Stop
Set-StrictMode -Version Latest

function Log { param($m) if ($VerboseLog) { Write-Output "$(Get-Date -Format s) $m" } }

if (-not (Test-Path $InputCsv)) { Throw "Input CSV not found: $InputCsv" }

$rows = Import-Csv -Path $InputCsv
$results = @()

foreach ($row in $rows) {
    $groupName = $row.GroupName.Trim()
    $desired = @()
    if ($row.Members) {
        $desired = ($row.Members -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    }

    $resItem = [ordered]@{
        Group = $groupName
        DesiredCount = $desired.Count
        CurrentCount = 0
        ToAdd = ''
        ToRemove = ''
        Result = ''
        Error = ''
    }

    try {
        $group = Get-ADGroup -Identity $groupName -ErrorAction Stop

        # Get current direct members SamAccountNames
        $currentMembers = Get-ADGroupMember -Identity $groupName -Recursive:$false -ErrorAction Stop |
            Where-Object { $_.objectClass -eq 'user' } |
            ForEach-Object {
                try { (Get-ADUser -Identity $_.DistinguishedName -Properties SamAccountName -ErrorAction Stop).SamAccountName }
                catch { $_.SamAccountName }
            }

        $resItem.CurrentCount = $currentMembers.Count

        # Normalize desired to samAccountName where possible
        $desiredSam = @()
        foreach ($d in $desired) {
            if ($d -match '@') {
                # userPrincipalName -> resolve to samAccountName
                $u = Get-ADUser -Filter { UserPrincipalName -eq $d } -ErrorAction SilentlyContinue
                if ($u) { $desiredSam += $u.SamAccountName } else { $desiredSam += $d }
            } else {
                # assume samAccountName; verify exists
                $u = Get-ADUser -Identity $d -ErrorAction SilentlyContinue
                if ($u) { $desiredSam += $u.SamAccountName } else { $desiredSam += $d }
            }
        }

        # Compute difference
        $toAdd = $desiredSam | Where-Object { $_ -and ($_ -notin $currentMembers) } | Sort-Object -Unique
        $toRemove = $currentMembers | Where-Object { $_ -and ($_ -notin $desiredSam) } | Sort-Object -Unique

        $resItem.ToAdd = ($toAdd -join ';')
        $resItem.ToRemove = ($toRemove -join ';')

        # Perform actions unless DryRun
        if ($toAdd.Count -gt 0) {
            foreach ($m in $toAdd) {
                if ($DryRun) {
                    Log "DRYRUN: Would add $m to $groupName"
                } else {
                    try {
                        Add-ADGroupMember -Identity $groupName -Members $m -ErrorAction Stop
                        Log "Added $m to $groupName"
                    } catch {
                        Log "Failed to add $m to $groupName: $($_.Exception.Message)"
                        $resItem.Error += "Add:$m:$($_.Exception.Message); "
                    }
                }
            }
        }

        if (-not $SkipRemove -and $toRemove.Count -gt 0) {
            foreach ($m in $toRemove) {
                if ($DryRun) {
                    Log "DRYRUN: Would remove $m from $groupName"
                } else {
                    try {
                        Remove-ADGroupMember -Identity $groupName -Members $m -Confirm:$false -ErrorAction Stop
                        Log "Removed $m from $groupName"
                    } catch {
                        Log "Failed to remove $m from $groupName: $($_.Exception.Message)"
                        $resItem.Error += "Remove:$m:$($_.Exception.Message); "
                    }
                }
            }
        } elseif ($SkipRemove -and $toRemove.Count -gt 0) {
            Log "SkipRemove set: not removing extras from $groupName"
        }

        $resItem.Result = 'Success'
    } catch {
        $resItem.Result = 'Failed'
        $resItem.Error = $_.Exception.Message
    }

    $results += New-Object psobject -Property $resItem
}

$results | Select-Object Group,DesiredCount,CurrentCount,ToAdd,ToRemove,Result,Error |
    Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Output "Reconciliation complete. Results: $OutputCsv"
