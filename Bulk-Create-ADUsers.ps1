<#
.SYNOPSIS
Bulk create AD users from CSV with dry-run and logging.

CSV columns required: GivenName, Surname, SamAccountName, OU, Password
Optional: DisplayName, UserPrincipalName, Groups (semicolon-separated), Description

Validate CSV exists and required columns per row: GivenName, Surname, SamAccountName, OU, Password.
Skip existing SamAccountName to make the script idempotent.
Build New-ADUser parameters; set ChangePasswordAtLogon = $true and PasswordNeverExpires = $false. Use SecureString for password.
Support DryRun: if -DryRun is passed, the script prints planned actions and records DryRun results without making changes.
Create user with New-ADUser, then Enable-ADAccount explicitly.
Add user to semicolon-separated group list; log group-level errors but continue.
Collect per-user results and export to results.csv with timestamp, status, and error messages.

Re-run a failing SamAccountName with -Verbose and wrap the New-ADUser call in try/catch 
to capture $.Exception | Out-String; also check AD replication latency between DCs (repadmin /replsummary) if creations appear inconsistent.
#>

param(
    [switch]$DryRun,
    [string]$InputCsv = ".\users.csv",
    [string]$OutputCsv = ".\results.csv",
    [switch]$VerboseLog
)

Set-StrictMode -Version Latest
Import-Module ActiveDirectory -ErrorAction Stop

function Write-Log {
    param($Message,$Level='INFO')
    if ($VerboseLog -or $Level -ne 'DEBUG') {
        $time = (Get-Date).ToString("s")
        Write-Output "$time [$Level] $Message"
    }
}

if (-not (Test-Path $InputCsv)) {
    Throw "Input CSV not found: $InputCsv"
}

$users = Import-Csv -Path $InputCsv
$results = [System.Collections.ArrayList]::new()

foreach ($u in $users) {
    $r = [ordered]@{
        Timestamp      = (Get-Date).ToString("s")
        SamAccountName = $u.SamAccountName
        GivenName      = $u.GivenName
        Surname        = $u.Surname
        OU             = $u.OU
        Result         = ''
        ErrorMessage   = ''
    }

    try {
        # Basic validation
        foreach ($col in @('GivenName','Surname','SamAccountName','OU','Password')) {
            if (-not $u.PSObject.Properties.Name -contains $col -or [string]::IsNullOrWhiteSpace($u.$col)) {
                throw "Missing required column/value: $col"
            }
        }

        # Check if account already exists
        $exists = Get-ADUser -Filter { SamAccountName -eq $u.SamAccountName } -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Log "SamAccountName '$($u.SamAccountName)' already exists. Skipping." 'INFO'
            $r.Result = 'Skipped - Exists'
            $results.Add((New-Object psobject -Property $r)) | Out-Null
            continue
        }

        # Build New-ADUser parameters
        $newParams = @{
            Name           = ($u.DisplayName -ne $null -and $u.DisplayName.Trim() -ne '') ? $u.DisplayName : ("$($u.GivenName) $($u.Surname)")
            GivenName      = $u.GivenName
            Surname        = $u.Surname
            SamAccountName = $u.SamAccountName
            Path           = $u.OU
            Enabled        = $false    # will enable after setting password
            AccountPassword = (ConvertTo-SecureString $u.Password -AsPlainText -Force)
            ChangePasswordAtLogon = $true
            PasswordNeverExpires = $false
            Description    = $u.Description
        }

        if ($u.UserPrincipalName -and $u.UserPrincipalName.Trim()) { $newParams.UserPrincipalName = $u.UserPrincipalName }

        # Dry-run: show planned action
        if ($DryRun) {
            Write-Log "DRY RUN: Would create user $($newParams.Name) with SamAccountName $($newParams.SamAccountName) in OU $($newParams.Path)" 'INFO'
            if ($u.Groups) {
                Write-Log "DRY RUN: Would add to groups: $($u.Groups)" 'INFO'
            }
            $r.Result = 'DryRun - OK'
            $results.Add((New-Object psobject -Property $r)) | Out-Null
            continue
        }

        # Create the user
        Write-Log "Creating user $($newParams.SamAccountName)" 'INFO'
        New-ADUser @newParams -ErrorAction Stop

        # Enable the account explicitly (New-ADUser with AccountPassword + Enabled should enable, but be explicit)
        Enable-ADAccount -Identity $u.SamAccountName -ErrorAction Stop

        # Add to groups (if provided)
        if ($u.Groups -and $u.Groups.Trim()) {
            $groupList = $u.Groups -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
            foreach ($g in $groupList) {
                try {
                    Add-ADGroupMember -Identity $g -Members $u.SamAccountName -ErrorAction Stop
                    Write-Log "Added $($u.SamAccountName) to group $g" 'INFO'
                } catch {
                    # If group not found, record but continue
                    Write-Log "Failed to add to group $g: $($_.Exception.Message)" 'ERROR'
                    # append to error message but don't fail whole user creation
                    $r.ErrorMessage += "Group:$g error:$($_.Exception.Message); "
                }
            }
        }

        $r.Result = 'Created'
        Write-Log "Created user $($u.SamAccountName) successfully." 'INFO'
    } catch {
        $msg = $_.Exception.Message
        Write-Log "ERROR processing $($u.SamAccountName): $msg" 'ERROR'
        $r.Result = 'Failed'
        $r.ErrorMessage = $msg
    }

    $results.Add((New-Object psobject -Property $r)) | Out-Null
}

# Export results
$results | Select-Object Timestamp,SamAccountName,GivenName,Surname,OU,Result,ErrorMessage |
    Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Log "Done. Results exported to $OutputCsv" 'INFO'
