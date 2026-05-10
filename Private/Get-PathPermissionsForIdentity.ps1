#Requires -Version 5.1

function Get-PathPermissionsForIdentity {
    <#
    .SYNOPSIS
        Checks whether an IIS application pool identity has explicit ACEs on a path.

    .DESCRIPTION
        Reads the ACL on the specified path and looks for Access Control Entries
        that match the effective Windows account for the given identity type.

        For ApplicationPoolIdentity and NetworkService, also checks IIS_IUSRS
        (the local group all IIS worker process accounts belong to).

        Returns a structured result. A Status of NoExplicitAce does not mean the
        identity has no access - inheritance, group membership, and share permissions
        are not evaluated. It means no direct ACE was found that we can confirm.

    .PARAMETER Path
        The local filesystem path to check. UNC paths are not supported.

    .PARAMETER IdentityType
        The pool identity type string (ApplicationPoolIdentity, NetworkService,
        LocalService, LocalSystem, SpecificUser).

    .PARAMETER UserName
        The configured username for SpecificUser identity.

    .PARAMETER PoolName
        The application pool name. Required for ApplicationPoolIdentity to
        construct the virtual account name (IIS AppPool\{PoolName}).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$IdentityType,
        [string]$UserName,
        [string]$PoolName
    )

    function New-Result {
        param([string]$Status, [string]$EffectiveIdentity, [string]$AccessRights, [string]$Detail)
        [pscustomobject]@{
            PSTypeName        = 'IISDiagnostics.PathPermissions'
            CheckPerformed    = $true
            Status            = $Status
            EffectiveIdentity = $EffectiveIdentity
            AccessRights      = $AccessRights
            Detail            = $Detail
        }
    }

    # LocalSystem has unrestricted local access - no ACL check needed
    if ($IdentityType -eq 'LocalSystem') {
        return [pscustomobject]@{
            PSTypeName        = 'IISDiagnostics.PathPermissions'
            CheckPerformed    = $false
            Status            = 'NotRequired'
            EffectiveIdentity = 'NT AUTHORITY\SYSTEM'
            AccessRights      = 'FullControl'
            Detail            = 'LocalSystem has unrestricted local access. No ACL check required.'
        }
    }

    # Resolve the primary account name to search for
    $primaryAccount = switch ($IdentityType) {
        'ApplicationPoolIdentity' {
            if ($PoolName) { "IIS AppPool\$PoolName" } else { $null }
        }
        'NetworkService' { 'NT AUTHORITY\NETWORK SERVICE' }
        'LocalService'   { 'NT AUTHORITY\LOCAL SERVICE'   }
        'SpecificUser'   { $UserName }
        default          { $null }
    }

    # ApplicationPoolIdentity and NetworkService are also members of IIS_IUSRS
    $checkIisIusrs = $IdentityType -in 'ApplicationPoolIdentity', 'NetworkService'

    if (-not $primaryAccount -and -not $checkIisIusrs) {
        return New-Result -Status 'CheckFailed' `
                           -EffectiveIdentity '(unknown)' `
                           -AccessRights $null `
                           -Detail "Could not determine the effective Windows account for identity type '$IdentityType'."
    }

    # Read the ACL
    $acl = $null
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        $effectiveIdentity = if ($primaryAccount) { $primaryAccount } else { '(unknown)' }
        return New-Result -Status 'CheckFailed' `
                           -EffectiveIdentity $effectiveIdentity `
                           -AccessRights $null `
                           -Detail "Could not read ACL on '$Path': $_"
    }

    # Search for matching ACEs (case-insensitive - Windows identity names are not case-sensitive)
    $matchedAce     = $null
    $iisIusrsAce    = $null
    $accountsToLog  = [System.Collections.Generic.List[string]]::new()
    if ($primaryAccount) { $accountsToLog.Add($primaryAccount) }
    if ($checkIisIusrs)  { $accountsToLog.Add('BUILTIN\IIS_IUSRS') }

    foreach ($ace in $acl.Access) {
        $ref = $ace.IdentityReference.Value

        if ($primaryAccount -and $ref -like "*$($primaryAccount.Split('\')[-1])*") {
            # Loose match on the account name portion (handles domain prefix variations)
            if ($null -eq $matchedAce -or $ace.AccessControlType -eq 'Allow') {
                $matchedAce = $ace
            }
        }

        if ($checkIisIusrs -and $ref -match 'IIS_IUSRS') {
            if ($null -eq $iisIusrsAce -or $ace.AccessControlType -eq 'Allow') {
                $iisIusrsAce = $ace
            }
        }
    }

    $effectiveDisplay = if ($primaryAccount) { $primaryAccount } else { 'IIS_IUSRS' }

    if ($matchedAce -and $matchedAce.AccessControlType -eq 'Allow') {
        return New-Result -Status 'OK' `
                           -EffectiveIdentity $primaryAccount `
                           -AccessRights $matchedAce.FileSystemRights.ToString() `
                           -Detail "Explicit Allow ACE found for '$primaryAccount'. Rights: $($matchedAce.FileSystemRights)."
    }

    if ($iisIusrsAce -and $iisIusrsAce.AccessControlType -eq 'Allow') {
        $coveredIdentity = if ($primaryAccount) { $primaryAccount } else { 'pool identity' }
        return New-Result -Status 'OK' `
                           -EffectiveIdentity "BUILTIN\IIS_IUSRS (covers $coveredIdentity)" `
                           -AccessRights $iisIusrsAce.FileSystemRights.ToString() `
                           -Detail "Explicit Allow ACE found on IIS_IUSRS group. Rights: $($iisIusrsAce.FileSystemRights). All IIS worker process accounts are members of this group."
    }

    if ($matchedAce -and $matchedAce.AccessControlType -eq 'Deny') {
        return New-Result -Status 'ExplicitDeny' `
                           -EffectiveIdentity $primaryAccount `
                           -AccessRights $matchedAce.FileSystemRights.ToString() `
                           -Detail "An explicit Deny ACE was found for '$primaryAccount'. This will block access regardless of Allow entries. Rights denied: $($matchedAce.FileSystemRights)."
    }

    # No matching ACE found
    $checked = ($accountsToLog | ForEach-Object { "'$_'" }) -join ' and '
    return New-Result -Status 'NoExplicitAce' `
                       -EffectiveIdentity $effectiveDisplay `
                       -AccessRights $null `
                       -Detail "No explicit ACE found for $checked. Access may still be granted via inheritance or group membership - this check reads direct ACEs only. Use icacls '$Path' to view effective permissions."
}