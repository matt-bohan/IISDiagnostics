#Requires -Version 5.1

function Test-DomainAccountStatus {
    <#
    .SYNOPSIS
        Checks the Active Directory status of an account used as an application pool identity.

    .DESCRIPTION
        Attempts to determine whether a domain account is locked out, disabled, or has an
        expired password. Tries the ActiveDirectory module (Get-ADUser) first, then falls
        back to an ADSI directory searcher if the module is not installed.

        Returns a structured object so that the caller can populate AccountStatus and
        AccountStatusDetail on the IISDiagnostics.AppPoolStatus output object.

        Handles three identity string formats:
          DOMAIN\username
          username@domain.com
          username           (assumed domain account; local accounts are identified separately)

        Local accounts (MACHINENAME\username where MACHINENAME matches $env:COMPUTERNAME)
        are identified and returned with Status = 'LocalAccount' - no AD query is attempted.

    .PARAMETER Username
        The identity string from the application pool ProcessModel.UserName property.

    .OUTPUTS
        PSCustomObject with:
          Status           - OK | LockedOut | Disabled | PasswordExpired | LocalAccount |
                             CheckFailed | NotApplicable
          Detail           - Human-readable explanation of the status
          Method           - ADModule | ADSI | None
          IsLockedOut      - [bool] or $null if unknown
          IsDisabled       - [bool] or $null if unknown
          PasswordExpired  - [bool] or $null if unknown (only populated via ADModule)
          SamAccountName   - the resolved SAM account name used for the query
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username
    )

    function New-Result([string]$Status, [string]$Detail, [string]$Method = 'None',
                         $IsLockedOut = $null, $IsDisabled = $null,
                         $ExpiryFlag = $null, [string]$Sam = '') {
        [pscustomobject]@{
            Status          = $Status
            Detail          = $Detail
            Method          = $Method
            IsLockedOut     = $IsLockedOut
            IsDisabled      = $IsDisabled
            PasswordExpired = $ExpiryFlag
            SamAccountName  = $Sam
        }
    }

    # ------------------------------------------------------------------
    # Parse the username into domain and SAM account name
    # ------------------------------------------------------------------
    $domain     = $null
    $samAccount = $null

    if ($Username -match '^(.+)\\(.+)$') {
        # DOMAIN\username format
        $domain     = $Matches[1]
        $samAccount = $Matches[2]

        # Local account - MACHINENAME\username
        if ($domain -eq $env:COMPUTERNAME) {
            return New-Result -Status 'LocalAccount' `
                               -Detail "Local machine account '$Username' - Active Directory check not applicable." `
                               -Sam $samAccount
        }
    }
    elseif ($Username -match '^(.+)@(.+)$') {
        # UPN format: username@domain.com
        $samAccount = $Matches[1]
        $domain     = $Matches[2]
    }
    else {
        # Bare username - assume domain, use as-is
        $samAccount = $Username
    }

    if ([string]::IsNullOrWhiteSpace($samAccount)) {
        return New-Result -Status 'CheckFailed' `
                           -Detail "Could not parse a username from '$Username'."
    }

    # ------------------------------------------------------------------
    # Attempt 1: ActiveDirectory module (most reliable, returns password expiry)
    # ------------------------------------------------------------------
    if (Get-Command -Name 'Get-ADUser' -ErrorAction SilentlyContinue) {
        try {
            $adProps = @('LockedOut', 'Enabled', 'PasswordExpired', 'PasswordNeverExpires',
                         'PasswordLastSet', 'LastLogonDate')
            $adUser  = Get-ADUser -Identity $samAccount -Properties $adProps -ErrorAction Stop

            $status = if (-not $adUser.Enabled) { 'Disabled' }
                      elseif ($adUser.LockedOut) { 'LockedOut' }
                      elseif ($adUser.PasswordExpired) { 'PasswordExpired' }
                      else { 'OK' }

            $detail = switch ($status) {
                'OK'              { "Account is enabled, unlocked, and password is current." }
                'Disabled'        { "Account is disabled in Active Directory." }
                'LockedOut'       { "Account is locked out. Unlock via Active Directory Users and Computers or Unlock-ADAccount." }
                'PasswordExpired' { "Account password has expired. Reset required before the pool identity will authenticate." }
            }

            if ($status -eq 'OK' -and -not $adUser.PasswordNeverExpires -and $adUser.PasswordLastSet) {
                # Add password age as context - useful even when not expired
                $age   = [math]::Round(((Get-Date) - $adUser.PasswordLastSet).TotalDays, 0)
                $detail += " Password last set $age day(s) ago."
            }

            return New-Result -Status $status -Detail $detail -Method 'ADModule' `
                               -IsLockedOut $adUser.LockedOut `
                               -IsDisabled (-not $adUser.Enabled) `
                               -ExpiryFlag $adUser.PasswordExpired `
                               -Sam $samAccount
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            return New-Result -Status 'CheckFailed' `
                               -Detail "Account '$samAccount' was not found in Active Directory." `
                               -Method 'ADModule' -Sam $samAccount
        }
        catch {
            Write-Verbose "Get-ADUser failed for '$samAccount': $_. Trying ADSI fallback."
            # Fall through to ADSI
        }
    }

    # ------------------------------------------------------------------
    # Attempt 2: ADSI directory searcher (no AD module required)
    # Note: only reliably determines locked-out and disabled states.
    # Password expiry requires domain policy knowledge not available via
    # a simple ADSI attribute read - it is reported as $null.
    # ------------------------------------------------------------------
    try {
        $searcher = [adsisearcher]::new()
        $searcher.Filter = "(samaccountname=$samAccount)"
        $searcher.PropertiesToLoad.AddRange([string[]]@(
            'lockouttime', 'useraccountcontrol', 'pwdlastset', 'distinguishedname'
        ))

        $result = $searcher.FindOne()
        $searcher.Dispose()

        if ($null -eq $result) {
            return New-Result -Status 'CheckFailed' `
                               -Detail "Account '$samAccount' was not found via directory search. Verify the account exists and this server can reach a domain controller." `
                               -Method 'ADSI' -Sam $samAccount
        }

        $lockoutTime = [long]($result.Properties['lockouttime'][0])
        $uac         = [int]($result.Properties['useraccountcontrol'][0])
        $isDisabled  = ($uac -band 2) -ne 0     # ADS_UF_ACCOUNTDISABLE flag
        $isLockedOut = $lockoutTime -gt 0

        $status = if ($isDisabled) { 'Disabled' }
                  elseif ($isLockedOut) { 'LockedOut' }
                  else { 'OK' }

        $detail = switch ($status) {
            'OK'       { "Account is enabled and not locked out (checked via ADSI - password expiry not available without the ActiveDirectory module)." }
            'Disabled' { "Account is disabled (userAccountControl flag). The pool will fail to start under this identity." }
            'LockedOut' {
                $lockoutDt = [datetime]::FromFileTime($lockoutTime)
                "Account locked out since $($lockoutDt.ToString('dd/MM/yyyy HH:mm:ss')). Unlock via Active Directory Users and Computers."
            }
        }

        return New-Result -Status $status -Detail $detail -Method 'ADSI' `
                           -IsLockedOut $isLockedOut -IsDisabled $isDisabled `
                           -ExpiryFlag $null -Sam $samAccount
    }
    catch {
        return New-Result -Status 'CheckFailed' `
                           -Detail "ADSI directory search failed: $_. The server may not be able to reach a domain controller, or the account may be in a domain without a trust from this machine." `
                           -Method 'ADSI' -Sam $samAccount
    }
}