#Requires -Version 5.1

function Assert-ElevatedSession {
    <#
    .SYNOPSIS
        Terminates the calling cmdlet with a clear message if the session is not elevated.

    .DESCRIPTION
        Most IIS diagnostic operations require administrator access — reading HTTPERR logs,
        querying WebAdministration, inspecting the certificate store. Call this at the top
        of any public cmdlet that touches those resources.

        Get-IISStatusHelp is the only cmdlet that does not need elevation (JSON file read only).

    .PARAMETER CmdletName
        Name of the calling cmdlet, included in the error message so the user knows
        which command triggered the check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CmdletName
    )

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $message = @(
            "$CmdletName requires an elevated PowerShell session.",
            '',
            "Current user: $($identity.Name)",
            '',
            'To open an elevated session:',
            '  Right-click the PowerShell icon and select "Run as administrator"',
            '  — or —',
            '  Start-Process powershell -Verb RunAs'
        ) -join [Environment]::NewLine

        # Use Write-Error with -ErrorAction Stop rather than throw so that the
        # ErrorRecord carries a proper CategoryInfo and the caller shows up correctly
        # in $Error[0].InvocationInfo.
        Write-Error -Message $message `
                    -Category PermissionDenied `
                    -ErrorId 'SessionNotElevated' `
                    -TargetObject $CmdletName `
                    -ErrorAction Stop
    }
}
