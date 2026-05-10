#Requires -Version 5.1

function Assert-WebAdminModule {
    <#
    .SYNOPSIS
        Ensures the WebAdministration module is available and imported, terminating if not.

    .DESCRIPTION
        WebAdministration is the IIS PowerShell module that provides access to app pools,
        site bindings, and IIS configuration via the IIS: PSDrive. It is installed as part
        of the IIS Management Console / IIS Management Scripts and Tools Windows feature —
        it is not present on machines where IIS itself is not installed.

        If the module is already loaded this function returns immediately. If it is available
        but not yet imported it imports it silently. If it cannot be found it terminates the
        calling cmdlet with a clear message explaining how to install the missing feature.

    .PARAMETER CmdletName
        Name of the calling cmdlet, included in the error message.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CmdletName
    )

    # Already loaded — nothing to do
    if (Get-Module -Name WebAdministration) { return }

    # Available but not yet imported — load it silently
    if (Get-Module -Name WebAdministration -ListAvailable) {
        Import-Module WebAdministration -ErrorAction Stop
        return
    }

    # Not available — tell the user exactly what to install
    $message = @(
        "$CmdletName requires the WebAdministration PowerShell module, which was not found.",
        '',
        'WebAdministration is installed with the IIS Management tools Windows feature.',
        'To install it, run one of the following in an elevated session:',
        '',
        '  # Windows Server (Server Manager feature):',
        '  Install-WindowsFeature -Name Web-Scripting-Tools',
        '',
        '  # Windows 10/11 (optional feature):',
        '  Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementScriptingTools',
        '',
        'A reboot is not normally required. Re-run this cmdlet after installation.'
    ) -join [Environment]::NewLine

    Write-Error -Message $message `
                -Category NotInstalled `
                -ErrorId 'WebAdminModuleNotFound' `
                -TargetObject $CmdletName `
                -ErrorAction Stop
}