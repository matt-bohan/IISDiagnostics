@{
    RootModule           = 'IISDiagnostics.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'eb7bbab6-b3a4-4d32-8f1a-1f01a72a4205'
    Author               = 'Matthew Bohan'
    CompanyName          = 'Matthew Bohan'
    Copyright            = '(c) Matt Bohan 2026'
    Description          = @'
Explains HTTP and IIS substatus codes with admin vs application guidance and checks.

Import from repo path:
  Import-Module .\IISDiagnostics\IISDiagnostics.psd1 -Force

Install for current user: copy the IISDiagnostics folder to
  $HOME\Documents\PowerShell\Modules (pwsh) or
  $HOME\Documents\WindowsPowerShell\Modules (Windows PowerShell), then Import-Module IISDiagnostics.
'@
    PowerShellVersion    = '5.1'
    FormatsToProcess     = @('IISDiagnostics.Format.ps1xml')
    FunctionsToExport    = '*'
    RequiredAssemblies         = @('System.DirectoryServices')
    CmdletsToExport            = @()
    VariablesToExport          = @()
    AliasesToExport            = @()
    PrivateData                = @{
        PSData = @{
            Tags       = @('IIS', 'Diagnostics', 'HTTP', 'Troubleshooting', 'Logs', 'MIT')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
