# IISDiagnostics

PowerShell module for IIS and HTTP diagnostics, focused on explaining status and substatus codes with practical remediation guidance.

## Features

- Explain HTTP and IIS substatus codes with admin vs application guidance.
- Parse and review IIS HTTPERR log entries.
- Run analysis workflows to surface likely causes and next actions.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- IIS logs/HTTPERR logs available on the target machine

## Installation

### Import directly from repo

```powershell
Import-Module .\IISDiagnostics\IISDiagnostics.psd1 -Force
```

### Install for current user

Copy the `IISDiagnostics` folder to one of these module locations:

- PowerShell (pwsh): `$HOME\Documents\PowerShell\Modules`
- Windows PowerShell: `$HOME\Documents\WindowsPowerShell\Modules`

Then import:

```powershell
Import-Module IISDiagnostics
```

## Commands

- `Get-IISStatusCodeHelp`
- `Get-IISHttpErrLog`
- `Invoke-IISHttpErrAnalysis`

## License

This module is licensed under the MIT License.
