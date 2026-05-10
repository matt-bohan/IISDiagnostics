Describe 'IISDiagnostics module basics' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'imports successfully' {
        $module = Get-Module IISDiagnostics
        if ($null -eq $module) { throw 'Expected module IISDiagnostics to be imported.' }
    }

    It 'exports expected public commands' {
        $module = Get-Module IISDiagnostics
        if (-not ($module.ExportedCommands.Keys -contains 'Get-IISStatusCodeHelp')) { throw 'Expected Get-IISStatusCodeHelp export.' }
        if (-not ($module.ExportedCommands.Keys -contains 'Get-IISHttpErrLog')) { throw 'Expected Get-IISHttpErrLog export.' }
        if (-not ($module.ExportedCommands.Keys -contains 'Invoke-IISHttpErrAnalysis')) { throw 'Expected Invoke-IISHttpErrAnalysis export.' }
        if (-not ($module.ExportedCommands.Keys -contains 'Get-IISSiteBindingReport')) { throw 'Expected Get-IISSiteBindingReport export.' }
        if (-not ($module.ExportedCommands.Keys -contains 'Get-IISSiteSummary')) { throw 'Expected Get-IISSiteSummary export.' }
    }
}
