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

    It 'exports exactly one function per Public/*.ps1 script (catches missing exports)' {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $publicDir = Join-Path $repoRoot 'Public'
        $expectedNames = @(Get-ChildItem -Path $publicDir -Filter '*.ps1' -File -ErrorAction Stop |
            Sort-Object Name |
            ForEach-Object { $_.BaseName })

        $module = Get-Module IISDiagnostics
        $exportedKeys = @($module.ExportedCommands.Keys | Sort-Object)

        if ($exportedKeys.Count -ne $expectedNames.Count) {
            throw "Export count $($exportedKeys.Count) does not match Public script count $($expectedNames.Count). Exported: $($exportedKeys -join ', '). Expected: $($expectedNames -join ', ')."
        }

        foreach ($name in $expectedNames) {
            if (-not $module.ExportedCommands.ContainsKey($name)) {
                throw "Missing exported function for Public script: $name"
            }
        }
    }

    It 'exports newer diagnostic cmdlets used by the sweep' {
        $module = Get-Module IISDiagnostics
        foreach ($cmd in @(
                'Get-IISSiteConfiguration',
                'Invoke-IISDiagnosticSweep',
                'Invoke-IISW3CLogAnalysis',
                'Get-IISEventLog',
                'Get-IISAppPoolStatus',
                'Get-IISW3CLog'
            )) {
            if (-not ($module.ExportedCommands.Keys -contains $cmd)) {
                throw "Expected export: $cmd"
            }
        }
    }
}
