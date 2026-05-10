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
        $module | Should Not BeNullOrEmpty
    }

    It 'exports expected public commands' {
        $module = Get-Module IISDiagnostics
        ($module.ExportedCommands.Keys -contains 'Get-IISStatusCodeHelp') | Should Be $true
        ($module.ExportedCommands.Keys -contains 'Get-IISHttpErrLog') | Should Be $true
        ($module.ExportedCommands.Keys -contains 'Invoke-IISHttpErrAnalysis') | Should Be $true
    }
}
