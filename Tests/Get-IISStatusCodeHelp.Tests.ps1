Describe 'Get-IISStatusCodeHelp' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'returns details for a known HTTP status code' {
        $result = Get-IISStatusCodeHelp 503

        $result.PSObject.TypeNames[0] | Should Be 'IISDiagnostics.StatusHelp'
        $result.StatusCode | Should Be '503'
        $result.Title | Should Be 'Service Unavailable'
        $result.LikelyCauses.Count | Should BeGreaterThan 0
    }

    It 'returns details for a known IIS substatus code' {
        $result = Get-IISStatusCodeHelp '500.30'

        $result.PSObject.TypeNames[0] | Should Be 'IISDiagnostics.StatusHelp'
        $result.StatusCode | Should Be '500.30'
        $result.Title | Should Be '500.30 - In-process start failure'
    }

    It 'returns unknown guidance for unmapped substatus values' {
        $result = Get-IISStatusCodeHelp '500.999'

        $result.StatusCode | Should Be '500.999'
        $result.Title | Should Be 'Unknown or undocumented status'
    }

    It 'throws for dotted numeric values not passed as strings' {
        { Get-IISStatusCodeHelp 500.30 } | Should Throw
    }
}
