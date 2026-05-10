Describe 'Invoke-IISW3CLogAnalysis' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'returns nothing when Get-IISW3CLog yields no entries' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Get-IISW3CLog { @() }

            $result = Invoke-IISW3CLogAnalysis -StartTime (Get-Date).AddHours(-1) -EndTime (Get-Date)

            if ($null -ne $result) {
                throw "Expected no output object when no W3C entries, got: $($result | Out-String)"
            }
        }
    }
}
