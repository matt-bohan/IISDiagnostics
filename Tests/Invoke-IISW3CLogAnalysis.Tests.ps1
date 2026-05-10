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

    It 'passes a LastHours-derived window to Get-IISW3CLog' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            $script:w3cWin = $null
            Mock Get-IISW3CLog {
                $script:w3cWin = @{
                    StartTime = $StartTime
                    EndTime   = $EndTime
                }
                @()
            }

            $null = Invoke-IISW3CLogAnalysis -LastHours 24

            if ($null -eq $script:w3cWin) {
                throw 'Get-IISW3CLog was not invoked.'
            }
            $hours = ($script:w3cWin.EndTime - $script:w3cWin.StartTime).TotalHours
            if ([math]::Abs($hours - 24) -gt 0.05) {
                throw "Expected ~24h window, got $hours hours."
            }
        }
    }
}
