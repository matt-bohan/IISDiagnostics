Describe 'Invoke-IISHttpErrAnalysis' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'returns Healthy when no HTTPERR entries are found' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Get-IISHttpErrLog { @() }

            $result = Invoke-IISHttpErrAnalysis

            $result.PSObject.TypeNames[0] | Should Be 'IISDiagnostics.HttpErrAnalysis'
            $result.OverallSeverity | Should Be 'Healthy'
            $result.TotalEntries | Should Be 0
            ($result.Findings.Count -ge 1) | Should Be $true
            @($result.Findings | Where-Object Category -eq 'NoData').Count | Should BeGreaterThan 0
        }
    }

    It 'returns Critical when a Timer_AppPool burst is detected' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Get-IISHttpErrLog {
                @(
                    [pscustomobject]@{
                        Timestamp = [datetime]'2026-05-10T10:00:00'
                        Reason    = 'Timer_AppPool'
                        ClientIp  = '127.0.0.1'
                        Uri       = '/health'
                        ServerPort = 80
                    },
                    [pscustomobject]@{
                        Timestamp = [datetime]'2026-05-10T10:01:00'
                        Reason    = 'Timer_AppPool'
                        ClientIp  = '127.0.0.2'
                        Uri       = '/api/a'
                        ServerPort = 80
                    },
                    [pscustomobject]@{
                        Timestamp = [datetime]'2026-05-10T10:02:00'
                        Reason    = 'Timer_AppPool'
                        ClientIp  = '127.0.0.3'
                        Uri       = '/api/b'
                        ServerPort = 80
                    },
                    [pscustomobject]@{
                        Timestamp = [datetime]'2026-05-10T10:03:00'
                        Reason    = 'Timer_AppPool'
                        ClientIp  = '127.0.0.4'
                        Uri       = '/api/c'
                        ServerPort = 80
                    },
                    [pscustomobject]@{
                        Timestamp = [datetime]'2026-05-10T10:04:00'
                        Reason    = 'Timer_AppPool'
                        ClientIp  = '127.0.0.5'
                        Uri       = '/api/d'
                        ServerPort = 80
                    }
                )
            }

            $result = Invoke-IISHttpErrAnalysis

            $result.OverallSeverity | Should Be 'Critical'
            @($result.Findings | Where-Object Category -eq 'QueueDrainStopped').Count | Should BeGreaterThan 0
        }
    }
}
