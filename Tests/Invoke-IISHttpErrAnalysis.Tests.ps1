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

            if ($result.PSObject.TypeNames[0] -ne 'IISDiagnostics.HttpErrAnalysis') { throw 'Expected IISDiagnostics.HttpErrAnalysis result type.' }
            if ($result.OverallSeverity -ne 'Healthy') { throw "Expected Healthy severity, got '$($result.OverallSeverity)'." }
            if ($result.TotalEntries -ne 0) { throw "Expected TotalEntries 0, got '$($result.TotalEntries)'." }
            if ($result.Findings.Count -lt 1) { throw 'Expected one or more findings.' }
            if (@($result.Findings | Where-Object Category -eq 'NoData').Count -le 0) { throw 'Expected NoData finding.' }
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

            if ($result.OverallSeverity -ne 'Critical') { throw "Expected Critical severity, got '$($result.OverallSeverity)'." }
            if (@($result.Findings | Where-Object Category -eq 'QueueDrainStopped').Count -le 0) { throw 'Expected QueueDrainStopped finding.' }
        }
    }
}
