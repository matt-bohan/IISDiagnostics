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

    It 'aggregates streamed W3C entries without materialising the full request list' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Get-IISW3CLog {
                [pscustomobject]@{
                    Timestamp  = (Get-Date).AddMinutes(-10)
                    StatusCode = 500
                    SubStatus  = 0
                    UriStem    = '/api/fail'
                    ClientIp   = '10.0.0.1'
                }
                [pscustomobject]@{
                    Timestamp  = (Get-Date).AddMinutes(-5)
                    StatusCode = 500
                    SubStatus  = 0
                    UriStem    = '/api/fail'
                    ClientIp   = '10.0.0.2'
                }
                [pscustomobject]@{
                    Timestamp  = (Get-Date).AddMinutes(-1)
                    StatusCode = 200
                    SubStatus  = 0
                    UriStem    = '/'
                    ClientIp   = '10.0.0.3'
                }
            }

            $result = Invoke-IISW3CLogAnalysis -StartTime (Get-Date).AddHours(-1) -EndTime (Get-Date)

            if ($result.TotalRequests -ne 3) {
                throw "Expected 3 total requests, got $($result.TotalRequests)."
            }
            if ($result.ServerErrors.Count -ne 1) {
                throw "Expected 1 server error group, got $($result.ServerErrors.Count)."
            }
            if ($result.ServerErrors[0].Count -ne 2) {
                throw "Expected 2 requests in the 500 group, got $($result.ServerErrors[0].Count)."
            }
            if ($result.ServerErrors[0].TopUris[0].UriStem -ne '/api/fail' -or $result.ServerErrors[0].TopUris[0].Count -ne 2) {
                throw 'Expected top URI /api/fail with count 2.'
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
