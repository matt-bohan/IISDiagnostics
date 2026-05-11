Describe 'Invoke-IISW3CLogAnalysis' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'returns nothing when no W3C log files are found' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Measure-IISW3CLogAnalysis {
                [pscustomobject]@{
                    LogDirectories = @('C:\logs')
                    LogFiles       = @()
                    Total          = 0
                    GroupData      = @{}
                }
            }

            $result = Invoke-IISW3CLogAnalysis -StartTime (Get-Date).AddHours(-1) -EndTime (Get-Date)

            if ($null -ne $result) {
                throw "Expected no output object when no W3C entries, got: $($result | Out-String)"
            }
        }
    }

    It 'aggregates W3C metrics without materialising the full request list' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Measure-IISW3CLogAnalysis {
                $groupData = @{
                    '500.0' = @{
                        StatusCode   = 500
                        SubStatus    = 0
                        Count        = 2
                        FirstSeen    = (Get-Date).AddMinutes(-10)
                        LastSeen     = (Get-Date).AddMinutes(-5)
                        UriCounts    = @{ '/api/fail' = 2 }
                        ClientCounts = @{ '10.0.0.1' = 1; '10.0.0.2' = 1 }
                    }
                    '200.0' = @{
                        StatusCode   = 200
                        SubStatus    = 0
                        Count        = 1
                        FirstSeen    = (Get-Date).AddMinutes(-1)
                        LastSeen     = (Get-Date).AddMinutes(-1)
                        UriCounts    = @{}
                        ClientCounts = @{}
                    }
                }

                [pscustomobject]@{
                    LogDirectories = @('C:\logs')
                    LogFiles       = @([System.IO.FileInfo]::new('C:\logs\u_ex260511.log'))
                    Total          = 3
                    GroupData      = $groupData
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

    It 'passes a LastHours-derived UTC window to Measure-IISW3CLogAnalysis' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            $script:w3cWin = $null
            Mock Measure-IISW3CLogAnalysis {
                $script:w3cWin = @{
                    StartUtc = $StartUtc
                    EndUtc   = $EndUtc
                }
                [pscustomobject]@{
                    LogDirectories = @()
                    LogFiles       = @()
                    Total          = 0
                    GroupData      = @{}
                }
            }

            $null = Invoke-IISW3CLogAnalysis -LastHours 24

            if ($null -eq $script:w3cWin) {
                throw 'Measure-IISW3CLogAnalysis was not invoked.'
            }
            $hours = ($script:w3cWin.EndUtc - $script:w3cWin.StartUtc).TotalHours
            if ([math]::Abs($hours - 24) -gt 0.05) {
                throw "Expected ~24h window, got $hours hours."
            }
        }
    }
}
