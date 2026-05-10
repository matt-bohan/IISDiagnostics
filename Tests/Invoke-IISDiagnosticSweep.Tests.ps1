Describe 'Invoke-IISDiagnosticSweep' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'returns IISDiagnostics.SweepResult and writes HTML when ReportPath is set' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}

            Mock Invoke-IISHttpErrAnalysis {
                [pscustomobject]@{
                    PSTypeName      = 'IISDiagnostics.HttpErrAnalysis'
                    GeneratedAt     = Get-Date
                    StartTime       = (Get-Date).AddHours(-1)
                    EndTime         = Get-Date
                    TotalEntries    = 0
                    OverallSeverity = 'Healthy'
                    Findings        = @(
                        [pscustomobject]@{
                            PSTypeName         = 'IISDiagnostics.HttpErrFinding'
                            Severity           = 'Healthy'
                            SeverityRank       = 1
                            Category           = 'NoData'
                            Title              = 'No HTTPERR entries in this window'
                            Detail             = 'Detail.'
                            Evidence           = 'Zero HTTPERR entries.'
                            RecommendedActions = @()
                        }
                    )
                    FindingsDisplay   = ''
                }
            }

            Mock Get-IISAppPoolStatus      { @() }
            Mock Get-IISSiteConfiguration { @() }
            Mock Get-IISSiteSummary       { @() }
            Mock Get-IISEventLog          { @() }

            $reportPath = Join-Path $TestDrive 'sweep-test.html'
            $result = Invoke-IISDiagnosticSweep `
                -ReportPath $reportPath `
                -SkipW3C `
                -SkipEventLog `
                -StartTime (Get-Date).AddHours(-1) `
                -EndTime (Get-Date)

            if ($result.PSObject.TypeNames[0] -ne 'IISDiagnostics.SweepResult') {
                throw "Expected IISDiagnostics.SweepResult, got '$($result.PSObject.TypeNames[0])'."
            }
            if ($result.ReportPath -ne $reportPath) {
                throw "Expected ReportPath '$reportPath', got '$($result.ReportPath)'."
            }
            if (-not (Test-Path -LiteralPath $reportPath)) {
                throw 'Expected HTML report file to exist.'
            }
            $content = Get-Content -LiteralPath $reportPath -Raw -ErrorAction Stop
            if ($content -notmatch '<!DOCTYPE html>') {
                throw 'Expected report file to contain HTML DOCTYPE.'
            }
        }
    }
}
