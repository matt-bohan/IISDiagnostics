Describe 'New-SweepHtmlReport' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'returns HTML containing DOCTYPE and key markers' {
        InModuleScope IISDiagnostics {
            $html = New-SweepHtmlReport `
                -ComputerName     'TESTSRV' `
                -GeneratedAt      ([datetime]'2026-05-10T12:00:00') `
                -StartTime        ([datetime]'2026-05-10T11:00:00') `
                -EndTime          ([datetime]'2026-05-10T12:00:00') `
                -OverallSeverity  'Healthy' `
                -Findings         @() `
                -HttpErrAnalysis  $null `
                -W3CAnalysis      $null `
                -AppPools         @() `
                -SiteConfigurations @() `
                -SiteSummary      @() `
                -EventLog         @() `
                -PerformanceCounters $null `
                -CollectionErrors @()

            if ($html -notmatch '<!DOCTYPE html>') { throw 'Expected HTML to start with DOCTYPE.' }
            if ($html -notmatch 'TESTSRV') { throw 'Expected computer name in generated HTML.' }
            if ($html -notmatch 'IIS Diagnostic Sweep') { throw 'Expected sweep title in HTML.' }
        }
    }

    It 'escapes angle brackets in finding detail text' {
        InModuleScope IISDiagnostics {
            $finding = [pscustomobject]@{
                PSTypeName         = 'IISDiagnostics.SweepFinding'
                SeverityRank       = 3
                Severity           = 'Warning'
                Source             = 'Test'
                Title              = 'Test finding'
                Detail             = 'Bad tag <script>'
                RecommendedActions = @('Fix <path>')
            }
            $html = New-SweepHtmlReport `
                -ComputerName 'X' -GeneratedAt (Get-Date) -StartTime (Get-Date) -EndTime (Get-Date) `
                -OverallSeverity 'Warning' -Findings @($finding) -HttpErrAnalysis $null -W3CAnalysis $null `
                -AppPools @() -SiteConfigurations @() -SiteSummary @() -EventLog @() -CollectionErrors @()

            if ($html -match '<script>') { throw 'Script tag should be HTML-escaped, not left raw.' }
            if ($html -notmatch '&lt;script&gt;') { throw 'Expected escaped script tag in HTML.' }
        }
    }
}
