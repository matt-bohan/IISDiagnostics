Describe 'Read-IISW3CLogAnalysis' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'aggregates only entries inside the requested UTC window' {
        InModuleScope IISDiagnostics {
            $logDir = Join-Path $TestDrive 'w3c-analysis'
            $null = New-Item -Path $logDir -ItemType Directory -Force

            $insideUtc = [datetime]::SpecifyKind((Get-Date).ToUniversalTime().AddMinutes(-10), 'Utc')
            $outsideUtc = [datetime]::SpecifyKind((Get-Date).ToUniversalTime().AddHours(-3), 'Utc')
            $logPath = Join-Path $logDir ('u_ex{0}.log' -f $insideUtc.ToLocalTime().ToString('yyMMdd'))
            @(
                '#Software: Microsoft Internet Information Services 10.0'
                '#Version: 1.0'
                '#Fields: date time s-sitename cs-method cs-uri-stem sc-status sc-substatus c-ip'
                ('{0} {1} Site GET /old 404 0 10.0.0.9' -f $outsideUtc.ToString('yyyy-MM-dd'), $outsideUtc.ToString('HH:mm:ss'))
                ('{0} {1} Site GET /new 500 0 10.0.0.1' -f $insideUtc.ToString('yyyy-MM-dd'), $insideUtc.ToString('HH:mm:ss'))
            ) | Set-Content -LiteralPath $logPath

            $state = New-IISW3CLogAnalysisState
            Read-IISW3CLogAnalysisFromFile -File ([System.IO.FileInfo]::new($logPath)) `
                -StartUtc $insideUtc.AddMinutes(-5) `
                -EndUtc $insideUtc.AddMinutes(5) `
                -State $state

            if ($state.Total -ne 1) {
                throw "Expected 1 aggregated entry, got $($state.Total)."
            }
            if (-not $state.GroupData.ContainsKey('500.0')) {
                throw 'Expected a 500.0 status group.'
            }
        }
    }
}
