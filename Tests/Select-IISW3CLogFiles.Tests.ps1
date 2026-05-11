Describe 'W3C log file selection' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'selects only daily log files that overlap the requested UTC window' {
        InModuleScope IISDiagnostics {
            $logDir = Join-Path $TestDrive 'w3c-select'
            $null = New-Item -Path $logDir -ItemType Directory -Force

            $inside = Join-Path $logDir 'u_ex260511.log'
            $outside = Join-Path $logDir 'u_ex260501.log'
            $null = New-Item -Path $inside -ItemType File -Force
            $null = New-Item -Path $outside -ItemType File -Force

            $startUtc = [datetime]::SpecifyKind([datetime]::new(2026, 5, 11, 8, 0, 0), 'Utc')
            $endUtc   = [datetime]::SpecifyKind([datetime]::new(2026, 5, 11, 9, 0, 0), 'Utc')

            $selected = @(Get-W3CLogFilesForTimeWindow -LogDirectories @($logDir) -StartUtc $startUtc -EndUtc $endUtc)

            if ($selected.Count -ne 1) {
                throw "Expected 1 selected log file, got $($selected.Count)."
            }
            if ($selected[0].Name -ne 'u_ex260511.log') {
                throw "Expected u_ex260511.log, got '$($selected[0].Name)'."
            }
        }
    }

    It 'selects hourly log files only when their hour overlaps the window' {
        InModuleScope IISDiagnostics {
            $logDir = Join-Path $TestDrive 'w3c-hourly'
            $null = New-Item -Path $logDir -ItemType Directory -Force

            $insideLocal  = [datetime]::new(2026, 5, 11, 9, 0, 0)
            $outsideLocal = [datetime]::new(2026, 5, 11, 7, 0, 0)
            $insideName   = 'u_ex{0}.log' -f $insideLocal.ToString('yyMMddHH')
            $outsideName  = 'u_ex{0}.log' -f $outsideLocal.ToString('yyMMddHH')
            $inside       = Join-Path $logDir $insideName
            $outside      = Join-Path $logDir $outsideName
            $null = New-Item -Path $inside -ItemType File -Force
            $null = New-Item -Path $outside -ItemType File -Force

            $startUtc = $insideLocal.AddMinutes(30).ToUniversalTime()
            $endUtc   = $insideLocal.AddMinutes(75).ToUniversalTime()

            $selected = @(Get-W3CLogFilesForTimeWindow -LogDirectories @($logDir) -StartUtc $startUtc -EndUtc $endUtc)
            $names = @($selected | ForEach-Object Name)

            if ($names -notcontains $insideName) {
                throw "Expected hourly file $insideName to be selected, got: $($names -join ', ')."
            }
            if ($names -contains $outsideName) {
                throw "Did not expect hourly file $outsideName to be selected."
            }
        }
    }
}
