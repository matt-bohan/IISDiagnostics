Describe 'Get-IISW3CLog' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'prefers the configured central W3C log directory when central logging is enabled' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Get-Module { [pscustomobject]@{ Name = 'WebAdministration' } } -ParameterFilter { $Name -eq 'WebAdministration' }
            Mock Get-W3CLogDirectoriesFromAllSites { @() }

            $centralRoot = Join-Path $TestDrive 'central-w3c'
            $null = New-Item -Path $centralRoot -ItemType Directory -Force

            $entryUtc = (Get-Date).ToUniversalTime().AddMinutes(-5)
            $logName = 'u_ex{0}.log' -f $entryUtc.ToString('yyMMdd')
            $logPath = Join-Path $centralRoot $logName
            @(
                '#Software: Microsoft Internet Information Services 10.0'
                '#Version: 1.0'
                '#Fields: date time s-sitename cs-method cs-uri-stem sc-status sc-substatus sc-win32-status time-taken'
                ('{0} {1} CentralSite GET / 200 0 0 15' -f $entryUtc.ToString('yyyy-MM-dd'), $entryUtc.ToString('HH:mm:ss'))
            ) | Set-Content -LiteralPath $logPath

            function Get-WebConfigurationProperty {
                param(
                    [string]$PSPath,
                    [string]$Filter,
                    [string]$Name
                )

                switch ("$Filter::$Name") {
                    'system.applicationHost/log/centralW3CLogFile::enabled' {
                        return [pscustomobject]@{ Value = $true }
                    }
                    'system.applicationHost/log/centralW3CLogFile::directory' {
                        return [pscustomobject]@{ Value = $centralRoot }
                    }
                    'system.applicationHost/sites/siteDefaults/logFile::directory' {
                        return [pscustomobject]@{ Value = 'C:\inetpub\logs\LogFiles' }
                    }
                }
            }

            $result = @(Get-IISW3CLog `
                -StartTime $entryUtc.ToLocalTime().AddMinutes(-1) `
                -EndTime $entryUtc.ToLocalTime().AddMinutes(1))

            if ($result.Count -ne 1) {
                throw "Expected 1 W3C entry, got $($result.Count)."
            }
            if ($result[0].SiteLogFolder -ne 'central-w3c') {
                throw "Expected entry to be read from central log directory, got '$($result[0].SiteLogFolder)'."
            }
            if ($result[0].SiteName -ne 'CentralSite') {
                throw "Expected SiteName 'CentralSite', got '$($result[0].SiteName)'."
            }
        }
    }
}
