Describe 'Get-IISW3CLog' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'reads W3C logs from per-site custom directories returned by IIS discovery' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}

            $customLogDirectory = Join-Path $TestDrive 'custom-site-w3c'
            $null = New-Item -Path $customLogDirectory -ItemType Directory -Force

            $entryUtc = (Get-Date).ToUniversalTime().AddMinutes(-5)
            $logName = 'u_ex{0}.log' -f $entryUtc.ToString('yyMMdd')
            $logPath = Join-Path $customLogDirectory $logName
            @(
                '#Software: Microsoft Internet Information Services 10.0'
                '#Version: 1.0'
                '#Fields: date time s-sitename cs-method cs-uri-stem sc-status sc-substatus sc-win32-status time-taken'
                ('{0} {1} CustomSite GET / 200 0 0 15' -f $entryUtc.ToString('yyyy-MM-dd'), $entryUtc.ToString('HH:mm:ss'))
            ) | Set-Content -LiteralPath $logPath

            Mock Get-Module { [pscustomobject]@{ Name = 'WebAdministration' } } -ParameterFilter { $Name -eq 'WebAdministration' }
            Mock Get-W3CLogDirectoriesFromAllSites { @($customLogDirectory) }

            $result = @(Get-IISW3CLog `
                -StartTime $entryUtc.ToLocalTime().AddMinutes(-1) `
                -EndTime $entryUtc.ToLocalTime().AddMinutes(1))

            if ($result.Count -ne 1) {
                throw "Expected 1 W3C entry, got $($result.Count)."
            }
            if ($result[0].SiteLogFolder -ne 'custom-site-w3c') {
                throw "Expected entry to be read from custom log directory, got '$($result[0].SiteLogFolder)'."
            }
        }
    }

    It 'prefers the configured central W3C log directory when central logging is enabled' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Get-Module { [pscustomobject]@{ Name = 'WebAdministration' } } -ParameterFilter { $Name -eq 'WebAdministration' }
            Mock Get-W3CLogDirectoriesFromAllSites { @() }

            $centralW3CLogDirectory = Join-Path $TestDrive 'central-w3c'
            $null = New-Item -Path $centralW3CLogDirectory -ItemType Directory -Force

            $entryUtc = (Get-Date).ToUniversalTime().AddMinutes(-5)
            $logName = 'u_ex{0}.log' -f $entryUtc.ToString('yyMMdd')
            $logPath = Join-Path $centralW3CLogDirectory $logName
            @(
                '#Software: Microsoft Internet Information Services 10.0'
                '#Version: 1.0'
                '#Fields: date time s-sitename cs-method cs-uri-stem sc-status sc-substatus sc-win32-status time-taken'
                ('{0} {1} CentralSite GET / 200 0 0 15' -f $entryUtc.ToString('yyyy-MM-dd'), $entryUtc.ToString('HH:mm:ss'))
            ) | Set-Content -LiteralPath $logPath

            function Get-WebConfigurationProperty {
                [CmdletBinding()]
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
                        return [pscustomobject]@{ Value = $centralW3CLogDirectory }
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

Describe 'W3C log directory resolution' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'resolves custom site roots that contain u_ex logs directly' {
        InModuleScope IISDiagnostics {
            $customRoot = Join-Path $TestDrive 'site-root'
            $null = New-Item -Path $customRoot -ItemType Directory -Force
            $null = New-Item -Path (Join-Path $customRoot 'u_ex260501.log') -ItemType File -Force

            $resolved = Resolve-W3CSiteLogDirectory -DirectoryFromIis $customRoot -SiteId 3

            if ($resolved -ne $customRoot) {
                throw "Expected custom root '$customRoot', got '$resolved'."
            }
        }
    }

    It 'resolves default LogFiles roots to W3SVC site folders' {
        InModuleScope IISDiagnostics {
            $logRoot = Join-Path $TestDrive 'LogFiles'
            $siteFolder = Join-Path $logRoot 'W3SVC2'
            $null = New-Item -Path $siteFolder -ItemType Directory -Force
            $null = New-Item -Path (Join-Path $siteFolder 'u_ex260501.log') -ItemType File -Force

            $resolved = Resolve-W3CSiteLogDirectory -DirectoryFromIis $logRoot -SiteId 2

            if ($resolved -ne $siteFolder) {
                throw "Expected site folder '$siteFolder', got '$resolved'."
            }
        }
    }
}
