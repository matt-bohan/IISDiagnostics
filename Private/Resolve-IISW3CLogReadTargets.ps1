#Requires -Version 5.1

function Resolve-IISW3CLogReadTargets {
    <#
    .SYNOPSIS
        Resolves W3C log directories and files for a time window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCmdlet]$PSCmdlet,

        [Parameter(Mandatory)]
        [string]$ParameterSetName,

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [int]$SiteId,

        [Parameter()]
        [string]$SiteName,

        [Parameter(Mandatory)]
        [datetime]$StartUtc,

        [Parameter(Mandatory)]
        [datetime]$EndUtc
    )

    $logDirs = [System.Collections.Generic.List[string]]::new()

    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Path')) {
        $expandedPath = Expand-IISDiagnosticsLogPath -Path $Path
        if (Test-Path -LiteralPath $expandedPath -PathType Leaf) {
            $logDirs.Add((Split-Path -LiteralPath $expandedPath -Parent))
        }
        elseif (Test-Path -LiteralPath $expandedPath -PathType Container) {
            $logDirs.Add($expandedPath)
        }
        else {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.IO.IOException]::new("Path '$expandedPath' does not exist."),
                    'W3CPathNotFound',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $expandedPath
                )
            )
        }
    }
    else {
        $resolvedFromSites = @()

        $webAdminLoaded = $false
        try {
            if (-not (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue)) {
                Import-Module WebAdministration -ErrorAction Stop
            }
            $webAdminLoaded = $true
        }
        catch {
            Write-Verbose "WebAdministration module could not be loaded for W3C path discovery: $_"
        }

        try {
            if ($ParameterSetName -eq 'AllSites') {
                $resolvedFromSites = @(Get-W3CLogDirectoriesFromAllSites)
                foreach ($d in $resolvedFromSites) {
                    $logDirs.Add($d)
                }
            }
            elseif ($ParameterSetName -in 'BySiteId', 'BySiteName') {
                $site = $null
                $resolvedSiteName = $null

                if ($webAdminLoaded) {
                    if ($ParameterSetName -eq 'BySiteName') {
                        $site = Get-ChildItem -Path 'IIS:\Sites' -ErrorAction Stop |
                            Where-Object { $_.Name -eq $SiteName } |
                            Select-Object -First 1
                        if ($site) {
                            $SiteId = [int]$site.Id
                            $resolvedSiteName = [string]$site.Name
                        }
                    }
                    else {
                        $site = Get-ChildItem -Path 'IIS:\Sites' -ErrorAction Stop |
                            Where-Object { [int]$_.Id -eq $SiteId } |
                            Select-Object -First 1
                        if ($site) {
                            $resolvedSiteName = [string]$site.Name
                        }
                    }
                }

                if (-not $resolvedSiteName -and $ParameterSetName -eq 'BySiteName') {
                    $resolvedSiteName = $SiteName
                }

                if (-not $resolvedSiteName) {
                    foreach ($entry in @(Get-W3CLogSiteEntriesFromApplicationHost)) {
                        if ($entry.SiteId -eq $SiteId) {
                            $resolvedSiteName = [string]$entry.SiteName
                            break
                        }
                    }
                }

                if (-not $site -and $webAdminLoaded) {
                    Write-Warning "Site not found in IIS (ParameterSet: $ParameterSetName). Trying applicationHost.config for the configured log directory."
                }

                if ($resolvedSiteName -or $ParameterSetName -eq 'BySiteId') {
                    $rawDir = Get-IISSiteW3CLogDirectoryRaw `
                        -SiteId $SiteId `
                        -SiteName $(if ($resolvedSiteName) { $resolvedSiteName } else { '' }) `
                        -SiteObject $site

                    if ($rawDir) {
                        $resolvedOne = Resolve-W3CSiteLogDirectory -DirectoryFromIis $rawDir -SiteId $SiteId
                        if ($resolvedOne) {
                            $resolvedFromSites = @($resolvedOne)
                            $logDirs.Add($resolvedOne)
                        }
                    }
                }
            }
        }
        catch {
            Write-Verbose "IIS site log discovery failed: $_. Falling back to default layout."
        }

        if ($logDirs.Count -eq 0) {
            $logRoot = $null
            $useDirectLogFilesInRoot = $false

            if (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue) {
                try {
                    $centralEnabled = $false
                    $central = Get-WebConfigurationProperty `
                        -PSPath 'MACHINE/WEBROOT/APPHOST' `
                        -Filter 'system.applicationHost/log/centralW3CLogFile' `
                        -Name enabled `
                        -ErrorAction SilentlyContinue
                    if ($central -and $null -ne $central.Value) {
                        $centralEnabled = [bool]$central.Value
                    }

                    if ($centralEnabled) {
                        $centralDir = Get-WebConfigurationProperty `
                            -PSPath 'MACHINE/WEBROOT/APPHOST' `
                            -Filter 'system.applicationHost/log/centralW3CLogFile' `
                            -Name directory `
                            -ErrorAction SilentlyContinue
                        if ($centralDir -and $centralDir.Value) {
                            $logRoot = Expand-IISDiagnosticsLogPath -Path ([string]$centralDir.Value)
                            $useDirectLogFilesInRoot = $true
                        }
                    }

                    if (-not $logRoot) {
                        $defaults = Get-WebConfigurationProperty `
                            -PSPath 'MACHINE/WEBROOT/APPHOST' `
                            -Filter 'system.applicationHost/sites/siteDefaults/logFile' `
                            -Name directory `
                            -ErrorAction SilentlyContinue
                        if ($defaults -and $defaults.Value) {
                            $logRoot = Expand-IISDiagnosticsLogPath -Path ([string]$defaults.Value)
                        }
                    }

                    if (-not $logRoot) {
                        $central = Get-WebConfigurationProperty `
                            -PSPath 'MACHINE/WEBROOT/APPHOST' `
                            -Filter 'system.applicationHost/log' `
                            -Name centralW3CLogFile.directory `
                            -ErrorAction SilentlyContinue
                        if ($central -and $central.Value) {
                            $logRoot = Expand-IISDiagnosticsLogPath -Path ([string]$central.Value)
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not read applicationHost log paths: $_"
                }
            }

            if (-not $logRoot) {
                $configPath = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
                if (Test-Path -LiteralPath $configPath) {
                    try {
                        [xml]$appHostDoc = Get-Content -LiteralPath $configPath -ErrorAction Stop
                        $appHostNode = $appHostDoc.configuration.'system.applicationHost'
                        if ($appHostNode -and $appHostNode.sites -and $appHostNode.sites.siteDefaults -and $appHostNode.sites.siteDefaults.logFile) {
                            $defaultLogDirectory = [string]$appHostNode.sites.siteDefaults.logFile.directory
                            if (-not [string]::IsNullOrWhiteSpace($defaultLogDirectory)) {
                                $logRoot = Expand-IISDiagnosticsLogPath -Path $defaultLogDirectory
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not read siteDefaults W3C directory from applicationHost.config: $_"
                    }
                }
            }

            if (-not $logRoot) {
                $logRoot = Join-Path $env:SystemDrive 'inetpub\logs\LogFiles'
            }

            if (-not (Test-Path -LiteralPath $logRoot)) {
                $PSCmdlet.ThrowTerminatingError(
                    [System.Management.Automation.ErrorRecord]::new(
                        [System.IO.DirectoryNotFoundException]::new(
                            "W3C log root '$logRoot' not found after IIS discovery and fallbacks. " +
                            "Specify the folder that contains u_ex*.log (or W3SVCn subfolders) with -Path. " +
                            "Check IIS Manager -> Sites -> site -> Logging, or applicationHost.config siteDefaults/logFile."),
                        'W3CLogRootNotFound',
                        [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                        $logRoot
                    )
                )
            }

            if ($ParameterSetName -in 'BySiteId', 'BySiteName') {
                $resolvedSiteLogDirectory = Resolve-W3CSiteLogDirectory -DirectoryFromIis $logRoot -SiteId $SiteId
                if ($resolvedSiteLogDirectory) {
                    $logDirs.Add($resolvedSiteLogDirectory)
                }
                else {
                    Write-Warning (
                        "Could not resolve a site log directory for SiteId '$SiteId' under fallback root '$logRoot'. " +
                        "The site may log to a custom folder; install WebAdministration, or pass -Path to the site's log directory " +
                        "(IIS Manager -> Site -> Logging -> Directory)."
                    )
                    return [pscustomobject]@{
                        LogDirectories = @($logDirs)
                        LogFiles       = @()
                    }
                }
            }
            else {
                $directLogs = @()
                if ($useDirectLogFilesInRoot) {
                    $directLogs = @(Get-ChildItem -LiteralPath $logRoot -Filter 'u_ex*.log' -File -ErrorAction SilentlyContinue)
                }

                if ($directLogs.Count -gt 0) {
                    $logDirs.Add($logRoot)
                }
                else {
                    $found = @(Get-ChildItem -LiteralPath $logRoot -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -match '^W3SVC\d+$' })

                    if (-not $found) {
                        Write-Warning (
                            "No W3SVC* site folders under '$logRoot' and per-site IIS discovery returned nothing. " +
                            "Confirm W3C logging is enabled, or pass -Path to your LogFiles folder or W3SVCn directory."
                        )
                        return [pscustomobject]@{
                            LogDirectories = @($logDirs)
                            LogFiles       = @()
                        }
                    }

                    $found | ForEach-Object { $logDirs.Add($_.FullName) }
                }
            }
        }
    }

    Write-Verbose "Log directories to scan: $($logDirs -join ', ')"

    $logFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    foreach ($file in @(Get-W3CLogFilesForTimeWindow -LogDirectories @($logDirs) -StartUtc $StartUtc -EndUtc $EndUtc)) {
        $logFiles.Add($file)
    }

    [pscustomobject]@{
        LogDirectories = @($logDirs)
        LogFiles       = @($logFiles)
    }
}
