#Requires -Version 5.1

function Expand-IISDiagnosticsLogPath {
    <#
    .SYNOPSIS
        Expands IIS-style %SystemDrive%, %SystemRoot%, etc. for log directory strings.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $Path
    }

    $p = $Path.Trim()

    # IIS and HTTP.sys often use these before ExpandEnvironmentVariables runs
    $p = $p -replace '(?i)^%SystemDrive%', $env:SystemDrive
    $p = $p -replace '(?i)%SystemDrive%', $env:SystemDrive
    if ($env:SystemRoot) {
        $p = $p -replace '(?i)%SystemRoot%', $env:SystemRoot
    }

    [Environment]::ExpandEnvironmentVariables($p)
}

function Get-HttpErrLogDirectoryCandidates {
    <#
    .SYNOPSIS
        Returns ordered HTTPERR folder paths to try (default location and registry-based).
    #>
    [CmdletBinding()]
    param()

    $list = [System.Collections.Generic.List[string]]::new()

    # Standard location (full path including HTTPERR)
    [void]$list.Add((Join-Path $env:SystemRoot 'System32\LogFiles\HTTPERR'))

    # HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters
    # ErrorLoggingDir = parent folder; HTTP.sys creates an "HTTPERR" subfolder under it.
    try {
        $regKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
        if (Test-Path -LiteralPath $regKey) {
            $rp = Get-ItemProperty -LiteralPath $regKey -ErrorAction Stop
            if ($rp.ErrorLoggingDir) {
                $parent = Expand-IISDiagnosticsLogPath -Path $rp.ErrorLoggingDir
                if (-not [string]::IsNullOrWhiteSpace($parent)) {
                    [void]$list.Add((Join-Path $parent 'HTTPERR'))
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not read HTTP Parameters registry for ErrorLoggingDir: $_"
    }

    # Unique, preserve order
    $seen = @{}
    foreach ($item in $list) {
        if ($item -and -not $seen.ContainsKey($item)) {
            $seen[$item] = $true
            $item
        }
    }
}

function ConvertFrom-IISWebConfigurationValue {
    <#
    .SYNOPSIS
        Unwraps WebAdministration configuration attribute values.
    #>
    [CmdletBinding()]
    param(
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject.PSObject.Properties['Value']) {
        return $InputObject.Value
    }

    return $InputObject
}

function Get-W3CLogSiteEntriesFromApplicationHost {
    <#
    .SYNOPSIS
        Reads site logFile directory settings from applicationHost.config (effective per site).
    #>
    [CmdletBinding()]
    param()

    $configPath = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    if (-not (Test-Path -LiteralPath $configPath)) {
        return @()
    }

    try {
        [xml]$doc = Get-Content -LiteralPath $configPath -ErrorAction Stop
    }
    catch {
        Write-Verbose "Could not read applicationHost.config for W3C paths: $_"
        return @()
    }

    $hostNode = $doc.configuration.'system.applicationHost'
    if (-not $hostNode -or -not $hostNode.sites) {
        return @()
    }

    $defaultDir = $null
    if ($hostNode.sites.siteDefaults -and $hostNode.sites.siteDefaults.logFile) {
        $defaultDir = [string]$hostNode.sites.siteDefaults.logFile.directory
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($siteNode in @($hostNode.sites.site)) {
        $siteId = [int]$siteNode.id
        $siteName = [string]$siteNode.name
        $dir = $null

        if ($siteNode.logFile) {
            $dir = [string]$siteNode.logFile.directory
        }

        if ([string]::IsNullOrWhiteSpace($dir)) {
            $dir = $defaultDir
        }

        if ([string]::IsNullOrWhiteSpace($dir)) {
            continue
        }

        $entries.Add([pscustomobject]@{
                SiteId        = $siteId
                SiteName      = $siteName
                RawDirectory  = $dir
            })
    }

    @($entries)
}

function Get-IISSiteW3CLogDirectoryRaw {
    <#
    .SYNOPSIS
        Returns the effective IIS logFile directory string for one site.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$SiteId,
        [Parameter(Mandatory)][string]$SiteName,
        $SiteObject
    )

    $rawValues = [System.Collections.Generic.List[string]]::new()

    if ($SiteObject) {
        foreach ($propertyName in @('LogFile', 'logFile')) {
            try {
                $logNode = $SiteObject.$propertyName
                if ($logNode -and $logNode.directory) {
                    [void]$rawValues.Add([string]$logNode.directory)
                }
            }
            catch { }
        }

        try {
            $fromDrive = [string]$SiteObject.LogFile.Directory
            if (-not [string]::IsNullOrWhiteSpace($fromDrive)) {
                [void]$rawValues.Add($fromDrive)
            }
        }
        catch { }
    }

    if (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue) {
        foreach ($filter in @('logFile', 'system.applicationHost/sites/site/logFile')) {
            try {
                $cfg = Get-WebConfigurationProperty `
                    -PSPath 'IIS:\' `
                    -Location $SiteName `
                    -Filter $filter `
                    -Name directory `
                    -ErrorAction SilentlyContinue
                $raw = ConvertFrom-IISWebConfigurationValue -InputObject $cfg
                if (-not [string]::IsNullOrWhiteSpace($raw)) {
                    [void]$rawValues.Add([string]$raw)
                }
            }
            catch { }
        }

        try {
            $escapedName = $SiteName.Replace("'", "''")
            $cfg = Get-WebConfigurationProperty `
                -PSPath 'MACHINE/WEBROOT/APPHOST' `
                -Filter "system.applicationHost/sites/site[@name='$escapedName']/logFile" `
                -Name directory `
                -ErrorAction SilentlyContinue
            $raw = ConvertFrom-IISWebConfigurationValue -InputObject $cfg
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                [void]$rawValues.Add([string]$raw)
            }
        }
        catch { }
    }

    foreach ($entry in @(Get-W3CLogSiteEntriesFromApplicationHost)) {
        if ($entry.SiteId -eq $SiteId -or $entry.SiteName -eq $SiteName) {
            [void]$rawValues.Add([string]$entry.RawDirectory)
        }
    }

    foreach ($raw in $rawValues) {
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            return $raw.Trim()
        }
    }

    return $null
}

function Get-W3CSiteLogDirectoryCandidates {
    <#
    .SYNOPSIS
        Builds likely physical folders for one site's W3C logs from an IIS directory setting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DirectoryFromIis,
        [Parameter(Mandatory)][int]$SiteId
    )

    $base = Expand-IISDiagnosticsLogPath -Path $DirectoryFromIis
    if ([string]::IsNullOrWhiteSpace($base)) {
        return @()
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($path in @(
            $base
            $(if ($base -notmatch '[\\/]W3SVC\d+$') { Join-Path $base "W3SVC$SiteId" })
            $(if ($base -notmatch '[\\/]W3SVC\d+$') { Join-Path $base "w3svc$SiteId" })
        )) {
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if ($seen.Add($path)) {
            [void]$candidates.Add($path)
        }
    }

    if (Test-Path -LiteralPath $base -PathType Container) {
        foreach ($child in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
            if ($child.Name -match '^W3SVC\d+$' -and $seen.Add($child.FullName)) {
                [void]$candidates.Add($child.FullName)
            }
        }
    }

    @($candidates)
}

function Resolve-W3CSiteLogDirectory {
    <#
    .SYNOPSIS
        Resolves the physical folder containing W3C logs for one site (handles ...\W3SVCn vs custom roots).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DirectoryFromIis,
        [Parameter(Mandatory)][int]$SiteId
    )

    $existing = [System.Collections.Generic.List[string]]::new()

    foreach ($candidate in @(Get-W3CSiteLogDirectoryCandidates -DirectoryFromIis $DirectoryFromIis -SiteId $SiteId)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
            continue
        }

        [void]$existing.Add($candidate)

        $logFiles = @(Get-ChildItem -LiteralPath $candidate -Filter 'u_ex*.log' -File -ErrorAction SilentlyContinue)
        if ($logFiles.Count -eq 0) {
            $logFiles = @(Get-ChildItem -LiteralPath $candidate -Filter '*.log' -File -ErrorAction SilentlyContinue)
        }

        if ($logFiles.Count -gt 0) {
            return $candidate
        }
    }

    if ($existing.Count -gt 0) {
        return $existing[0]
    }

    return $null
}

function Get-W3CLogDirectoriesFromAllSites {
    <#
    .SYNOPSIS
        Enumerates IIS sites and returns distinct physical log directories that exist.
    #>
    [CmdletBinding()]
    param()

    $dirs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
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

    if ($webAdminLoaded) {
        try {
            foreach ($site in @(Get-ChildItem -Path 'IIS:\Sites' -ErrorAction Stop)) {
                $siteId = [int]$site.Id
                $siteName = [string]$site.Name
                $raw = Get-IISSiteW3CLogDirectoryRaw -SiteId $siteId -SiteName $siteName -SiteObject $site
                if ([string]::IsNullOrWhiteSpace($raw)) {
                    continue
                }

                $resolved = Resolve-W3CSiteLogDirectory -DirectoryFromIis $raw -SiteId $siteId
                if ($resolved) {
                    [void]$dirs.Add($resolved)
                }
            }
        }
        catch {
            Write-Verbose "Could not enumerate IIS:\Sites for W3C paths: $_"
        }

        if ($dirs.Count -eq 0) {
            try {
                foreach ($site in @(Get-Website -ErrorAction SilentlyContinue)) {
                    $siteId = [int]$site.Id
                    $siteName = [string]$site.Name
                    $raw = Get-IISSiteW3CLogDirectoryRaw -SiteId $siteId -SiteName $siteName -SiteObject $site
                    if ([string]::IsNullOrWhiteSpace($raw)) {
                        continue
                    }

                    $resolved = Resolve-W3CSiteLogDirectory -DirectoryFromIis $raw -SiteId $siteId
                    if ($resolved) {
                        [void]$dirs.Add($resolved)
                    }
                }
            }
            catch {
                Write-Verbose "Get-Website enumeration failed for W3C paths: $_"
            }
        }
    }

    if ($dirs.Count -eq 0) {
        foreach ($entry in @(Get-W3CLogSiteEntriesFromApplicationHost)) {
            $resolved = Resolve-W3CSiteLogDirectory -DirectoryFromIis $entry.RawDirectory -SiteId $entry.SiteId
            if ($resolved) {
                [void]$dirs.Add($resolved)
            }
        }
    }

    @($dirs)
}
