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

    $base = Expand-IISDiagnosticsLogPath -Path $DirectoryFromIis
    if ([string]::IsNullOrWhiteSpace($base)) {
        return $null
    }

    # Already points at W3SVC folder
    if ($base -match '[\\/]W3SVC\d+$') {
        if (Test-Path -LiteralPath $base) { return $base }
        return $null
    }

    $sub = Join-Path $base "W3SVC$SiteId"
    if (Test-Path -LiteralPath $sub) {
        return $sub
    }

    # Custom layout: u_ex*.log directly under configured directory (no W3SVC subfolder)
    $directLogs = @(Get-ChildItem -LiteralPath $base -Filter 'u_ex*.log' -File -ErrorAction SilentlyContinue)
    if ($directLogs.Count -gt 0) {
        return $base
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

    try {
        if (-not (Get-Module -Name WebAdministration -ErrorAction SilentlyContinue)) {
            Import-Module WebAdministration -ErrorAction Stop
        }

        foreach ($site in @(Get-ChildItem -Path 'IIS:\Sites' -ErrorAction Stop)) {
            $siteId = [int]$site.Id
            $raw = $null

            try {
                $webCfg = Get-WebConfigurationProperty `
                    -PSPath "IIS:\Sites\$($site.Name)" `
                    -Filter 'system.applicationHost/sites/site/logFile' `
                    -Name directory `
                    -ErrorAction SilentlyContinue
                if ($webCfg -and $webCfg.Value) {
                    $raw = [string]$webCfg.Value
                }
            }
            catch { }

            if (-not $raw) {
                try {
                    $raw = [string]$site.LogFile.Directory
                }
                catch { }
            }

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
        Write-Verbose "Could not enumerate IIS sites for W3C paths: $_"
    }

    @($dirs)
}
