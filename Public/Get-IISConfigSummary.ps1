#Requires -Version 5.1

function Get-IISConfigSummary {
    <#
    .SYNOPSIS
        Returns a quick snapshot of the IIS configuration on this server: application pools,
        sites, bindings, and key log file locations.

    .DESCRIPTION
        Answers "what am I dealing with?" before starting a diagnostic session.

        Surfaces the facts that are otherwise spread across multiple cmdlets and config files:

          Application pools
            Name, current state, identity type and username (if SpecificUser), pipeline mode,
            and managed runtime version.

          Sites and bindings
            Site name, ID, state, application pool, and all configured bindings with their
            protocol, address, port, and host header.

          W3C access log locations
            The effective W3C log directory for each site, resolved using the same multi-source
            logic as Get-IISW3CLog (IIS: drive, Get-WebConfigurationProperty,
            applicationHost.config fallback, and environment variable expansion).

          HTTP.sys error log (HTTPERR)
            The resolved HTTPERR folder, checked against both the standard path and the
            registry override (HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\ErrorLoggingDir).

          Windows Event Log reminder
            Points operators to the System log (WAS source) for application pool lifecycle
            events, and to the Application log for .NET and ASP.NET runtime errors.

        Unlike Invoke-IISDiagnosticSweep this cmdlet does not analyse log content - it only
        enumerates what is configured. It is fast and suitable for orientation and inventory.

    .EXAMPLE
        Get-IISConfigSummary

        Prints a colour-coded console summary and returns a IISDiagnostics.ConfigSummary object.

    .EXAMPLE
        $summary = Get-IISConfigSummary
        $summary.Sites | Format-Table

        Capture the result for scripting and inspect the site list as a table.

    .EXAMPLE
        $summary = Get-IISConfigSummary
        $summary.W3CLogPaths | Format-Table

        Inspect W3C log paths for all sites.

    .EXAMPLE
        $summary = Get-IISConfigSummary
        $summary.AppPools | Where-Object State -ne 'Started'

        Find application pools that are not currently running.

    .NOTES
        Requires an elevated session and the WebAdministration module.
        The WebAdministration module is installed with the IIS Management tools Windows feature:
          Install-WindowsFeature -Name Web-Scripting-Tools
    #>
    [CmdletBinding()]
    param()

    Assert-ElevatedSession -CmdletName $MyInvocation.MyCommand.Name
    Assert-WebAdminModule  -CmdletName $MyInvocation.MyCommand.Name

    # Identity type integers returned by WebAdministration configuration API - same map as
    # Get-IISAppPoolStatus, duplicated here to keep this function self-contained.
    $identityTypeMap = @{
        '0' = 'LocalSystem'
        '1' = 'LocalService'
        '2' = 'NetworkService'
        '3' = 'SpecificUser'
        '4' = 'ApplicationPoolIdentity'
    }

    $lineWidth = 68

    function Write-SummaryBanner([string]$Text, [switch]$Double) {
        $char = if ($Double) { '=' } else { '-' }
        $line = $char * $lineWidth
        Write-Host "  $line" -ForegroundColor DarkGray
        if ($Text) { Write-Host "    $Text" -ForegroundColor White }
    }

    function Write-SummarySection([string]$Title) {
        $pad = '-' * [math]::Max(2, $lineWidth - $Title.Length - 5)
        Write-Host ''
        Write-Host "  --- $Title $pad" -ForegroundColor DarkGray
    }

    function Write-SummaryItem([string]$Severity, [string]$Text) {
        $badge  = switch ($Severity) {
            'Critical' { '[CRIT]' } 'Warning' { '[WARN]' }
            'Info'     { '[INFO]' } default   { '[ OK ]' }
        }
        $colour = switch ($Severity) {
            'Critical' { 'Red'    } 'Warning' { 'Yellow' }
            'Info'     { 'Cyan'   } default   { 'Green'  }
        }
        Write-Host "  $badge  $Text" -ForegroundColor $colour
    }

    # ── Banner ────────────────────────────────────────────────────────────────
    Write-Host ''
    Write-SummaryBanner -Double
    Write-Host "    IIS Configuration Summary" -ForegroundColor White -NoNewline
    Write-Host "  *  $($env:COMPUTERNAME)  *  $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor DarkGray
    Write-SummaryBanner -Double

    # ── Application pools ─────────────────────────────────────────────────────
    Write-SummarySection 'APPLICATION POOLS'

    $poolRows = [System.Collections.Generic.List[pscustomobject]]::new()

    try {
        $allPools = @(Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop)

        if ($allPools.Count -eq 0) {
            Write-SummaryItem -Severity 'Info' -Text 'No application pools found.'
        }

        foreach ($pool in $allPools) {
            $state = try { [string]$pool.State } catch { 'Unknown' }

            $rawIdentityType = try { [string]$pool.ProcessModel.IdentityType } catch { $null }
            $identityType    = if ($rawIdentityType -and $identityTypeMap.ContainsKey($rawIdentityType)) {
                $identityTypeMap[$rawIdentityType]
            } else {
                $rawIdentityType
            }

            $userName = try {
                if ($identityType -eq 'SpecificUser') { [string]$pool.ProcessModel.UserName }
                else { $null }
            } catch { $null }

            $pipelineMode   = try { [string]$pool.ManagedPipelineMode }  catch { $null }
            $runtimeVersion = try {
                $rv = [string]$pool.ManagedRuntimeVersion
                if ([string]::IsNullOrWhiteSpace($rv)) { 'No Managed Code' } else { $rv }
            } catch { $null }

            $severity    = if ($state -eq 'Started') { 'OK' } else { 'Warning' }
            $identityStr = if ($userName) { "$identityType ($userName)" } else { $identityType }

            Write-SummaryItem -Severity $severity `
                -Text "$($pool.Name)  |  $state  |  $identityStr  |  $pipelineMode  |  $runtimeVersion"

            $poolRows.Add([pscustomobject]@{
                PSTypeName     = 'IISDiagnostics.ConfigSummary.AppPool'
                Name           = $pool.Name
                State          = $state
                IdentityType   = $identityType
                UserName       = $userName
                PipelineMode   = $pipelineMode
                RuntimeVersion = $runtimeVersion
            })
        }
    }
    catch {
        Write-SummaryItem -Severity 'Warning' -Text "Could not enumerate application pools: $_"
    }

    # ── Sites ─────────────────────────────────────────────────────────────────
    Write-SummarySection 'SITES'

    $siteRows    = [System.Collections.Generic.List[pscustomobject]]::new()
    $w3cLogPaths = [System.Collections.Generic.List[pscustomobject]]::new()

    try {
        $allSites = @(Get-ChildItem 'IIS:\Sites' -ErrorAction Stop)

        if ($allSites.Count -eq 0) {
            Write-SummaryItem -Severity 'Info' -Text 'No sites found.'
        }

        foreach ($site in $allSites) {
            $siteId   = [int]$site.Id
            $siteName = [string]$site.Name
            $state    = try { [string]$site.State }           catch { 'Unknown' }
            $pool     = try { [string]$site.ApplicationPool } catch { $null }

            # Bindings - bindingInformation is "ip:port:hostheader"
            $bindingObjects = [System.Collections.Generic.List[pscustomobject]]::new()
            try {
                foreach ($b in @($site.Bindings.Collection)) {
                    $proto = [string]$b.Protocol
                    $info  = [string]$b.bindingInformation   # e.g. "*:80:" or "*:443:example.com"
                    $parts = $info -split ':'
                    $ip    = if ($parts.Count -ge 1 -and $parts[0]) { $parts[0] } else { '*' }
                    $port  = if ($parts.Count -ge 2) { $parts[1] } else { '' }
                    $host  = if ($parts.Count -ge 3) { $parts[2] } else { '' }

                    $bindingObjects.Add([pscustomobject]@{
                        Protocol = $proto
                        IP       = $ip
                        Port     = $port
                        HostName = $host
                    })
                }
            }
            catch {
                Write-Verbose "  Could not read bindings for '$siteName': $_"
            }

            $severity = if ($state -eq 'Started') { 'OK' } else { 'Warning' }
            Write-SummaryItem -Severity $severity `
                -Text "$siteName  (ID: $siteId)  |  $state  |  Pool: $(if ($pool) { $pool } else { '-' })"

            foreach ($b in $bindingObjects) {
                $addr = "$($b.Protocol)  $($b.IP):$($b.Port)$(if ($b.HostName) { "  [$($b.HostName)]" })"
                Write-Host "             $addr" -ForegroundColor DarkGray
            }

            # Resolve W3C log path using existing private helpers
            $rawLogDir      = Get-IISSiteW3CLogDirectoryRaw -SiteId $siteId -SiteName $siteName -SiteObject $site
            $resolvedLogDir = if ($rawLogDir) {
                Resolve-W3CSiteLogDirectory -DirectoryFromIis $rawLogDir -SiteId $siteId
            } else { $null }

            # Fall back to the expanded raw path if the directory cannot be confirmed on disk
            $effectiveLogDir = if ($resolvedLogDir) {
                $resolvedLogDir
            } elseif ($rawLogDir) {
                Expand-IISDiagnosticsLogPath -Path $rawLogDir
            } else {
                $null
            }

            $logDirExists = if ($effectiveLogDir) {
                Test-Path -LiteralPath $effectiveLogDir -PathType Container
            } else { $false }

            $w3cLogPaths.Add([pscustomobject]@{
                PSTypeName   = 'IISDiagnostics.ConfigSummary.W3CLogPath'
                SiteId       = $siteId
                SiteName     = $siteName
                RawPath      = $rawLogDir
                ResolvedPath = $effectiveLogDir
                Exists       = $logDirExists
            })

            $siteRows.Add([pscustomobject]@{
                PSTypeName      = 'IISDiagnostics.ConfigSummary.Site'
                SiteId          = $siteId
                SiteName        = $siteName
                State           = $state
                ApplicationPool = $pool
                Bindings        = $bindingObjects.ToArray()
                W3CLogPath      = $effectiveLogDir
            })
        }
    }
    catch {
        Write-SummaryItem -Severity 'Warning' -Text "Could not enumerate sites: $_"
    }

    # ── W3C log locations ─────────────────────────────────────────────────────
    Write-SummarySection 'W3C ACCESS LOG LOCATIONS'

    if ($w3cLogPaths.Count -eq 0) {
        Write-SummaryItem -Severity 'Info' -Text 'No W3C log paths resolved.'
    }
    else {
        foreach ($entry in $w3cLogPaths) {
            if ($entry.ResolvedPath) {
                $pathDisplay = $entry.ResolvedPath
                $suffix      = if (-not $entry.Exists) { '  [directory not found on disk]' } else { '' }
                $severity    = if ($entry.Exists) { 'OK' } else { 'Warning' }
            } elseif ($entry.RawPath) {
                $pathDisplay = $entry.RawPath
                $suffix      = '  [path not yet expanded / directory not found]'
                $severity    = 'Warning'
            } else {
                $pathDisplay = '(could not determine log path)'
                $suffix      = ''
                $severity    = 'Info'
            }

            Write-SummaryItem -Severity $severity `
                -Text "$($entry.SiteName)  ->  $pathDisplay$suffix"
        }
    }

    # ── HTTPERR log location ──────────────────────────────────────────────────
    Write-SummarySection 'HTTP.SYS ERROR LOG (HTTPERR)'

    $httpErrPath       = $null
    $httpErrCandidates = @(Get-HttpErrLogDirectoryCandidates)

    foreach ($candidate in $httpErrCandidates) {
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            $httpErrPath = $candidate
            break
        }
    }

    if ($httpErrPath) {
        Write-SummaryItem -Severity 'OK' -Text $httpErrPath
    } elseif ($httpErrCandidates.Count -gt 0) {
        Write-SummaryItem -Severity 'Info' `
            -Text "$($httpErrCandidates[0])  [not found - HTTP.sys may not have logged any errors yet]"
        $httpErrPath = $httpErrCandidates[0]
    } else {
        Write-SummaryItem -Severity 'Info' -Text 'Could not determine HTTPERR log location.'
    }

    # ── Windows Event Log reminder ────────────────────────────────────────────
    Write-SummarySection 'WINDOWS EVENT LOG (REMINDER)'

    Write-SummaryItem -Severity 'Info' `
        -Text 'System log / WAS: application pool lifecycle events (crashes, rapid-fail, recycling)'
    Write-SummaryItem -Severity 'Info' `
        -Text 'System log / HttpService: HTTP.sys binding and SSL errors'
    Write-SummaryItem -Severity 'Info' `
        -Text 'Application log / .NET Runtime + ASP.NET: managed code errors and crashes'
    Write-Host "           -> Use: Get-IISEventLog -Significant" -ForegroundColor DarkGray

    Write-Host ''

    # ── Return object ─────────────────────────────────────────────────────────
    [pscustomobject]@{
        PSTypeName     = 'IISDiagnostics.ConfigSummary'
        ComputerName   = $env:COMPUTERNAME
        GeneratedAt    = Get-Date
        AppPools       = $poolRows.ToArray()
        Sites          = $siteRows.ToArray()
        W3CLogPaths    = $w3cLogPaths.ToArray()
        HttpErrLogPath = $httpErrPath
    }
}
