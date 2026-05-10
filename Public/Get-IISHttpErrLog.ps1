#Requires -Version 5.1

# s-reason values emitted by HTTP.sys, with plain-English descriptions.
# Stored at script scope so they load once when the module imports.
$script:HttpErrReasons = @{
    'App_InitFailed'          = 'Application initialisation failed before handling the request'
    'AppOffline'              = 'An app_offline.htm file is present; application is intentionally offline'
    'BadRequest'              = 'HTTP.sys rejected a malformed request before it reached IIS'
    'ConnLimit'               = 'Server connection limit reached'
    'Connections'             = 'Connection limit reached; no new connections accepted'
    'DynamicCompression'      = 'Dynamic response compression failed'
    'EntityTooLarge'          = 'Request entity body exceeds the configured limit'
    'FieldLength'             = 'A request header field exceeds the configured length limit'
    'Forbidden'               = 'Request refused due to a URL or verb restriction'
    'InternalError'           = 'An internal HTTP.sys error occurred'
    'MaxCGIReqs'              = 'Maximum concurrent CGI request limit reached'
    'N/A'                     = 'Reason not available; connection may have dropped before classification'
    'NotSupported'            = 'Requested feature or method is not supported'
    'PayloadSize'             = 'Payload size exceeds the configured maximum'
    'QueueFull'               = 'Application request queue is full; requests are being rejected'
    'Rejected'                = 'Connection rejected — often rapid-fail protection has kicked in'
    'RequestLength'           = 'Total request length exceeds the configured limit'
    'SslError'                = 'SSL/TLS handshake failed — check certificate and protocol configuration'
    'Timer_AppPool'           = 'Request timed out waiting for an available application pool thread'
    'Timer_ConnectionIdle'    = 'Keep-alive connection timed out waiting for the next request from the client'
    'Timer_EntityBody'        = 'Request timed out waiting for the client to finish sending the request body'
    'Timer_HeaderWait'        = 'Connection timed out waiting for the client to send request headers'
    'Timer_MinBytesPerSecond' = 'Response was sent too slowly; minimum bytes-per-second threshold exceeded'
    'Timer_Response'          = 'Response generation timed out'
    'URL'                     = 'URL is disallowed by URL Authorization or request filtering rules'
    'Verb'                    = 'HTTP verb is disallowed by request filtering'
}

function Get-IISHttpErrLog {
    <#
    .SYNOPSIS
        Parses HTTPERR log files and returns entries or a summary for a given time window.

    .DESCRIPTION
        Reads HTTP.sys error logs. The default folder is
        %SystemRoot%\System32\LogFiles\HTTPERR. If administrators relocate logs via
        HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters **ErrorLoggingDir**
        (parent folder; HTTP.sys creates an **HTTPERR** subfolder), that location is
        discovered automatically. Override with **-Path** if logs live elsewhere.

        HTTPERR logs capture requests that HTTP.sys rejected before they reached IIS or any
        application pool. Critically, these errors do NOT appear in W3C access logs, making
        this the first place to check for:

          - Connection timeouts (Timer_ConnectionIdle, Timer_HeaderWait, Timer_EntityBody)
          - Queue saturation (Timer_AppPool, QueueFull)
          - Application pool crashes (Rejected — rapid-fail protection)
          - App offline conditions (AppOffline)
          - Malformed or oversized requests (BadRequest, RequestLength, EntityTooLarge)
          - SSL handshake failures (SslError)

        By default returns individual IISDiagnostics.HttpErrEntry objects suitable for
        pipeline use (Group-Object, Where-Object, Export-Csv). Use -Summarise to return a
        single IISDiagnostics.HttpErrSummary instead.

        HTTP.sys logs timestamps in UTC; returned objects show local time.

    .PARAMETER StartTime
        Start of the time window to analyse (inclusive). Defaults to one hour ago.

    .PARAMETER EndTime
        End of the time window to analyse (inclusive). Defaults to now.

    .PARAMETER LastHours
        Whole-hour window ending now (sets StartTime/EndTime internally). Use instead of
        typing dates on servers with unfamiliar locale settings.

    .PARAMETER Path
        Folder containing httperr*.log files (not the parent defined by ErrorLoggingDir
        unless your logs were moved there without the HTTPERR subfolder). When omitted,
        the cmdlet tries the default path and the registry-based location.

    .PARAMETER Reason
        Return only entries matching this s-reason value, e.g. Timer_AppPool.
        Case-sensitive to match the log exactly.

    .PARAMETER ClientIp
        Return only entries from this client IP address.

    .PARAMETER Port
        Return only entries destined for this server port.

    .PARAMETER Summarise
        Return a single IISDiagnostics.HttpErrSummary object aggregating counts by reason,
        top client IPs, top URIs, and port breakdown.

    .EXAMPLE
        Get-IISHttpErrLog

        Returns all HTTPERR entries from the past hour.

    .EXAMPLE
        Get-IISHttpErrLog -StartTime (Get-Date).AddHours(-4) |
            Group-Object Reason | Sort-Object Count -Descending

        Groups errors from the last four hours by reason code.

    .EXAMPLE
        Get-IISHttpErrLog -StartTime (Get-Date).AddDays(-1) -Summarise

        Returns a summary report for the past 24 hours.

    .EXAMPLE
        Get-IISHttpErrLog -Reason Timer_AppPool | Select-Object Timestamp, Uri, ClientIp

        Returns all queue-timeout entries from the past hour.

    .EXAMPLE
        Get-IISHttpErrLog | Where-Object StatusCode -eq 400 | Export-Csv .\bad-requests.csv -NoTypeInformation

        Exports 400-level rejections for further analysis.

    .NOTES
        Requires read access to %SystemRoot%\System32\LogFiles\HTTPERR.
        Run as Administrator, or grant explicit read access to that directory.

        The active log file is opened with FileShare.ReadWrite so it can be read while
        HTTP.sys continues writing to it.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddHours(-1),

        [Parameter()]
        [datetime]$EndTime = (Get-Date),

        [Parameter()]
        [ValidateRange(1, 8760)]
        [Alias('Hours')]
        [int]$LastHours,

        [Parameter()]
        [ValidateScript({
            $expanded = Expand-IISDiagnosticsLogPath -Path $_
            if (-not (Test-Path -LiteralPath $expanded -PathType Container)) {
                throw "Path '$expanded' does not exist or is not a directory."
            }
            $true
        })]
        [string]$Path,

        [Parameter()]
        [string]$Reason,

        [Parameter()]
        [string]$ClientIp,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [Parameter()]
        [switch]$Summarise
    )

    Assert-ElevatedSession -CmdletName $MyInvocation.MyCommand.Name

    if ($PSBoundParameters.ContainsKey('LastHours')) {
        if ($PSBoundParameters.ContainsKey('StartTime') -or $PSBoundParameters.ContainsKey('EndTime')) {
            Write-Warning 'LastHours is set; StartTime and EndTime are ignored.'
        }
        $EndTime   = Get-Date
        $StartTime = $EndTime.AddHours(-$LastHours)
    }

    # -----------------------------------------------------------------------
    # Resolve log directory and validate time window
    # -----------------------------------------------------------------------
    if ($PSBoundParameters.ContainsKey('Path')) {
        $logDir = Expand-IISDiagnosticsLogPath -Path $Path
    }
    else {
        $candidates = @(Get-HttpErrLogDirectoryCandidates)
        $logDir = $null
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) {
                $logDir = $c
                Write-Verbose "Using HTTPERR directory: $logDir"
                break
            }
            Write-Verbose "HTTPERR candidate not found (skipped): $c"
        }

        if (-not $logDir) {
            $tried = $candidates -join "`n  "
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.IO.DirectoryNotFoundException]::new(
                        "HTTPERR log directory not found. Tried:`n  $tried`n" +
                        "Custom locations: set registry HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters " +
                        "ErrorLoggingDir to the parent folder (HTTP.sys creates an HTTPERR subfolder), restart HTTP " +
                        "(net stop http / net start http), or pass -Path to the folder that contains httperr*.log files."),
                    'HttpErrDirNotFound',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $candidates
                )
            )
        }
    }

    if ($StartTime -ge $EndTime) {
        throw "StartTime ($StartTime) must be earlier than EndTime ($EndTime)."
    }

    # Work in UTC for timestamp comparisons; display will be local time
    $startUtc = $StartTime.ToUniversalTime()
    $endUtc   = $EndTime.ToUniversalTime()

    # -----------------------------------------------------------------------
    # Discover log files
    # Include all httperr*.log files in the directory and filter by line timestamps below.
    # (Filtering files by LastWriteTime incorrectly skipped logs for historical windows
    # when files were not modified recently.)
    # -----------------------------------------------------------------------
    $logFiles = @(Get-ChildItem -LiteralPath $logDir -Filter 'httperr*.log' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime)

    if (-not $logFiles) {
        Write-Warning (
            "No httperr*.log files in '$logDir'. " +
            "Confirm HTTP.sys error logging is enabled and this path is correct (see -Path). " +
            "Registry parent: HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\ErrorLoggingDir " +
            "(actual logs are usually in an HTTPERR subfolder under that parent)."
        )
        return
    }

    Write-Verbose "Scanning $($logFiles.Count) log file(s) in '$logDir'."

    # When summarising we must accumulate all entries; when streaming we emit as we go.
    $accumulated = if ($Summarise) {
        [System.Collections.Generic.List[psobject]]::new()
    } else { $null }

    $entriesInWindow = 0

    # -----------------------------------------------------------------------
    # Parse each log file
    # -----------------------------------------------------------------------
    foreach ($file in $logFiles) {
        Write-Verbose "Parsing: $($file.Name)"

        $fieldNames = $null

        # FileShare.ReadWrite allows reading the active httperr log while HTTP.sys writes it
        $stream = [System.IO.File]::Open(
            $file.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)

        try {
            while ($null -ne ($rawLine = $reader.ReadLine())) {

                # Comment/directive lines
                if ($rawLine.StartsWith('#')) {
                    # #Fields: defines column layout — must parse it, not assume fixed order
                    if ($rawLine -match '^#Fields:\s+(.+)') {
                        $fieldNames = $Matches[1].Trim() -split '\s+'
                        Write-Verbose "  Fields: $($fieldNames -join ', ')"
                    }
                    continue
                }

                if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }

                # Skip data lines that appear before a #Fields header (shouldn't happen but be safe)
                if ($null -eq $fieldNames) {
                    Write-Verbose "  Skipping line before #Fields header: $rawLine"
                    continue
                }

                $parts = $rawLine -split '\s+'
                if ($parts.Count -lt $fieldNames.Count) { continue }

                # Map field names → values; HTTP.sys uses '-' as a null sentinel
                $f = @{}
                for ($i = 0; $i -lt $fieldNames.Count; $i++) {
                    $f[$fieldNames[$i]] = if ($parts[$i] -eq '-') { $null } else { $parts[$i] }
                }

                # -------------------------------------------------------
                # Parse timestamp (UTC in the log, present as local time)
                # -------------------------------------------------------
                if (-not ($f['date'] -and $f['time'])) { continue }

                $entryUtc = [datetime]::MinValue
                $parsed   = [datetime]::TryParseExact(
                    "$($f['date']) $($f['time'])",
                    'yyyy-MM-dd HH:mm:ss',
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    ([System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                     [System.Globalization.DateTimeStyles]::AdjustToUniversal),
                    [ref]$entryUtc
                )
                if (-not $parsed) { continue }

                if ($entryUtc -lt $startUtc -or $entryUtc -gt $endUtc) { continue }

                # -------------------------------------------------------
                # Apply caller filters
                # -------------------------------------------------------
                $entryReason = $f['s-reason']
                $entryPort   = $null
                if ($f['s-port']) { $null = [int]::TryParse($f['s-port'], [ref]$entryPort) }

                if ($PSBoundParameters.ContainsKey('Reason')   -and $entryReason   -ne $Reason)   { continue }
                if ($PSBoundParameters.ContainsKey('ClientIp') -and $f['c-ip']     -ne $ClientIp) { continue }
                if ($PSBoundParameters.ContainsKey('Port')     -and $entryPort     -ne $Port)     { continue }

                # -------------------------------------------------------
                # Build the entry object
                # -------------------------------------------------------
                $statusCode = $null
                if ($f['sc-status']) { $null = [int]::TryParse($f['sc-status'], [ref]$statusCode) }

                $clientPort = $null
                if ($f['c-port']) { $null = [int]::TryParse($f['c-port'], [ref]$clientPort) }

                $reasonDesc = if ($entryReason -and $script:HttpErrReasons.ContainsKey($entryReason)) {
                    $script:HttpErrReasons[$entryReason]
                } else { $null }

                $entry = [pscustomobject]@{
                    PSTypeName        = 'IISDiagnostics.HttpErrEntry'
                    Timestamp         = $entryUtc.ToLocalTime()
                    ClientIp          = $f['c-ip']
                    ClientPort        = $clientPort
                    ServerIp          = $f['s-ip']
                    ServerPort        = $entryPort
                    HttpVersion       = $f['cs-version']
                    Method            = $f['cs-method']
                    Uri               = $f['cs-uri']
                    StatusCode        = $statusCode
                    SiteId            = $f['s-siteid']
                    Reason            = $entryReason
                    ReasonDescription = $reasonDesc
                    QueueName         = $f['s-queuename']
                    SourceFile        = $file.Name
                }

                $entriesInWindow++

                if ($Summarise) {
                    $accumulated.Add($entry)
                } else {
                    $entry          # stream to pipeline immediately
                }
            }
        }
        catch {
            Write-Warning "Error reading '$($file.FullName)': $_"
        }
        finally {
            $reader.Dispose()
            $stream.Dispose()
        }
    }

    if ($entriesInWindow -eq 0 -and $logFiles.Count -gt 0) {
        Write-Warning (
            "No HTTPERR entries fell between $StartTime and $EndTime (local) after parsing $($logFiles.Count) file(s) under '$logDir'. " +
            "Try a wider -LastHours window, confirm -Path points at the folder containing httperr*.log, " +
            "or verify the server clock (log lines are UTC; the window uses local time converted to UTC)."
        )
    }

    # -----------------------------------------------------------------------
    # Build summary if requested
    # -----------------------------------------------------------------------
    if (-not $Summarise) {
        return
    }

    $total = $accumulated.Count

    $reasonBreakdown = $accumulated |
        Group-Object Reason |
        Sort-Object Count -Descending |
        ForEach-Object {
            $desc = $null
            if ($_.Name -and $script:HttpErrReasons.ContainsKey($_.Name)) {
                $desc = $script:HttpErrReasons[$_.Name]
            }
            [pscustomobject]@{
                Reason      = $_.Name
                Count       = $_.Count
                Percent     = if ($total -gt 0) { [math]::Round(($_.Count / $total) * 100, 1) } else { 0.0 }
                Description = $desc
            }
        }

    $topClients = $accumulated |
        Where-Object { $_.ClientIp } |
        Group-Object ClientIp |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object { [pscustomobject]@{ ClientIp = $_.Name; Count = $_.Count } }

    $topUris = $accumulated |
        Where-Object { $_.Uri } |
        Group-Object Uri |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object { [pscustomobject]@{ Uri = $_.Name; Count = $_.Count } }

    $portBreakdown = $accumulated |
        Where-Object { $_.ServerPort } |
        Group-Object ServerPort |
        Sort-Object Count -Descending |
        ForEach-Object { [pscustomobject]@{ Port = [int]$_.Name; Count = $_.Count } }

    # Pre-render display strings for the format file (same pattern as StatusHelp)
    $reasonDisplay = if ($reasonBreakdown) {
        ($reasonBreakdown | ForEach-Object {
            $truncDesc = if ($_.Description -and $_.Description.Length -gt 55) {
                $_.Description.Substring(0, 52) + '...'
            } else { $_.Description }
            '{0,-28} {1,6:N0}  {2,5:F1}%  {3}' -f $_.Reason, $_.Count, $_.Percent, $truncDesc
        }) -join [Environment]::NewLine
    } else { '(no entries)' }

    $clientDisplay = if ($topClients) {
        ($topClients | ForEach-Object { '{0,-18} {1,6:N0}' -f $_.ClientIp, $_.Count }) -join [Environment]::NewLine
    } else { '(no client data)' }

    $uriDisplay = if ($topUris) {
        ($topUris | ForEach-Object {
            $truncUri = if ($_.Uri -and $_.Uri.Length -gt 60) { $_.Uri.Substring(0, 57) + '...' } else { $_.Uri }
            '{0,-62} {1,6:N0}' -f $truncUri, $_.Count
        }) -join [Environment]::NewLine
    } else { '(no URI data)' }

    $portDisplay = if ($portBreakdown) {
        ($portBreakdown | ForEach-Object { '{0,-8} {1,6:N0}' -f $_.Port, $_.Count }) -join [Environment]::NewLine
    } else { '(no port data)' }

    $earliest = if ($total -gt 0) { ($accumulated | Sort-Object Timestamp)[0].Timestamp } else { $null }
    $latest   = if ($total -gt 0) { ($accumulated | Sort-Object Timestamp)[-1].Timestamp } else { $null }

    [pscustomobject]@{
        PSTypeName             = 'IISDiagnostics.HttpErrSummary'
        StartTime              = $StartTime
        EndTime                = $EndTime
        TotalEntries           = $total
        LogFilesScanned        = $logFiles.Count
        EarliestEntry          = $earliest
        LatestEntry            = $latest
        ReasonBreakdown        = @($reasonBreakdown)
        TopClients             = @($topClients)
        TopUris                = @($topUris)
        PortBreakdown          = @($portBreakdown)
        ReasonBreakdownDisplay = $reasonDisplay
        TopClientsDisplay      = $clientDisplay
        TopUrisDisplay         = $uriDisplay
        PortBreakdownDisplay   = $portDisplay
    }
}