#Requires -Version 5.1

function Get-IISW3CLog {
    <#
    .SYNOPSIS
        Parses IIS W3C access logs and returns entries or a summary for a given time window.

    .DESCRIPTION
        Reads IIS W3C-format access logs from the configured log directory (default:
        %SystemDrive%\inetpub\logs\LogFiles).

        Unlike HTTPERR logs, W3C logs record requests that reached IIS and were processed
        by an application pool - including errors the application returned deliberately
        (404, 500, etc.). HTTPERR and W3C are complementary:

          HTTPERR - requests HTTP.sys rejected before they reached IIS
          W3C     - requests IIS processed (or attempted to process)

        The sc-win32-status field is particularly useful for post-incident analysis:
          64  ERROR_NETNAME_DELETED  Connection reset during processing - the client
                                    connection dropped. Seen during app pool crashes when
                                    the worker process died mid-request.
          0   Success               Normal completion regardless of sc-status.

        Field parsing is dynamic - the #Fields: header is honoured rather than assuming
        fixed column positions. Administrators may log different field sets; the parser
        handles any valid W3C log without modification.

        Common named properties are surfaced directly on each output object. Fields not
        in the standard set are available in the AdditionalFields hashtable.

        By default returns individual IISDiagnostics.W3CEntry objects for pipeline use.
        Use -Summarise for an aggregated IISDiagnostics.W3CSummary.

    .PARAMETER StartTime
        Start of the time window (inclusive). Defaults to one hour ago.

    .PARAMETER EndTime
        End of the time window (inclusive). Defaults to now.

    .PARAMETER LastHours
        Whole-hour window ending now. Avoids locale-dependent date entry.

    .PARAMETER Path
        Full path to a W3C log directory or file. Overrides all automatic path resolution.
        Use when logs are in a non-standard location.

    .PARAMETER SiteId
        IIS numeric site ID. Logs are read from W3SVC{SiteId} under the log root.
        Mutually exclusive with -SiteName.

    .PARAMETER SiteName
        IIS site name. Resolved to a site ID via WebAdministration to locate the log
        subfolder. Requires the WebAdministration module. Mutually exclusive with -SiteId.

    .PARAMETER StatusCode
        Return only entries with this HTTP status code (sc-status).

    .PARAMETER SlowThresholdMs
        Requests with time-taken above this value (milliseconds) are flagged as slow.
        Used in -Summarise output. Default: 5000 (5 seconds).

    .PARAMETER Summarise
        Return a single IISDiagnostics.W3CSummary instead of individual entries.

    .EXAMPLE
        Get-IISW3CLog

        Returns all W3C entries from the past hour across all sites.

    .EXAMPLE
        Get-IISW3CLog -SiteName 'MySite' -StartTime (Get-Date).AddHours(-4)

        Returns entries for a specific site over a four-hour window.

    .EXAMPLE
        Get-IISW3CLog -StartTime (Get-Date).AddDays(-1) -Summarise

        Summary report for the past 24 hours.

    .EXAMPLE
        Get-IISW3CLog | Where-Object IsConnectionReset

        Returns entries where the client connection was reset during processing
        (sc-win32-status = 64). Cross-reference with Get-IISHttpErrLog output
        to correlate with app pool failures.

    .EXAMPLE
        Get-IISW3CLog | Where-Object { $_.StatusCode -ge 500 } |
            Group-Object UriStem | Sort-Object Count -Descending

        Groups server errors by URI - useful for finding which endpoint is failing.

    .EXAMPLE
        Get-IISW3CLog -StatusCode 200 |
            Sort-Object TimeTakenMs -Descending | Select-Object -First 20

        The 20 slowest successful requests in the past hour.

    .NOTES
        Requires an elevated session. IIS log files are protected by default.
        -SiteName resolution additionally requires the WebAdministration module.

        W3C log timestamps are UTC. Returned Timestamp values are local time.
        TimeTakenMs is in milliseconds as logged by IIS.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllSites')]
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
        [string]$Path,

        [Parameter(ParameterSetName = 'BySiteId')]
        [int]$SiteId,

        [Parameter(ParameterSetName = 'BySiteName')]
        [string]$SiteName,

        [Parameter()]
        [int]$StatusCode,

        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$SlowThresholdMs = 5000,

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

    if ($StartTime -ge $EndTime) {
        throw "StartTime ($StartTime) must be earlier than EndTime ($EndTime)."
    }

    $startUtc = $StartTime.ToUniversalTime()
    $endUtc   = $EndTime.ToUniversalTime()

    # ------------------------------------------------------------------
    # Resolve log directories
    # ------------------------------------------------------------------
    $logDirs = [System.Collections.Generic.List[string]]::new()

    if ($PSBoundParameters.ContainsKey('Path')) {
        # Explicit override - accept a file or directory
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            # Single file passed - treat its parent as the directory
            $logDirs.Add((Split-Path $Path -Parent))
        }
        elseif (Test-Path -LiteralPath $Path -PathType Container) {
            $logDirs.Add($Path)
        }
        else {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.IO.IOException]::new("Path '$Path' does not exist."),
                    'W3CPathNotFound',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $Path
                )
            )
        }
    }
    else {
        # Discover default log root from IIS configuration if WebAdministration is available,
        # otherwise fall back to the well-known default location.
        $logRoot = $null

        if (Get-Module -Name WebAdministration -ListAvailable -ErrorAction SilentlyContinue) {
            try {
                if (-not (Get-Module -Name WebAdministration)) {
                    Import-Module WebAdministration -ErrorAction Stop
                }

                if ($PSCmdlet.ParameterSetName -eq 'BySiteName') {
                    # Resolve site name to ID and log directory
                    $site = Get-ChildItem 'IIS:\Sites' -ErrorAction Stop |
                            Where-Object { $_.Name -eq $SiteName } |
                            Select-Object -First 1

                    if (-not $site) {
                        Write-Warning "Site '$SiteName' not found. Falling back to default log root."
                    }
                    else {
                        $SiteId  = [int]$site.Id
                        $siteLog = try { [string]$site.LogFile.Directory } catch { $null }

                        if ($siteLog -and (Test-Path ($siteLog -replace '^%SystemDrive%', $env:SystemDrive))) {
                            $logRoot = $siteLog -replace '^%SystemDrive%', $env:SystemDrive
                        }
                    }
                }

                if (-not $logRoot) {
                    # Read the global default log directory from IIS config
                    $globalLog = try {
                        (Get-WebConfigurationProperty -Filter 'system.applicationHost/log' `
                                                      -Name centralW3CLogFile.directory `
                                                      -ErrorAction SilentlyContinue).Value
                    } catch { $null }

                    if ($globalLog) {
                        $logRoot = $globalLog -replace '^%SystemDrive%', $env:SystemDrive
                    }
                }
            }
            catch {
                Write-Verbose "WebAdministration log path discovery failed: $_. Using default."
            }
        }

        # Final fallback - the IIS default that has been true since IIS 7
        if (-not $logRoot) {
            $logRoot = Join-Path $env:SystemDrive 'inetpub\logs\LogFiles'
        }

        if (-not (Test-Path -LiteralPath $logRoot)) {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.IO.DirectoryNotFoundException]::new(
                        "W3C log root '$logRoot' not found. " +
                        "Use -Path to specify the log directory explicitly, " +
                        "or verify IIS is installed and W3C logging is enabled."),
                    'W3CLogRootNotFound',
                    [System.Management.Automation.ErrorCategory]::ObjectNotFound,
                    $logRoot
                )
            )
        }

        if ($PSCmdlet.ParameterSetName -in 'BySiteId','BySiteName') {
            # Specific site - one subfolder
            $subDir = Join-Path $logRoot "W3SVC$SiteId"
            if (Test-Path -LiteralPath $subDir) {
                $logDirs.Add($subDir)
            }
            else {
                Write-Warning "Log directory '$subDir' not found. Verify the site ID and that W3C logging is enabled for this site."
                return
            }
        }
        else {
            # All sites - enumerate W3SVC* subfolders
            $found = @(Get-ChildItem -LiteralPath $logRoot -Directory -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -match '^W3SVC\d+$' })

            if (-not $found) {
                Write-Warning "No W3SVC* log directories found under '$logRoot'. Verify IIS W3C logging is enabled."
                return
            }

            $found | ForEach-Object { $logDirs.Add($_.FullName) }
        }
    }

    Write-Verbose "Log directories to scan: $($logDirs -join ', ')"

    # ------------------------------------------------------------------
    # Discover log files across all directories
    # W3C log filenames follow predictable patterns:
    #   Daily:  u_exYYMMDD.log
    #   Hourly: u_exYYMMDDHH.log
    #   Other:  no date in name - fall back to LastWriteTime filtering
    # ------------------------------------------------------------------
    $startDate = $startUtc.Date
    $endDate   = $endUtc.Date.AddDays(1)   # inclusive upper bound for date comparison

    $logFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

    foreach ($dir in $logDirs) {
        $candidates = @(Get-ChildItem -LiteralPath $dir -Filter '*.log' -ErrorAction SilentlyContinue |
                        Sort-Object Name)

        foreach ($file in $candidates) {
            $include = $false

            if ($file.Name -match '^u_ex(\d{2})(\d{2})(\d{2})(\d{2})?') {
                # Parse date from filename (century assumed 20xx)
                $fileYear  = 2000 + [int]$Matches[1]
                $fileMonth = [int]$Matches[2]
                $fileDay   = [int]$Matches[3]
                try {
                    $fileDate = [datetime]::new($fileYear, $fileMonth, $fileDay)
                    # Include if the file's date falls within or adjacent to the window
                    $include  = ($fileDate -ge $startDate.AddDays(-1)) -and ($fileDate -le $endDate)
                }
                catch { $include = $true }   # date parse failed - include and let timestamp filter handle it
            }
            else {
                # Non-standard name - fall back to LastWriteTime
                $include = $file.LastWriteTimeUtc -ge $startUtc.AddHours(-1)
            }

            if ($include) { $logFiles.Add($file) }
        }
    }

    if ($logFiles.Count -eq 0) {
        Write-Warning "No W3C log files found for the window $StartTime to $EndTime."
        return
    }

    Write-Verbose "Scanning $($logFiles.Count) log file(s)."

    # ------------------------------------------------------------------
    # Well-known W3C field names mapped to output property names.
    # Fields not in this map land in AdditionalFields.
    # ------------------------------------------------------------------
    $knownFields = @{
        'date'            = 'date'          # parsed into Timestamp with 'time'
        'time'            = 'time'          # parsed into Timestamp with 'date'
        'c-ip'            = 'ClientIp'
        'c-port'          = 'ClientPort'
        's-ip'            = 'ServerIp'
        's-port'          = 'ServerPort'
        's-sitename'      = 'SiteName'
        's-computername'  = 'ComputerName'
        'cs-method'       = 'Method'
        'cs-uri-stem'     = 'UriStem'
        'cs-uri-query'    = 'UriQuery'
        'cs-version'      = 'HttpVersion'
        'cs-username'     = 'Username'
        'cs-host'         = 'Host'
        'cs(User-Agent)'  = 'UserAgent'
        'cs(Referer)'     = 'Referer'
        'cs-bytes'        = 'BytesReceived'
        'sc-bytes'        = 'BytesSent'
        'sc-status'       = 'StatusCode'
        'sc-substatus'    = 'SubStatus'
        'sc-win32-status' = 'Win32Status'
        'time-taken'      = 'TimeTakenMs'
    }

    # ------------------------------------------------------------------
    # Accumulate all entries (needed for -Summarise; stream otherwise)
    # ------------------------------------------------------------------
    $accumulated = if ($Summarise) {
        [System.Collections.Generic.List[psobject]]::new()
    } else { $null }

    $filesScanned = 0

    foreach ($file in $logFiles) {
        $filesScanned++
        Write-Verbose "Parsing: $($file.FullName)"

        $fieldNames  = $null
        $fieldCount  = 0

        $stream = [System.IO.File]::Open(
            $file.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)

        try {
            while ($null -ne ($rawLine = $reader.ReadLine())) {

                if ($rawLine.StartsWith('#')) {
                    if ($rawLine -match '^#Fields:\s+(.+)') {
                        $fieldNames = $Matches[1].Trim() -split '\s+'
                        $fieldCount = $fieldNames.Count
                        Write-Verbose "  Fields ($fieldCount): $($fieldNames -join ', ')"
                    }
                    continue
                }

                if ([string]::IsNullOrWhiteSpace($rawLine) -or $null -eq $fieldNames) { continue }

                $parts = $rawLine -split '\s+'
                # Guard: W3C lines can have trailing spaces or extra fields in rare cases
                if ($parts.Count -lt 2) { continue }

                # ----------------------------------------------------------
                # Parse timestamp - requires both date and time fields
                # ----------------------------------------------------------
                $dateIdx = [Array]::IndexOf($fieldNames, 'date')
                $timeIdx = [Array]::IndexOf($fieldNames, 'time')

                if ($dateIdx -lt 0 -or $timeIdx -lt 0) { continue }
                if ($dateIdx -ge $parts.Count -or $timeIdx -ge $parts.Count) { continue }

                $entryUtc = [datetime]::MinValue
                $parsed   = [datetime]::TryParseExact(
                    "$($parts[$dateIdx]) $($parts[$timeIdx])",
                    'yyyy-MM-dd HH:mm:ss',
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    ([System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                     [System.Globalization.DateTimeStyles]::AdjustToUniversal),
                    [ref]$entryUtc
                )
                if (-not $parsed) { continue }
                if ($entryUtc -lt $startUtc -or $entryUtc -gt $endUtc) { continue }

                # ----------------------------------------------------------
                # Map fields to a hashtable by name for clean access below.
                # Use '-' (IIS null sentinel) → $null conversion.
                # ----------------------------------------------------------
                $f = @{}
                for ($i = 0; $i -lt $fieldNames.Count -and $i -lt $parts.Count; $i++) {
                    $f[$fieldNames[$i]] = if ($parts[$i] -eq '-') { $null } else { $parts[$i] }
                }

                # ----------------------------------------------------------
                # Apply caller filters before building the object
                # ----------------------------------------------------------
                $scStatus = $null
                if ($f['sc-status']) { $null = [int]::TryParse($f['sc-status'], [ref]$scStatus) }

                if ($PSBoundParameters.ContainsKey('StatusCode') -and $scStatus -ne $StatusCode) { continue }

                # ----------------------------------------------------------
                # Parse typed fields
                # ----------------------------------------------------------
                $clientPort  = $null ; if ($f['c-port'])          { $null = [int]::TryParse($f['c-port'],          [ref]$clientPort)  }
                $serverPort  = $null ; if ($f['s-port'])          { $null = [int]::TryParse($f['s-port'],          [ref]$serverPort)  }
                $subStatus   = $null ; if ($f['sc-substatus'])    { $null = [int]::TryParse($f['sc-substatus'],    [ref]$subStatus)   }
                $win32Status = $null ; if ($f['sc-win32-status']) { $null = [int]::TryParse($f['sc-win32-status'], [ref]$win32Status) }
                $timeTaken   = $null ; if ($f['time-taken'])      { $null = [int]::TryParse($f['time-taken'],      [ref]$timeTaken)   }
                $bytesSent   = $null ; if ($f['sc-bytes'])        { $null = [int]::TryParse($f['sc-bytes'],        [ref]$bytesSent)   }
                $bytesRecv   = $null ; if ($f['cs-bytes'])        { $null = [int]::TryParse($f['cs-bytes'],        [ref]$bytesRecv)   }

                # ----------------------------------------------------------
                # AdditionalFields - anything not in the known map
                # ----------------------------------------------------------
                $additional = @{}
                foreach ($key in $f.Keys) {
                    if (-not $knownFields.ContainsKey($key) -and $key -ne 'date' -and $key -ne 'time') {
                        $additional[$key] = $f[$key]
                    }
                }

                # ----------------------------------------------------------
                # Build the entry object
                # IsConnectionReset is a derived convenience property.
                # sc-win32-status 64 = ERROR_NETNAME_DELETED - the TCP
                # connection was reset. In a crash scenario, requests being
                # actively processed when the worker process died will appear
                # in W3C logs with this status.
                # ----------------------------------------------------------
                $entry = [pscustomobject]@{
                    PSTypeName        = 'IISDiagnostics.W3CEntry'
                    Timestamp         = $entryUtc.ToLocalTime()
                    ClientIp          = $f['c-ip']
                    ClientPort        = $clientPort
                    ServerIp          = $f['s-ip']
                    ServerPort        = $serverPort
                    SiteName          = $f['s-sitename']
                    SiteLogFolder     = $file.Directory.Name          # e.g. W3SVC1 - reliable even when s-sitename is not logged
                    ComputerName      = $f['s-computername']
                    Method            = $f['cs-method']
                    UriStem           = $f['cs-uri-stem']
                    UriQuery          = $f['cs-uri-query']
                    HttpVersion       = $f['cs-version']
                    Username          = $f['cs-username']
                    Host              = $f['cs-host']
                    UserAgent         = $f['cs(User-Agent)']
                    Referer           = $f['cs(Referer)']
                    StatusCode        = $scStatus
                    SubStatus         = $subStatus
                    Win32Status       = $win32Status
                    IsConnectionReset = ($win32Status -eq 64)
                    TimeTakenMs       = $timeTaken
                    BytesSent         = $bytesSent
                    BytesReceived     = $bytesRecv
                    AdditionalFields  = $additional
                    SourceFile        = "$($file.Directory.Name)\$($file.Name)"  # W3SVC1\u_ex260510.log
                }

                if ($Summarise) { $accumulated.Add($entry) }
                else            { $entry }
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

    # ------------------------------------------------------------------
    # Build summary if requested
    # ------------------------------------------------------------------
    if (-not $Summarise) { return }

    $total = $accumulated.Count

    # Status code breakdown
    $statusBreakdown = $accumulated |
        Where-Object { $_.StatusCode } |
        Group-Object StatusCode |
        Sort-Object Count -Descending |
        ForEach-Object {
            $code  = [int]$_.Name
            $class = switch ([math]::Floor($code / 100)) {
                2 { 'Success'       }
                3 { 'Redirect'      }
                4 { 'ClientError'   }
                5 { 'ServerError'   }
                default { 'Other'  }
            }
            [pscustomobject]@{
                StatusCode = $code
                Class      = $class
                Count      = $_.Count
                Percent    = if ($total -gt 0) { [math]::Round(($_.Count / $total) * 100, 1) } else { 0.0 }
            }
        }

    # Error counts
    $count4xx             = ($statusBreakdown | Where-Object Class -eq 'ClientError' | Measure-Object Count -Sum).Sum
    $count5xx             = ($statusBreakdown | Where-Object Class -eq 'ServerError' | Measure-Object Count -Sum).Sum
    $errorTotal           = [int]$count4xx + [int]$count5xx
    $errorRate            = if ($total -gt 0) { [math]::Round(($errorTotal / $total) * 100, 2) } else { 0.0 }

    # Connection resets (sc-win32-status = 64)
    $connectionResets     = @($accumulated | Where-Object IsConnectionReset)
    $connectionResetCount = $connectionResets.Count

    # Slow requests
    $slowRequests = @($accumulated | Where-Object {
        $null -ne $_.TimeTakenMs -and $_.TimeTakenMs -gt $SlowThresholdMs
    } | Sort-Object TimeTakenMs -Descending)
    $slowCount = $slowRequests.Count

    # Top URIs by request count
    $topUrisByCount = $accumulated |
        Where-Object { $_.UriStem } |
        Group-Object UriStem |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            $times = @($_.Group | Where-Object { $_.TimeTakenMs } | ForEach-Object { $_.TimeTakenMs })
            [pscustomobject]@{
                UriStem   = $_.Name
                Count     = $_.Count
                AvgMs     = if ($times.Count -gt 0) { [math]::Round(($times | Measure-Object -Average).Average, 0) } else { $null }
                MaxMs     = if ($times.Count -gt 0) { ($times | Measure-Object -Maximum).Maximum } else { $null }
            }
        }

    # Top URIs by total time consumed (bottleneck finder - a URI called 1000 times
    # at 200ms contributes more load than one called 10 times at 1000ms)
    $topUrisByTime = $accumulated |
        Where-Object { $_.UriStem -and $_.TimeTakenMs } |
        Group-Object UriStem |
        ForEach-Object {
            $times    = @($_.Group | ForEach-Object { $_.TimeTakenMs })
            $totalMs  = ($times | Measure-Object -Sum).Sum
            [pscustomobject]@{ UriStem = $_.Name; Count = $_.Count; TotalMs = $totalMs }
        } |
        Sort-Object TotalMs -Descending |
        Select-Object -First 10

    # Top client IPs
    $topClients = $accumulated |
        Where-Object { $_.ClientIp } |
        Group-Object ClientIp |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object { [pscustomobject]@{ ClientIp = $_.Name; Count = $_.Count } }

    # Traffic shape - requests per 5-minute bucket
    $trafficShape = $accumulated |
        Group-Object {
            $ts     = $_.Timestamp
            $bucket = [math]::Floor($ts.Minute / 5) * 5
            [datetime]::new($ts.Year, $ts.Month, $ts.Day, $ts.Hour, $bucket, 0)
        } |
        Sort-Object Name |
        ForEach-Object {
            [pscustomobject]@{
                BucketStart  = $_.Name
                RequestCount = $_.Count
            }
        }

    # Slowest individual requests
    $slowestRequests = $slowRequests |
        Select-Object -First 10 |
        ForEach-Object {
            [pscustomobject]@{
                Timestamp   = $_.Timestamp
                UriStem     = $_.UriStem
                StatusCode  = $_.StatusCode
                TimeTakenMs = $_.TimeTakenMs
                ClientIp    = $_.ClientIp
            }
        }

    # ------------------------------------------------------------------
    # Pre-rendered display strings
    # ------------------------------------------------------------------
    $statusDisplay = if ($statusBreakdown) {
        ($statusBreakdown | Select-Object -First 15 | ForEach-Object {
            '{0,6}  {1,-14} {2,8:N0}  {3,5:F1}%' -f $_.StatusCode, $_.Class, $_.Count, $_.Percent
        }) -join [Environment]::NewLine
    } else { '(no status data)' }

    $uriCountDisplay = if ($topUrisByCount) {
        ($topUrisByCount | ForEach-Object {
            $uri = if ($_.UriStem -and $_.UriStem.Length -gt 55) { $_.UriStem.Substring(0,52) + '...' } else { $_.UriStem }
            '{0,-58} {1,6:N0}  avg {2,6}ms  max {3,7}ms' -f $uri, $_.Count,
                (if ($_.AvgMs) { $_.AvgMs } else { '-' }),
                (if ($_.MaxMs) { $_.MaxMs } else { '-' })
        }) -join [Environment]::NewLine
    } else { '(no URI data)' }

    $slowDisplay = if ($slowestRequests) {
        ($slowestRequests | ForEach-Object {
            $uri = if ($_.UriStem -and $_.UriStem.Length -gt 45) { $_.UriStem.Substring(0,42) + '...' } else { $_.UriStem }
            '{0}  {1,-48} {2,3}  {3,8:N0}ms' -f
                $_.Timestamp.ToString('HH:mm:ss'), $uri, $_.StatusCode, $_.TimeTakenMs
        }) -join [Environment]::NewLine
    } else { "(no requests exceeded ${SlowThresholdMs}ms threshold)" }

    $resetDisplay = if ($connectionResetCount -gt 0) {
        $uriBreakdown = ($connectionResets |
            Where-Object { $_.UriStem } |
            Group-Object UriStem |
            Sort-Object Count -Descending |
            Select-Object -First 5 |
            ForEach-Object { "$($_.Count)x $($_.Name)" }) -join ', '
        "$connectionResetCount connection reset(s) (sc-win32-status=64). Top URIs: $uriBreakdown"
    } else { 'None' }

    [pscustomobject]@{
        PSTypeName               = 'IISDiagnostics.W3CSummary'
        StartTime                = $StartTime
        EndTime                  = $EndTime
        LogFilesScanned          = $filesScanned
        TotalRequests            = $total
        ErrorRequests4xx         = [int]$count4xx
        ErrorRequests5xx         = [int]$count5xx
        ErrorRate                = $errorRate
        SlowRequestCount         = $slowCount
        SlowThresholdMs          = $SlowThresholdMs
        ConnectionResetCount     = $connectionResetCount
        StatusBreakdown          = @($statusBreakdown)
        TopUrisByCount           = @($topUrisByCount)
        TopUrisByTime            = @($topUrisByTime)
        TopClients               = @($topClients)
        SlowestRequests          = @($slowestRequests)
        TrafficShape             = @($trafficShape)
        StatusBreakdownDisplay   = $statusDisplay
        TopUrisByCountDisplay    = $uriCountDisplay
        SlowestRequestsDisplay   = $slowDisplay
        ConnectionResetDisplay   = $resetDisplay
    }
}