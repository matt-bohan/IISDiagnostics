#Requires -Version 5.1

# WAS event IDs that represent significant pool lifecycle events.
# Used to set IsSignificant on entries and to drive the -Significant filter.
$script:WasSignificantIds = [System.Collections.Generic.HashSet[int]]@(
    5009,   # Worker process failed to respond to ping - terminated
    5010,   # Worker process requested recycle - private bytes limit
    5011,   # Worker process shutdown callback failed
    5012,   # Rapid-fail protection triggered - pool disabled
    5077,   # Worker process did not shut down in a timely fashion
    5117,   # Worker process exited with non-zero exit code
    5189    # Pool automatically re-enabled after rapid-fail wait period
)

# Providers queried from the System event log
$script:SystemProviders = @(
    'Microsoft-Windows-WAS',
    'WAS',                                  # Legacy name on older Server versions
    'Microsoft-Windows-HttpService',
    'Microsoft-Windows-IIS-W3SVC',
    'W3SVC',                                # Legacy
    'Microsoft-Windows-IIS-Configuration'
)

# Providers queried from the Application event log
$script:ApplicationProviders = @(
    'ASP.NET 4.0.30319.0',
    'ASP.NET 2.0.50727.0',
    '.NET Runtime',
    'Application Error',
    'IIS AspNetCore Module',
    'IIS AspNetCore Module V2'
)

function Get-IISEventLog {
    <#
    .SYNOPSIS
        Returns IIS-relevant Windows Event Log entries from the System and Application logs.

    .DESCRIPTION
        Queries Windows Event Log providers that record IIS and application pool activity,
        returning a time-bounded set of entries suitable for cross-referencing with
        HTTPERR and W3C log analysis.

        Sources queried:

          System log
            Microsoft-Windows-WAS / WAS
              The authoritative record of application pool lifecycle events: starts, stops,
              crashes, rapid-fail protection triggers, and worker process recycling.
              When Invoke-IISHttpErrAnalysis identifies a crash pattern, WAS events explain why
              the pool stopped.

            Microsoft-Windows-HttpService
              HTTP.sys kernel-mode events - binding failures, SSL binding errors, and
              driver-level problems that predate even HTTPERR log entries.

            Microsoft-Windows-IIS-W3SVC / W3SVC
              IIS web service events - site start/stop, metabase access failures.

            Microsoft-Windows-IIS-Configuration
              IIS configuration change events - useful for establishing what changed
              before a failure began.

          Application log
            ASP.NET 4.0.30319.0 / ASP.NET 2.0.50727.0
              ASP.NET runtime errors and unhandled exceptions from managed applications.

            .NET Runtime
              CLR-level crashes, out-of-memory conditions, and unhandled exceptions
              across .NET Framework versions.

            Application Error
              Windows-level crash records for w3wp.exe - includes the faulting module name
              and exception code. Appears when the worker process crashes hard enough for
              Windows Error Reporting to record it.

            IIS AspNetCore Module / IIS AspNetCore Module V2
              ANCM startup failures, stdout log path errors, port binding conflicts, and
              process launch failures for ASP.NET Core applications.

        IsSignificant is set to $true on entries that represent definitive pool failure
        events (WAS 5009, 5011, 5012, 5117) or any Error/Critical from the Application log.
        Use -Significant to return only these entries.

    .PARAMETER StartTime
        Start of the time window (inclusive). Defaults to one hour ago.

    .PARAMETER EndTime
        End of the time window (inclusive). Defaults to now.

    .PARAMETER LastHours
        Whole-hour window ending now. Prefer this over typed dates when locale formats differ.

    .PARAMETER AppPoolName
        Filter WAS entries to those referencing a specific application pool name.
        Matched against the extracted AppPoolName property (case-insensitive).
        Non-WAS entries are unaffected by this filter.

    .PARAMETER EntryType
        Filter by entry level. Accepts one or more of: Error, Warning, Information, Critical.
        Critical is included in Error when both are specified. Defaults to all levels.

    .PARAMETER Source
        Filter to one or more specific provider names. Use tab completion or
        Get-WinEvent -ListProvider to discover available provider names.

    .PARAMETER Significant
        Return only entries classified as significant: WAS crash/disable events
        (5009, 5011, 5012, 5077, 5117, 5189) and Application log errors.

    .PARAMETER IncludeInformation
        By default, Information-level entries are suppressed when -Significant is used.
        This switch includes them. Has no effect without -Significant.

    .EXAMPLE
        Get-IISEventLog

        Returns all IIS-relevant events from the past hour.

    .EXAMPLE
        Get-IISEventLog -StartTime (Get-Date).AddHours(-4) -EntryType Error, Warning

        Errors and warnings from the past four hours.

    .EXAMPLE
        Get-IISEventLog -AppPoolName 'MyAppPool'

        WAS events for a specific application pool.

    .EXAMPLE
        Get-IISEventLog -Significant

        Only crash/disable events and application errors - the events that explain why
        something stopped working.

    .EXAMPLE
        Get-IISEventLog -Significant -StartTime (Get-Date).AddHours(-4) |
            Sort-Object TimeCreated |
            Select-Object TimeCreated, Source, EventId, AppPoolName, ShortMessage

        Timeline of significant events - good for correlating with HTTPERR findings.

    .EXAMPLE
        Get-IISEventLog | Where-Object EventId -eq 5012

        Find all rapid-fail protection trigger events in the past hour.

    .EXAMPLE
        Get-IISEventLog | Where-Object Source -like '*WAS*' |
            Group-Object EventId | Sort-Object Count -Descending

        Frequency of WAS event IDs - shows the shape of pool activity.

    .NOTES
        Requires an elevated session.

        The Security event log is not queried - authentication failure events require
        separate audit policy configuration and additional permissions beyond standard
        administrator access.

        If a provider is not installed (e.g. ANCM on a server with no ASP.NET Core apps)
        Get-WinEvent silently skips it rather than throwing an error.
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
        [string]$AppPoolName,

        [Parameter()]
        [ValidateSet('Error', 'Warning', 'Information', 'Critical')]
        [string[]]$EntryType,

        [Parameter()]
        [string[]]$Source,

        [Parameter()]
        [switch]$Significant
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

    # ------------------------------------------------------------------
    # Resolve which providers to query
    # ------------------------------------------------------------------
    $systemProviders = if ($PSBoundParameters.ContainsKey('Source')) {
        $Source | Where-Object { $script:SystemProviders -contains $_ }
    } else {
        $script:SystemProviders
    }

    $appProviders = if ($PSBoundParameters.ContainsKey('Source')) {
        $Source | Where-Object { $script:ApplicationProviders -contains $_ }
    } else {
        $script:ApplicationProviders
    }

    # ------------------------------------------------------------------
    # WinEvent Level mapping
    # Level: 1=Critical, 2=Error, 3=Warning, 4=Information, 5=Verbose
    # We treat Critical as a subset of Error for user-facing filtering.
    # ------------------------------------------------------------------
    $levelFilter = $null
    if ($PSBoundParameters.ContainsKey('EntryType')) {
        $levels = [System.Collections.Generic.List[int]]::new()
        foreach ($type in $EntryType) {
            switch ($type) {
                'Critical'    { if ($levels -notcontains 1) { $levels.Add(1) } }
                'Error'       { if ($levels -notcontains 1) { $levels.Add(1) }
                                if ($levels -notcontains 2) { $levels.Add(2) } }
                'Warning'     { if ($levels -notcontains 3) { $levels.Add(3) } }
                'Information' { if ($levels -notcontains 4) { $levels.Add(4) } }
            }
        }
        $levelFilter = $levels.ToArray()
    }

    # ------------------------------------------------------------------
    # Query helper - queries one log for an array of providers,
    # returning raw WinEvent objects. Handles missing providers gracefully.
    # ------------------------------------------------------------------
    function Invoke-EventQuery {
        param([string]$LogName, [string[]]$Providers)

        if (-not $Providers -or $Providers.Count -eq 0) { return @() }

        $filter = @{
            LogName      = $LogName
            ProviderName = $Providers
            StartTime    = $StartTime
            EndTime      = $EndTime
        }
        if ($levelFilter) { $filter['Level'] = $levelFilter }

        try {
            $raw = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
            Write-Verbose "  $LogName/$($Providers -join ','): $($raw.Count) event(s)"
            return $raw
        }
        catch [System.Exception] {
            # Get-WinEvent throws when no matching events exist on some OS versions
            # even with -ErrorAction SilentlyContinue - treat as empty result.
            Write-Verbose "  $LogName query returned no results or provider unavailable: $_"
            return @()
        }
    }

    # ------------------------------------------------------------------
    # Run queries
    # ------------------------------------------------------------------
    Write-Verbose "Querying System log..."
    $systemEvents = Invoke-EventQuery -LogName 'System' -Providers $systemProviders

    Write-Verbose "Querying Application log..."
    $appEvents    = Invoke-EventQuery -LogName 'Application' -Providers $appProviders

    $allRaw = @($systemEvents) + @($appEvents)

    if ($allRaw.Count -eq 0) {
        Write-Verbose "No events found matching the specified criteria."
        return
    }

    Write-Verbose "Total events before filtering: $($allRaw.Count)"

    # ------------------------------------------------------------------
    # AppPoolName extraction regex
    # WAS messages consistently use the pattern: application pool 'PoolName'
    # Some events use double-quotes; handle both.
    # ------------------------------------------------------------------
    $poolPattern = [regex]::new(
        "application pool ['\u201c]([^'\u201d]+)['\u201d]",
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    # Worker process ID extraction: "process id of 'NNN'" or "process id was 'NNN'"
    $pidPattern = [regex]::new(
        "process id (?:of|was) ['\u201c]?(\d+)['\u201d]?",
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    # ------------------------------------------------------------------
    # Build output objects
    # ------------------------------------------------------------------
    foreach ($raw in ($allRaw | Sort-Object TimeCreated)) {

        $message      = try { [string]$raw.Message } catch { '' }
        $providerName = [string]$raw.ProviderName
        $eventId      = [int]$raw.Id
        $logName      = [string]$raw.LogName

        # Normalise level to a friendly EntryType string
        $entryTypeStr = switch ($raw.Level) {
            1       { 'Critical'    }
            2       { 'Error'       }
            3       { 'Warning'     }
            4       { 'Information' }
            5       { 'Verbose'     }
            default { 'Unknown'     }
        }

        # Extract pool name from message where possible
        $extractedPool = $null
        $poolMatch     = $poolPattern.Match($message)
        if ($poolMatch.Success) { $extractedPool = $poolMatch.Groups[1].Value }

        # Extract worker process ID from message where possible
        $extractedPid = $null
        $pidMatch     = $pidPattern.Match($message)
        if ($pidMatch.Success) { $null = [int]::TryParse($pidMatch.Groups[1].Value, [ref]$extractedPid) }

        # Apply -AppPoolName filter
        # Filter applies to entries that have an extracted pool name.
        # Entries from non-WAS sources without a pool name are not filtered out.
        if ($PSBoundParameters.ContainsKey('AppPoolName') -and $extractedPool) {
            if ($extractedPool -notlike "*$AppPoolName*") { continue }
        }

        # Classify significance:
        # WAS crash/disable events are always significant.
        # Any Error or Critical from the Application log is significant.
        $isSignificant = (
            ($logName -eq 'System' -and $script:WasSignificantIds.Contains($eventId)) -or
            ($logName -eq 'Application' -and $raw.Level -in 1, 2)
        )

        if ($Significant -and -not $isSignificant) { continue }

        # Short message for table display - first non-empty line, up to 120 chars
        $shortMessage = ($message -split "`n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ } |
            Select-Object -First 1)
        if ($shortMessage -and $shortMessage.Length -gt 120) {
            $shortMessage = $shortMessage.Substring(0, 117) + '...'
        }

        # Friendly description for well-known WAS event IDs
        $knownDescription = switch ($eventId) {
            5009 { 'Worker process failed to respond to ping - process terminated' }
            5010 { 'Worker process requested recycle - private bytes memory limit reached' }
            5011 { 'Worker process shutdown callback failed' }
            5012 { 'Rapid-fail protection triggered - application pool disabled' }
            5074 { 'Application pool started successfully' }
            5075 { 'Application pool stopped' }
            5076 { 'Application pool recycled' }
            5077 { 'Worker process did not shut down in a timely fashion' }
            5079 { 'Application pool disabled' }
            5080 { 'Worker process started' }
            5083 { 'Application pool recycled - scheduled recycle time' }
            5117 { 'Worker process exited with non-zero exit code' }
            5186 { 'Worker process exit code recorded' }
            5189 { 'Application pool automatically re-enabled after rapid-fail wait period' }
            default { $null }
        }

        [pscustomobject]@{
            PSTypeName         = 'IISDiagnostics.EventLogEntry'
            TimeCreated        = $raw.TimeCreated
            LogName            = $logName
            Source             = $providerName
            EventId            = $eventId
            EntryType          = $entryTypeStr
            AppPoolName        = $extractedPool
            WorkerProcessId    = $extractedPid
            IsSignificant      = $isSignificant
            KnownDescription   = $knownDescription
            ShortMessage       = $shortMessage
            Message            = $message
        }
    }
}