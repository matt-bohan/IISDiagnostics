#Requires -Version 5.1

function Invoke-IISHttpErrAnalysis {
    <#
    .SYNOPSIS
        Analyses HTTPERR logs and returns severity-graded findings - built for fast triage
        when something has gone wrong.

    .DESCRIPTION
        Calls Get-IISHttpErrLog internally, then applies diagnostic rules to the entries and
        returns an IISDiagnostics.HttpErrAnalysis object containing:

         - An overall severity (Critical / Warning / Info / Healthy)
         - A list of specific findings, each with severity, evidence, and suggested next steps

        This cmdlet presents what the HTTPERR log recorded and what patterns were observed.
        It does not assert root causes - those require corroboration from the Windows Event Log,
        W3C access logs, application logs, and current pool state.

        Patterns detected:

          Pool stopped draining its queue (Timer_AppPool clustering)
            Timer_AppPool means a request sat in the queue until it timed out without being
            processed. When these cluster into a short window it indicates the pool abruptly
            stopped draining - requests already queued were abandoned. Distinct from a gradual
            build-up under sustained load.

          Pool stopped accepting connections (Rejected)
            HTTP.sys records Rejected when it cannot pass a request to the pool. A burst
            and a gradual spread are both reported with timing - what caused the pool to be
            unavailable is not asserted here.

          Combined pattern: queue stopped then connections refused
            When both patterns appear close together in time the sequence is noted as an
            observation. Root cause still requires the Windows Event Log (WAS source).

          App_InitFailed, AppOffline, QueueFull, SslError, client timeouts, malformed requests.

    .PARAMETER StartTime
        Start of the window to analyse. Defaults to one hour ago.

    .PARAMETER EndTime
        End of the window to analyse. Defaults to now.

    .PARAMETER Path
        Override the HTTPERR log directory. Passed through to Get-IISHttpErrLog.

    .PARAMETER BurstWindowMinutes
        Size of the time bucket used when detecting a burst of entries. Default: 5 minutes.
        Increase for low-traffic sites where a sudden failure may produce fewer entries per minute.

    .PARAMETER BurstThreshold
        Minimum entries in a single BurstWindowMinutes bucket to classify the pattern as a
        burst rather than a gradual spread. Default: 5.

    .EXAMPLE
        Invoke-IISHttpErrAnalysis

    .EXAMPLE
        Invoke-IISHttpErrAnalysis -StartTime (Get-Date).AddHours(-4)

    .EXAMPLE
        $result = Invoke-IISHttpErrAnalysis
        $result.Findings | Where-Object Severity -eq 'Critical'

    .NOTES
        Requires an elevated session.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [datetime]$StartTime = (Get-Date).AddHours(-1),
        [Parameter()] [datetime]$EndTime   = (Get-Date),
        [Parameter()] [string]$Path,
        [Parameter()] [ValidateRange(1, 60)]  [int]$BurstWindowMinutes = 5,
        [Parameter()] [ValidateRange(1, 100)] [int]$BurstThreshold     = 5
    )

    Assert-ElevatedSession -CmdletName $MyInvocation.MyCommand.Name

    $getParams = @{ StartTime = $StartTime; EndTime = $EndTime; Verbose = $false }
    if ($PSBoundParameters.ContainsKey('Path')) { $getParams['Path'] = $Path }

    Write-Verbose "Collecting HTTPERR entries for window $StartTime to $EndTime"
    $entries = @(Get-IISHttpErrLog @getParams)
    $total   = $entries.Count
    Write-Verbose "Collected $total entries. Running analysis rules."

    $byReason = @{}
    foreach ($e in $entries) {
        $r = if ($e.Reason) { $e.Reason } else { 'Unknown' }
        if (-not $byReason.ContainsKey($r)) { $byReason[$r] = [System.Collections.Generic.List[psobject]]::new() }
        $byReason[$r].Add($e)
    }

    function CountOf([string]$Reason) { if ($byReason.ContainsKey($Reason)) { $byReason[$Reason].Count } else { 0 } }
    function Pct([int]$n) { if ($total -gt 0) { [math]::Round(($n / $total) * 100, 1) } else { 0.0 } }

    function Get-BurstInfo([psobject[]]$Items) {
        if (-not $Items -or $Items.Count -eq 0) {
            return @{ IsBurst = $false; PeakCount = 0; PeakWindowStart = $null; FirstEntry = $null; LastEntry = $null }
        }
        $sorted = $Items | Sort-Object Timestamp
        $windows = $Items | Group-Object {
            $ts     = $_.Timestamp
            $bucket = [math]::Floor($ts.Minute / $BurstWindowMinutes) * $BurstWindowMinutes
            [datetime]::new($ts.Year, $ts.Month, $ts.Day, $ts.Hour, $bucket, 0)
        }
        $peak = $windows | Sort-Object Count -Descending | Select-Object -First 1
        return @{
            IsBurst         = ($peak.Count -ge $BurstThreshold)
            PeakCount       = $peak.Count
            PeakWindowStart = $peak.Group[0].Timestamp
            FirstEntry      = ($sorted | Select-Object -First 1)
            LastEntry       = ($sorted | Select-Object -Last  1)
        }
    }

    function Format-PeakBucketTime {
        param($Timestamp)
        if ($null -eq $Timestamp) { return 'n/a' }
        $ts = [datetime]$Timestamp
        [datetime]::new($ts.Year, $ts.Month, $ts.Day, $ts.Hour,
            ([math]::Floor($ts.Minute / $BurstWindowMinutes) * $BurstWindowMinutes), 0).ToString('HH:mm')
    }

    $findings = [System.Collections.Generic.List[psobject]]::new()

    function Add-Finding([string]$Severity, [string]$Category, [string]$Title,
                         [string]$Detail, [string]$Evidence, [string[]]$RecommendedActions) {
        $rank = switch ($Severity) { 'Critical' { 4 } 'Warning' { 3 } 'Info' { 2 } default { 1 } }
        $findings.Add([pscustomobject]@{
            PSTypeName         = 'IISDiagnostics.HttpErrFinding'
            Severity           = $Severity
            SeverityRank       = $rank
            Category           = $Category
            Title              = $Title
            Detail             = $Detail
            Evidence           = $Evidence
            RecommendedActions = [string[]]$RecommendedActions
        })
    }

    # ------------------------------------------------------------------
    # Rule: Pool stopped draining its queue - Timer_AppPool clustering
    #
    # A sudden cluster means the pool abruptly stopped processing requests
    # that were already queued - those requests were abandoned with no
    # response sent. Distinct from a gradual build-up under load.
    # ------------------------------------------------------------------
    $appPoolTimerEntries = if ($byReason.ContainsKey('Timer_AppPool')) { @($byReason['Timer_AppPool']) } else { @() }
    $appPoolBurst        = Get-BurstInfo $appPoolTimerEntries
    $appPoolCount        = $appPoolTimerEntries.Count
    $appPoolPct          = Pct $appPoolCount

    if ($appPoolCount -gt 0) {
        if ($appPoolBurst.IsBurst) {
            $first    = $appPoolBurst.FirstEntry.Timestamp.ToString('HH:mm:ss')
            $last     = $appPoolBurst.LastEntry.Timestamp.ToString('HH:mm:ss')
            $duration = [math]::Round(($appPoolBurst.LastEntry.Timestamp - $appPoolBurst.FirstEntry.Timestamp).TotalMinutes, 1)

            Add-Finding -Severity 'Critical' `
                -Category 'QueueDrainStopped' `
                -Title 'Pool stopped draining its request queue - burst of abandoned requests' `
                -Detail (
                    "$appPoolCount queued request(s) expired between $first and $last " +
                    "(approximately $duration minutes). The entries are clustered, indicating " +
                    "the pool stopped processing its queue abruptly. Requests that were already " +
                    "queued when the pool stopped were abandoned - their clients received no response. " +
                    "The cause requires corroboration from the Windows Event Log."
                ) `
                -Evidence (
                    "$appPoolCount Timer_AppPool entries ($($appPoolPct)% of HTTPERR errors). " +
                    "Peak: $($appPoolBurst.PeakCount) in a $BurstWindowMinutes-minute window " +
                    "starting $(Format-PeakBucketTime $appPoolBurst.PeakWindowStart). " +
                    "Spread: $first to $last."
                ) `
                -RecommendedActions @(
                    'Check Windows Event Log (source: WAS) for worker process lifecycle events at this time'
                    'Run Get-IISAppPool to check current pool state and rapid-fail protection status'
                    'Review application logs for exceptions in the period before the burst'
                    'Cross-reference Get-IISW3CLog - affected requests may appear with sc-win32-status 64 (connection reset)'
                )
        }
        else {
            $severity = if ($appPoolPct -ge 20 -or $appPoolCount -ge 50) { 'Warning' } else { 'Info' }
            Add-Finding -Severity $severity `
                -Category 'QueueBackpressure' `
                -Title 'Requests timing out in the application pool queue' `
                -Detail (
                    "$appPoolCount request(s) reached the application pool queue but expired before " +
                    "being processed. Entries are distributed across the window rather than clustered, " +
                    "consistent with sustained load backpressure rather than a sudden stop. " +
                    "At $($appPoolPct)% of all HTTPERR errors this warrants investigation of " +
                    "what is occupying worker threads."
                ) `
                -Evidence "$appPoolCount Timer_AppPool entries ($($appPoolPct)% of HTTPERR errors) spread across the window." `
                -RecommendedActions @(
                    'Check Get-IISW3CLog for requests with high time-taken values in the same window'
                    'Review application code for long-running synchronous operations'
                    'Check CPU and memory - are worker processes under resource pressure?'
                )
        }
    }

    # ------------------------------------------------------------------
    # Rule: Pool stopped accepting new connections - Rejected entries
    #
    # What caused the pool to be unavailable is not asserted - that
    # requires the Windows Event Log. Burst vs spread is reported.
    # ------------------------------------------------------------------
    $rejectedEntries = if ($byReason.ContainsKey('Rejected')) { @($byReason['Rejected']) } else { @() }
    $rejectedBurst   = Get-BurstInfo $rejectedEntries
    $rejectedCount   = $rejectedEntries.Count

    if ($rejectedCount -gt 0) {
        $first    = $rejectedBurst.FirstEntry.Timestamp.ToString('HH:mm:ss')
        $last     = $rejectedBurst.LastEntry.Timestamp.ToString('HH:mm:ss')
        $duration = [math]::Round(($rejectedBurst.LastEntry.Timestamp - $rejectedBurst.FirstEntry.Timestamp).TotalMinutes, 1)

        if ($rejectedBurst.IsBurst) {
            Add-Finding -Severity 'Critical' `
                -Category 'PoolNotAccepting' `
                -Title 'Pool stopped accepting connections - burst of rejected requests' `
                -Detail (
                    "$rejectedCount request(s) were rejected by HTTP.sys between $first and $last " +
                    "(approximately $duration minutes). Entries are densely clustered, indicating " +
                    "the pool became unavailable suddenly. All incoming requests were turned away " +
                    "at the HTTP.sys layer before reaching IIS. Whether the pool was stopped " +
                    "manually, failed, or triggered rapid-fail protection requires the " +
                    "Windows Event Log (WAS source) to confirm."
                ) `
                -Evidence (
                    "$rejectedCount Rejected entries from $first to $last. " +
                    "Peak: $($rejectedBurst.PeakCount) in a $BurstWindowMinutes-minute window " +
                    "starting $(Format-PeakBucketTime $rejectedBurst.PeakWindowStart)."
                ) `
                -RecommendedActions @(
                    'Run Get-IISAppPool to check whether the pool is currently running'
                    'Check Windows Event Log (source: WAS) for pool lifecycle events at this time'
                    'Determine whether a deployment, manual stop, or automatic restart occurred'
                    'Run Get-IISEventLog to surface any ASP.NET or WAS errors around this window'
                )
        }
        else {
            Add-Finding -Severity 'Warning' `
                -Category 'PoolNotAccepting' `
                -Title 'Pool not accepting connections - rejected requests over a period' `
                -Detail (
                    "$rejectedCount request(s) were rejected between $first and $last " +
                    "($duration minutes). Entries are spread across the window rather than " +
                    "clustered into a sharp burst. The pool was unavailable for a sustained period."
                ) `
                -Evidence "$rejectedCount Rejected entries from $first to $last ($duration min spread)." `
                -RecommendedActions @(
                    'Run Get-IISAppPool to check current pool state'
                    'Check Windows Event Log (source: WAS) for pool start/stop events'
                    'Determine whether a deployment or scheduled maintenance occurred in this window'
                )
        }
    }

    # ------------------------------------------------------------------
    # Combined pattern: Timer_AppPool cluster followed by Rejected burst
    #
    # When both appear close in time the sequence is reported as a
    # separate observation. Root cause still requires the Event Log.
    # ------------------------------------------------------------------
    if ($appPoolBurst.IsBurst -and $rejectedBurst.IsBurst) {
        $appPoolStart  = $appPoolBurst.FirstEntry.Timestamp
        $rejectedStart = $rejectedBurst.FirstEntry.Timestamp
        $gapMinutes    = [math]::Round(($rejectedStart - $appPoolStart).TotalMinutes, 1)

        if ([math]::Abs($gapMinutes) -le ($BurstWindowMinutes * 3)) {
            $sequence = if ($appPoolStart -le $rejectedStart) {
                "Timer_AppPool burst started at $($appPoolStart.ToString('HH:mm:ss')), " +
                "followed by Rejected burst at $($rejectedStart.ToString('HH:mm:ss')) " +
                "($([math]::Abs($gapMinutes)) min later)."
            } else {
                "Rejected burst started at $($rejectedStart.ToString('HH:mm:ss')), " +
                "Timer_AppPool burst at $($appPoolStart.ToString('HH:mm:ss')) (near-simultaneous)."
            }

            Add-Finding -Severity 'Critical' `
                -Category 'CombinedPoolFailure' `
                -Title 'Combined pattern: queue stopped draining then connections refused' `
                -Detail (
                    "Both a Timer_AppPool burst and a Rejected burst were detected close together " +
                    "in the analysis window. The pool stopped processing its existing queue AND " +
                    "stopped accepting new connections. The sequence is noted as an observation - " +
                    "whether caused by a worker process failure, rapid-fail protection, or an " +
                    "operator action requires the Windows Event Log to confirm."
                ) `
                -Evidence $sequence `
                -RecommendedActions @(
                    'Check Windows Event Log (source: WAS) for worker process exit events at the time the Timer_AppPool burst began'
                    'Note the exact time the queue stopped draining and search application logs for exceptions at that moment'
                    'Run Get-IISAppPool - check the rapid-fail protection trip count and last start time'
                )
        }
    }

    # ------------------------------------------------------------------
    # Rule: App_InitFailed
    # ------------------------------------------------------------------
    $initFailCount = CountOf 'App_InitFailed'
    if ($initFailCount -gt 0) {
        Add-Finding -Severity 'Critical' `
            -Category 'AppInitFailed' `
            -Title 'Application did not initialise - worker process started but application failed' `
            -Detail (
                "App_InitFailed is recorded when the worker process started but the application " +
                "did not complete initialisation. No requests were processed. The specific failure " +
                "will be in the Windows Application Event Log or the application's own startup logging."
            ) `
            -Evidence "$initFailCount App_InitFailed entries." `
            -RecommendedActions @(
                'Check Windows Application Event Log for ASP.NET or ASP.NET Core Module events'
                'Review web.config for syntax errors or missing connection strings'
                'Enable stdout logging (ASP.NET Core) or check %temp%\aspnet_error.txt'
            )
    }

    # ------------------------------------------------------------------
    # Rule: AppOffline
    # ------------------------------------------------------------------
    $offlineCount = CountOf 'AppOffline'
    if ($offlineCount -gt 0) {
        Add-Finding -Severity 'Critical' `
            -Category 'AppOffline' `
            -Title 'Application offline - app_offline.htm detected' `
            -Detail (
                "HTTP.sys is serving an app_offline.htm file; the application is not running. " +
                "Commonly placed by deployment pipelines during an update. If unexpected, a " +
                "failed deployment may have left it behind."
            ) `
            -Evidence "$offlineCount AppOffline entries." `
            -RecommendedActions @(
                'Verify whether a deployment is in progress or recently completed'
                'If unexpected: locate and remove app_offline.htm from the application root'
            )
    }

    # ------------------------------------------------------------------
    # Rule: QueueFull
    # ------------------------------------------------------------------
    $queueFullCount = CountOf 'QueueFull'
    if ($queueFullCount -gt 0) {
        Add-Finding -Severity 'Critical' `
            -Category 'QueueFull' `
            -Title 'Request queue at capacity - requests refused before queuing' `
            -Detail (
                "$queueFullCount request(s) were refused because the pool request queue was at " +
                "its configured limit. These requests never entered the queue."
            ) `
            -Evidence "$queueFullCount QueueFull entries." `
            -RecommendedActions @(
                'Check CPU, memory, and worker process responsiveness'
                'Run Get-IISAppPool to verify pool state'
                'Review the pool queue length limit in IIS Manager (default: 1000)'
            )
    }

    # ------------------------------------------------------------------
    # Rule: SslError
    # ------------------------------------------------------------------
    $sslCount = CountOf 'SslError'
    if ($sslCount -gt 0) {
        $severity = if ($sslCount -ge 10) { 'Critical' } else { 'Warning' }
        Add-Finding -Severity $severity `
            -Category 'SslFailure' `
            -Title 'SSL/TLS handshake failures recorded by HTTP.sys' `
            -Detail (
                "$sslCount SslError entries recorded at the HTTP.sys layer before any request " +
                "reached IIS. Possible causes: expired or invalid certificate, TLS protocol or " +
                "cipher mismatch, certificate unbound from the HTTPS port."
            ) `
            -Evidence "$sslCount SslError entries." `
            -RecommendedActions @(
                'Run Get-IISSiteBinding to check certificate expiry and binding configuration'
                'Run: netsh http show sslcert - confirm the certificate is still bound to the port'
                'Check whether clients are negotiating TLS versions or cipher suites that have been disabled'
            )
    }

    # ------------------------------------------------------------------
    # Rule: Client-side timeouts
    # ------------------------------------------------------------------
    $idleCount   = CountOf 'Timer_ConnectionIdle'
    $idlePct     = Pct $idleCount
    $headerWait  = CountOf 'Timer_HeaderWait'
    $entityBody  = CountOf 'Timer_EntityBody'
    $clientTotal = $idleCount + $headerWait + $entityBody
    $clientPct   = Pct $clientTotal

    if ($clientTotal -gt 0) {
        if ($idlePct -ge 70 -and $total -ge 100) {
            Add-Finding -Severity 'Warning' `
                -Category 'ClientTimeouts' `
                -Title 'High proportion of client connection timeouts' `
                -Detail (
                    "$idleCount Timer_ConnectionIdle entries account for $($idlePct)% of HTTPERR errors. " +
                    "Some idle timeout is expected keep-alive housekeeping. At this proportion " +
                    "it is worth cross-referencing with W3C log response times."
                ) `
                -Evidence "Client timeout entries: ConnectionIdle=$idleCount, HeaderWait=$headerWait, EntityBody=$entityBody ($($clientPct)% of total)." `
                -RecommendedActions @(
                    'Cross-reference with Get-IISW3CLog time-taken values for the same window'
                    'Check whether a load balancer or proxy is resetting connections upstream of IIS'
                )
        }
        elseif ($headerWait -ge 20) {
            Add-Finding -Severity 'Warning' `
                -Category 'HeaderWaitTimeout' `
                -Title 'Connections accepted but request headers not received' `
                -Detail (
                    "$headerWait Timer_HeaderWait entries: TCP connection accepted but headers " +
                    "not sent within timeout. May be scanning, misconfigured health probes, " +
                    "or network conditions."
                ) `
                -Evidence "$headerWait Timer_HeaderWait entries." `
                -RecommendedActions @(
                    'Run Get-IISHttpErrLog -Summarise and review the Top Client IPs for a concentrated source'
                    'Check load balancer and reverse proxy health probe configuration'
                )
        }
        else {
            Add-Finding -Severity 'Info' `
                -Category 'ClientTimeouts' `
                -Title 'Client connection timeouts present - within normal range' `
                -Detail (
                    "$clientTotal client-side timeout entries (ConnectionIdle=$idleCount, " +
                    "HeaderWait=$headerWait, EntityBody=$entityBody). No specific action indicated."
                ) `
                -Evidence "$clientTotal client timeout entries ($($clientPct)% of HTTPERR errors)." `
                -RecommendedActions @()
        }
    }

    # ------------------------------------------------------------------
    # Rule: Malformed / disallowed requests
    # ------------------------------------------------------------------
    $malformedReasons = @('BadRequest', 'RequestLength', 'EntityTooLarge', 'FieldLength', 'Verb', 'URL')
    $malformedEntries = @($entries | Where-Object { $malformedReasons -contains $_.Reason })
    $malformedCount   = $malformedEntries.Count

    if ($malformedCount -gt 0) {
        $topSourceIp    = $malformedEntries | Where-Object { $_.ClientIp } |
            Group-Object ClientIp | Sort-Object Count -Descending | Select-Object -First 1
        $topIpCount     = if ($topSourceIp) { $topSourceIp.Count } else { 0 }
        $topIpPct       = if ($malformedCount -gt 0) { [math]::Round(($topIpCount / $malformedCount) * 100, 0) } else { 0 }
        $isConcentrated = $topIpCount -ge 10 -and $topIpPct -ge 50
        $severity       = if ($isConcentrated -or $malformedCount -ge 50) { 'Warning' } else { 'Info' }

        Add-Finding -Severity $severity `
            -Category 'MalformedRequests' `
            -Title 'Malformed or disallowed requests detected' `
            -Detail (if ($isConcentrated) {
                "$malformedCount malformed/disallowed request(s). $topIpCount ($($topIpPct)%) from a single IP ($($topSourceIp.Name))."
            } else {
                "$malformedCount malformed/disallowed request(s) distributed across multiple sources."
            }) `
            -Evidence (
                "$malformedCount entries. Breakdown: " +
                (($malformedReasons | Where-Object { (CountOf $_) -gt 0 } |
                    ForEach-Object { "$_=$(CountOf $_)" }) -join ', ')
            ) `
            -RecommendedActions $(if ($isConcentrated) {
                @(
                    "Investigate traffic from $($topSourceIp.Name) - verify it is a legitimate system"
                    'Consider IP-level filtering if confirmed automated scanning'
                )
            } else {
                @('No immediate action required - monitor for volume increases')
            })
    }

    # ------------------------------------------------------------------
    # Rule: No data
    # ------------------------------------------------------------------
    if ($total -eq 0) {
        Add-Finding -Severity 'Healthy' `
            -Category 'NoData' `
            -Title 'No HTTPERR entries in this window' `
            -Detail (
                "HTTP.sys recorded no errors between $StartTime and $EndTime. " +
                "All requests passed through the HTTP.sys layer successfully. " +
                "If errors were reported, they will be in IIS W3C logs or application logs."
            ) `
            -Evidence 'Zero HTTPERR entries.' `
            -RecommendedActions @()
    }

    # ------------------------------------------------------------------
    # Overall severity
    # ------------------------------------------------------------------
    $maxRank = if ($findings.Count -gt 0) {
        ($findings | Measure-Object SeverityRank -Maximum).Maximum
    } else { 1 }

    $overallSeverity = switch ($maxRank) {
        4 { 'Critical' } 3 { 'Warning' } 2 { 'Info' } default { 'Healthy' }
    }

    # ------------------------------------------------------------------
    # Pre-render display string
    # ------------------------------------------------------------------
    $indent = ' ' * '[CRITICAL] '.Length

    $findingsDisplay = ($findings | Sort-Object SeverityRank -Descending | ForEach-Object {
        $prefix = switch ($_.Severity) {
            'Critical' { '[CRITICAL]' } 'Warning' { '[WARNING] ' }
            'Info'     { '[INFO]    ' } default   { '[HEALTHY] ' }
        }
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add("$prefix $($_.Title)")
        $lines.Add("$indent $($_.Detail)")
        if ($_.Evidence) { $lines.Add("$indent Evidence: $($_.Evidence)") }
        foreach ($action in $_.RecommendedActions) { $lines.Add("$indent -> $action") }
        $lines -join [Environment]::NewLine
    }) -join ([Environment]::NewLine + [Environment]::NewLine)

    [pscustomobject]@{
        PSTypeName      = 'IISDiagnostics.HttpErrAnalysis'
        GeneratedAt     = Get-Date
        StartTime       = $StartTime
        EndTime         = $EndTime
        TotalEntries    = $total
        OverallSeverity = $overallSeverity
        Findings        = @($findings | Sort-Object SeverityRank -Descending)
        FindingsDisplay = $findingsDisplay
    }
}