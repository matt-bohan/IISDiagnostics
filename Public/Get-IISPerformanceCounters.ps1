#Requires -Version 5.1

function Get-IISPerformanceCounters {
    <#
    .SYNOPSIS
        Samples IIS-related Windows performance counters and grades each value with operator guidance.

    .DESCRIPTION
        Captures a point-in-time snapshot of the counters most useful when IIS is slow, queuing,
        or rejecting traffic. Each measure is returned with colour-coded severity, what to expect,
        and suggested next steps.

        Categories sampled:

          HTTP.sys request queues
            Queue depth, oldest queued item age, arrivals, and rejections per application pool queue.

          Application pools (WAS)
            Pool state, worker process count, and recent worker failures.

          Worker processes (w3wp)
            CPU, thread count, handle count, and private bytes per w3wp instance.

          IIS worker pipeline (W3SVC_W3WP)
            Active requests, active threads, and maximum thread ceiling per worker.

          Web service (_Total)
            Current connections, connection attempts, and service uptime.

          SQL Client connection pooling (.NET)
            Pooled and free connections, reclaimed or stasis connections, and hard connect failures
            when the .NET SqlClient performance counters are installed.

          System (host context)
            Available physical memory and total CPU to interpret worker pressure.

          .NET CLR (w3wp workers)
            Time in GC, heap size, exception rate, and lock contention when CLR counters are present.

          ASP.NET v4 (machine-wide)
            Global request queue, rejections, wait time, and worker restarts.

          ASP.NET Applications (per site / app)
            Application queue depth and unhandled error rate for hot instances only (non-zero).

    .PARAMETER Quiet
        Suppress the colour-coded console report. The snapshot object is still returned.
        Use for automation, logging, or when piping only the result.

    .PARAMETER AppPoolName
        Limit HTTP.sys queue, WAS, and worker-process measures to one application pool.
        Accepts wildcards.

    .PARAMETER SampleIntervalSeconds
        Seconds between counter samples. Default: 1.

    .PARAMETER MaxSamples
        Number of samples to average. Default: 1 (single snapshot).

    .EXAMPLE
        Get-IISPerformanceCounters

        Samples all IIS performance counters on the local server.

    .EXAMPLE
        Get-IISPerformanceCounters -AppPoolName 'DefaultAppPool'

        Limits queue and worker-process measures to DefaultAppPool.

    .EXAMPLE
        Get-IISPerformanceCounters -Quiet

        Returns only the snapshot object with no colour host report (for scripts and piping).

    .EXAMPLE
        $perf = Get-IISPerformanceCounters
        $perf.Measures | Where-Object Severity -ne 'OK' | Format-Table

        Review only measures outside the healthy range.

    .NOTES
        Requires an elevated session. Missing counter sets are reported as informational measures
        rather than failing the whole snapshot.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [SupportsWildcards()]
        [string]$AppPoolName,

        [Parameter()]
        [ValidateRange(1, 30)]
        [int]$SampleIntervalSeconds = 1,

        [Parameter()]
        [ValidateRange(1, 10)]
        [int]$MaxSamples = 1,

        [Parameter()]
        [switch]$Quiet
    )

    Assert-ElevatedSession -CmdletName $MyInvocation.MyCommand.Name

    $measures   = [System.Collections.Generic.List[psobject]]::new()
    $findings   = [System.Collections.Generic.List[psobject]]::new()
    $poolFilter = if (-not [string]::IsNullOrWhiteSpace($AppPoolName)) { $AppPoolName } else { $null }

    function Test-PoolInstance([string]$InstanceName) {
        if (-not $poolFilter) { return $true }
        if ([string]::IsNullOrWhiteSpace($InstanceName)) { return $false }
        if ($InstanceName -eq '_Total' -or $InstanceName -eq '---1') { return $false }
        return $InstanceName -like $poolFilter
    }

    function Format-PerfNumber([double]$Number, [int]$Precision = 1) {
        if ($Number -ge 1GB) { return '{0:N2} GB' -f ($Number / 1GB) }
        if ($Number -ge 1MB) { return '{0:N1} MB' -f ($Number / 1MB) }
        if ($Number -ge 10KB) { return '{0:N1} KB' -f ($Number / 1KB) }
        if ($Number -eq [math]::Floor($Number)) { return '{0:N0}' -f $Number }
        return ('{0:N' + $Precision + '}' -f $Number)
    }

    function Read-CounterMap {
        param([string[]]$Paths)

        $map = @{}
        if (-not $Paths -or $Paths.Count -eq 0) { return $map }

        try {
            $sample = Get-Counter -Counter $Paths -SampleInterval $SampleIntervalSeconds -MaxSamples $MaxSamples -ErrorAction Stop
            foreach ($reading in $sample.CounterSamples) {
                $map[$reading.Path] = [double]$reading.CookedValue
            }
        }
        catch {
            Write-Verbose "Counter read failed for batch ($($Paths.Count) paths): $_"
            foreach ($path in $Paths) {
                try {
                    $single = Get-Counter -Counter $path -SampleInterval $SampleIntervalSeconds -MaxSamples $MaxSamples -ErrorAction Stop
                    foreach ($reading in $single.CounterSamples) {
                        $map[$reading.Path] = [double]$reading.CookedValue
                    }
                }
                catch {
                    Write-Verbose "Counter unavailable: $path ($_)"
                }
            }
        }

        return $map
    }

    function Add-Measure([psobject]$Measure) {
        $measures.Add($Measure)
        Add-IISPerformanceFinding -Findings $findings -Measure $Measure
    }

    function Add-UnavailableMeasure {
        param(
            [string]$Category,
            [string]$Name,
            [string]$CounterPath,
            [string]$Reason
        )

        Add-Measure (New-IISPerformanceMeasure `
            -Category $Category `
            -Name $Name `
            -CounterPath $CounterPath `
            -FormattedValue 'Unavailable' `
            -Severity 'Info' `
            -WhatToExpect 'Counter set is only present when the related IIS or .NET feature is installed and active.' `
            -OkGuidance 'Counter available and readable.' `
            -WarningGuidance 'Counter missing on this server or no matching instances are running.' `
            -CriticalGuidance 'Counter missing on this server or no matching instances are running.' `
            -RecommendedActions @(
                $Reason
                'Install or start the related IIS role feature, or run the workload so instances exist.'
            ))
    }

    function Get-QueueSeverity([double]$QueueSize) {
        if ($QueueSize -le 0) { return 'OK' }
        if ($QueueSize -le 25) { return 'Warning' }
        return 'Critical'
    }

    function Get-QueueAgeSeverity([double]$AgeMs) {
        if ($AgeMs -lt 1000) { return 'OK' }
        if ($AgeMs -lt 5000) { return 'Warning' }
        return 'Critical'
    }

    function Get-RateSeverity([double]$Rate) {
        if ($Rate -le 0) { return 'OK' }
        if ($Rate -lt 5) { return 'Warning' }
        return 'Critical'
    }

    function Get-CpuSeverity([double]$CpuPercent) {
        if ($CpuPercent -lt 70) { return 'OK' }
        if ($CpuPercent -lt 90) { return 'Warning' }
        return 'Critical'
    }

    function Get-ThreadSeverity([double]$Threads, [double]$MaxThreads) {
        if ($MaxThreads -gt 0) {
            $ratio = $Threads / $MaxThreads
            if ($ratio -lt 0.6) { return 'OK' }
            if ($ratio -lt 0.85) { return 'Warning' }
            return 'Critical'
        }

        if ($Threads -lt 80) { return 'OK' }
        if ($Threads -lt 150) { return 'Warning' }
        return 'Critical'
    }

    function Get-HandleSeverity([double]$Handles) {
        if ($Handles -lt 5000) { return 'OK' }
        if ($Handles -lt 10000) { return 'Warning' }
        return 'Critical'
    }

    function Get-MemorySeverity([double]$Bytes) {
        if ($Bytes -lt 1GB) { return 'OK' }
        if ($Bytes -lt 2GB) { return 'Warning' }
        return 'Critical'
    }

    function Get-PoolStateLabel([int]$State) {
        switch ($State) {
            1 { 'Uninitialized' }
            2 { 'Initialized' }
            3 { 'Running' }
            4 { 'Disabling' }
            5 { 'Disabled' }
            6 { 'Stopping' }
            7 { 'Stopped' }
            8 { 'Pausing' }
            9 { 'Paused' }
            10 { 'Continuing' }
            default { "State $State" }
        }
    }

    function Get-PoolStateSeverity([int]$State) {
        if ($State -eq 3) { return 'OK' }
        if ($State -in 2, 10) { return 'Info' }
        if ($State -in 4, 6, 8) { return 'Warning' }
        return 'Critical'
    }

    function Get-WorkerFailureSeverity([double]$Failures) {
        if ($Failures -le 0) { return 'OK' }
        if ($Failures -lt 3) { return 'Warning' }
        return 'Critical'
    }

    function Get-ConnectionSeverity([double]$Current, [double]$Maximum) {
        if ($Maximum -le 0) { return 'Info' }
        $ratio = $Current / $Maximum
        if ($ratio -lt 0.7) { return 'OK' }
        if ($ratio -lt 0.9) { return 'Warning' }
        return 'Critical'
    }

    function Get-StasisSeverity([double]$Count) {
        if ($Count -le 0) { return 'OK' }
        if ($Count -lt 10) { return 'Warning' }
        return 'Critical'
    }

    function Get-SqlFailureSeverity([double]$Rate) {
        if ($Rate -le 0) { return 'OK' }
        if ($Rate -lt 1) { return 'Warning' }
        return 'Critical'
    }

    function Test-IsWorkerClrInstance([string]$InstanceName) {
        if ([string]::IsNullOrWhiteSpace($InstanceName)) { return $false }
        return $InstanceName -like 'w3wp*'
    }

    function Get-AvailableMemorySeverity([double]$Megabytes) {
        if ($Megabytes -ge 1024) { return 'OK' }
        if ($Megabytes -ge 512) { return 'Warning' }
        return 'Critical'
    }

    function Get-GcTimeSeverity([double]$Percent) {
        if ($Percent -lt 10) { return 'OK' }
        if ($Percent -lt 25) { return 'Warning' }
        return 'Critical'
    }

    function Get-ExceptionRateSeverity([double]$PerSec) {
        if ($PerSec -le 0) { return 'OK' }
        if ($PerSec -lt 5) { return 'Warning' }
        return 'Critical'
    }

    function Get-ContentionRateSeverity([double]$PerSec) {
        if ($PerSec -le 0) { return 'OK' }
        if ($PerSec -lt 50) { return 'Warning' }
        return 'Critical'
    }

    function Get-AspNetGlobalQueueSeverity([double]$Queued) {
        if ($Queued -le 0) { return 'OK' }
        if ($Queued -lt 25) { return 'Warning' }
        return 'Critical'
    }

    function Get-AspAppQueueSeverity([double]$Queued) {
        if ($Queued -le 0) { return 'OK' }
        if ($Queued -lt 10) { return 'Warning' }
        return 'Critical'
    }

    $counterSets = @{}
    foreach ($setName in @(
            'HTTP Service Request Queues',
            'APP_POOL_WAS',
            'Process',
            'W3SVC_W3WP',
            'Web Service',
            'Memory',
            'Processor',
            '.NET CLR Memory',
            '.NET CLR Exceptions',
            '.NET CLR LocksAndThreads',
            'ASP.NET v4.0.30319',
            'ASP.NET Applications',
            '.NET Data Provider for SqlClient',
            '.NET Data Provider for SqlServer'
        )) {
        try {
            $set = Get-Counter -ListSet $setName -ErrorAction Stop
            $counterSets[$setName] = $set
        }
        catch {
            Write-Verbose "Counter set '$setName' is not available."
        }
    }

    if ($counterSets.ContainsKey('HTTP Service Request Queues')) {
        $queuePaths = @(
            '\HTTP Service Request Queues(*)\CurrentQueueSize',
            '\HTTP Service Request Queues(*)\MaxQueueItemAge',
            '\HTTP Service Request Queues(*)\ArrivalRate',
            '\HTTP Service Request Queues(*)\RejectionRate',
            '\HTTP Service Request Queues(*)\RejectedRequests'
        )
        $queueMap = Read-CounterMap -Paths $queuePaths

        if ($queueMap.Count -eq 0) {
            Add-UnavailableMeasure -Category 'HttpSys' -Name 'HTTP.sys request queues' `
                -CounterPath '\HTTP Service Request Queues(*)\*' `
                -Reason 'No HTTP.sys request queue instances were returned.'
        }
        else {
            $instances = @($queueMap.Keys | ForEach-Object {
                if ($_ -match '\\HTTP Service Request Queues\(([^)]+)\)\\') { $Matches[1] }
            } | Sort-Object -Unique)

            foreach ($instance in $instances) {
                if (-not (Test-PoolInstance $instance)) { continue }

                $sizePath = "\HTTP Service Request Queues($instance)\CurrentQueueSize"
                $agePath  = "\HTTP Service Request Queues($instance)\MaxQueueItemAge"
                $arrPath  = "\HTTP Service Request Queues($instance)\ArrivalRate"
                $rejPath  = "\HTTP Service Request Queues($instance)\RejectionRate"
                $rejTot   = "\HTTP Service Request Queues($instance)\RejectedRequests"

                if ($queueMap.ContainsKey($sizePath)) {
                    $value = $queueMap[$sizePath]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'HttpSys' -Instance $instance -Name 'Current queue size' -CounterPath $sizePath `
                        -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'requests' `
                        -Severity (Get-QueueSeverity $value) `
                        -WhatToExpect 'Requests waiting in the HTTP.sys queue for this pool should usually be zero under normal load.' `
                        -OkGuidance 'Queue is empty - HTTP.sys is handing requests to worker processes immediately.' `
                        -WarningGuidance 'A small backlog is building. Watch for rising queue age and worker CPU saturation.' `
                        -CriticalGuidance 'Requests are backing up in HTTP.sys. Workers are not keeping up or the pool is unavailable.' `
                        -RecommendedActions @(
                            'Check worker CPU, thread count, and recent pool failures for this application pool.'
                            'Correlate with HTTPERR Timer_AppPool or Rejected entries and WAS event log messages.'
                        ))
                }

                if ($queueMap.ContainsKey($agePath)) {
                    $value = $queueMap[$agePath]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'HttpSys' -Instance $instance -Name 'Oldest queued item age' -CounterPath $agePath `
                        -Value $value -FormattedValue ('{0:N0} ms' -f $value) -Unit 'ms' `
                        -Severity (Get-QueueAgeSeverity $value) `
                        -WhatToExpect 'Oldest queue age should stay low unless the site is under brief load spikes.' `
                        -OkGuidance 'Queued requests are not waiting long at HTTP.sys.' `
                        -WarningGuidance 'Requests are waiting several seconds before a worker accepts them.' `
                        -CriticalGuidance 'Requests are ageing in the HTTP.sys queue - clients will see timeouts or 503 responses.' `
                        -RecommendedActions @(
                            'Inspect w3wp CPU and active thread usage for this pool.'
                            'Look for app pool stops, recycles, or thread-pool starvation in the event log.'
                        ))
                }

                if ($queueMap.ContainsKey($rejPath)) {
                    $value = $queueMap[$rejPath]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'HttpSys' -Instance $instance -Name 'Rejection rate' -CounterPath $rejPath `
                        -Value $value -FormattedValue ('{0:N2}/s' -f $value) -Unit 'per second' `
                        -Severity (Get-RateSeverity $value) `
                        -WhatToExpect 'Rejections should be zero in steady state.' `
                        -OkGuidance 'HTTP.sys is not rejecting requests for this queue.' `
                        -WarningGuidance 'Some requests are being rejected - often when the pool is unavailable or overloaded.' `
                        -CriticalGuidance 'HTTP.sys is actively rejecting traffic for this queue.' `
                        -RecommendedActions @(
                            'Verify the application pool is Started and has healthy worker processes.'
                            'Review HTTPERR Rejected entries and queue length for the same window.'
                        ))
                }

                if ($queueMap.ContainsKey($arrPath)) {
                    $value = $queueMap[$arrPath]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'HttpSys' -Instance $instance -Name 'Arrival rate' -CounterPath $arrPath `
                        -Value $value -FormattedValue ('{0:N2}/s' -f $value) -Unit 'per second' `
                        -Severity 'Info' `
                        -WhatToExpect 'Arrival rate is informational - compare it with queue size and rejection rate.' `
                        -OkGuidance 'Current request arrival rate for this queue.' `
                        -WarningGuidance 'High arrival rate with a growing queue indicates saturation.' `
                        -CriticalGuidance 'Sustained high arrival rate with rejections indicates capacity exhaustion.' `
                        -RecommendedActions @('Compare arrival rate with worker throughput and scale or tune the application if needed.'))
                }

                if ($queueMap.ContainsKey($rejTot)) {
                    $value = $queueMap[$rejTot]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'HttpSys' -Instance $instance -Name 'Rejected requests (total)' -CounterPath $rejTot `
                        -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'requests' `
                        -Severity ($(if ($value -gt 0) { 'Warning' } else { 'OK' }) ) `
                        -WhatToExpect 'Total rejected requests should not climb during normal operation.' `
                        -OkGuidance 'No cumulative rejections recorded for this queue.' `
                        -WarningGuidance 'Rejections have occurred for this queue since the counter last reset.' `
                        -CriticalGuidance 'Rejections are accumulating - clients are being turned away at HTTP.sys.' `
                        -RecommendedActions @('Treat rising totals as incident evidence and inspect pool availability at the same timestamps.'))
                }
            }
        }
    }
    else {
        Add-UnavailableMeasure -Category 'HttpSys' -Name 'HTTP.sys request queues' `
            -CounterPath '\HTTP Service Request Queues(*)\*' `
            -Reason 'HTTP Service Request Queues performance counters are not installed.'
    }

    if ($counterSets.ContainsKey('APP_POOL_WAS')) {
        $wasPaths = @(
            '\APP_POOL_WAS(*)\Current Application Pool State',
            '\APP_POOL_WAS(*)\Current Worker Processes',
            '\APP_POOL_WAS(*)\Recent Worker Process Failures',
            '\APP_POOL_WAS(*)\Total Worker Process Failures'
        )
        $wasMap = Read-CounterMap -Paths $wasPaths

        if ($wasMap.Count -eq 0) {
            Add-UnavailableMeasure -Category 'AppPool' -Name 'WAS application pool counters' `
                -CounterPath '\APP_POOL_WAS(*)\*' `
                -Reason 'No WAS application pool counter instances were returned.'
        }
        else {
            $instances = @($wasMap.Keys | ForEach-Object {
                if ($_ -match '\\APP_POOL_WAS\(([^)]+)\)\\') { $Matches[1] }
            } | Sort-Object -Unique)

            foreach ($instance in $instances) {
                if ($instance -eq '_Total') { continue }
                if (-not (Test-PoolInstance $instance)) { continue }

                $statePath = "\APP_POOL_WAS($instance)\Current Application Pool State"
                if ($wasMap.ContainsKey($statePath)) {
                    $value = [int]$wasMap[$statePath]
                    $label = Get-PoolStateLabel $value
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'AppPool' -Instance $instance -Name 'Application pool state' -CounterPath $statePath `
                        -Value $value -FormattedValue $label -Unit 'state' `
                        -Severity (Get-PoolStateSeverity $value) `
                        -WhatToExpect 'A healthy pool serving traffic reports Running (3).' `
                        -OkGuidance 'Pool is running and available to accept requests.' `
                        -WarningGuidance 'Pool is changing state or not fully running yet.' `
                        -CriticalGuidance 'Pool is stopped, disabled, or otherwise unavailable to serve requests.' `
                        -RecommendedActions @(
                            "Run Get-IISAppPoolStatus -Name '$instance' | Format-List"
                            "Run Get-IISEventLog -AppPoolName '$instance' -Significant"
                        ))
                }

                $workerPath = "\APP_POOL_WAS($instance)\Current Worker Processes"
                if ($wasMap.ContainsKey($workerPath)) {
                    $value = $wasMap[$workerPath]
                    $severity = if ($value -gt 0) { 'OK' } else { 'Warning' }
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'AppPool' -Instance $instance -Name 'Current worker processes' -CounterPath $workerPath `
                        -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'processes' `
                        -Severity $severity `
                        -WhatToExpect 'Started pools should have at least one worker process while handling requests.' `
                        -OkGuidance 'At least one worker process is running for this pool.' `
                        -WarningGuidance 'Pool has no active worker process - requests may queue or fail.' `
                        -CriticalGuidance 'Pool has no active worker process while traffic is expected.' `
                        -RecommendedActions @(
                            'Check for recent recycles, rapid-fail protection, or startup failures.'
                            "Run Get-IISEventLog -AppPoolName '$instance' -Significant"
                        ))
                }

                $recentFailPath = "\APP_POOL_WAS($instance)\Recent Worker Process Failures"
                if ($wasMap.ContainsKey($recentFailPath)) {
                    $value = $wasMap[$recentFailPath]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'AppPool' -Instance $instance -Name 'Recent worker process failures' -CounterPath $recentFailPath `
                        -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'failures' `
                        -Severity (Get-WorkerFailureSeverity $value) `
                        -WhatToExpect 'Recent worker failures should remain zero outside of deliberate recycles.' `
                        -OkGuidance 'No recent worker process failures recorded.' `
                        -WarningGuidance 'Workers are failing or crashing - performance will degrade before the pool stops.' `
                        -CriticalGuidance 'Repeated worker failures indicate instability and often precede rapid-fail protection.' `
                        -RecommendedActions @(
                            'Inspect Application and System event logs for w3wp crash details.'
                            "Run Get-IISAppPoolStatus -Name '$instance' | Format-List"
                        ))
                }
            }
        }
    }
    else {
        Add-UnavailableMeasure -Category 'AppPool' -Name 'WAS application pool counters' `
            -CounterPath '\APP_POOL_WAS(*)\*' `
            -Reason 'APP_POOL_WAS performance counters are not installed.'
    }

    if ($counterSets.ContainsKey('W3SVC_W3WP')) {
        $w3wpPaths = @(
            '\W3SVC_W3WP(*)\Active Requests',
            '\W3SVC_W3WP(*)\Active Threads Count',
            '\W3SVC_W3WP(*)\Maximum Threads Count',
            '\W3SVC_W3WP(*)\Requests / Sec'
        )
        $w3wpMap = Read-CounterMap -Paths $w3wpPaths

        foreach ($path in $w3wpMap.Keys) {
            if ($path -match '\\W3SVC_W3WP\(([^)]+)\)\\') {
                $instance = $Matches[1]
                $poolName = if ($instance -match '__(.+)$') { $Matches[1] } else { $instance }
                if (-not (Test-PoolInstance $poolName)) { continue }

                if ($path -like '*Active Threads Count*') {
                    $threads = $w3wpMap[$path]
                    $maxPath = $path.Replace('Active Threads Count', 'Maximum Threads Count')
                    $maxThreads = if ($w3wpMap.ContainsKey($maxPath)) { $w3wpMap[$maxPath] } else { 0 }
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'WorkerProcess' -Instance $poolName -Name 'Active worker threads' -CounterPath $path `
                        -Value $threads -FormattedValue (Format-PerfNumber $threads 0) -Unit 'threads' `
                        -Severity (Get-ThreadSeverity $threads $maxThreads) `
                        -WhatToExpect 'Active threads should stay comfortably below the worker maximum under normal load.' `
                        -OkGuidance 'Worker thread usage is within a healthy range.' `
                        -WarningGuidance 'Thread usage is elevated and may indicate blocking calls or thread-pool starvation.' `
                        -CriticalGuidance 'Worker threads are near the ceiling - new work will queue and latency will spike.' `
                        -RecommendedActions @(
                            'Look for synchronous I/O, long database calls, or external API waits in the application.'
                            'Capture a dump or profiler if thread counts remain high under moderate load.'
                        ))
                }
                elseif ($path -like '*Active Requests*') {
                    $value = $w3wpMap[$path]
                    $severity = if ($value -lt 100) { 'OK' } elseif ($value -lt 250) { 'Warning' } else { 'Critical' }
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'WorkerProcess' -Instance $poolName -Name 'Active requests' -CounterPath $path `
                        -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'requests' `
                        -Severity $severity `
                        -WhatToExpect 'Active requests vary by application, but sustained high concurrency usually raises latency.' `
                        -OkGuidance 'Active request count is within a typical operating range.' `
                        -WarningGuidance 'Many concurrent requests are in flight - check downstream dependencies and thread usage.' `
                        -CriticalGuidance 'Worker is saturated with in-flight requests - expect timeouts and queue growth.' `
                        -RecommendedActions @('Compare with HTTP.sys queue size and SQL connection pool counters for the same period.'))
                }
                elseif ($path -like '*Requests / Sec*') {
                    $value = $w3wpMap[$path]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'WorkerProcess' -Instance $poolName -Name 'Requests per second' -CounterPath $path `
                        -Value $value -FormattedValue ('{0:N2}/s' -f $value) -Unit 'per second' `
                        -Severity 'Info' `
                        -WhatToExpect 'Throughput is informational - compare it with queue depth and error rates.' `
                        -OkGuidance 'Current worker throughput.' `
                        -WarningGuidance 'Throughput is falling while queues grow.' `
                        -CriticalGuidance 'Throughput collapse with queue growth indicates severe worker-side blocking.' `
                        -RecommendedActions @('Use alongside W3C log volume and CPU counters when investigating slow periods.'))
                }
            }
        }

        if ($w3wpMap.Count -eq 0) {
            Add-UnavailableMeasure -Category 'WorkerProcess' -Name 'IIS worker pipeline counters' `
                -CounterPath '\W3SVC_W3WP(*)\*' `
                -Reason 'No W3SVC_W3WP instances were returned - workers may not be running.'
        }
    }
    else {
        Add-UnavailableMeasure -Category 'WorkerProcess' -Name 'IIS worker pipeline counters' `
            -CounterPath '\W3SVC_W3WP(*)\*' `
            -Reason 'W3SVC_W3WP performance counters are not installed.'
    }

    if ($counterSets.ContainsKey('Process')) {
        $processPaths = @(
            '\Process(w3wp*)\% Processor Time',
            '\Process(w3wp*)\Thread Count',
            '\Process(w3wp*)\Handle Count',
            '\Process(w3wp*)\Private Bytes'
        )
        $processMap = Read-CounterMap -Paths $processPaths

        foreach ($path in $processMap.Keys) {
            if ($path -match '\\Process\(([^)]+)\)\\(.+)') {
                $instance = $Matches[1]
                $metric   = $Matches[2]
            }
            else { continue }

            switch -Wildcard ($metric) {
                '% Processor Time' {
                    $value = $processMap[$path]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'WorkerProcess' -Instance $instance -Name 'Worker CPU' -CounterPath $path `
                        -Value $value -FormattedValue ('{0:N1}%' -f $value) -Unit 'percent' `
                        -Severity (Get-CpuSeverity $value) `
                        -WhatToExpect 'Sustained CPU near 100% per worker usually means the process is compute-bound or spinning.' `
                        -OkGuidance 'Worker CPU is within a healthy range for the current load.' `
                        -WarningGuidance 'Worker CPU is elevated - expect higher latency and queue growth if it persists.' `
                        -CriticalGuidance 'Worker CPU is saturated - the process is the bottleneck.' `
                        -RecommendedActions @(
                            'Profile hot code paths or scale out additional workers / servers.'
                            'Check for tight loops, expensive serialization, or runaway logging.'
                        ))
                }
                'Thread Count' {
                    $value = $processMap[$path]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'WorkerProcess' -Instance $instance -Name 'Worker thread count' -CounterPath $path `
                        -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'threads' `
                        -Severity (Get-ThreadSeverity $value 0) `
                        -WhatToExpect 'Thread count should track active work and remain stable outside of load spikes.' `
                        -OkGuidance 'Thread count is within a typical range for a worker process.' `
                        -WarningGuidance 'Thread count is elevated - look for blocked threads or thread leaks.' `
                        -CriticalGuidance 'Thread count is very high - risk of thread-pool exhaustion and failed requests.' `
                        -RecommendedActions @('Capture a memory dump and inspect thread stacks if counts remain high.'))
                }
                'Handle Count' {
                    $value = $processMap[$path]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'WorkerProcess' -Instance $instance -Name 'Worker handle count' -CounterPath $path `
                        -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'handles' `
                        -Severity (Get-HandleSeverity $value) `
                        -WhatToExpect 'Handle growth should be gradual; sudden jumps often indicate leaks.' `
                        -OkGuidance 'Handle usage is within a healthy range.' `
                        -WarningGuidance 'Handle usage is elevated - monitor for leaks in sockets, files, or sync objects.' `
                        -CriticalGuidance 'Handle usage is very high - the worker may fail unpredictably.' `
                        -RecommendedActions @('Review undisposed IDisposable objects and connection/session leaks.'))
                }
                'Private Bytes' {
                    $value = $processMap[$path]
                    Add-Measure (New-IISPerformanceMeasure `
                        -Category 'WorkerProcess' -Instance $instance -Name 'Worker private bytes' -CounterPath $path `
                        -Value $value -FormattedValue (Format-PerfNumber $value 1) -Unit 'bytes' `
                        -Severity (Get-MemorySeverity $value) `
                        -WhatToExpect 'Private bytes rise with load and cached data but should not grow without bound.' `
                        -OkGuidance 'Worker memory usage is within a typical range.' `
                        -WarningGuidance 'Worker memory is elevated - watch for leaks or oversized caches.' `
                        -CriticalGuidance 'Worker memory is very high - recycling or out-of-memory failures may follow.' `
                        -RecommendedActions @(
                            'Compare with app pool private-memory recycle limits.'
                            'Investigate large object heap usage and per-request allocations.'
                        ))
                }
            }
        }

        if ($processMap.Count -eq 0) {
            Add-UnavailableMeasure -Category 'WorkerProcess' -Name 'w3wp process counters' `
                -CounterPath '\Process(w3wp*)\*' `
                -Reason 'No w3wp process counter instances were returned.'
        }
    }
    else {
        Add-UnavailableMeasure -Category 'WorkerProcess' -Name 'w3wp process counters' `
            -CounterPath '\Process(w3wp*)\*' `
            -Reason 'Process performance counters are not available.'
    }

    if ($counterSets.ContainsKey('Web Service')) {
        $webPaths = @(
            '\Web Service(_Total)\Current Connections',
            '\Web Service(_Total)\Maximum Connections',
            '\Web Service(_Total)\Connection Attempts/sec',
            '\Web Service(_Total)\Service Uptime'
        )
        $webMap = Read-CounterMap -Paths $webPaths

        if ($webMap.ContainsKey('\Web Service(_Total)\Current Connections')) {
            $current = $webMap['\Web Service(_Total)\Current Connections']
            $maximum = if ($webMap.ContainsKey('\Web Service(_Total)\Maximum Connections')) {
                $webMap['\Web Service(_Total)\Maximum Connections']
            } else { 0 }
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'WebService' -Instance '_Total' -Name 'Current connections' `
                -CounterPath '\Web Service(_Total)\Current Connections' `
                -Value $current -FormattedValue (Format-PerfNumber $current 0) -Unit 'connections' `
                -Severity (Get-ConnectionSeverity $current $maximum) `
                -WhatToExpect 'Current connections should stay below the configured maximum under normal operation.' `
                -OkGuidance 'Connection count is comfortably below the server maximum.' `
                -WarningGuidance 'Connection usage is high relative to the configured maximum.' `
                -CriticalGuidance 'Connection usage is near the server maximum - new clients may be refused.' `
                -RecommendedActions @('Review connection limits, keep-alive settings, and upstream load balancer behaviour.'))
        }

        if ($webMap.ContainsKey('\Web Service(_Total)\Connection Attempts/sec')) {
            $value = $webMap['\Web Service(_Total)\Connection Attempts/sec']
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'WebService' -Instance '_Total' -Name 'Connection attempts per second' `
                -CounterPath '\Web Service(_Total)\Connection Attempts/sec' `
                -Value $value -FormattedValue ('{0:N2}/s' -f $value) -Unit 'per second' `
                -Severity 'Info' `
                -WhatToExpect 'Connection attempt rate is informational - compare with active connections and HTTP.sys queues.' `
                -OkGuidance 'Current connection attempt rate.' `
                -WarningGuidance 'High connection churn can inflate CPU and reduce throughput.' `
                -CriticalGuidance 'Connection storms can overwhelm HTTP.sys and worker processes.' `
                -RecommendedActions @('Check for client retry storms, health probes, or misconfigured keep-alive timeouts.'))
        }

        if ($webMap.ContainsKey('\Web Service(_Total)\Service Uptime')) {
            $value = $webMap['\Web Service(_Total)\Service Uptime']
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'WebService' -Instance '_Total' -Name 'Service uptime' `
                -CounterPath '\Web Service(_Total)\Service Uptime' `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'seconds' `
                -Severity 'Info' `
                -WhatToExpect 'Uptime helps correlate sudden counter changes with recent service restarts.' `
                -OkGuidance 'Web service uptime in seconds.' `
                -WarningGuidance 'Recent restarts may explain empty queues or missing worker instances.' `
                -CriticalGuidance 'Very low uptime during an incident window suggests the service or server recently restarted.' `
                -RecommendedActions @('Correlate uptime with WAS and HTTP.sys events in the System log.'))
        }
    }
    else {
        Add-UnavailableMeasure -Category 'WebService' -Name 'Web Service counters' `
            -CounterPath '\Web Service(_Total)\*' `
            -Reason 'Web Service performance counters are not installed.'
    }

    if ($counterSets.ContainsKey('Memory')) {
        $memMap = Read-CounterMap -Paths @('\Memory\Available MBytes')
        if ($memMap.ContainsKey('\Memory\Available MBytes')) {
            $value = $memMap['\Memory\Available MBytes']
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'System' -Instance '_Total' -Name 'Available physical memory' `
                -CounterPath '\Memory\Available MBytes' `
                -Value $value -FormattedValue ('{0:N0} MB' -f $value) -Unit 'MB' `
                -Severity (Get-AvailableMemorySeverity $value) `
                -WhatToExpect 'Leave headroom for the OS, SQL, and other services - not only IIS workers.' `
                -OkGuidance 'The host still has comfortable free RAM for allocation spikes.' `
                -WarningGuidance 'Free RAM is getting tight - workers may thrash or fail under load spikes.' `
                -CriticalGuidance 'Very low free memory risks paging, OOM kills, and unstable IIS workers.' `
                -RecommendedActions @(
                    'Identify other processes consuming RAM (SQL Server, caches, other services).'
                    'Consider more RAM, reducing worker limits, or moving workloads.'
                ))
        }
    }

    if ($counterSets.ContainsKey('Processor')) {
        $procMap = Read-CounterMap -Paths @('\Processor(_Total)\% Processor Time')
        if ($procMap.ContainsKey('\Processor(_Total)\% Processor Time')) {
            $value = $procMap['\Processor(_Total)\% Processor Time']
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'System' -Instance '_Total' -Name 'Host CPU' `
                -CounterPath '\Processor(_Total)\% Processor Time' `
                -Value $value -FormattedValue ('{0:N1}%' -f $value) -Unit 'percent' `
                -Severity (Get-CpuSeverity $value) `
                -WhatToExpect 'Compare host CPU with individual w3wp CPU to see whether IIS or something else dominates.' `
                -OkGuidance 'Total machine CPU is within a normal range for this sample.' `
                -WarningGuidance 'Host CPU is elevated - correlate with SQL, antivirus, backups, or other services.' `
                -CriticalGuidance 'Host CPU is saturated - IIS workers compete with everything else on the box.' `
                -RecommendedActions @('Use Task Manager or Get-Process to find non-w3wp consumers alongside worker CPU.'))
        }
    }

    if ($counterSets.ContainsKey('.NET CLR Memory')) {
        $clrMemPaths = @(
            '\.NET CLR Memory(w3wp*)\% Time in GC',
            '\.NET CLR Memory(w3wp*)\# Bytes in All Heaps'
        )
        $clrMemMap = Read-CounterMap -Paths $clrMemPaths
        foreach ($path in $clrMemMap.Keys) {
            if ($path -notmatch '\.NET CLR Memory\(([^)]+)\)\\(.+)$') { continue }
            $clrInst = $Matches[1]
            if (-not (Test-IsWorkerClrInstance $clrInst)) { continue }
            $metricName = $Matches[2]
            $value = $clrMemMap[$path]

            if ($metricName -eq '% Time in GC') {
                Add-Measure (New-IISPerformanceMeasure `
                    -Category 'DotNetRuntime' -Instance $clrInst -Name '% Time in GC' -CounterPath $path `
                    -Value $value -FormattedValue ('{0:N1}%' -f $value) -Unit 'percent' `
                    -Severity (Get-GcTimeSeverity $value) `
                    -WhatToExpect 'Sustained high % Time in GC often correlates with allocation churn or memory pressure.' `
                    -OkGuidance 'GC overhead is low for this worker snapshot.' `
                    -WarningGuidance 'GC is taking a noticeable slice of CPU - check allocations and large object churn.' `
                    -CriticalGuidance 'GC overhead is very high - expect request latency spikes and CPU starvation.' `
                    -RecommendedActions @(
                        'Profile allocations and Gen2 / LOH growth in the application.'
                        'Correlate with worker private bytes and Available MBytes on the host.'
                    ))
            }
            elseif ($metricName -eq '# Bytes in All Heaps') {
                Add-Measure (New-IISPerformanceMeasure `
                    -Category 'DotNetRuntime' -Instance $clrInst -Name 'Bytes in all heaps' -CounterPath $path `
                    -Value $value -FormattedValue (Format-PerfNumber $value 1) -Unit 'bytes' `
                    -Severity 'Info' `
                    -WhatToExpect 'Heap size depends on workload - watch for runaway growth between snapshots or across recycles.' `
                    -OkGuidance 'Managed heap size snapshot for this worker.' `
                    -WarningGuidance 'Heap growth with rising Gen2 collections suggests a leak or unbounded caches.' `
                    -CriticalGuidance 'Very large heaps increase GC pause times and risk OOM on 32-bit workers.' `
                    -RecommendedActions @('Compare with private bytes and investigate LOH / static caches.'))
            }
        }
    }

    if ($counterSets.ContainsKey('.NET CLR Exceptions')) {
        $clrExMap = Read-CounterMap -Paths @('\.NET CLR Exceptions(w3wp*)\# of Exceps Thrown / sec')
        foreach ($path in $clrExMap.Keys) {
            if ($path -notmatch '\.NET CLR Exceptions\(([^)]+)\)\\') { continue }
            $clrInst = $Matches[1]
            if (-not (Test-IsWorkerClrInstance $clrInst)) { continue }
            $value = $clrExMap[$path]
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'DotNetRuntime' -Instance $clrInst -Name 'Exceptions thrown per second' -CounterPath $path `
                -Value $value -FormattedValue ('{0:N2}/s' -f $value) -Unit 'per second' `
                -Severity (Get-ExceptionRateSeverity $value) `
                -WhatToExpect 'First-chance exceptions should be rare in production steady state.' `
                -OkGuidance 'No meaningful exception throw rate observed for this worker.' `
                -WarningGuidance 'Exceptions are being thrown frequently - often caught but still expensive.' `
                -CriticalGuidance 'High exception rates usually indicate control-flow misuse or repeated failures.' `
                -RecommendedActions @('Check Application log for .NET runtime errors and fix hot exception paths.'))
        }
    }

    if ($counterSets.ContainsKey('.NET CLR LocksAndThreads')) {
        $lockMap = Read-CounterMap -Paths @(
            '\.NET CLR LocksAndThreads(w3wp*)\Contention Rate / sec',
            '\.NET CLR LocksAndThreads(w3wp*)\Current Queue Length'
        )
        foreach ($path in $lockMap.Keys) {
            if ($path -notmatch '\.NET CLR LocksAndThreads\(([^)]+)\)\\(.+)$') { continue }
            $clrInst = $Matches[1]
            if (-not (Test-IsWorkerClrInstance $clrInst)) { continue }
            $metricName = $Matches[2]
            $value = $lockMap[$path]

            if ($metricName -eq 'Contention Rate / sec') {
                Add-Measure (New-IISPerformanceMeasure `
                    -Category 'DotNetRuntime' -Instance $clrInst -Name 'Lock contention rate' -CounterPath $path `
                    -Value $value -FormattedValue ('{0:N2}/s' -f $value) -Unit 'per second' `
                    -Severity (Get-ContentionRateSeverity $value) `
                    -WhatToExpect 'Lock contention indicates threads waiting on Monitor locks or similar primitives.' `
                    -OkGuidance 'Negligible managed lock contention for this worker.' `
                    -WarningGuidance 'Contention is present - look for hot locks and synchronous shared state.' `
                    -CriticalGuidance 'Heavy contention serializes work and inflates thread counts and latency.' `
                    -RecommendedActions @('Review locking around caches, singletons, and static initialization.'))
            }
            elseif ($metricName -eq 'Current Queue Length') {
                $severity = if ($value -le 0) { 'OK' } elseif ($value -lt 50) { 'Warning' } else { 'Critical' }
                Add-Measure (New-IISPerformanceMeasure `
                    -Category 'DotNetRuntime' -Instance $clrInst -Name 'Thread pool queue length' -CounterPath $path `
                    -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'work items' `
                    -Severity $severity `
                    -WhatToExpect 'A non-zero queue means work is waiting for thread-pool threads.' `
                    -OkGuidance 'Thread pool queue is empty - work is not backing up at the CLR scheduler.' `
                    -WarningGuidance 'Work is queuing for thread-pool threads - often blocked workers or sync-over-async.' `
                    -CriticalGuidance 'Thread pool queue is deep - requests will stall and IIS queues will grow.' `
                    -RecommendedActions @('Avoid blocking async code; offload long sync work to dedicated threads.'))
            }
        }
    }

    if ($counterSets.ContainsKey('ASP.NET v4.0.30319')) {
        $aspGlobalPaths = @(
            '\ASP.NET v4.0.30319\Requests Queued',
            '\ASP.NET v4.0.30319\Requests Rejected',
            '\ASP.NET v4.0.30319\Request Wait Time',
            '\ASP.NET v4.0.30319\Worker Process Restarts',
            '\ASP.NET v4.0.30319\Requests Current'
        )
        $aspGlobalMap = Read-CounterMap -Paths $aspGlobalPaths

        if ($aspGlobalMap.ContainsKey('\ASP.NET v4.0.30319\Requests Queued')) {
            $value = $aspGlobalMap['\ASP.NET v4.0.30319\Requests Queued']
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'AspNet' -Instance 'v4.0.30319' -Name 'Requests queued (global)' `
                -CounterPath '\ASP.NET v4.0.30319\Requests Queued' `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'requests' `
                -Severity (Get-AspNetGlobalQueueSeverity $value) `
                -WhatToExpect 'The global ASP.NET queue should usually be near zero when workers keep up.' `
                -OkGuidance 'No significant global ASP.NET queue backlog.' `
                -WarningGuidance 'Requests are waiting in the global ASP.NET queue - workers are falling behind.' `
                -CriticalGuidance 'Large global queue - expect 503s, high latency, and HTTP.sys queue growth.' `
                -RecommendedActions @(
                    'Check worker CPU, thread pool queue, and database latency.'
                    'Review recent deployments and app pool recycle settings.'
                ))
        }

        if ($aspGlobalMap.ContainsKey('\ASP.NET v4.0.30319\Requests Rejected')) {
            $value = $aspGlobalMap['\ASP.NET v4.0.30319\Requests Rejected']
            $severity = if ($value -le 0) { 'OK' } else { 'Warning' }
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'AspNet' -Instance 'v4.0.30319' -Name 'Requests rejected (global total)' `
                -CounterPath '\ASP.NET v4.0.30319\Requests Rejected' `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'requests' `
                -Severity $severity `
                -WhatToExpect 'Rejected requests should not increase during normal operation.' `
                -OkGuidance 'No rejected requests recorded on the global ASP.NET counter.' `
                -WarningGuidance 'ASP.NET has rejected requests - often overload, queue limits, or unhealthy workers.' `
                -CriticalGuidance 'Rejections are user-visible failures - treat as incident evidence.' `
                -RecommendedActions @('Review HTTP.sys and ASP.NET queue counters together with event logs.'))
        }

        if ($aspGlobalMap.ContainsKey('\ASP.NET v4.0.30319\Request Wait Time')) {
            $value = $aspGlobalMap['\ASP.NET v4.0.30319\Request Wait Time']
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'AspNet' -Instance 'v4.0.30319' -Name 'Request wait time (global)' `
                -CounterPath '\ASP.NET v4.0.30319\Request Wait Time' `
                -Value $value -FormattedValue ('{0:N0} ms' -f $value) -Unit 'ms' `
                -Severity 'Info' `
                -WhatToExpect 'Wait time semantics vary by version - compare with queue depth and worker latency.' `
                -OkGuidance 'Snapshot of global ASP.NET reported wait time.' `
                -WarningGuidance 'Rising wait time with queued requests indicates worker saturation.' `
                -CriticalGuidance 'Very high wait time with queues indicates severe thread or dependency blocking.' `
                -RecommendedActions @('Correlate with SQL, external HTTP calls, and lock contention counters.'))
        }

        if ($aspGlobalMap.ContainsKey('\ASP.NET v4.0.30319\Worker Process Restarts')) {
            $value = $aspGlobalMap['\ASP.NET v4.0.30319\Worker Process Restarts']
            $severity = if ($value -le 0) { 'OK' } elseif ($value -lt 5) { 'Warning' } else { 'Critical' }
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'AspNet' -Instance 'v4.0.30319' -Name 'Worker process restarts (total)' `
                -CounterPath '\ASP.NET v4.0.30319\Worker Process Restarts' `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'restarts' `
                -Severity $severity `
                -WhatToExpect 'Restarts should be rare outside planned recycles and deployments.' `
                -OkGuidance 'No unusual restart count on the global counter.' `
                -WarningGuidance 'Worker processes have restarted - correlate with WAS events and app errors.' `
                -CriticalGuidance 'Frequent restarts indicate instability or aggressive recycling under load.' `
                -RecommendedActions @('Inspect Application and System logs for crash signatures before each restart.'))
        }

        if ($aspGlobalMap.ContainsKey('\ASP.NET v4.0.30319\Requests Current')) {
            $value = $aspGlobalMap['\ASP.NET v4.0.30319\Requests Current']
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'AspNet' -Instance 'v4.0.30319' -Name 'Requests current (global)' `
                -CounterPath '\ASP.NET v4.0.30319\Requests Current' `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'requests' `
                -Severity 'Info' `
                -WhatToExpect 'Current executing requests across ASP.NET - compare with per-worker active requests.' `
                -OkGuidance 'Global in-flight request count snapshot.' `
                -WarningGuidance 'High in-flight requests with queues suggests saturation.' `
                -CriticalGuidance 'Extreme in-flight counts with errors indicate runaway concurrency or deadlocks.' `
                -RecommendedActions @('Compare with W3SVC_W3WP Active Requests for each pool.'))
        }
    }

    if ($counterSets.ContainsKey('ASP.NET Applications')) {
        $aspAppMap = Read-CounterMap -Paths @(
            '\ASP.NET Applications(*)\Requests In Application Queue',
            '\ASP.NET Applications(*)\Errors Unhandled During Execution/Sec'
        )

        $byApp = @{}
        foreach ($entry in $aspAppMap.GetEnumerator()) {
            if ($entry.Key -notmatch '\\ASP.NET Applications\(([^)]+)\)\\(.+)$') { continue }
            $appInst = $Matches[1]
            $ctr = $Matches[2]
            if (-not $byApp.ContainsKey($appInst)) {
                $byApp[$appInst] = @{}
            }
            $byApp[$appInst][$ctr] = $entry.Value
        }

        $hotApps = foreach ($appInst in $byApp.Keys) {
            $row = $byApp[$appInst]
            $q = if ($row.ContainsKey('Requests In Application Queue')) {
                [double]$row['Requests In Application Queue']
            } else { 0 }
            $e = if ($row.ContainsKey('Errors Unhandled During Execution/Sec')) {
                [double]$row['Errors Unhandled During Execution/Sec']
            } else { 0 }
            if ($q -gt 0 -or $e -gt 0) {
                [pscustomobject]@{ Instance = $appInst; Queue = $q; ErrorsPerSec = $e }
            }
        }

        foreach ($row in ($hotApps | Sort-Object @{ Expression = 'Queue'; Descending = $true }, @{ Expression = 'ErrorsPerSec'; Descending = $true } | Select-Object -First 20)) {
            $qPath = "\ASP.NET Applications($($row.Instance))\Requests In Application Queue"
            if ($row.Queue -gt 0) {
                Add-Measure (New-IISPerformanceMeasure `
                    -Category 'AspNet' -Instance $row.Instance -Name 'Requests in application queue' `
                    -CounterPath $qPath `
                    -Value $row.Queue -FormattedValue (Format-PerfNumber $row.Queue 0) -Unit 'requests' `
                    -Severity (Get-AspAppQueueSeverity $row.Queue) `
                    -WhatToExpect 'Per-application queue shows requests waiting inside ASP.NET for this app path.' `
                    -OkGuidance 'No queued requests for this application instance.' `
                    -WarningGuidance 'Requests are piling up inside this ASP.NET application queue.' `
                    -CriticalGuidance 'Deep per-app queue - this app is the bottleneck within the worker.' `
                    -RecommendedActions @(
                        'Profile slow pages, database calls, and session state for this application.'
                        'Compare with HTTP.sys queue and global ASP.NET queue counters.'
                    ))
            }

            if ($row.ErrorsPerSec -gt 0) {
                $ePath = "\ASP.NET Applications($($row.Instance))\Errors Unhandled During Execution/Sec"
                Add-Measure (New-IISPerformanceMeasure `
                    -Category 'AspNet' -Instance $row.Instance -Name 'Unhandled exceptions per second' `
                    -CounterPath $ePath `
                    -Value $row.ErrorsPerSec -FormattedValue ('{0:N2}/s' -f $row.ErrorsPerSec) -Unit 'per second' `
                    -Severity (Get-ExceptionRateSeverity $row.ErrorsPerSec) `
                    -WhatToExpect 'Unhandled exception rate should be zero in production.' `
                    -OkGuidance 'No unhandled exception rate reported for this application instance.' `
                    -WarningGuidance 'Unhandled exceptions are occurring in this application.' `
                    -CriticalGuidance 'Unhandled exceptions are frequent - users see errors and workers may recycle.' `
                    -RecommendedActions @('Review Application log and failed request tracing for this app path.'))
            }
        }
    }

    $sqlSetName = if ($counterSets.ContainsKey('.NET Data Provider for SqlClient')) {
        '.NET Data Provider for SqlClient'
    } elseif ($counterSets.ContainsKey('.NET Data Provider for SqlServer')) {
        '.NET Data Provider for SqlServer'
    } else {
        $null
    }

    if ($sqlSetName) {
        $sqlPaths = @(
            "\$sqlSetName\NumberOfPooledConnections",
            "\$sqlSetName\NumberOfFreeConnections",
            "\$sqlSetName\NumberOfReclaimedConnections",
            "\$sqlSetName\NumberOfStasisConnections",
            "\$sqlSetName\HardConnectFailuresPerSecond",
            "\$sqlSetName\NumberOfActiveConnectionPools"
        )
        $sqlMap = Read-CounterMap -Paths $sqlPaths

        if ($sqlMap.ContainsKey("\$sqlSetName\NumberOfPooledConnections")) {
            $value = $sqlMap["\$sqlSetName\NumberOfPooledConnections"]
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'SqlClient' -Name 'Pooled SQL connections' -CounterPath "\$sqlSetName\NumberOfPooledConnections" `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'connections' `
                -Severity 'Info' `
                -WhatToExpect 'Pooled connections should track application demand and return to the free pool after use.' `
                -OkGuidance 'Current pooled connection count.' `
                -WarningGuidance 'Pooled connections are climbing with free connections near zero.' `
                -CriticalGuidance 'Pool exhaustion causes timeouts and cascading queue growth in IIS workers.' `
                -RecommendedActions @('Review connection string pooling settings and ensure connections are disposed.'))
        }

        if ($sqlMap.ContainsKey("\$sqlSetName\NumberOfFreeConnections")) {
            $value = $sqlMap["\$sqlSetName\NumberOfFreeConnections"]
            $severity = if ($value -gt 0) { 'OK' } else { 'Warning' }
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'SqlClient' -Name 'Free SQL connections' -CounterPath "\$sqlSetName\NumberOfFreeConnections" `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'connections' `
                -Severity $severity `
                -WhatToExpect 'A healthy pool keeps some free connections ready for new requests.' `
                -OkGuidance 'Free pooled connections are available.' `
                -WarningGuidance 'No free pooled connections - new work may block waiting for SQL.' `
                -CriticalGuidance 'Connection pool starvation is likely - expect rising latency and thread growth.' `
                -RecommendedActions @('Increase Max Pool Size only after confirming connections are returned promptly.'))
        }

        if ($sqlMap.ContainsKey("\$sqlSetName\NumberOfReclaimedConnections")) {
            $value = $sqlMap["\$sqlSetName\NumberOfReclaimedConnections"]
            $severity = if ($value -le 0) { 'OK' } elseif ($value -lt 50) { 'Warning' } else { 'Critical' }
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'SqlClient' -Name 'Reclaimed SQL connections' -CounterPath "\$sqlSetName\NumberOfReclaimedConnections" `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'connections' `
                -Severity $severity `
                -WhatToExpect 'Reclaimed connections should stay low - spikes mean connections are not returned cleanly.' `
                -OkGuidance 'Few or no reclaimed connections.' `
                -WarningGuidance 'Connections are being reclaimed by the pool - check for leaked or long-running commands.' `
                -CriticalGuidance 'Heavy reclaim activity indicates pool churn and unstable database access patterns.' `
                -RecommendedActions @('Audit code paths that open SqlConnection without using blocks or dispose.'))
        }

        if ($sqlMap.ContainsKey("\$sqlSetName\NumberOfStasisConnections")) {
            $value = $sqlMap["\$sqlSetName\NumberOfStasisConnections"]
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'SqlClient' -Name 'Stasis SQL connections' -CounterPath "\$sqlSetName\NumberOfStasisConnections" `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'connections' `
                -Severity (Get-StasisSeverity $value) `
                -WhatToExpect 'Stasis connections should be zero - they represent broken pooled connections.' `
                -OkGuidance 'No broken pooled connections are waiting in stasis.' `
                -WarningGuidance 'Broken pooled connections are accumulating.' `
                -CriticalGuidance 'Many stasis connections indicate repeated SQL connect failures or network issues.' `
                -RecommendedActions @('Check SQL Server availability, firewall rules, and connection timeout settings.'))
        }

        if ($sqlMap.ContainsKey("\$sqlSetName\HardConnectFailuresPerSecond")) {
            $value = $sqlMap["\$sqlSetName\HardConnectFailuresPerSecond"]
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'SqlClient' -Name 'Hard SQL connect failures per second' -CounterPath "\$sqlSetName\HardConnectFailuresPerSecond" `
                -Value $value -FormattedValue ('{0:N2}/s' -f $value) -Unit 'per second' `
                -Severity (Get-SqlFailureSeverity $value) `
                -WhatToExpect 'Hard connect failures should remain zero during normal operation.' `
                -OkGuidance 'No hard SQL connect failures are occurring.' `
                -WarningGuidance 'Some SQL connection attempts are failing outright.' `
                -CriticalGuidance 'SQL connect failures are happening continuously - workers will block and queues will grow.' `
                -RecommendedActions @(
                    'Verify SQL Server reachability, DNS, authentication, and firewall rules.'
                    'Correlate with application error logs and IIS worker thread growth.'
                ))
        }

        if ($sqlMap.ContainsKey("\$sqlSetName\NumberOfActiveConnectionPools")) {
            $value = $sqlMap["\$sqlSetName\NumberOfActiveConnectionPools"]
            Add-Measure (New-IISPerformanceMeasure `
                -Category 'SqlClient' -Name 'Active SQL connection pools' -CounterPath "\$sqlSetName\NumberOfActiveConnectionPools" `
                -Value $value -FormattedValue (Format-PerfNumber $value 0) -Unit 'pools' `
                -Severity 'Info' `
                -WhatToExpect 'Many distinct pools can indicate many unique connection strings or tenants.' `
                -OkGuidance 'Current active connection pool count.' `
                -WarningGuidance 'High pool counts increase memory overhead and make exhaustion harder to spot.' `
                -CriticalGuidance 'Excessive pool proliferation can exhaust worker memory and SQL endpoint limits.' `
                -RecommendedActions @('Standardise connection strings and pool settings across the application.'))
        }
    }
    else {
        Add-UnavailableMeasure -Category 'SqlClient' -Name 'SQL Client connection pooling counters' `
            -CounterPath '\.NET Data Provider for SqlClient\*' `
            -Reason 'SqlClient performance counters are not installed on this server.'
    }

    $maxRank = if ($findings.Count -gt 0) {
        ($findings | Measure-Object SeverityRank -Maximum).Maximum
    } else { 1 }

    $overallSeverity = switch ($maxRank) {
        4 { 'Critical' }
        3 { 'Warning' }
        2 { 'Info' }
        default { 'Healthy' }
    }

    $snapshot = [pscustomobject]@{
        PSTypeName            = 'IISDiagnostics.PerformanceCounterSnapshot'
        GeneratedAt           = Get-Date
        ComputerName          = $env:COMPUTERNAME
        SampleIntervalSeconds = $SampleIntervalSeconds
        MaxSamples            = $MaxSamples
        OverallSeverity       = $overallSeverity
        Measures              = @($measures | Sort-Object Category, Instance, Name)
        Findings              = @($findings | Sort-Object SeverityRank -Descending)
    }

    if (-not $Quiet) {
        Write-IISPerformanceCounterConsoleReport -Snapshot $snapshot
    }

    return $snapshot
}
