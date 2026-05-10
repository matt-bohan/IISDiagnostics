#Requires -Version 5.1

# Identity type integers returned by WebAdministration when queried via
# Get-WebConfigurationProperty. Direct IIS:\ drive access returns strings;
# configuration API access may return ints. Normalise both.
$script:IdentityTypeMap = @{
    '0' = 'LocalSystem'
    '1' = 'LocalService'
    '2' = 'NetworkService'
    '3' = 'SpecificUser'
    '4' = 'ApplicationPoolIdentity'
}

function Get-IISAppPoolStatus {
    <#
    .SYNOPSIS
        Returns the state, identity, and configuration of one or more IIS application pools,
        with Active Directory account status checks for domain service accounts.

    .DESCRIPTION
        Queries all application pools via the WebAdministration module and returns a
        IISDiagnostics.AppPoolStatus object per pool, enriched with:

          State and worker process information
            Current state (Started / Stopped / Starting / Stopping / Unknown), whether
            AutoStart is enabled, how many worker processes are currently running and
            their process IDs.

          Identity details
            Identity type (ApplicationPoolIdentity, NetworkService, LocalSystem, LocalService,
            SpecificUser). For SpecificUser, the username is surfaced without the password.

          Active Directory account status
            For SpecificUser identities using a domain account, queries Active Directory
            for lock-out, disabled, and password-expiry status. Uses Get-ADUser if the
            ActiveDirectory module is available, or an ADSI directory searcher as a fallback.
            Local accounts and built-in identities are marked NotApplicable.

          Rapid-fail protection configuration
            Whether rapid-fail protection is enabled, the crash threshold, and the observation
            window. A stopped pool with rapid-fail protection enabled is noted in Notices as
            something to cross-reference with the Windows Event Log.

          Notices
            Pre-computed observations about anything worth investigating: stopped pools,
            problematic account states, rapid-fail configuration. Used by
            Invoke-IISDiagnosticSweep to surface pool issues without re-implementing logic.

    .PARAMETER Name
        Name of the application pool to query. Accepts wildcards. Defaults to all pools.
        Accepts pipeline input.

    .PARAMETER SkipAccountCheck
        Skip the Active Directory account status check for SpecificUser identities.
        Useful when running on a server that cannot reach a domain controller, or when
        the check would be slow due to DC latency.

    .EXAMPLE
        Get-IISAppPool

        Returns status for all application pools.

    .EXAMPLE
        Get-IISAppPool -Name DefaultAppPool

        Returns status for a single named pool.

    .EXAMPLE
        Get-IISAppPool -Name *MyAppPool*

        Returns all pools whose name contains CyberArk.

    .EXAMPLE
        Get-IISAppPool | Where-Object State -ne 'Started'

        Returns all pools that are not currently running.

    .EXAMPLE
        Get-IISAppPool | Where-Object AccountStatus -eq 'LockedOut'

        Returns pools whose service account is locked out in Active Directory.

    .NOTES
        Requires an elevated session and the WebAdministration module.
        The WebAdministration module is installed with the IIS Management tools Windows feature:
          Install-WindowsFeature -Name Web-Scripting-Tools
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [SupportsWildcards()]
        [string]$Name = '*',

        [Parameter()]
        [switch]$SkipAccountCheck
    )

    begin {
        Assert-ElevatedSession  -CmdletName $MyInvocation.MyCommand.Name
        Assert-WebAdminModule   -CmdletName $MyInvocation.MyCommand.Name

        # Load all pools once in begin so that piping multiple names does not
        # hit the IIS: drive once per pipeline object.
        try {
            $allPools = @(Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop)
        }
        catch {
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.InvalidOperationException]::new(
                        "Failed to enumerate application pools from IIS:\AppPools. " +
                        "Verify IIS is installed and running. Error: $_"),
                    'AppPoolEnumerationFailed',
                    [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
                    'IIS:\AppPools'
                )
            )
        }
    }

    process {
        $matchingPools = if ($Name -eq '*') {
            $allPools
        } else {
            $allPools | Where-Object { $_.Name -like $Name }
        }

        if (-not $matchingPools) {
            Write-Warning "No application pools found matching '$Name'."
            return
        }

        foreach ($pool in $matchingPools) {
            Write-Verbose "Processing pool: $($pool.Name)"

            # ------------------------------------------------------------------
            # State
            # ------------------------------------------------------------------
            $state = try { [string]$pool.State } catch { 'Unknown' }

            # ------------------------------------------------------------------
            # Worker processes currently running for this pool
            # ------------------------------------------------------------------
            $workerProcessIds   = @()
            $workerProcessCount = 0
            try {
                $wpPath = "IIS:\AppPools\$($pool.Name)\WorkerProcesses"
                $wps    = @(Get-ChildItem $wpPath -ErrorAction SilentlyContinue)
                if ($wps) {
                    $workerProcessCount = $wps.Count
                    $workerProcessIds   = @($wps | ForEach-Object { [int]$_.processId })
                }
            }
            catch {
                Write-Verbose "  Could not enumerate worker processes for '$($pool.Name)': $_"
            }

            # ------------------------------------------------------------------
            # Identity type - normalise integer to string if needed
            # ------------------------------------------------------------------
            $rawIdentityType = try { [string]$pool.ProcessModel.IdentityType } catch { $null }
            $identityType    = if ($rawIdentityType -and $script:IdentityTypeMap.ContainsKey($rawIdentityType)) {
                $script:IdentityTypeMap[$rawIdentityType]
            } else {
                $rawIdentityType   # already a string from IIS:\ drive access
            }

            $userName = try {
                if ($identityType -eq 'SpecificUser') { [string]$pool.ProcessModel.UserName }
                else { $null }
            } catch { $null }

            # ------------------------------------------------------------------
            # Active Directory account status
            # ------------------------------------------------------------------
            $accountStatus = 'N/A'
            $accountDetail = 'Built-in or virtual identity - no Active Directory check required.'
            $adResult      = $null

            if ($identityType -eq 'SpecificUser' -and -not [string]::IsNullOrWhiteSpace($userName)) {
                if ($SkipAccountCheck) {
                    $accountStatus = 'Skipped'
                    $accountDetail = 'Account check skipped (-SkipAccountCheck).'
                }
                else {
                    Write-Verbose "  Checking account status for '$userName'"
                    $adResult      = Test-DomainAccountStatus -Username $userName
                    $accountStatus = $adResult.Status
                    $accountDetail = $adResult.Detail
                }
            }
            elseif ($identityType -eq 'SpecificUser' -and [string]::IsNullOrWhiteSpace($userName)) {
                $accountStatus = 'CheckFailed'
                $accountDetail = 'Pool uses SpecificUser identity but no username is configured.'
            }

            # ------------------------------------------------------------------
            # Rapid-fail protection
            # ------------------------------------------------------------------
            $rfpEnabled     = $false
            $rfpMaxCrashes  = $null
            $rfpInterval    = $null

            try {
                $rfpEnabled    = [bool]$pool.Failure.RapidFailProtection
                $rfpMaxCrashes = [int]$pool.Failure.RapidFailProtectionMaxCrashes
                $rfpInterval   = $pool.Failure.RapidFailProtectionInterval
            }
            catch {
                Write-Verbose "  Could not read rapid-fail protection settings for '$($pool.Name)': $_"
            }

            # ------------------------------------------------------------------
            # Pipeline mode and runtime
            # ------------------------------------------------------------------
            $pipelineMode   = try { [string]$pool.ManagedPipelineMode } catch { $null }
            $runtimeVersion = try {
                $rv = [string]$pool.ManagedRuntimeVersion
                if ([string]::IsNullOrWhiteSpace($rv)) { 'No Managed Code' } else { $rv }
            } catch { $null }

            $startMode   = try { [string]$pool.StartMode }   catch { $null }
            $autoStart   = try { [bool]$pool.AutoStart }     catch { $null }
            $queueLength = try { [int]$pool.QueueLength }    catch { $null }

            # ------------------------------------------------------------------
            # Recycling schedule (informational - useful context for triage)
            # ------------------------------------------------------------------
            $recycleSchedule = @()
            try {
                $times = $pool.Recycling.PeriodicRestart.Schedule.Collection
                if ($times) {
                    $recycleSchedule = @($times | ForEach-Object { $_.Value.ToString('HH:mm') })
                }
            }
            catch {
                Write-Verbose "  Could not read recycle schedule for '$($pool.Name)': $_"
            }

            $recycleMemoryKb        = try { [int]$pool.Recycling.PeriodicRestart.Memory }        catch { 0 }
            $recyclePrivateMemoryKb = try { [int]$pool.Recycling.PeriodicRestart.PrivateMemory } catch { 0 }
            $recycleTimeMinutes     = try { [int]$pool.Recycling.PeriodicRestart.Time }          catch { 0 }

            # ------------------------------------------------------------------
            # Notices - pre-computed observations for the sweep and operators
            # ------------------------------------------------------------------
            $notices = [System.Collections.Generic.List[string]]::new()

            if ($state -eq 'Stopped') {
                if ($rfpEnabled) {
                    $notices.Add(
                        "Pool is stopped and rapid-fail protection is enabled " +
                        "(threshold: $rfpMaxCrashes crashes per $rfpInterval). " +
                        "Check Windows Event Log (source: WAS) to determine whether " +
                        "rapid-fail protection tripped or the pool was stopped manually."
                    )
                } else {
                    $notices.Add(
                        "Pool is stopped. AutoStart is $(if ($autoStart) { 'enabled' } else { 'disabled' }). " +
                        "Check whether this was intentional or the result of a failure."
                    )
                }
            }

            if ($state -eq 'Started' -and $workerProcessCount -eq 0) {
                $notices.Add(
                    "Pool is in Started state but has no running worker processes. " +
                    "This can occur immediately after a recycle before the new process has spawned."
                )
            }

            switch ($accountStatus) {
                'LockedOut' {
                    $notices.Add(
                        "Service account '$userName' is locked out in Active Directory. " +
                        "The pool will fail to authenticate and cannot start worker processes."
                    )
                }
                'Disabled' {
                    $notices.Add(
                        "Service account '$userName' is disabled in Active Directory. " +
                        "The pool cannot start until the account is re-enabled."
                    )
                }
                'PasswordExpired' {
                    $notices.Add(
                        "Password for service account '$userName' has expired. " +
                        "Reset the password and update the pool identity configuration."
                    )
                }
                'CheckFailed' {
                    $notices.Add(
                        "Could not verify Active Directory status of '$userName'. " +
                        "Run Get-IISAppPool -Verbose for detail, or check manually."
                    )
                }
            }

            if ($identityType -eq 'LocalSystem') {
                $notices.Add(
                    "Pool runs as LocalSystem - this account has unrestricted local access. " +
                    "Best practice is ApplicationPoolIdentity or a least-privilege service account."
                )
            }

            # ------------------------------------------------------------------
            # Emit the status object
            # ------------------------------------------------------------------
            [pscustomobject]@{
                PSTypeName                    = 'IISDiagnostics.AppPoolStatus'
                Name                          = $pool.Name
                State                         = $state
                AutoStart                     = $autoStart
                StartMode                     = $startMode
                PipelineMode                  = $pipelineMode
                RuntimeVersion                = $runtimeVersion
                QueueLength                   = $queueLength
                IdentityType                  = $identityType
                UserName                      = $userName
                AccountStatus                 = $accountStatus
                AccountStatusDetail           = $accountDetail
                RapidFailProtectionEnabled    = $rfpEnabled
                RapidFailProtectionMaxCrashes = $rfpMaxCrashes
                RapidFailProtectionInterval   = $rfpInterval
                WorkerProcessCount            = $workerProcessCount
                WorkerProcessIds              = $workerProcessIds
                RecycleSchedule               = $recycleSchedule
                RecycleTimeMinutes            = $recycleTimeMinutes
                RecycleMemoryKb               = $recycleMemoryKb
                RecyclePrivateMemoryKb        = $recyclePrivateMemoryKb
                Notices                       = $notices.ToArray()
            }
        }
    }

    end {}
}