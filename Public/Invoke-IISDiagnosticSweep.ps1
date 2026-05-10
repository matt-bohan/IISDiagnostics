#Requires -Version 5.1

function Invoke-IISDiagnosticSweep {
    <#
    .SYNOPSIS
        Runs a full IIS diagnostic sweep and presents colour-coded findings.

    .DESCRIPTION
        Orchestrates all IISDiagnostics cmdlets into a single command - designed for
        the 2am call where you need answers fast.

        Runs in sequence:
          1. HTTP.sys error log analysis    (Invoke-IISHttpErrAnalysis)
          2. W3C access log analysis        (Invoke-IISW3CLogAnalysis)
          3. Application pool status        (Get-IISAppPool)
          4. Site configuration             (Get-IISSiteConfiguration)
          5. Site bindings and certificates (Get-IISSiteSummary)
          6. Windows Event Log              (Get-IISEventLog -Significant)

        Each component is run inside a try/catch - if one fails (e.g. WebAdministration
        not installed) the others continue and the failure is reported at the end.

        Console output uses colour to encode severity:
          Red    - Critical: something is broken right now
          Yellow - Warning: degraded or at risk
          Cyan   - Info: notable but not urgent
          Green  - OK: confirmed healthy

        The returned IISDiagnostics.SweepResult object carries all raw results plus a
        consolidated Findings array, suitable for piping, exporting, or further scripting.

    .PARAMETER StartTime
        Start of the log analysis window. Defaults to one hour ago.

    .PARAMETER EndTime
        End of the log analysis window. Defaults to now.

    .PARAMETER SiteName
        Limit log analysis and configuration checks to one site.

    .PARAMETER ReportPath
        Path to write a self-contained HTML report. If omitted, no file is written.
        Example: -ReportPath C:\Reports\sweep-$(Get-Date -f yyyyMMdd-HHmm).html

    .PARAMETER OpenReport
        Open the HTML report in the default browser after writing it.
        Requires -ReportPath.

    .PARAMETER SkipW3C
        Skip W3C log analysis. Faster for large log volumes or when only the
        infrastructure checks are needed.

    .PARAMETER SkipEventLog
        Skip the Windows Event Log query.

    .PARAMETER SkipPermissionCheck
        Skip ACL checks in Get-IISSiteConfiguration. Useful when the app pool
        identity or domain controller is unreachable.

    .EXAMPLE
        Invoke-IISDiagnosticSweep

        Standard sweep of the last hour. Coloured output to the console.

    .EXAMPLE
        Invoke-IISDiagnosticSweep -StartTime (Get-Date).AddHours(-4)

        Extended window - useful when reviewing an incident that started earlier.

    .EXAMPLE
        Invoke-IISDiagnosticSweep -ReportPath C:\Reports\sweep.html -OpenReport

        Console output plus an HTML report that opens immediately.

    .EXAMPLE
        $result = Invoke-IISDiagnosticSweep
        $result.Findings | Where-Object Severity -eq 'Critical'

        Capture the result object for scripting while still seeing coloured output.

    .NOTES
        Requires an elevated session. WebAdministration must be installed for pool,
        site configuration, and certificate checks.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [datetime]$StartTime  = (Get-Date).AddHours(-1),
        [Parameter()] [datetime]$EndTime    = (Get-Date),
        [Parameter()] [string]$SiteName,
        [Parameter()] [string]$ReportPath,
        [Parameter()] [switch]$OpenReport,
        [Parameter()] [switch]$SkipW3C,
        [Parameter()] [switch]$SkipEventLog,
        [Parameter()] [switch]$SkipPermissionCheck
    )

    Assert-ElevatedSession -CmdletName $MyInvocation.MyCommand.Name

    # ── Console output helpers ──────────────────────────────────────────
    $lineWidth = 68

    function Write-Banner([string]$Text, [switch]$Double) {
        $char  = if ($Double) { '=' } else { '-' }
        $line  = $char * $lineWidth
        Write-Host "  $line" -ForegroundColor DarkGray
        if ($Text) { Write-Host "    $Text" -ForegroundColor White }
    }

    function Write-Section([string]$Title) {
        $pad  = '-' * [math]::Max(2, $lineWidth - $Title.Length - 5)
        Write-Host ''
        Write-Host "  --- $Title $pad" -ForegroundColor DarkGray
    }

    function Write-Item([string]$Severity, [string]$Text, [string[]]$Actions) {
        $badge = switch ($Severity) {
            'Critical' { '[CRIT]' } 'Warning' { '[WARN]' }
            'Info'     { '[INFO]' } default   { '[ OK ]' }
        }
        $colour = switch ($Severity) {
            'Critical' { 'Red'    } 'Warning' { 'Yellow' }
            'Info'     { 'Cyan'   } default   { 'Green'  }
        }
        Write-Host "  $badge  $Text" -ForegroundColor $colour
        foreach ($a in $Actions) {
            Write-Host "           -> $a" -ForegroundColor DarkGray
        }
    }

    # ── Finding accumulator ─────────────────────────────────────────────
    $findings = [System.Collections.Generic.List[psobject]]::new()

    function Add-Finding([string]$Severity, [string]$Source, [string]$Title,
                         [string]$Detail, [string[]]$Actions) {
        $rank = switch ($Severity) { 'Critical'{4} 'Warning'{3} 'Info'{2} default{1} }
        $findings.Add([pscustomobject]@{
            PSTypeName         = 'IISDiagnostics.SweepFinding'
            SeverityRank       = $rank
            Severity           = $Severity
            Source             = $Source
            Title              = $Title
            Detail             = $Detail
            RecommendedActions = if ($Actions) { [string[]]$Actions } else { @() }
        })
    }

    # ── Collection errors log ───────────────────────────────────────────
    $collectionErrors = [System.Collections.Generic.List[string]]::new()

    # ── Shared parameters ───────────────────────────────────────────────
    $window = @{ StartTime = $StartTime; EndTime = $EndTime; Verbose = $false }
    $siteFilter = if (-not [string]::IsNullOrWhiteSpace($SiteName)) { $SiteName } else { $null }

    # ── Banner ──────────────────────────────────────────────────────────
    $windowMins = [math]::Round(($EndTime - $StartTime).TotalMinutes, 0)
    Write-Host ''
    Write-Banner -Double
    Write-Host "    IIS Diagnostic Sweep" -ForegroundColor White -NoNewline
    Write-Host "  *  $($env:COMPUTERNAME)  *  $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "    Window: $($StartTime.ToString('HH:mm')) -> $($EndTime.ToString('HH:mm'))  ($windowMins min)" -ForegroundColor DarkGray
    Write-Banner -Double

    # ══════════════════════════════════════════════════════════════════════
    # 1. HTTP.sys error log analysis
    # ══════════════════════════════════════════════════════════════════════
    $httpErrAnalysis = $null
    try {
        Write-Progress -Activity 'IIS Diagnostic Sweep' -Status 'Analysing HTTP.sys error log...' -PercentComplete 10
        $httpErrAnalysis = Invoke-IISHttpErrAnalysis @window -ErrorAction Stop
    }
    catch { $collectionErrors.Add("HTTP.sys analysis: $($_.Exception.Message)") }

    Write-Section 'HTTP.SYS LAYER'
    if ($httpErrAnalysis) {
        $significantFindings = @($httpErrAnalysis.Findings | Where-Object { $_.SeverityRank -ge 3 })
        if ($significantFindings.Count -eq 0) {
            Write-Item -Severity 'OK' -Text "No significant HTTPERR patterns in window ($($httpErrAnalysis.TotalEntries) entries)"
        }
        else {
            foreach ($f in ($significantFindings | Sort-Object SeverityRank -Descending)) {
                Write-Item -Severity $f.Severity -Text $f.Title -Actions ($f.RecommendedActions | Select-Object -First 2)
                Add-Finding -Severity $f.Severity -Source 'HTTP.sys' -Title $f.Title `
                            -Detail $f.Evidence -Actions $f.RecommendedActions
            }
        }
        # Info-level findings get a single-line summary
        $infoFindings = @($httpErrAnalysis.Findings | Where-Object { $_.SeverityRank -eq 2 })
        if ($infoFindings.Count -gt 0) {
            Write-Item -Severity 'Info' -Text "$($infoFindings.Count) info-level finding(s) - run Invoke-IISHttpErrAnalysis for detail"
        }
    }
    else {
        Write-Item -Severity 'Info' -Text 'HTTP.sys analysis not available'
    }

    # ══════════════════════════════════════════════════════════════════════
    # 2. W3C access log analysis
    # ══════════════════════════════════════════════════════════════════════
    $w3cAnalysis = $null
    if (-not $SkipW3C) {
        try {
            Write-Progress -Activity 'IIS Diagnostic Sweep' -Status 'Analysing W3C access logs...' -PercentComplete 25
            $w3cParams = $window.Clone()
            if ($siteFilter) { $w3cParams['SiteName'] = $siteFilter }
            $w3cAnalysis = Invoke-IISW3CLogAnalysis @w3cParams -ErrorAction Stop
        }
        catch { $collectionErrors.Add("W3C log analysis: $($_.Exception.Message)") }
    }

    Write-Section 'W3C ACCESS LOGS'
    if ($SkipW3C) {
        Write-Item -Severity 'Info' -Text 'Skipped (-SkipW3C)'
    }
    elseif ($w3cAnalysis) {
        $total   = $w3cAnalysis.TotalRequests
        $errRate = if ($total -gt 0) {
            $err = ($w3cAnalysis.ErrorGroups | Measure-Object Count -Sum).Sum
            [math]::Round(($err / $total) * 100, 1)
        } else { 0 }

        Write-Item -Severity 'OK' -Text "$total requests  *  Error rate $errRate%"

        foreach ($group in ($w3cAnalysis.ServerErrors | Sort-Object Count -Descending | Select-Object -First 5)) {
            $title = if ($group.Title) { $group.Title } else { 'Unknown' }
            Write-Item -Severity 'Critical' -Text "$($group.StatusKey)  x$($group.Count)  -  $title"
            Add-Finding -Severity 'Critical' -Source 'W3C' `
                        -Title  "$($group.StatusKey) - $title" `
                        -Detail "$($group.Count) requests returned $($group.StatusKey)" `
                        -Actions @("Run: Invoke-IISW3CLogAnalysis | Where-Object StatusKey -eq '$($group.StatusKey)' | Format-List")
        }

        foreach ($group in ($w3cAnalysis.ErrorGroups | Where-Object { $_.StatusCode -lt 500 } |
                            Sort-Object Count -Descending | Select-Object -First 3)) {
            if ($group.Count -ge 10) {
                $title = if ($group.Title) { $group.Title } else { 'Unknown' }
                Write-Item -Severity 'Warning' -Text "$($group.StatusKey)  x$($group.Count)  -  $title"
                Add-Finding -Severity 'Warning' -Source 'W3C' `
                            -Title  "$($group.StatusKey) - $title" `
                            -Detail "$($group.Count) client errors" `
                            -Actions @("Run: Invoke-IISW3CLogAnalysis -ErrorsOnly | Format-List")
            }
        }
    }
    else {
        Write-Item -Severity 'Info' -Text 'W3C analysis not available'
    }

    # ══════════════════════════════════════════════════════════════════════
    # 3. Application pools
    # ══════════════════════════════════════════════════════════════════════
    $appPools = $null
    try {
        Write-Progress -Activity 'IIS Diagnostic Sweep' -Status 'Checking application pools...' -PercentComplete 45
        $appPools = @(Get-IISAppPoolStatus -SkipAccountCheck:$SkipPermissionCheck -Verbose:$false -ErrorAction Stop)
    }
    catch { $collectionErrors.Add("App pool check: $($_.Exception.Message)") }

    Write-Section 'APP POOLS'
    if ($appPools) {
        foreach ($pool in ($appPools | Sort-Object { if ($_.State -ne 'Started') { 0 } else { 1 } }, Name)) {
            $identity = if ($pool.IdentityType -eq 'SpecificUser' -and $pool.UserName) {
                $pool.UserName
            } else { $pool.IdentityType }
            $workers  = if ($pool.WorkerProcessCount -gt 0) { "$($pool.WorkerProcessCount) worker(s)" } else { '' }

            if ($pool.State -ne 'Started') {
                $rfp  = if ($pool.RapidFailProtectionEnabled) { '  (rapid-fail protection enabled)' } else { '' }
                Write-Item -Severity 'Critical' -Text "$($pool.Name)  STOPPED$rfp" `
                    -Actions @(
                        "Run Get-IISEventLog -AppPoolName '$($pool.Name)' -Significant to find the cause",
                        "Run Get-IISAppPoolStatus -Name '$($pool.Name)' | Format-List for full detail"
                    )
                Add-Finding -Severity 'Critical' -Source 'AppPool' `
                            -Title  "$($pool.Name) - application pool is stopped" `
                            -Detail "State: $($pool.State). RapidFailProtection: $($pool.RapidFailProtectionEnabled)." `
                            -Actions @(
                                "Run Get-IISEventLog -AppPoolName '$($pool.Name)' -Significant",
                                "Run Get-IISAppPoolStatus -Name '$($pool.Name)' | Format-List"
                            )
            }
            else {
                $accountNote = switch ($pool.AccountStatus) {
                    'LockedOut'      { '  [!] IDENTITY LOCKED OUT' }
                    'Disabled'       { '  [!] IDENTITY DISABLED' }
                    'PasswordExpired'{ '  [!] IDENTITY PASSWORD EXPIRED' }
                    default          { '' }
                }

                if ($accountNote) {
                    Write-Item -Severity 'Warning' -Text "$($pool.Name)  Started  *  $identity$accountNote" `
                        -Actions @("Unlock or reset the '$($pool.UserName)' service account in Active Directory")
                    Add-Finding -Severity 'Warning' -Source 'AppPool' `
                                -Title  "$($pool.Name) - service account issue: $($pool.AccountStatus)" `
                                -Detail $pool.AccountStatusDetail `
                                -Actions @("Resolve the '$($pool.UserName)' account status in Active Directory")
                }
                else {
                    Write-Item -Severity 'OK' -Text "$($pool.Name)  Started  *  $identity  $workers"
                }
            }
        }
    }
    else {
        Write-Item -Severity 'Info' -Text 'App pool data not available (WebAdministration required)'
    }

    # ══════════════════════════════════════════════════════════════════════
    # 4. Site configuration
    # ══════════════════════════════════════════════════════════════════════
    $siteConfigs = $null
    try {
        Write-Progress -Activity 'IIS Diagnostic Sweep' -Status 'Checking site configuration...' -PercentComplete 60
        $cfgParams = @{ SkipPermissionCheck = $SkipPermissionCheck; Verbose = $false; ErrorAction = 'Stop' }
        if ($siteFilter) { $cfgParams['SiteName'] = $siteFilter }
        $siteConfigs = @(Get-IISSiteConfiguration @cfgParams)
    }
    catch { $collectionErrors.Add("Site configuration: $($_.Exception.Message)") }

    Write-Section 'SITE CONFIGURATION'
    if ($siteConfigs) {
        foreach ($cfg in $siteConfigs) {
            $auth = if ($cfg.Authentication.EnabledMethods) {
                $cfg.Authentication.EnabledMethods -join ' + '
            } else { 'No auth methods enabled' }

            if ($cfg.PhysicalPathStatus -eq 'Missing') {
                Write-Item -Severity 'Critical' -Text "$($cfg.SiteName)  -  Physical path missing: $($cfg.PhysicalPath)" `
                    -Actions @('Verify the path exists and the application was deployed correctly')
                Add-Finding -Severity 'Critical' -Source 'SiteConfig' `
                            -Title  "$($cfg.SiteName) - physical path does not exist" `
                            -Detail "Configured path: $($cfg.PhysicalPath)" `
                            -Actions @('Verify deployment and path configuration in IIS Manager')
            }
            elseif ($cfg.PathPermissions.Status -eq 'ExplicitDeny') {
                Write-Item -Severity 'Critical' -Text "$($cfg.SiteName)  -  Explicit Deny ACE on physical path" `
                    -Actions @("Run Get-IISSiteConfiguration -SiteName '$($cfg.SiteName)' | Format-List")
                Add-Finding -Severity 'Critical' -Source 'SiteConfig' `
                            -Title  "$($cfg.SiteName) - identity explicitly denied access to physical path" `
                            -Detail $cfg.PathPermissions.Detail `
                            -Actions @("Review ACL on $($cfg.PhysicalPath)")
            }
            elseif ($cfg.Notices.Count -gt 0) {
                Write-Item -Severity 'Warning' -Text "$($cfg.SiteName)  -  $($cfg.Notices.Count) configuration notice(s)" `
                    -Actions @("Run Get-IISSiteConfiguration -SiteName '$($cfg.SiteName)' | Format-List")
                foreach ($notice in $cfg.Notices) {
                    Add-Finding -Severity 'Warning' -Source 'SiteConfig' `
                                -Title  "$($cfg.SiteName) - configuration notice" `
                                -Detail $notice `
                                -Actions @("Run Get-IISSiteConfiguration -SiteName '$($cfg.SiteName)' | Format-List")
                }
            }
            else {
                $permNote = switch ($cfg.PathPermissions.Status) {
                    'OK'          { 'ACE OK' }
                    'NotRequired' { 'LocalSystem' }
                    default       { '' }
                }
                Write-Item -Severity 'OK' -Text "$($cfg.SiteName)  *  Path OK  $permNote  *  $auth"
            }
        }
    }
    else {
        Write-Item -Severity 'Info' -Text 'Site configuration not available (WebAdministration required)'
    }

    # ══════════════════════════════════════════════════════════════════════
    # 5. Certificates (via site summary)
    # ══════════════════════════════════════════════════════════════════════
    $siteSummary = $null
    try {
        Write-Progress -Activity 'IIS Diagnostic Sweep' -Status 'Checking SSL certificates...' -PercentComplete 75
        $sumParams = @{ Verbose = $false; ErrorAction = 'Stop' }
        if ($siteFilter) { $sumParams['SiteName'] = $siteFilter }
        $siteSummary = @(Get-IISSiteSummary @sumParams)
    }
    catch { $collectionErrors.Add("Certificate check: $($_.Exception.Message)") }

    Write-Section 'CERTIFICATES'
    if ($siteSummary) {
        $httpsOnly = @($siteSummary | Where-Object { $_.HttpsBindings -gt 0 })
        if ($httpsOnly.Count -eq 0) {
            Write-Item -Severity 'Info' -Text 'No HTTPS bindings found across any site'
        }
        else {
            foreach ($site in ($httpsOnly | Sort-Object {
                    switch ($_.WorstCertStatus) {
                        'Expired'{ 0 } 'NoCertificate'{ 1 } 'ExpiringSoon'{ 2 } default{ 3 }
                    }
                })) {
                switch ($site.WorstCertStatus) {
                    'Expired' {
                        Write-Item -Severity 'Critical' -Text "$($site.SiteName)  -  Certificate EXPIRED  ($($site.NearestExpiry.ToString('dd/MM/yyyy')))" `
                            -Actions @('Replace the certificate immediately - HTTPS connections will fail')
                        Add-Finding -Severity 'Critical' -Source 'Certificate' `
                                    -Title  "$($site.SiteName) - SSL certificate has expired" `
                                    -Detail "Expiry: $($site.NearestExpiry.ToString('dd/MM/yyyy HH:mm')). Subject: $($site.NearestCertSubject)" `
                                    -Actions @('Replace the certificate - all HTTPS connections are failing')
                    }
                    'NoCertificate' {
                        Write-Item -Severity 'Critical' -Text "$($site.SiteName)  -  HTTPS binding has no certificate" `
                            -Actions @("Run Get-IISSiteBinding -SiteName '$($site.SiteName)' | Format-List")
                        Add-Finding -Severity 'Critical' -Source 'Certificate' `
                                    -Title  "$($site.SiteName) - HTTPS binding without a certificate" `
                                    -Detail 'No certificate bound to HTTPS port. All HTTPS connections will fail.' `
                                    -Actions @('Bind a valid certificate via IIS Manager or netsh http add sslcert')
                    }
                    'ExpiringSoon' {
                        Write-Item -Severity 'Warning' -Text "$($site.SiteName)  -  Expires in $($site.NearestExpiryDays) days  ($($site.NearestExpiry.ToString('dd/MM/yyyy')))" `
                            -Actions @('Plan certificate renewal before expiry')
                        Add-Finding -Severity 'Warning' -Source 'Certificate' `
                                    -Title  "$($site.SiteName) - certificate expiring in $($site.NearestExpiryDays) days" `
                                    -Detail "Expiry: $($site.NearestExpiry.ToString('dd/MM/yyyy')). Subject: $($site.NearestCertSubject)" `
                                    -Actions @('Renew the certificate before expiry to avoid service disruption')
                    }
                    default {
                        $days = if ($null -ne $site.NearestExpiryDays) { "  ($($site.NearestExpiryDays) days remaining)" } else { '' }
                        Write-Item -Severity 'OK' -Text "$($site.SiteName)  -  Valid$days"
                    }
                }
            }
        }
    }
    else {
        Write-Item -Severity 'Info' -Text 'Certificate data not available (WebAdministration required)'
    }

    # ══════════════════════════════════════════════════════════════════════
    # 6. Event log
    # ══════════════════════════════════════════════════════════════════════
    $eventLog = $null
    if (-not $SkipEventLog) {
        try {
            Write-Progress -Activity 'IIS Diagnostic Sweep' -Status 'Querying event log...' -PercentComplete 88
            $evtParams = @{ Significant = $true; Verbose = $false; ErrorAction = 'Stop' }
            $evtParams['StartTime'] = $StartTime; $evtParams['EndTime'] = $EndTime
            if ($siteFilter) { $evtParams['AppPoolName'] = $siteFilter }
            $eventLog = @(Get-IISEventLog @evtParams)
        }
        catch { $collectionErrors.Add("Event log: $($_.Exception.Message)") }
    }

    Write-Section 'EVENT LOG'
    if ($SkipEventLog) {
        Write-Item -Severity 'Info' -Text 'Skipped (-SkipEventLog)'
    }
    elseif ($eventLog -and $eventLog.Count -gt 0) {
        foreach ($evt in ($eventLog | Sort-Object TimeCreated -Descending | Select-Object -First 8)) {
            $severity = if ($evt.EntryType -in 'Critical','Error') { 'Critical' } else { 'Warning' }
            $pool     = if ($evt.AppPoolName) { "  - $($evt.AppPoolName)" } else { '' }
            $desc     = if ($evt.KnownDescription) { $evt.KnownDescription } else { $evt.ShortMessage }
            Write-Item -Severity $severity -Text "$($evt.TimeCreated.ToString('HH:mm:ss'))  $($evt.Source -replace 'Microsoft-Windows-','')  $($evt.EventId)  -  $desc$pool"

            if ($evt.IsSignificant) {
                Add-Finding -Severity $severity -Source 'EventLog' `
                            -Title  "$($evt.Source) event $($evt.EventId) - $desc" `
                            -Detail "Time: $($evt.TimeCreated.ToString('dd/MM/yyyy HH:mm:ss')). Pool: $(if ($evt.AppPoolName) { $evt.AppPoolName } else { 'N/A' })" `
                            -Actions @("Run Get-IISEventLog -Significant | Format-List for full message")
            }
        }
        if ($eventLog.Count -gt 8) {
            Write-Host "           ... and $($eventLog.Count - 8) more - run Get-IISEventLog -Significant for full list" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Item -Severity 'OK' -Text 'No significant events in this window'
    }

    Write-Progress -Activity 'IIS Diagnostic Sweep' -Completed

    # ── Footer ──────────────────────────────────────────────────────────
    $critCount = ($findings | Where-Object Severity -eq 'Critical').Count
    $warnCount = ($findings | Where-Object Severity -eq 'Warning').Count
    $infoCount = ($findings | Where-Object Severity -eq 'Info').Count

    $overallSeverity = if ($critCount -gt 0)    { 'Critical' }
                       elseif ($warnCount -gt 0) { 'Warning'  }
                       elseif ($infoCount -gt 0) { 'Info'     }
                       else                      { 'Healthy'  }

    $overallColour = switch ($overallSeverity) {
        'Critical' { 'Red' } 'Warning' { 'Yellow' } 'Info' { 'Cyan' } default { 'Green' }
    }

    $summaryParts = @()
    if ($critCount -gt 0) { $summaryParts += "$critCount critical" }
    if ($warnCount -gt 0) { $summaryParts += "$warnCount warning" }
    if ($infoCount -gt 0) { $summaryParts += "$infoCount info" }
    $summary = if ($summaryParts) { $summaryParts -join '  |  ' } else { 'No issues detected' }

    Write-Host ''
    Write-Banner -Double
    Write-Host "    OVERALL: " -ForegroundColor DarkGray -NoNewline
    Write-Host $overallSeverity.ToUpper() -ForegroundColor $overallColour -NoNewline
    Write-Host "  |  $summary" -ForegroundColor DarkGray

    if ($collectionErrors.Count -gt 0) {
        Write-Host "    Errors:  $($collectionErrors.Count) component(s) failed - check -Verbose for detail" -ForegroundColor DarkYellow
    }
    if (-not $ReportPath) {
        Write-Host "    Tip:     -ReportPath sweep.html for a formatted HTML report" -ForegroundColor DarkGray
    }
    Write-Banner -Double
    Write-Host ''

    # ── HTML report ─────────────────────────────────────────────────────
    if ($ReportPath) {
        try {
            $html = New-SweepHtmlReport `
                -ComputerName      $env:COMPUTERNAME `
                -GeneratedAt       (Get-Date) `
                -StartTime         $StartTime `
                -EndTime           $EndTime `
                -OverallSeverity   $overallSeverity `
                -Findings          $findings.ToArray() `
                -HttpErrAnalysis   $httpErrAnalysis `
                -W3CAnalysis       $w3cAnalysis `
                -AppPools          $appPools `
                -SiteConfigurations $siteConfigs `
                -SiteSummary       $siteSummary `
                -EventLog          $eventLog `
                -CollectionErrors  $collectionErrors.ToArray()

            $html | Set-Content -LiteralPath $ReportPath -Encoding UTF8
            Write-Host "  HTML report written: $ReportPath" -ForegroundColor Cyan

            if ($OpenReport) { Start-Process $ReportPath }
        }
        catch {
            Write-Warning "Failed to write HTML report to '$ReportPath': $_"
        }
    }

    # ── Return object ────────────────────────────────────────────────────
    [pscustomobject]@{
        PSTypeName          = 'IISDiagnostics.SweepResult'
        GeneratedAt         = Get-Date
        ComputerName        = $env:COMPUTERNAME
        StartTime           = $StartTime
        EndTime             = $EndTime
        OverallSeverity     = $overallSeverity
        CriticalCount       = $critCount
        WarningCount        = $warnCount
        InfoCount           = $infoCount
        Findings            = @($findings | Sort-Object SeverityRank -Descending)
        HttpErrAnalysis     = $httpErrAnalysis
        W3CAnalysis         = $w3cAnalysis
        AppPools            = $appPools
        SiteConfigurations  = $siteConfigs
        SiteSummary         = $siteSummary
        EventLog            = $eventLog
        CollectionErrors    = $collectionErrors.ToArray()
        ReportPath          = $ReportPath
    }
}