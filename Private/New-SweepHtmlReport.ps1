#Requires -Version 5.1

function New-SweepHtmlReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML diagnostic report from sweep results.
        Called internally by Invoke-IISDiagnosticSweep.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [datetime]$GeneratedAt,
        [datetime]$StartTime,
        [datetime]$EndTime,
        [string]$OverallSeverity,
        [psobject[]]$Findings,
        [psobject]$HttpErrAnalysis,
        [psobject]$W3CAnalysis,
        [psobject[]]$AppPools,
        [psobject[]]$SiteConfigurations,
        [psobject[]]$SiteSummary,
        [psobject[]]$EventLog,
        [string[]]$CollectionErrors
    )

    # ── Helpers ──────────────────────────────────────────────────────────
    function e([string]$s) {
        if (-not $s) { return '' }
        $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
    }
    function badge([string]$severity) {
        $cls = $severity.ToLower()
        "<span class='badge $cls'>$(e $severity)</span>"
    }
    function row([string]$class, [string[]]$cells) {
        $tds = ($cells | ForEach-Object { "<td>$_</td>" }) -join ''
        "<tr class='$class'>$tds</tr>"
    }

    # ── Findings table rows ──────────────────────────────────────────────
    $findingRows = ($Findings | Sort-Object SeverityRank -Descending | ForEach-Object {
        $actions = if ($_.RecommendedActions) {
            '<ul class="actions">' + (($_.RecommendedActions | ForEach-Object { "<li>$(e $_)</li>" }) -join '') + '</ul>'
        } else { '' }
        "<tr class='finding-row'>
          <td>$(badge $_.Severity)</td>
          <td><span class='source'>$(e $_.Source)</span></td>
          <td><strong>$(e $_.Title)</strong><div class='detail'>$(e $_.Detail)</div>$actions</td>
        </tr>"
    }) -join "`n"

    if (-not $findingRows) {
        $findingRows = "<tr><td colspan='3' class='empty'>No findings - all checks passed</td></tr>"
    }

    # ── App pools table ──────────────────────────────────────────────────
    $poolRows = ''
    if ($AppPools) {
        $poolRows = ($AppPools | Sort-Object { if ($_.State -ne 'Started'){0}else{1} }, Name |
            ForEach-Object {
                $state    = if ($_.State -ne 'Started') { "<span class='badge critical'>$(e $_.State)</span>" } else { "<span class='badge ok'>$(e $_.State)</span>" }
                $identityRaw = if ($_.IdentityType -eq 'SpecificUser' -and $_.UserName) { $_.UserName } else { $_.IdentityType }
                $identity = e $identityRaw
                $acct     = if ($_.AccountStatus -notin 'OK','N/A','LocalAccount','NotApplicable','Skipped','CheckFailed') {
                    " <span class='badge warning'>$(e $_.AccountStatus)</span>"
                } else { '' }
                $rfp      = if ($_.RapidFailProtectionEnabled) { "<span class='badge info'>RapidFail</span>" } else { '' }
                "<tr><td><code>$(e $_.Name)</code></td><td>$state</td><td>$identity$acct</td><td>$rfp</td></tr>"
            }) -join "`n"
    }

    # ── Site configuration table ─────────────────────────────────────────
    $siteConfigRows = ''
    if ($SiteConfigurations) {
        $siteConfigRows = ($SiteConfigurations | Sort-Object SiteName | ForEach-Object {
            $pathBadge = switch ($_.PhysicalPathStatus) {
                'Exists'  { "<span class='badge ok'>Exists</span>" }
                'Missing' { "<span class='badge critical'>Missing</span>" }
                'UncPath' { "<span class='badge info'>UNC</span>" }
                default   { "<span class='badge info'>$(e $_.PhysicalPathStatus)</span>" }
            }
            $permBadge = switch ($_.PathPermissions.Status) {
                'OK'          { "<span class='badge ok'>ACE OK</span>" }
                'NotRequired' { "<span class='badge ok'>N/A</span>" }
                'NoExplicitAce' { "<span class='badge warning'>No ACE</span>" }
                'ExplicitDeny'  { "<span class='badge critical'>Denied</span>" }
                default       { "<span class='badge info'>$(e $_.PathPermissions.Status)</span>" }
            }
            $authRaw  = if ($_.Authentication.EnabledMethods) { $_.Authentication.EnabledMethods -join ', ' } else { '-' }
            $auth = e $authRaw
            $noticeCount = $_.Notices.Count
            $noticeBadge = if ($noticeCount -gt 0) { "<span class='badge warning'>$noticeCount notice(s)</span>" } else { '' }
            "<tr><td><code>$(e $_.SiteName)</code></td><td>$pathBadge</td><td>$permBadge</td><td>$auth</td><td>$noticeBadge</td></tr>"
        }) -join "`n"
    }

    # ── Certificate table ─────────────────────────────────────────────────
    $certRows = ''
    if ($SiteSummary) {
        $certRows = ($SiteSummary | Where-Object { $_.HttpsBindings -gt 0 } |
            Sort-Object {
                switch ($_.WorstCertStatus) {
                    'Expired'       { 0 }
                    'NoCertificate' { 1 }
                    'ExpiringSoon'  { 2 }
                    default         { 3 }
                }
            } |
            ForEach-Object {
                $statusBadge = switch ($_.WorstCertStatus) {
                    'Valid'         { "<span class='badge ok'>Valid</span>" }
                    'ExpiringSoon'  { "<span class='badge warning'>Expiring</span>" }
                    'Expired'       { "<span class='badge critical'>Expired</span>" }
                    'NoCertificate' { "<span class='badge critical'>Missing</span>" }
                    default         { "<span class='badge info'>$(e $_.WorstCertStatus)</span>" }
                }
                $expiry  = if ($_.NearestExpiry) { "$(e $_.NearestExpiry.ToString('dd MMM yyyy')) ($($_.NearestExpiryDays)d)" } else { '-' }
                $subjectRaw = if ($_.NearestCertSubject) { $_.NearestCertSubject -replace 'CN=','' } else { '-' }
                $subject = e $subjectRaw
                "<tr><td><code>$(e $_.SiteName)</code></td><td>$statusBadge</td><td>$expiry</td><td class='muted'>$subject</td></tr>"
            }) -join "`n"
    }
    if (-not $certRows) {
        $certRows = "<tr><td colspan='4' class='empty'>No HTTPS bindings found</td></tr>"
    }

    # ── Event log table ───────────────────────────────────────────────────
    $eventRows = ''
    if ($EventLog -and $EventLog.Count -gt 0) {
        $eventRows = ($EventLog | Sort-Object TimeCreated -Descending | Select-Object -First 20 |
            ForEach-Object {
                $sev     = if ($_.EntryType -in 'Critical','Error') { 'critical' } else { 'warning' }
                $time    = e $_.TimeCreated.ToString('dd/MM HH:mm:ss')
                $src     = e ($_.Source -replace 'Microsoft-Windows-','')
                $descRaw = if ($_.KnownDescription) { $_.KnownDescription } else { $_.ShortMessage }
                $desc = e $descRaw
                $pool    = if ($_.AppPoolName) { "<span class='source'>$(e $_.AppPoolName)</span>" } else { '' }
                "<tr><td>$(badge $sev)</td><td class='mono'>$time</td><td class='mono'>$src $($_.EventId)</td><td>$desc $pool</td></tr>"
            }) -join "`n"
    }
    else {
        $eventRows = "<tr><td colspan='4' class='empty'>No significant events in this window</td></tr>"
    }

    # ── W3C status group table ────────────────────────────────────────────
    $w3cRows = ''
    if ($W3CAnalysis -and $W3CAnalysis.Groups) {
        $w3cRows = ($W3CAnalysis.Groups | Where-Object { $_.StatusCode -ge 400 } |
            Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
                $sev  = if ($_.StatusCode -ge 500) { 'critical' } else { 'warning' }
                $titleRaw = if ($_.Title) { $_.Title } else { 'Not documented' }
                $title = e $titleRaw
                "<tr><td>$(badge $sev)</td><td class='mono'>$(e $_.StatusKey)</td><td>$($_.Count)</td><td>$title</td></tr>"
            }) -join "`n"
        if (-not $w3cRows) {
            $w3cRows = "<tr><td colspan='4' class='empty'>No error status codes recorded</td></tr>"
        }
    }
    else {
        $w3cRows = "<tr><td colspan='4' class='empty'>W3C analysis not available or skipped</td></tr>"
    }

    # ── Summary metrics ───────────────────────────────────────────────────
    $totalRequests  = if ($W3CAnalysis) { '{0:N0}' -f $W3CAnalysis.TotalRequests } else { 'N/A' }
    $httperrCount   = if ($HttpErrAnalysis) { '{0:N0}' -f $HttpErrAnalysis.TotalEntries } else { 'N/A' }
    $stoppedPools   = if ($AppPools) { ($AppPools | Where-Object { $_.State -ne 'Started' }).Count } else { 'N/A' }
    $missingPaths   = if ($SiteConfigurations) { ($SiteConfigurations | Where-Object { $_.PhysicalPathStatus -eq 'Missing' }).Count } else { 'N/A' }
    $expiringCerts  = if ($SiteSummary) { ($SiteSummary | Where-Object { $_.WorstCertStatus -in 'Expired','ExpiringSoon' }).Count } else { 'N/A' }
    $sigEvents      = if ($EventLog) { $EventLog.Count } else { 'N/A' }

    $critCount = ($Findings | Where-Object Severity -eq 'Critical').Count
    $warnCount = ($Findings | Where-Object Severity -eq 'Warning').Count

    $overallClass = $OverallSeverity.ToLower()
    $overallLabel = $OverallSeverity.ToUpper()

    $collectionErrorHtml = ''
    if ($CollectionErrors -and $CollectionErrors.Count -gt 0) {
        $items = ($CollectionErrors | ForEach-Object { "<li>$(e $_)</li>" }) -join ''
        $collectionErrorHtml = "<div class='collection-errors'><strong>Collection errors:</strong><ul>$items</ul></div>"
    }

    $windowMins = [math]::Round(($EndTime - $StartTime).TotalMinutes, 0)

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IIS Diagnostic Sweep - $(e $ComputerName) - $(e $GeneratedAt.ToString('dd MMM yyyy HH:mm'))</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e14;--surface:#0d1117;--card:#161b22;--border:#21262d;
  --text:#e6edf3;--muted:#7d8590;--mono:'Cascadia Code','Consolas','Courier New',monospace;
  --critical:#f85149;--warning:#d29922;--ok:#3fb950;--info:#58a6ff;
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6}
a{color:var(--info);text-decoration:none}
code,pre,.mono{font-family:var(--mono)}
.header{background:var(--surface);border-bottom:1px solid var(--border);padding:28px 40px;display:flex;align-items:flex-start;justify-content:space-between;gap:24px}
.header-left h1{font-family:var(--mono);font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.header-left .server{font-size:26px;font-weight:600;color:var(--text);letter-spacing:-.3px}
.header-left .meta{margin-top:6px;font-size:13px;color:var(--muted)}
.header-left .meta span{margin-right:20px}
.status-pill{font-family:var(--mono);font-size:13px;font-weight:700;letter-spacing:.08em;padding:8px 18px;border-radius:4px;white-space:nowrap;align-self:flex-start}
.status-pill.critical{background:rgba(248,81,73,.15);color:var(--critical);border:1px solid rgba(248,81,73,.35)}
.status-pill.warning{background:rgba(210,153,34,.15);color:var(--warning);border:1px solid rgba(210,153,34,.35)}
.status-pill.info{background:rgba(88,166,255,.15);color:var(--info);border:1px solid rgba(88,166,255,.35)}
.status-pill.healthy,.status-pill.ok{background:rgba(63,185,80,.15);color:var(--ok);border:1px solid rgba(63,185,80,.35)}
.metrics{display:flex;gap:1px;background:var(--border);border-bottom:1px solid var(--border)}
.metric{flex:1;background:var(--surface);padding:16px 20px;text-align:center}
.metric .val{font-family:var(--mono);font-size:22px;font-weight:700;line-height:1.2}
.metric .val.critical{color:var(--critical)}
.metric .val.warning{color:var(--warning)}
.metric .val.ok{color:var(--ok)}
.metric .lbl{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-top:2px}
.main{max-width:1200px;margin:0 auto;padding:32px 40px;display:flex;flex-direction:column;gap:24px}
.section{background:var(--card);border:1px solid var(--border);border-radius:6px;overflow:hidden}
.section summary{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;padding:14px 20px;cursor:pointer;display:flex;align-items:center;gap:8px;user-select:none;color:var(--muted)}
.section summary:hover{background:rgba(255,255,255,.03)}
.section summary::before{content:'>';font-size:10px;transition:transform .15s}
.section[open] summary::before{transform:rotate(90deg)}
.section-title{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;padding:14px 20px;color:var(--muted);border-bottom:1px solid var(--border)}
.section table{width:100%;border-collapse:collapse}
.section th{font-family:var(--mono);font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:10px 16px;border-bottom:1px solid var(--border);text-align:left;font-weight:500;background:var(--surface)}
.section td{padding:11px 16px;border-bottom:1px solid var(--border);vertical-align:top;font-size:13px}
.section tr:last-child td{border-bottom:none}
.section tr:hover td{background:rgba(255,255,255,.015)}
.badge{display:inline-flex;align-items:center;font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.08em;padding:2px 7px;border-radius:3px;white-space:nowrap;text-transform:uppercase}
.badge.critical{background:rgba(248,81,73,.12);color:var(--critical);border:1px solid rgba(248,81,73,.25)}
.badge.warning{background:rgba(210,153,34,.12);color:var(--warning);border:1px solid rgba(210,153,34,.25)}
.badge.ok,.badge.healthy{background:rgba(63,185,80,.12);color:var(--ok);border:1px solid rgba(63,185,80,.25)}
.badge.info{background:rgba(88,166,255,.12);color:var(--info);border:1px solid rgba(88,166,255,.25)}
.detail{font-size:12px;color:var(--muted);margin-top:3px}
.actions{margin:5px 0 0 0;padding:0;list-style:none}
.actions li{font-size:12px;color:var(--muted);padding:1px 0}
.actions li::before{content:'> ';color:var(--info)}
.source{font-family:var(--mono);font-size:11px;background:rgba(255,255,255,.06);padding:2px 6px;border-radius:3px;color:var(--muted)}
.finding-row td:first-child{width:88px}
.finding-row td:nth-child(2){width:100px}
.empty{text-align:center;color:var(--muted);padding:24px;font-style:italic}
.collection-errors{margin:16px 20px;padding:12px 16px;background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.2);border-radius:4px;font-size:12px;color:var(--warning)}
.collection-errors ul{margin:6px 0 0 16px}
.footer{text-align:center;padding:32px;font-size:12px;color:var(--muted);border-top:1px solid var(--border)}
.footer a{color:var(--muted)}
code{font-family:var(--mono);font-size:12px;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px}
.muted{color:var(--muted)}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <h1>IIS Diagnostic Sweep - IISDiagnostics PowerShell Module</h1>
    <div class="server">$(e $ComputerName)</div>
    <div class="meta">
      <span>$(e $GeneratedAt.ToString('dd MMM yyyy HH:mm:ss'))</span>
      <span>Window: $(e $StartTime.ToString('HH:mm')) -&gt; $(e $EndTime.ToString('HH:mm'))  ($windowMins min)</span>
    </div>
  </div>
  <div class="status-pill $overallClass">$overallLabel - $critCount critical - $warnCount warning</div>
</div>

<div class="metrics">
  <div class="metric">
    <div class="val$(if ($httperrCount -ne 'N/A' -and [int]$httperrCount.Replace(',','') -gt 0){' warning'}else{' ok'})">$httperrCount</div>
    <div class="lbl">HTTP.sys errors</div>
  </div>
  <div class="metric">
    <div class="val ok">$totalRequests</div>
    <div class="lbl">W3C requests</div>
  </div>
  <div class="metric">
    <div class="val$(if ($stoppedPools -ne 'N/A' -and $stoppedPools -gt 0){' critical'}else{' ok'})">$stoppedPools</div>
    <div class="lbl">Stopped pools</div>
  </div>
  <div class="metric">
    <div class="val$(if ($missingPaths -ne 'N/A' -and $missingPaths -gt 0){' critical'}else{' ok'})">$missingPaths</div>
    <div class="lbl">Missing paths</div>
  </div>
  <div class="metric">
    <div class="val$(if ($expiringCerts -ne 'N/A' -and $expiringCerts -gt 0){' warning'}else{' ok'})">$expiringCerts</div>
    <div class="lbl">Cert issues</div>
  </div>
  <div class="metric">
    <div class="val$(if ($sigEvents -ne 'N/A' -and $sigEvents -gt 0){' warning'}else{' ok'})">$sigEvents</div>
    <div class="lbl">Sig. events</div>
  </div>
</div>

<div class="main">
$collectionErrorHtml
  <!-- Findings -->
  <div class="section" open>
    <div class="section-title">Findings</div>
    <table>
      <thead><tr><th>Severity</th><th>Source</th><th>Detail</th></tr></thead>
      <tbody>
$findingRows
      </tbody>
    </table>
  </div>

  <!-- App Pools -->
  <details class="section" open>
    <summary>Application pools</summary>
    <table>
      <thead><tr><th>Pool name</th><th>State</th><th>Identity</th><th>Flags</th></tr></thead>
      <tbody>$(if ($poolRows) { $poolRows } else { "<tr><td colspan='4' class='empty'>No data available (WebAdministration required)</td></tr>" })</tbody>
    </table>
  </details>

  <!-- W3C Status Codes -->
  <details class="section">
    <summary>W3C error status codes</summary>
    <table>
      <thead><tr><th>Severity</th><th>Code</th><th>Count</th><th>Description</th></tr></thead>
      <tbody>$w3cRows</tbody>
    </table>
  </details>

  <!-- Site Configuration -->
  <details class="section">
    <summary>Site configuration</summary>
    <table>
      <thead><tr><th>Site</th><th>Path</th><th>Permissions</th><th>Authentication</th><th>Notices</th></tr></thead>
      <tbody>$(if ($siteConfigRows) { $siteConfigRows } else { "<tr><td colspan='5' class='empty'>No data available</td></tr>" })</tbody>
    </table>
  </details>

  <!-- Certificates -->
  <details class="section">
    <summary>SSL certificates</summary>
    <table>
      <thead><tr><th>Site</th><th>Status</th><th>Expiry</th><th>Subject</th></tr></thead>
      <tbody>$certRows</tbody>
    </table>
  </details>

  <!-- Event Log -->
  <details class="section">
    <summary>Event log (significant events)</summary>
    <table>
      <thead><tr><th>Type</th><th>Time</th><th>Source / ID</th><th>Message</th></tr></thead>
      <tbody>$eventRows</tbody>
    </table>
  </details>
</div>

<div class="footer">
  Generated by <a href="https://github.com">IISDiagnostics</a> PowerShell module
  &nbsp;|&nbsp; $(e $ComputerName) &nbsp;|&nbsp; $(e $GeneratedAt.ToString('dd MMM yyyy HH:mm:ss'))
</div>

</body>
</html>
"@
}