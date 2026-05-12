# IISDiagnostics

A PowerShell module for diagnosing IIS problems - designed for teams and individuals who 
support Windows web applications and want faster, more systematic triage than manually reading log files.

The module has a single main purpose: 

- **Operational toolkit** - the same cmdlets are useful in production incidents, particularly
  for teams who may reach for application logs before checking the IIS and HTTP.sys layers.

> **Note:** This module targets local execution on the IIS server itself. Remote execution via
> PowerShell remoting is left to the caller - invoke the cmdlets inside a PSSession rather than
> adding `-ComputerName` complexity to each one.

## Compatibility

- PowerShell 5.1 (Windows PowerShell) - primary target
- PowerShell 7+ - compatible; no PS7-specific features are used intentionally

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or later |
| OS | Windows Server (IIS installed) |
| Elevation | Administrator session required for all cmdlets except `Get-IISStatusHelp` |
| WebAdministration | Required for `Get-IISAppPool`, `Get-IISSiteBinding`, `Get-IISSiteSummary`, and `-SiteName` resolution in log cmdlets. Installed with the IIS Management tools feature. |
| ActiveDirectory module | Optional. Enhances `Get-IISAppPool` with password expiry data. Falls back to ADSI if not present. |

**Installing the WebAdministration module** (if not already present):

```powershell
# Windows Server
Install-WindowsFeature -Name Web-Scripting-Tools

# Windows 10/11
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementScriptingTools
```

---

## License

This module is licensed under the MIT License.


---

## Installation

### Import directly from repo

```powershell
Import-Module .\IISDiagnostics\IISDiagnostics.psd1 -Force
```

### Install for current user

Copy the `IISDiagnostics` folder to one of these module locations:

- PowerShell (pwsh): `$HOME\Documents\PowerShell\Modules`
- Windows PowerShell: `$HOME\Documents\WindowsPowerShell\Modules`

Then import:

```powershell
Import-Module IISDiagnostics
```

During development, import directly from the repo:

```powershell
Import-Module .\IISDiagnostics\IISDiagnostics.psd1 -Force
```
---

## Quick Start

```powershell
# What went wrong in the last hour at the HTTP.sys layer?
Invoke-IISHttpErrAnalysis

# What status codes is the application returning, and what do they mean?
Invoke-IISW3CLogAnalysis -ErrorsOnly | Format-Table StatusKey, Count, Title

# Are all app pools running? Are any service accounts locked out?
Get-IISAppPool

# Certificate health across all sites
Get-IISSiteSummary | Sort-Object NearestExpiryDays | Format-Table
```

---


## Cmdlets

### `Get-IISStatusHelp`

Looks up curated descriptions and remediation guidance for an HTTP status code or IIS
substatus combination, using the module's built-in `StatusCodes.json` data.

**Does not require elevation.** Works in any PowerShell session, including non-admin.

```powershell
# Plain status code
Get-IISStatusHelp 503

# IIS substatus - must be quoted (unquoted 500.30 becomes the float 500.3)
Get-IISStatusHelp '403.16'

# Alternative syntax
Get-IISStatusHelp 403 -Substatus 16

# Pipe from a W3C analysis
(Invoke-IISW3CLogAnalysis).ErrorGroups | ForEach-Object {
    Get-IISStatusHelp $_.StatusKey
}
```

**Output:** `IISDiagnostics.StatusHelp` - title, description, likely causes (numbered list),
things to check, see-also links, and separate concern levels for server admins vs application
support teams.

---

### `Get-IISHttpErrLog`

Parses HTTP.sys error logs from `%SystemRoot%\System32\LogFiles\HTTPERR`.

**Why this matters:** HTTPERR logs capture requests that HTTP.sys rejected *before* they
reached IIS. These errors are completely invisible in W3C access logs. If clients are
reporting errors but the W3C log shows nothing, start here.

```powershell
# Last hour (default)
Get-IISHttpErrLog

# Extended window
Get-IISHttpErrLog -StartTime (Get-Date).AddHours(-4)

# Filter to a specific reason
Get-IISHttpErrLog -Reason Timer_AppPool

# Filter to a specific client IP
Get-IISHttpErrLog -ClientIp 10.0.0.45

# Summary report instead of individual entries
Get-IISHttpErrLog -StartTime (Get-Date).AddDays(-1) -Summarise

# Export for analysis
Get-IISHttpErrLog | Where-Object StatusCode -eq 400 | Export-Csv .\bad-requests.csv -NoTypeInformation

# Group by reason to see the shape of errors
Get-IISHttpErrLog | Group-Object Reason | Sort-Object Count -Descending
```

**Output:** `IISDiagnostics.W3CEntry` (stream) or `IISDiagnostics.HttpErrSummary` (`-Summarise`).

**Things worth knowing:**

- Timestamps in the log are UTC. `Timestamp` on the output object is local time.
- The `#Fields:` header is parsed dynamically - the column order is not assumed. This matters
  because IIS allows administrators to customise which fields are logged.
- The active log file is opened with `FileShare.ReadWrite`, so it can be read while HTTP.sys
  continues writing to it.
- Log files are pre-filtered by `LastWriteTime` before opening, but the timestamp check is
  authoritative - pre-filtering is an optimisation, not the gate.
- `ReasonDescription` on each entry provides a human-readable explanation of the `s-reason`
  field value, useful during training sessions.

**Common `s-reason` values:**

| Reason | Meaning |
|---|---|
| `Timer_AppPool` | Request queued but no thread available - pool may be under load or stopped |
| `Timer_ConnectionIdle` | Keep-alive connection timed out - usually normal background noise |
| `Timer_HeaderWait` | Client connected but never sent request headers |
| `Rejected` | Pool unavailable - crashed, stopped, or rapid-fail protection triggered |
| `QueueFull` | Request queue at capacity - refused before entering the queue |
| `App_InitFailed` | Worker process started but application failed to initialise |
| `AppOffline` | `app_offline.htm` present |
| `SslError` | TLS handshake failed at HTTP.sys before reaching IIS |

---

### `Invoke-IISHttpErrAnalysis`

Calls `Get-IISHttpErrLog` internally and applies diagnostic rules to produce severity-graded
findings. Designed for fast triage - run this first when something is wrong.

```powershell
# Default - last hour
Invoke-IISHttpErrAnalysis

# Extended window
Invoke-IISHttpErrAnalysis -StartTime (Get-Date).AddHours(-4)

# Get Critical findings as objects
$result = Invoke-IISHttpErrAnalysis
$result.Findings | Where-Object Severity -eq 'Critical'

# Adjust burst detection for a low-traffic site
Invoke-IISHttpErrAnalysis -BurstWindowMinutes 10 -BurstThreshold 3
```

**Output:** `IISDiagnostics.HttpErrAnalysis` - overall severity, list of
`IISDiagnostics.HttpErrFinding` objects, and `FindingsDisplay` (pre-rendered console text).

**Severity levels:** `Critical` / `Warning` / `Info` / `Healthy`

**Patterns detected:**

| Category | What it means |
|---|---|
| `QueueDrainStopped` | `Timer_AppPool` entries clustered into a burst - pool stopped draining abruptly |
| `QueueBackpressure` | `Timer_AppPool` spread across the window - sustained load, not a sudden stop |
| `PoolNotAccepting` | `Rejected` entries - pool became unavailable (burst or sustained) |
| `CombinedPoolFailure` | Both patterns close together - queue stopped draining then connections refused |
| `AppInitFailed` | Application failed to initialise after worker process started |
| `AppOffline` | `app_offline.htm` detected |
| `QueueFull` | Queue at capacity - requests refused before queuing |
| `SslFailure` | TLS handshake failures at HTTP.sys |
| `ClientTimeouts` | Timer_* entries - classified as normal, elevated, or concentrated |
| `MalformedRequests` | BadRequest, RequestLength etc - checks for concentrated source (scanning) |

**Things worth knowing:**

- The `QueueDrainStopped` / `PoolNotAccepting` distinction is important. A pool crash
  produces *both*: first `Timer_AppPool` (requests already queued are abandoned), then
  `Rejected` (new connections refused). The `CombinedPoolFailure` finding surfaces when both
  appear close together and reports the sequence as an observation.
- The cmdlet **does not assert root causes**. Every finding says what the log recorded and
  directs you to the Windows Event Log (WAS source) for confirmation. Determining whether
  `Rejected` entries were caused by a crash, rapid-fail protection, or a manual stop requires
  the Event Log.
- `-BurstWindowMinutes` and `-BurstThreshold` tune the burst detection. On a low-traffic site,
  five events in five minutes may represent the entire load - increase these parameters to avoid
  false-positive burst detection.
- `$result.Findings` is a structured array - suitable for feeding into scripts or the upcoming
  `Invoke-IISDiagnosticSweep`.

---

### `Get-IISW3CLog`

Parses IIS W3C access logs from `%SystemDrive%\inetpub\logs\LogFiles` (or a configured
alternative). Records requests that reached IIS and were processed by an application pool.

```powershell
# Last hour, all sites
Get-IISW3CLog

# Specific site by name (requires WebAdministration)
Get-IISW3CLog -SiteName 'MyImportantSite'

# Specific site by ID
Get-IISW3CLog -SiteId 1

# Summary report
Get-IISW3CLog -StartTime (Get-Date).AddHours(-4) -Summarise

# Connection resets - requests mid-flight when a pool crash occurred
Get-IISW3CLog | Where-Object IsConnectionReset

# Server errors grouped by URI
Get-IISW3CLog | Where-Object { $_.StatusCode -ge 500 } |
    Group-Object UriStem | Sort-Object Count -Descending

# Slowest requests
Get-IISW3CLog | Sort-Object TimeTakenMs -Descending | Select-Object -First 20

# Non-default slow threshold in summary
Get-IISW3CLog -Summarise -SlowThresholdMs 2000
```

**Output:** `IISDiagnostics.W3CEntry` (stream) or `IISDiagnostics.W3CSummary` (`-Summarise`).

**Key properties on `W3CEntry`:**

| Property | Source field | Notes |
|---|---|---|
| `Timestamp` | `date` + `time` | UTC in the log, converted to local time |
| `StatusCode` | `sc-status` | HTTP status |
| `SubStatus` | `sc-substatus` | IIS substatus |
| `Win32Status` | `sc-win32-status` | 0 = success, 64 = connection reset |
| `IsConnectionReset` | Derived | `true` when `Win32Status` is 64 |
| `TimeTakenMs` | `time-taken` | Milliseconds |
| `SiteLogFolder` | Filesystem | `W3SVC1`, `W3SVC3` etc - reliable even when `s-sitename` is not logged |
| `SiteName` | `s-sitename` | Only present if the administrator enabled this field |
| `AdditionalFields` | Any custom fields | Hashtable of fields not in the standard set |

**Things worth knowing:**

- The `#Fields:` header is parsed dynamically. IIS lets administrators choose which fields to
  log and in what order. The parser never assumes column positions.
- When called without `-SiteId` or `-SiteName`, **all** `W3SVC*` subdirectories under the log
  root are scanned. Each entry carries `SiteLogFolder` (e.g. `W3SVC1`) to identify its source.
  Use `Group-Object SiteLogFolder` to separate sites in the output.
- `SiteLogFolder` is more reliable than `SiteName` because `s-sitename` is not in IIS's default
  logging field set and must be explicitly enabled by an administrator.
- The W3SVC number in the folder name corresponds directly to the IIS site ID. `W3SVC3` = site
  ID 3. This lets you cross-reference with `Get-IISSiteBinding -SiteId 3` or
  `Get-IISAppPool`.
- Log files are pre-filtered by date extracted from the filename (`u_ex260510.log` → 10 May 2026)
  before being opened, avoiding parsing of files outside the window. Non-standard filenames
  fall back to `LastWriteTime` pre-filtering.
- The active log file is read with `FileShare.ReadWrite`.
- **`sc-win32-status = 64`** (`IsConnectionReset`) is significant for post-incident analysis:
  these are requests the server was actively processing when the client connection dropped.
  During a pool crash, in-flight requests appear in the W3C log with this status. Correlate
  the timestamps with `Invoke-IISHttpErrAnalysis` - a `QueueDrainStopped` finding and a cluster
  of `IsConnectionReset` entries at the same time is strong evidence of a mid-request crash.
- `-Summarise` produces two URI lists: `TopUrisByCount` (most frequently requested) and
  `TopUrisByTime` (highest aggregate time consumed). A URI called 5,000 times at 50ms
  contributes less server load than one called 20 times at 30,000ms - `TopUrisByTime` finds
  the second kind.

---

### `Invoke-IISW3CLogAnalysis`

Groups W3C log entries by `sc-status` + `sc-substatus` and enriches each group with curated
descriptions from the module's `StatusCodes.json` data (the same data used by
`Get-IISStatusHelp`).

```powershell
# Default - last hour, all status codes
Invoke-IISW3CLogAnalysis

# Errors only
Invoke-IISW3CLogAnalysis -ErrorsOnly

# Specific site, extended window
Invoke-IISW3CLogAnalysis -SiteName 'MyImportantSite' -StartTime (Get-Date).AddHours(-4) -ErrorsOnly

# Suppress low-volume noise (only show codes seen 5+ times)
Invoke-IISW3CLogAnalysis -ErrorsOnly -MinCount 5

# Quick error table
Invoke-IISW3CLogAnalysis -ErrorsOnly | Format-Table StatusKey, Count, Title

# Drill into a specific group
$analysis = Invoke-IISW3CLogAnalysis
$analysis.Groups | Where-Object StatusKey -eq '403.16' | Format-List

# 5xx groups only
$analysis.ServerErrors

# Status codes not yet in the data file
$analysis.UnknownGroups

# One-liner summary of all 5xx groups
$analysis.ServerErrors | ForEach-Object { "$($_.StatusKey) ($($_.Count)x): $($_.Title)" }
```

**Output:** `IISDiagnostics.W3CLogAnalysis` - a wrapper object containing:

| Property | Contents |
|---|---|
| `Groups` | All status groups, sorted by count descending |
| `ErrorGroups` | 4xx and 5xx groups only |
| `ServerErrors` | 5xx groups only |
| `UnknownGroups` | Groups with no curated description in the data file |

Each group is an `IISDiagnostics.W3CStatusGroup` with count, percent, first/last seen,
title, description, likely causes, things to check, top URIs, and top client IPs.

**Things worth knowing:**

- The lookup tries the exact `status.substatus` key first (e.g. `403.16`), then falls back to
  the parent status code (`403`). `LookupSource` on each group tells you which was used:
  `Substatus` or `HttpCode`. When the fallback is used, a note is appended to the description
  so you know the text is for the parent code, not the specific substatus.
- `IsKnown = $false` means neither lookup found data. The group is still returned - see
  `UnknownGroups` on the analysis object to collect them. Run `Get-IISStatusHelp` on
  unknown codes and consider adding them to `StatusCodes.json`.
- Each group's `TopUris` and `TopClients` show the five most frequent URI stems and client IPs
  for *that specific status code*, not the overall top. A 403.16 from one URI and one client IP
  is a very different problem from a 403.16 spread across all URIs and all clients.
- `-MinCount` is useful on high-traffic servers where dozens of one-off status codes would
  obscure the patterns worth investigating.
- `SubStatus` is stored as 0 when `sc-substatus` is absent from the log or logged as 0.
  The `StatusKey` will be `200.0`, `404.0` etc.

---

### `Get-IISAppPoolStatus`

Returns the state, identity, and configuration of IIS application pools, enriched with Active
Directory account status checks for domain service accounts.

```powershell
# All pools
Get-IISAppPoolStatus

# Single pool
Get-IISAppPoolStatus -Name 'MyAppPool'

# Wildcard
Get-IISAppPoolStatus -Name '*MyApp*'

# Pools that are not running
Get-IISAppPoolStatus | Where-Object State -ne 'Started'

# Pools with locked-out service accounts
Get-IISAppPoolStatus | Where-Object AccountStatus -eq 'LockedOut'

# Skip AD check (useful if DC is unreachable)
Get-IISAppPoolStatus -SkipAccountCheck

# All pools with any notices
Get-IISAppPoolStatus | Where-Object { $_.Notices.Count -gt 0 } | Format-List Name, State, Notices

# Pipeline - names from another source
'Pool1', 'Pool2' | Get-IISAppPoolStatus
```

**Output:** `IISDiagnostics.AppPoolStatus` per pool.

**`AccountStatus` values:**

| Value | Meaning |
|---|---|
| `OK` | Account is enabled, unlocked, and password is current |
| `LockedOut` | Account locked in AD - pool will fail to authenticate |
| `Disabled` | Account disabled in AD - pool cannot start |
| `PasswordExpired` | Password has expired - reset required |
| `LocalAccount` | Local machine account - no AD check applicable |
| `CheckFailed` | AD query failed - network, permissions, or account not found |
| `Skipped` | `-SkipAccountCheck` was specified |
| `N/A` | Built-in identity (ApplicationPoolIdentity, NetworkService etc) |

**Things worth knowing:**

- The AD check tries the **ActiveDirectory module** (`Get-ADUser`) first. If unavailable, it
  falls back to an **ADSI directory searcher**. The ADSI path can determine locked-out and
  disabled states but cannot reliably determine password expiry (that requires domain policy
  knowledge). `LookupSource` on the result indicates which path was used.
- `PasswordExpired` is only populated via the AD module path. Via ADSI it will not be detected
  even if expired - the status will show `OK` for unlocked/enabled accounts regardless of
  password state.
- Worker processes are enumerated from `IIS:\AppPools\{name}\WorkerProcesses`. A pool in
  `Started` state with zero worker processes can occur immediately after a recycle before the
  new process has spawned - this is noted in `Notices`.
- The `Notices` array carries pre-computed observations (stopped pool with rapid-fail enabled,
  locked account, `LocalSystem` identity in use) in a format suitable for consumption by
  `Invoke-IISDiagnosticSweep` without re-implementing analysis logic.
- All pools are loaded once at the start of the pipeline (`begin` block) so that piping
  multiple names does not enumerate the IIS drive once per object.

---

### `Get-IISSiteBindingReport`

Returns IIS site bindings enriched with SSL certificate details, expiry status, and SNI
configuration.

```powershell
# All bindings across all sites
Get-IISSiteBindingReport

# Specific site
Get-IISSiteBindingReport -SiteName 'MySite'

# Bindings with certificate problems
Get-IISSiteBindingReport | Where-Object ExpiryStatus -ne 'Valid'

# Expiring soon
Get-IISSiteBindingReport | Where-Object ExpiryStatus -eq 'ExpiringSoon'

# Custom warning horizon
Get-IISSiteBindingReport -WarnDaysRemaining 60 |
    Where-Object ExpiryStatus -in 'ExpiringSoon','Expired' |
    Select-Object SiteName, HostName, CertExpiry, DaysUntilExpiry

# Wildcard certificates in use
Get-IISSiteBindingReport | Where-Object IsWildcard | Select-Object SiteName, CertSubject

# Include HTTP bindings (filtered out by default)
Get-IISSiteBindingReport -IncludeNonHttps

# Detail view for a single binding
Get-IISSiteBindingReport -SiteName 'MyImportantSite' | Format-List
```

**Output:** `IISDiagnostics.SiteBinding` per binding.

**`ExpiryStatus` values:**

| Value | Meaning |
|---|---|
| `Valid` | Certificate present and not near expiry |
| `ExpiringSoon` | Within `-WarnDaysRemaining` days of expiry (default 30) |
| `Expired` | Certificate has already expired |
| `NoCertificate` | HTTPS binding exists but no certificate could be resolved |
| `NotHttps` | Non-HTTPS binding, no certificate applicable |

**Things worth knowing:**

- Certificate resolution follows a **three-hop chain**: site binding → `IIS:\SslBindings`
  (HTTP.sys binding table, keyed by `ip!port` or `ip!port!hostname` for SNI) → certificate
  store (`Cert:\LocalMachine\My`, then `Cert:\LocalMachine\WebHosting`).
- The SSL binding table is loaded once upfront into a dictionary for O(1) per-binding lookups.
  Certificate objects are cached by thumbprint - if multiple sites share a wildcard certificate,
  it is only read from the store once.
- **`NoCertificate` with a thumbprint** means the binding references a certificate that no
  longer exists in the store. This is the "cert was deleted but the binding wasn't cleaned up"
  scenario that produces cryptic TLS errors.
- **SNI misconfiguration** is detected and noted:
  - SNI flag set (`sslFlags` bit 1) but no hostname configured - HTTP.sys cannot match SNI
    `ClientHello` messages.
  - Hostname configured without SNI on a port shared by multiple HTTPS sites - the wrong
    certificate may be served.
- `-WarnDaysRemaining 0` suppresses expiry warnings entirely, showing only `Expired` and
  `NoCertificate` findings.
- Non-HTTPS bindings are excluded by default. Use `-IncludeNonHttps` to include them with
  `ExpiryStatus = 'NotHttps'`.

---


### `Get-IISSiteConfiguration`

Returns site configuration that cannot be read from logs — physical path, app pool identity
permissions, authentication methods, and request filtering limits.

This cmdlet answers the class of problems where logs show an error but the cause is
configuration: a missing physical path producing 404s, an identity with no access to its
own files producing 500s with Win32 status 5, or request filtering silently rejecting
requests before they reach the application.

```powershell
# All sites
Get-IISSiteConfiguration

# Specific site
Get-IISSiteConfiguration -SiteName 'My Web Site'

# Sites with a missing or unconfigured physical path
Get-IISSiteConfiguration | Where-Object PhysicalPathStatus -ne 'Exists'

# Sites where the identity has no confirmed ACE on its physical path
Get-IISSiteConfiguration |
    Where-Object { $_.PathPermissions.Status -notin 'OK', 'NotRequired' }

# Sites with any notices
Get-IISSiteConfiguration | Where-Object { $_.Notices.Count -gt 0 } | Format-List

# Quick summary table
Get-IISSiteConfiguration |
    Select-Object SiteName, PhysicalPathStatus,
        @{ n='Auth';    e={ $_.Authentication.EnabledMethods -join ', ' } },
        @{ n='Notices'; e={ $_.Notices.Count } }

# Skip the ACL check (useful when the identity or DC is unreachable)
Get-IISSiteConfiguration -SkipPermissionCheck
```

**Output:** `IISDiagnostics.SiteConfiguration` per site.

**`PhysicalPathStatus` values:**

| Value | Meaning |
|---|---|
| `Exists` | Path is present on disk |
| `Missing` | Configured path does not exist — requests will fail |
| `UncPath` | Network path — existence checked but share permissions are not |
| `NotConfigured` | No physical path set on the site |
| `AccessDenied` | `Test-Path` was denied — running as non-admin or ACL blocks even reading |
| `Unknown` | Path could not be determined |

**`PathPermissions.Status` values:**

| Value | Meaning |
|---|---|
| `OK` | Explicit Allow ACE found for the identity or `IIS_IUSRS` group |
| `NoExplicitAce` | No direct ACE found — access may still exist via inheritance or group membership |
| `ExplicitDeny` | A Deny ACE was found — access blocked regardless of Allow entries |
| `NotRequired` | `LocalSystem` identity — has unrestricted local access, no check needed |
| `PathMissing` | Physical path does not exist — check not applicable |
| `CheckFailed` | ACL could not be read |
| `Skipped` | `-SkipPermissionCheck` was used, or path is UNC |

**Things worth knowing:**

- The permission check reads **explicit ACEs** from the path ACL only. Access granted via
  NTFS inheritance or Windows group membership is not resolved. `NoExplicitAce` does not mean
  the identity has no access — use `icacls` for effective permissions. The notice generated
  when `NoExplicitAce` is returned includes the exact `icacls` command to run.
- For `ApplicationPoolIdentity`, two accounts are checked: the virtual account
  `IIS AppPool\{PoolName}` and the `IIS_IUSRS` local group (which all IIS worker process
  accounts belong to). An `IIS_IUSRS` ACE is sufficient — IIS grants access this way by
  default when you use the IIS Manager to set a physical path.
- `LocalSystem` identity skips the check entirely with `Status = NotRequired` — it has
  unrestricted local access by definition.
- Authentication data comes from two separate configuration sections. The IIS auth modules
  (`Anonymous`, `Windows`, `Basic`, `Digest`) are in `system.webServer/security/authentication`.
  ASP.NET Forms Authentication is in `system.web/authentication` — a different section that is
  often overlooked. Both are surfaced on the `Authentication` sub-object.
- **Windows Authentication provider order matters.** `Negotiate` must be first in the
  providers list for Kerberos to be attempted. If `NTLM` is listed first, clients fall back
  to NTLM silently — everything works but Kerberos delegation is unavailable and you won't
  know why. A notice is raised when the order is wrong.
- `MaxAllowedContentLength` defaults to 30 MB (31,457,280 bytes). A common misconfiguration
  is setting this very low during hardening and forgetting it. The cmdlet flags values below
  1 MB with a notice explaining what status code will be returned and the default value.
- Scope is the **root application of each site**. Sub-applications within a site (e.g.
  `/api` running under a different app pool) are not included in this release.

---


### `Get-IISEventLog`

Returns IIS-relevant Windows Event Log entries from the System and Application logs,
covering application pool lifecycle, HTTP.sys, ASP.NET, and application crash sources.

This is the cmdlet that answers *why* — where `Invoke-IISHttpErrAnalysis` tells you a crash
pattern was detected at 14:22, `Get-IISEventLog` finds the WAS event at 14:22:58 that says
rapid-fail protection fired.

**Does not require WebAdministration.** Event log access needs elevation only.

```powershell
# Last hour, all sources
Get-IISEventLog

# Extended window, errors and warnings only
Get-IISEventLog -StartTime (Get-Date).AddHours(-4) -EntryType Error, Warning

# Only the events that matter — crash and disable events, application errors
Get-IISEventLog -Significant

# Pool-specific WAS events
Get-IISEventLog -AppPoolName 'MyAppPool'

# Timeline for a specific window — good for correlating with HTTPERR findings
Get-IISEventLog -Significant -StartTime (Get-Date).AddHours(-4) |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Source, EventId, AppPoolName, ShortMessage

# All rapid-fail protection triggers in the past hour
Get-IISEventLog | Where-Object EventId -eq 5012

# Frequency of WAS event IDs — shows the shape of pool activity
Get-IISEventLog | Where-Object Source -like '*WAS*' |
    Group-Object EventId | Sort-Object Count -Descending

# Full message for a specific event
Get-IISEventLog -Significant | Where-Object EventId -eq 5009 | Format-List
```

**Output:** `IISDiagnostics.EventLogEntry` — one object per event, sorted by `TimeCreated`.

**Sources queried:**

| Log | Provider | What it records |
|---|---|---|
| System | `Microsoft-Windows-WAS` | Pool lifecycle — starts, stops, crashes, rapid-fail. **Most important.** |
| System | `Microsoft-Windows-HttpService` | HTTP.sys driver events — binding and SSL failures at kernel level |
| System | `Microsoft-Windows-IIS-W3SVC` | IIS web service events — site start/stop |
| System | `Microsoft-Windows-IIS-Configuration` | IIS configuration changes |
| Application | `ASP.NET 4.0.30319.0` | ASP.NET runtime errors and unhandled exceptions |
| Application | `.NET Runtime` | CLR crashes, OOM, unhandled exceptions |
| Application | `Application Error` | Windows crash records for `w3wp.exe` — faulting module and exception code |
| Application | `IIS AspNetCore Module V2` | ANCM startup failures, port conflicts, stdout log errors |

Legacy provider names (`WAS`, `W3SVC`, `ASP.NET 2.0.50727.0`) are also included for
compatibility with older Server versions.

**Key WAS event IDs:**

| Event ID | Meaning | `IsSignificant` |
|---|---|---|
| 5009 | Worker process failed to respond to ping — terminated | ✓ |
| 5010 | Worker process requested recycle — private bytes limit | ✓ |
| 5011 | Worker process shutdown callback failed | ✓ |
| 5012 | Rapid-fail protection triggered — pool disabled | ✓ |
| 5074 | Pool started successfully | — |
| 5075 | Pool stopped | — |
| 5076 | Pool recycled | — |
| 5077 | Worker process did not shut down in a timely fashion | ✓ |
| 5080 | Worker process started | — |
| 5117 | Worker process exited with non-zero exit code | ✓ |
| 5189 | Pool automatically re-enabled after rapid-fail wait period | ✓ |

**Things worth knowing:**

- `-Significant` returns only WAS crash/disable events (5009, 5011, 5012, 5077, 5117, 5189)
  and any Error or Critical from the Application log. This is the fast path during an incident
  — it cuts through recycling noise and Information-level lifecycle events.
- `KnownDescription` on each entry gives a plain-English summary of well-known WAS event IDs.
  The table view shows this in preference to the raw (often verbose) event message.
- `AppPoolName` is extracted from the event message text using a regex pattern. It is
  populated on most WAS events but not on Application log entries where the pool name isn't
  mentioned. The full `Message` property is always available via `Format-List`.
- `-AppPoolName` filtering only excludes entries that *have* an extractable pool name but it
  doesn't match — Application log entries without a pool name in the message are always
  included. This means a `.NET Runtime` crash record for `w3wp.exe` is returned even though
  it doesn't mention the pool by name.
- Providers that are not installed on the server (e.g. `IIS AspNetCore Module V2` on a
  server with no ASP.NET Core applications) are silently skipped rather than causing errors.
- The Security event log is not queried — authentication failure events require separate
  audit policy configuration and differ from standard administrator access.

---


### `Get-IISSiteSummary`

Wraps `Get-IISSiteBindingReport` and collapses per-binding results into one row per site, making
it practical to assess certificate health across many sites at a glance.

```powershell
# All sites - one row each
Get-IISSiteSummary

# Sites with any problem or notice
Get-IISSiteSummary | Where-Object { $_.WorstCertStatus -ne 'Valid' -or $_.NoticeCount -gt 0 }

# Sorted by certificate expiry - soonest first
Get-IISSiteSummary | Sort-Object NearestExpiryDays | Format-Table

# Custom warning horizon
Get-IISSiteSummary -WarnDaysRemaining 60

# Full detail for a flagged site
Get-IISSiteSummary -SiteName 'MySite' | Format-List

# All notices across all sites
Get-IISSiteSummary | Where-Object NoticeCount -gt 0 |
    ForEach-Object { $_.Notices | ForEach-Object { "[$($_.Binding)] $($_.Notice)" } }

# Feed into Get-IISSiteBindingReport for full detail on problem sites
Get-IISSiteSummary |
    Where-Object WorstCertStatus -ne 'Valid' |
    ForEach-Object { Get-IISSiteBindingReport -SiteName $_.SiteName }
```

**Output:** `IISDiagnostics.SiteSummary` per site, sorted alphabetically.

**Things worth knowing:**

- `WorstCertStatus` reflects the highest-severity status across all HTTPS bindings for the
  site. Severity order: `Expired` > `NoCertificate` > `ExpiringSoon` > `Valid` > `NoHttps`.
- `NearestExpiry` and `NearestExpiryDays` show the soonest-expiring certificate across all
  HTTPS bindings - the one requiring action first.
- `Notices` on the summary object is a structured array: each notice has `SiteName`,
  `Binding` (e.g. `https://0.0.0.0:443/pvwa.example.com`), and `Notice` (the text). This is
  more useful than a flat text list when a site has multiple HTTPS bindings.
- The application pool name is fetched from `IIS:\Sites` in a separate pass rather than from
  the binding objects, because IIS stores the pool name on the site, not the binding.

---

### `Get-IISConfigSummary`

Returns a quick snapshot of the IIS configuration on this server: application pools, sites,
bindings, and key log file locations. Designed to answer "what am I dealing with?" before
starting any investigation.

```powershell
# Console overview of everything on this server
Get-IISConfigSummary

# Capture the result for scripting
$summary = Get-IISConfigSummary

# App pools as a table
$summary.AppPools | Format-Table

# Sites with their W3C log path
$summary.Sites | Format-Table SiteId, SiteName, State, ApplicationPool, W3CLogPath

# W3C log path detail (includes Exists flag)
$summary.W3CLogPaths | Format-Table

# Stopped app pools
$summary.AppPools | Where-Object State -ne 'Started'

# Stopped sites
$summary.Sites | Where-Object State -ne 'Started'
```

**Output:** `IISDiagnostics.ConfigSummary` with the following properties:

| Property | Type | Description |
|---|---|---|
| `ComputerName` | string | Server name |
| `GeneratedAt` | datetime | When the summary was collected |
| `AppPools` | `IISDiagnostics.ConfigSummary.AppPool[]` | One row per application pool |
| `Sites` | `IISDiagnostics.ConfigSummary.Site[]` | One row per site |
| `W3CLogPaths` | `IISDiagnostics.ConfigSummary.W3CLogPath[]` | Resolved W3C log directory per site |
| `HttpErrLogPath` | string | First HTTPERR candidate path checked (may not exist on disk if HTTP.sys has not yet written errors; `$null` if no candidate could be determined) |

**Things worth knowing:**

- W3C log paths are resolved using the same multi-source logic as `Get-IISW3CLog`: IIS
  drive properties, `Get-WebConfigurationProperty`, `applicationHost.config` fallback, and
  environment variable expansion (`%SystemDrive%`, `%SystemRoot%`). The `Exists` flag on
  each `W3CLogPaths` entry indicates whether the directory is present on disk right now.
- The HTTPERR path is checked against the standard location
  (`%SystemRoot%\System32\LogFiles\HTTPERR`) and any registry override under
  `HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\ErrorLoggingDir`.
- Unlike `Invoke-IISDiagnosticSweep`, this cmdlet does not parse or analyse log content.
  It is fast and safe to run at any time for inventory or orientation.

---

## Investigation Recipes

### What am I dealing with? (start here)

Before diagnosing a problem, get the lay of the land:

```powershell
Get-IISConfigSummary
```

This prints a colour-coded overview showing app pools, sites, bindings, W3C and HTTPERR log
locations, and a reminder about the Windows Event Log. Use it to orient yourself on any server
before running deeper diagnostics.

```powershell
# Capture the result object for scripting
$summary = Get-IISConfigSummary

# List app pools as a table
$summary.AppPools | Format-Table

# Find stopped sites
$summary.Sites | Where-Object State -ne 'Started'

# Show all W3C log paths (useful before running Get-IISW3CLog)
$summary.W3CLogPaths | Format-Table
```

---

### Something is wrong right now - where do I start?

```powershell
# 1. HTTP.sys layer - did requests reach IIS at all?
Invoke-IISHttpErrAnalysis

# 2. If pools are involved - are they running?
Get-IISAppPoolStatus | Where-Object { $_.State -ne 'Started' -or $_.Notices.Count -gt 0 }

# 3. What is IIS returning?
Invoke-IISW3CLogAnalysis -ErrorsOnly

# 4. Are there connection resets suggesting a mid-request crash?
Get-IISW3CLog | Where-Object IsConnectionReset | Select-Object Timestamp, UriStem, TimeTakenMs
```

### App pool crash investigation

The signature of a pool crash in IIS logs:

1. **HTTPERR** - `Timer_AppPool` burst (queue stopped draining) followed by `Rejected` burst
   (new connections refused)
2. **W3C** - `IsConnectionReset` entries clustered at the same time (in-flight requests aborted)

```powershell
# Find the crash window
$httperr = Invoke-IISHttpErrAnalysis -StartTime (Get-Date).AddHours(-4)
$httperr.Findings | Where-Object Category -in 'QueueDrainStopped','CombinedPoolFailure'

# Correlate with W3C connection resets
Get-IISW3CLog -StartTime (Get-Date).AddHours(-4) |
    Where-Object IsConnectionReset |
    Select-Object Timestamp, UriStem, StatusCode |
    Sort-Object Timestamp

# Check current pool state and rapid-fail protection
Get-IISAppPoolStatus -Name 'MyAppPool' | Format-List
```

The Windows Event Log (WAS source) is the definitive record of why the pool stopped - the
HTTPERR and W3C logs tell you *when* and *what was affected*, not *why*.

### Certificate expiry audit

```powershell
# Quick view - all sites sorted by expiry
Get-IISSiteSummary | Sort-Object NearestExpiryDays |
    Format-Table SiteName, WorstCertStatus, NearestExpiryDays, NearestExpiry

# 60-day lookahead for planning
Get-IISSiteBindingReport -WarnDaysRemaining 60 |
    Where-Object ExpiryStatus -in 'ExpiringSoon','Expired' |
    Select-Object SiteName, HostName, IsWildcard, CertExpiry, DaysUntilExpiry, CertSubject |
    Sort-Object DaysUntilExpiry

# Full cert detail for a specific site
Get-IISSiteBindingReport -SiteName 'My Site' | Format-List
```

### Diagnosing 403 errors

```powershell
# What 403 substatuses are occurring and how often?
Invoke-IISW3CLogAnalysis |
    Where-Object { $_.Groups | Where-Object { $_.StatusCode -eq 403 } }  # outer object
# Better:
(Invoke-IISW3CLogAnalysis).Groups | Where-Object StatusCode -eq 403 |
    Format-Table StatusKey, Count, Title

# Drill into a specific substatus
(Invoke-IISW3CLogAnalysis).Groups |
    Where-Object StatusKey -eq '403.16' |
    Format-List   # shows description, top URIs, top clients, likely causes
```

Common IIS 403 substatuses:

| Code | Meaning |
|---|---|
| `403.4` | SSL required |
| `403.7` | Client certificate required |
| `403.16` | Client certificate untrusted or invalid |
| `403.17` | Client certificate has expired |

### Slow request investigation

```powershell
# Summary with 2-second threshold
Get-IISW3CLog -Summarise -SlowThresholdMs 2000

# Raw slow requests sorted by time taken
Get-IISW3CLog | Where-Object { $_.TimeTakenMs -gt 5000 } |
    Sort-Object TimeTakenMs -Descending |
    Select-Object Timestamp, UriStem, StatusCode, TimeTakenMs, ClientIp

# Which URIs consume the most total server time?
(Get-IISW3CLog -Summarise).TopUrisByTime |
    Select-Object UriStem, Count, TotalMs |
    Sort-Object TotalMs -Descending
```

### Scanning / attack traffic

```powershell
# BadRequest entries from a single source
Get-IISHttpErrLog -Reason BadRequest |
    Group-Object ClientIp | Sort-Object Count -Descending

# All malformed request types with client breakdown
Invoke-IISHttpErrAnalysis |
    ForEach-Object { $_.Findings | Where-Object Category -eq 'MalformedRequests' }
```

---

## Architecture

```
IISDiagnostics/
├── IISDiagnostics.psd1          Module manifest
├── IISDiagnostics.psm1          Loader - dot-sources Public/* and Private/*
├── IISDiagnostics_Format.ps1xml Display formatting for all output types
├── Data/
│   └── StatusCodes.json         Status code and substatus descriptions
├── Public/                      Exported cmdlets (one file per cmdlet)
│   ├── Get-IISStatusHelp.ps1
│   ├── Get-IISHttpErrLog.ps1
│   ├── Invoke-IISHttpErrAnalysis.ps1
│   ├── Get-IISW3CLog.ps1
│   ├── Invoke-IISW3CLogAnalysis.ps1
│   ├── Get-IISAppPoolStatus.ps1
│   ├── Get-IISSiteBindingReport.ps1
│   ├── Get-IISSiteSummary.ps1
│   └── Get-IISConfigSummary.ps1
└── Private/                     Internal helpers - not exported
    ├── Assert-ElevatedSession.ps1
    ├── Assert-WebAdminModule.ps1
    ├── Test-DomainAccountStatus.ps1
    ├── Initialize-StatusData.ps1
    ├── ConvertTo-StatusResult.ps1
    ├── Format-NumberedLines.ps1
    └── Get-UnknownStatusGuidance.ps1
```

Adding a new cmdlet: create a `.ps1` file in `Public\` and the loader picks it up
automatically. No manifest edit required - `FunctionsToExport = '*'` in the `.psd1` covers it.

---

## Output Types

| Type | Produced by | Format-List |
|---|---|---|
| `IISDiagnostics.StatusHelp` | `Get-IISStatusHelp` | `IISDiagnostics.StatusHelp` |
| `IISDiagnostics.HttpErrEntry` | `Get-IISHttpErrLog` | `IISDiagnostics.HttpErrEntry.Detail` |
| `IISDiagnostics.HttpErrSummary` | `Get-IISHttpErrLog -Summarise` | - |
| `IISDiagnostics.HttpErrAnalysis` | `Invoke-IISHttpErrAnalysis` | - |
| `IISDiagnostics.HttpErrFinding` | `$analysis.Findings` | - |
| `IISDiagnostics.W3CEntry` | `Get-IISW3CLog` | `IISDiagnostics.W3CEntry.Detail` |
| `IISDiagnostics.W3CSummary` | `Get-IISW3CLog -Summarise` | - |
| `IISDiagnostics.W3CLogAnalysis` | `Invoke-IISW3CLogAnalysis` | - |
| `IISDiagnostics.W3CStatusGroup` | `$analysis.Groups` | `IISDiagnostics.W3CStatusGroup.Detail` |
| `IISDiagnostics.AppPoolStatus` | `Get-IISAppPoolStatus` | `IISDiagnostics.AppPoolStatus.Detail` |
| `IISDiagnostics.SiteBinding` | `Get-IISSiteBindingReport` | `IISDiagnostics.SiteBinding.Detail` |
| `IISDiagnostics.SiteSummary` | `Get-IISSiteSummary` | `IISDiagnostics.SiteSummary.Detail` |

All types are registered in `IISDiagnostics_Format.ps1xml`. The default table view is optimised
for triage. `Format-List` (where a detail view is defined) shows the full enrichment including
descriptions, causes, and notices.

---
 

## Testing

This project uses [Pester](https://pester.dev/) for unit tests.

Install Pester (CurrentUser scope):

```powershell
Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck
```

Run tests from the module root:

```powershell
Invoke-Pester .\Tests
```



## Contributing

Pull requests welcome. When adding a new cmdlet:

1. One `.ps1` file in `Public\`, named after the cmdlet
2. Output objects use `PSTypeName` for type registration
3. Add format views to `IISDiagnostics_Format.ps1xml` - default table for triage, detail list
   for `Format-List`
4. Pre-rendered display strings (e.g. `TopUrisDisplay`) follow the existing pattern for complex
   nested data - avoids scriptblock complexity in the format XML
5. All cmdlets requiring elevation call `Assert-ElevatedSession` as their first line
6. Cmdlets using WebAdministration call `Assert-WebAdminModule` immediately after
