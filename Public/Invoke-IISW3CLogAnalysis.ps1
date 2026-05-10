#Requires -Version 5.1

function Invoke-IISW3CLogAnalysis {
    <#
    .SYNOPSIS
        Groups W3C log entries by status and substatus code, enriched with curated
        descriptions and remediation guidance from the module's status code data.

    .DESCRIPTION
        Calls Get-IISW3CLog internally, groups entries by sc-status and sc-substatus
        combination, and looks up each combination in the module's StatusCodes.json data
        (the same data used by Get-IISStatusHelp).

        For each group the output includes:

          The status combination
            StatusCode, SubStatus, and a combined StatusKey (e.g. "403.16", "500.0").
            SubStatus is shown as 0 when IIS logs substatus as 0 or when it is absent.

          Volume
            Count and percentage of total requests in the window.
            FirstSeen and LastSeen timestamps within the window.

          Curated description (when available)
            Title, Description, ServerAdminConcern, ApplicationSupportConcern.
            The substatus entry is tried first; the parent status code is the fallback.
            IsKnown is false when neither lookup has data - the raw code is shown
            and Get-IISStatusHelp is suggested for further research.

          Top URIs and clients for this status group
            The five most frequent URI stems and client IPs producing this code.
            Useful for narrowing down whether a 403.16 is from one endpoint or everywhere.

        The outer analysis object includes pre-sorted group lists:
          Groups          - all groups, sorted by count descending
          ErrorGroups     - 4xx and 5xx only
          ServerErrors    - 5xx only
          UnknownGroups   - groups with no curated description

    .PARAMETER StartTime
        Passed through to Get-IISW3CLog. Defaults to one hour ago.

    .PARAMETER EndTime
        Passed through to Get-IISW3CLog. Defaults to now.

    .PARAMETER Path
        Override the W3C log directory. Passed through to Get-IISW3CLog.

    .PARAMETER SiteId
        IIS numeric site ID. Passed through to Get-IISW3CLog.

    .PARAMETER SiteName
        IIS site name. Passed through to Get-IISW3CLog.

    .PARAMETER MinCount
        Only include status groups with at least this many entries. Useful for
        suppressing low-volume noise on busy servers. Default: 1 (include all).

    .PARAMETER ErrorsOnly
        Only return 4xx and 5xx groups. Suppresses 2xx and 3xx from the output.

    .EXAMPLE
        Invoke-IISW3CLogAnalysis

        Analyses the past hour across all sites.

    .EXAMPLE
        Invoke-IISW3CLogAnalysis -SiteName 'MySite' -StartTime (Get-Date).AddHours(-4)

        Analysis for a specific site over four hours.

    .EXAMPLE
        Invoke-IISW3CLogAnalysis -ErrorsOnly | Format-Table StatusKey, Count, Title

        Quick error table - status codes, counts, and one-line descriptions.

    .EXAMPLE
        (Invoke-IISW3CLogAnalysis).Groups | Where-Object { -not $_.IsKnown }

        Surface status combinations not yet in the module's data file - useful for
        identifying gaps in coverage.

    .EXAMPLE
        (Invoke-IISW3CLogAnalysis).ServerErrors |
            ForEach-Object { "$($_.StatusKey) ($($_.Count)x): $($_.Title)" }

        One-liner summary of all 5xx groups.

    .NOTES
        Requires an elevated session. Inherits all requirements from Get-IISW3CLog.
    #>
    [CmdletBinding(DefaultParameterSetName = 'AllSites')]
    param(
        [Parameter()]
        [datetime]$StartTime = (Get-Date).AddHours(-1),

        [Parameter()]
        [datetime]$EndTime = (Get-Date),

        [Parameter()]
        [string]$Path,

        [Parameter(ParameterSetName = 'BySiteId')]
        [int]$SiteId,

        [Parameter(ParameterSetName = 'BySiteName')]
        [string]$SiteName,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$MinCount = 1,

        [Parameter()]
        [switch]$ErrorsOnly
    )

    # Elevation is asserted inside Get-IISW3CLog - no need to duplicate it here,
    # but call it early so the error is clear if running non-elevated.
    Assert-ElevatedSession -CmdletName $MyInvocation.MyCommand.Name

    # Ensure status data is loaded (normally done at module import; guard here
    # in case this cmdlet is dot-sourced in isolation during development).
    if ($null -eq $script:StatusData) { Initialize-StatusData }

    # ------------------------------------------------------------------
    # Collect raw entries via Get-IISW3CLog
    # ------------------------------------------------------------------
    $getParams = @{
        StartTime = $StartTime
        EndTime   = $EndTime
        Verbose   = $false
    }
    if ($PSBoundParameters.ContainsKey('Path'))     { $getParams['Path']     = $Path     }
    if ($PSBoundParameters.ContainsKey('SiteId'))   { $getParams['SiteId']   = $SiteId   }
    if ($PSBoundParameters.ContainsKey('SiteName')) { $getParams['SiteName'] = $SiteName }

    Write-Verbose "Collecting W3C entries for analysis..."
    $entries = @(Get-IISW3CLog @getParams)
    $total   = $entries.Count

    Write-Verbose "Collected $total entries. Grouping by status code..."

    if ($total -eq 0) {
        Write-Warning "No W3C entries found for the specified window and site."
        return
    }

    # ------------------------------------------------------------------
    # Group by StatusCode + SubStatus
    # Treat $null SubStatus as 0 - IIS logs 0 for requests with no substatus.
    # ------------------------------------------------------------------
    $groups = $entries | Group-Object {
        $sc  = if ($null -ne $_.StatusCode) { $_.StatusCode } else { 0 }
        $sub = if ($null -ne $_.SubStatus)  { $_.SubStatus  } else { 0 }
        "$sc.$sub"
    }

    $resultGroups = [System.Collections.Generic.List[psobject]]::new()

    foreach ($group in $groups) {
        $count = $group.Count

        if ($count -lt $MinCount) { continue }

        # Parse the grouping key back into its parts
        $keyParts   = $group.Name -split '\.'
        $statusCode = [int]$keyParts[0]
        $subStatus  = [int]$keyParts[1]

        if ($ErrorsOnly -and $statusCode -lt 400) { continue }

        $percent    = [math]::Round(($count / $total) * 100, 2)
        $statusKey  = "$statusCode.$subStatus"

        # Sort group entries once for FirstSeen/LastSeen
        $sorted   = $group.Group | Sort-Object Timestamp
        $firstSeen = $sorted[0].Timestamp
        $lastSeen  = $sorted[-1].Timestamp

        # ------------------------------------------------------------------
        # Look up curated description
        # Priority: exact substatus entry ("403.16") → parent code ("403") → unknown
        # ------------------------------------------------------------------
        $statusEntry   = $null
        $isKnown       = $false
        $lookupSource  = $null   # 'Substatus' | 'HttpCode' | $null

        if ($subStatus -gt 0) {
            $statusEntry = Get-SubstatusEntry -Major ([string]$statusCode) -Minor ([string]$subStatus)
            if ($statusEntry) { $isKnown = $true; $lookupSource = 'Substatus' }
        }

        if (-not $statusEntry) {
            $statusEntry = Get-HttpEntry -Code ([string]$statusCode)
            if ($statusEntry) { $isKnown = $true; $lookupSource = 'HttpCode' }
        }

        $title              = if ($statusEntry) { [string]$statusEntry.title }              else { $null }
        $description        = if ($statusEntry) { [string]$statusEntry.description }        else { $null }
        $adminConcern       = if ($statusEntry) { [string]$statusEntry.serverAdminConcern }        else { $null }
        $appConcern         = if ($statusEntry) { [string]$statusEntry.applicationSupportConcern } else { $null }
        $likelyCauses       = if ($statusEntry -and $statusEntry.likelyCauses) { @($statusEntry.likelyCauses) } else { @() }
        $checks             = if ($statusEntry -and $statusEntry.checks)       { @($statusEntry.checks)       } else { @() }

        # When we only found the parent code, note that the specific substatus
        # isn't documented so the operator knows to look further.
        $descriptionNote = if ($lookupSource -eq 'HttpCode' -and $subStatus -gt 0) {
            " (Substatus $subStatus has no specific entry - description is for $statusCode in general.)"
        } else { '' }

        # ------------------------------------------------------------------
        # Top URIs and clients for this group
        # ------------------------------------------------------------------
        $topUris = @($group.Group |
            Where-Object { $_.UriStem } |
            Group-Object UriStem |
            Sort-Object Count -Descending |
            Select-Object -First 5 |
            ForEach-Object { [pscustomobject]@{ UriStem = $_.Name; Count = $_.Count } })

        $topClients = @($group.Group |
            Where-Object { $_.ClientIp } |
            Group-Object ClientIp |
            Sort-Object Count -Descending |
            Select-Object -First 5 |
            ForEach-Object { [pscustomobject]@{ ClientIp = $_.Name; Count = $_.Count } })

        # ------------------------------------------------------------------
        # Pre-render display strings for the format file
        # ------------------------------------------------------------------
        $topUriDisplay = if ($topUris) {
            ($topUris | ForEach-Object {
                $uri = if ($_.UriStem.Length -gt 60) { $_.UriStem.Substring(0, 57) + '...' } else { $_.UriStem }
                '  {0,-63} {1,5:N0}' -f $uri, $_.Count
            }) -join [Environment]::NewLine
        } else { '  (no URI data)' }

        $topClientDisplay = if ($topClients) {
            ($topClients | ForEach-Object { '  {0,-20} {1,5:N0}' -f $_.ClientIp, $_.Count }) -join [Environment]::NewLine
        } else { '  (no client data)' }

        $causesDisplay = if ($likelyCauses) {
            ($likelyCauses | ForEach-Object -Begin { $n = 1 } -Process { "  $n. $_"; $n++ }) -join [Environment]::NewLine
        } else { '  (none documented)' }

        $checksDisplay = if ($checks) {
            ($checks | ForEach-Object -Begin { $n = 1 } -Process { "  $n. $_"; $n++ }) -join [Environment]::NewLine
        } else { '  (none documented)' }

        $resultGroups.Add([pscustomobject]@{
            PSTypeName                = 'IISDiagnostics.W3CStatusGroup'
            StatusCode                = $statusCode
            SubStatus                 = $subStatus
            StatusKey                 = $statusKey
            Count                     = $count
            Percent                   = $percent
            FirstSeen                 = $firstSeen
            LastSeen                  = $lastSeen
            IsKnown                   = $isKnown
            LookupSource              = $lookupSource
            Title                     = $title
            Description               = if ($description) { $description + $descriptionNote } else { $null }
            ServerAdminConcern        = $adminConcern
            ApplicationSupportConcern = $appConcern
            LikelyCauses              = $likelyCauses
            Checks                    = $checks
            TopUris                   = $topUris
            TopClients                = $topClients
            TopUrisDisplay            = $topUriDisplay
            TopClientsDisplay         = $topClientDisplay
            LikelyCausesDisplay       = $causesDisplay
            ChecksDisplay             = $checksDisplay
        })
    }

    # Sort by count descending for default display
    $sorted = @($resultGroups | Sort-Object Count -Descending)

    [pscustomobject]@{
        PSTypeName     = 'IISDiagnostics.W3CLogAnalysis'
        GeneratedAt    = Get-Date
        StartTime      = $StartTime
        EndTime        = $EndTime
        TotalRequests  = $total
        TotalGroups    = $sorted.Count
        Groups         = $sorted
        ErrorGroups    = @($sorted | Where-Object { $_.StatusCode -ge 400 })
        ServerErrors   = @($sorted | Where-Object { $_.StatusCode -ge 500 })
        UnknownGroups  = @($sorted | Where-Object { -not $_.IsKnown })
    }
}