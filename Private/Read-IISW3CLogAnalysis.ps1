#Requires -Version 5.1

function New-IISW3CLogAnalysisState {
    [CmdletBinding()]
    param()

    return @{
        Total     = 0
        GroupData = @{}
    }
}

function Add-IISW3CLogAnalysisEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$State,

        [Parameter(Mandatory)]
        [datetime]$TimestampLocal,

        [Parameter()]
        [int]$StatusCode,

        [Parameter()]
        [int]$SubStatus,

        [Parameter()]
        [string]$UriStem,

        [Parameter()]
        [string]$ClientIp
    )

    $State.Total++
    $statusKey = "$StatusCode.$SubStatus"

    if (-not $State.GroupData.ContainsKey($statusKey)) {
        $State.GroupData[$statusKey] = @{
            StatusCode   = $StatusCode
            SubStatus    = $SubStatus
            Count        = 0
            FirstSeen    = $TimestampLocal
            LastSeen     = $TimestampLocal
            UriCounts    = @{}
            ClientCounts = @{}
        }
    }

    $bucket = $State.GroupData[$statusKey]
    $bucket.Count++
    if ($TimestampLocal -lt $bucket.FirstSeen) { $bucket.FirstSeen = $TimestampLocal }
    if ($TimestampLocal -gt $bucket.LastSeen)  { $bucket.LastSeen  = $TimestampLocal }

    if ($StatusCode -ge 400) {
        if ($UriStem) {
            if ($bucket.UriCounts.ContainsKey($UriStem)) {
                $bucket.UriCounts[$UriStem]++
            }
            else {
                $bucket.UriCounts[$UriStem] = 1
            }
        }

        if ($ClientIp) {
            if ($bucket.ClientCounts.ContainsKey($ClientIp)) {
                $bucket.ClientCounts[$ClientIp]++
            }
            else {
                $bucket.ClientCounts[$ClientIp] = 1
            }
        }
    }
}

function Read-IISW3CLogFieldsHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.StreamReader]$Reader,

        [ref]$FieldNames,
        [ref]$DateIdx,
        [ref]$TimeIdx,
        [ref]$StatusIdx,
        [ref]$SubStatusIdx,
        [ref]$UriIdx,
        [ref]$ClientIdx,
        [ref]$FieldCount
    )

    while ($null -ne ($rawLine = $Reader.ReadLine())) {
        if ($rawLine.StartsWith('#Fields:')) {
            if ($rawLine -match '^#Fields:\s+(.+)') {
                $FieldNames.Value = $Matches[1].Trim() -split '\s+'
                $FieldCount.Value = $FieldNames.Value.Count
                $DateIdx.Value = [Array]::IndexOf($FieldNames.Value, 'date')
                $TimeIdx.Value = [Array]::IndexOf($FieldNames.Value, 'time')
                $StatusIdx.Value = [Array]::IndexOf($FieldNames.Value, 'sc-status')
                $SubStatusIdx.Value = [Array]::IndexOf($FieldNames.Value, 'sc-substatus')
                $UriIdx.Value = [Array]::IndexOf($FieldNames.Value, 'cs-uri-stem')
                $ClientIdx.Value = [Array]::IndexOf($FieldNames.Value, 'c-ip')
            }
            break
        }
    }
}

function Read-IISW3CLogAnalysisFromFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File,

        [Parameter(Mandatory)]
        [datetime]$StartUtc,

        [Parameter(Mandatory)]
        [datetime]$EndUtc,

        [Parameter(Mandatory)]
        [hashtable]$State,

        [Parameter()]
        [switch]$SkipTailRead
    )

    if ($SkipTailRead) {
        $startOffset = 0
    }
    else {
        $startOffset = Get-W3CLogTailReadStartOffset -File $File -StartUtc $StartUtc -EndUtc $EndUtc
    }

    $fieldNames = $null
    $fieldCount = 0
    $dateIdx = -1
    $timeIdx = -1
    $statusIdx = -1
    $subStatusIdx = -1
    $uriIdx = -1
    $clientIdx = -1
    $matched = 0

    $stream = [System.IO.File]::Open(
        $File.FullName,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )

    try {
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8, $false, 65536)

        try {
            Read-IISW3CLogFieldsHeader -Reader $reader `
                -FieldNames ([ref]$fieldNames) `
                -DateIdx ([ref]$dateIdx) `
                -TimeIdx ([ref]$timeIdx) `
                -StatusIdx ([ref]$statusIdx) `
                -SubStatusIdx ([ref]$subStatusIdx) `
                -UriIdx ([ref]$uriIdx) `
                -ClientIdx ([ref]$clientIdx) `
                -FieldCount ([ref]$fieldCount)

            if ($startOffset -gt 0) {
                $stream.Seek($startOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
                $reader.DiscardBufferedData()
                $null = $reader.ReadLine()
            }

            while ($null -ne ($rawLine = $reader.ReadLine())) {
                if ($rawLine.StartsWith('#')) {
                    if ($rawLine -match '^#Fields:\s+(.+)') {
                        $fieldNames = $Matches[1].Trim() -split '\s+'
                        $fieldCount = $fieldNames.Count
                        $dateIdx = [Array]::IndexOf($fieldNames, 'date')
                        $timeIdx = [Array]::IndexOf($fieldNames, 'time')
                        $statusIdx = [Array]::IndexOf($fieldNames, 'sc-status')
                        $subStatusIdx = [Array]::IndexOf($fieldNames, 'sc-substatus')
                        $uriIdx = [Array]::IndexOf($fieldNames, 'cs-uri-stem')
                        $clientIdx = [Array]::IndexOf($fieldNames, 'c-ip')
                    }
                    continue
                }

                if ([string]::IsNullOrWhiteSpace($rawLine) -or $null -eq $fieldNames) {
                    continue
                }

                if ($dateIdx -lt 0 -or $timeIdx -lt 0) {
                    continue
                }

                $parts = $rawLine -split '\s+', ($fieldCount + 1)
                if ($parts.Count -le $timeIdx) {
                    continue
                }

                $entryUtc = [datetime]::MinValue
                $parsed = [datetime]::TryParseExact(
                    "$($parts[$dateIdx]) $($parts[$timeIdx])",
                    'yyyy-MM-dd HH:mm:ss',
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    ([System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                     [System.Globalization.DateTimeStyles]::AdjustToUniversal),
                    [ref]$entryUtc
                )
                if (-not $parsed) {
                    continue
                }

                if ($entryUtc -lt $StartUtc) {
                    continue
                }

                if ($entryUtc -gt $EndUtc) {
                    break
                }

                $scStatus = 0
                if ($statusIdx -ge 0 -and $statusIdx -lt $parts.Count -and $parts[$statusIdx] -and $parts[$statusIdx] -ne '-') {
                    [void][int]::TryParse($parts[$statusIdx], [ref]$scStatus)
                }

                $subStatus = 0
                if ($subStatusIdx -ge 0 -and $subStatusIdx -lt $parts.Count -and $parts[$subStatusIdx] -and $parts[$subStatusIdx] -ne '-') {
                    [void][int]::TryParse($parts[$subStatusIdx], [ref]$subStatus)
                }

                $uriStem = $null
                if ($uriIdx -ge 0 -and $uriIdx -lt $parts.Count -and $parts[$uriIdx] -ne '-') {
                    $uriStem = $parts[$uriIdx]
                }

                $clientIp = $null
                if ($clientIdx -ge 0 -and $clientIdx -lt $parts.Count -and $parts[$clientIdx] -ne '-') {
                    $clientIp = $parts[$clientIdx]
                }

                Add-IISW3CLogAnalysisEntry -State $State `
                    -TimestampLocal $entryUtc.ToLocalTime() `
                    -StatusCode $scStatus `
                    -SubStatus $subStatus `
                    -UriStem $uriStem `
                    -ClientIp $clientIp
                $matched++
            }
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }

    if ($startOffset -gt 0 -and $matched -eq 0 -and -not $SkipTailRead) {
        Read-IISW3CLogAnalysisFromFile -File $File -StartUtc $StartUtc -EndUtc $EndUtc -State $State -SkipTailRead
    }
}

function Measure-IISW3CLogAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCmdlet]$PSCmdlet,

        [Parameter(Mandatory)]
        [string]$ParameterSetName,

        [Parameter()]
        [string]$Path,

        [Parameter()]
        [int]$SiteId,

        [Parameter()]
        [string]$SiteName,

        [Parameter(Mandatory)]
        [datetime]$StartUtc,

        [Parameter(Mandatory)]
        [datetime]$EndUtc
    )

    $resolveParams = @{
        PSCmdlet         = $PSCmdlet
        ParameterSetName = $ParameterSetName
        StartUtc         = $StartUtc
        EndUtc           = $EndUtc
    }
    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Path')) {
        $resolveParams['Path'] = $Path
    }
    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('SiteId')) {
        $resolveParams['SiteId'] = $SiteId
    }
    if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('SiteName')) {
        $resolveParams['SiteName'] = $SiteName
    }

    $targets = Resolve-IISW3CLogReadTargets @resolveParams
    $state = New-IISW3CLogAnalysisState

    foreach ($file in @($targets.LogFiles)) {
        Write-Verbose "Analysing W3C log file: $($file.FullName)"
        Read-IISW3CLogAnalysisFromFile -File $file -StartUtc $StartUtc -EndUtc $EndUtc -State $state
    }

    [pscustomobject]@{
        LogDirectories = $targets.LogDirectories
        LogFiles       = $targets.LogFiles
        Total          = $state.Total
        GroupData      = $state.GroupData
    }
}
