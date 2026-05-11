#Requires -Version 5.1

function Get-ExpectedW3CLogFileNamesForTimeWindow {
    <#
    .SYNOPSIS
        Builds likely IIS W3C log file names for a UTC window (daily and hourly rolls).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$StartUtc,
        [Parameter(Mandatory)][datetime]$EndUtc
    )

    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $startLocal = $StartUtc.ToLocalTime()
    $endLocal   = $EndUtc.ToLocalTime()

    $day = $startLocal.Date
    while ($day -le $endLocal.Date) {
        [void]$names.Add(('u_ex{0}.log' -f $day.ToString('yyMMdd')))
        $day = $day.AddDays(1)
    }

    $hour = [datetime]::new($startLocal.Year, $startLocal.Month, $startLocal.Day, $startLocal.Hour, 0, 0)
    $hourEnd = [datetime]::new($endLocal.Year, $endLocal.Month, $endLocal.Day, $endLocal.Hour, 0, 0)
    while ($hour -le $hourEnd) {
        [void]$names.Add(('u_ex{0}.log' -f $hour.ToString('yyMMddHH')))
        $hour = $hour.AddHours(1)
    }

    @($names)
}

function Get-W3CLogTailReadStartOffset {
    <#
    .SYNOPSIS
        Returns a byte offset for short windows on large daily W3C logs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.FileInfo]$File,
        [Parameter(Mandatory)][datetime]$StartUtc,
        [Parameter(Mandatory)][datetime]$EndUtc
    )

    if ($File.Length -lt 262144) {
        return 0
    }

    if ($File.Name -notmatch '^u_ex(\d{2})(\d{2})(\d{2})\.log$') {
        return 0
    }

    $windowHours = ($EndUtc - $StartUtc).TotalHours
    if ($windowHours -ge 24) {
        return 0
    }

    $bufferHours = [Math]::Max(2.0, $windowHours * 1.5)
    $readHours   = [Math]::Min(24.0, $windowHours + $bufferHours)
    $fraction    = [Math]::Min(0.98, $readHours / 24.0)
    $offset      = [int][Math]::Floor($File.Length * (1.0 - $fraction))

    if ($offset -lt 0) {
        return 0
    }

    $offset
}

function Test-W3CLogFileOverlapsTimeWindow {
    <#
    .SYNOPSIS
        Returns whether a W3C log file can contain entries in the requested UTC window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.FileInfo]$File,
        [Parameter(Mandatory)][datetime]$StartUtc,
        [Parameter(Mandatory)][datetime]$EndUtc
    )

    if ($File.Name -match '^u_ex(\d{2})(\d{2})(\d{2})(\d{2})?\.log$') {
        $year  = 2000 + [int]$Matches[1]
        $month = [int]$Matches[2]
        $day   = [int]$Matches[3]

        try {
            if ($Matches[4]) {
                $hour = [int]$Matches[4]
                $fileStartLocal = [datetime]::new($year, $month, $day, $hour, 0, 0)
                $fileEndLocal   = $fileStartLocal.AddHours(1)
                $fileStartUtc   = $fileStartLocal.ToUniversalTime()
                $fileEndUtc     = $fileEndLocal.ToUniversalTime()
            }
            else {
                $fileDateLocal = [datetime]::new($year, $month, $day)
                $fileStartUtc  = $fileDateLocal.ToUniversalTime()
                $fileEndUtc    = $fileDateLocal.AddDays(1).ToUniversalTime()
            }

            return ($fileEndUtc -gt $StartUtc) -and ($fileStartUtc -le $EndUtc)
        }
        catch {
            return $true
        }
    }

    return ($File.LastWriteTimeUtc -ge $StartUtc.AddHours(-1)) -and ($File.LastWriteTimeUtc -le $EndUtc.AddHours(1))
}

function Get-W3CLogFilesForTimeWindow {
    <#
    .SYNOPSIS
        Returns W3C log files under the given directories that may contain entries in the window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$LogDirectories,
        [Parameter(Mandatory)][datetime]$StartUtc,
        [Parameter(Mandatory)][datetime]$EndUtc
    )

    $selected = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    $expectedNames = @(Get-ExpectedW3CLogFileNamesForTimeWindow -StartUtc $StartUtc -EndUtc $EndUtc)

    foreach ($dir in @($LogDirectories)) {
        if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path -LiteralPath $dir -PathType Container)) {
            continue
        }

        $candidates = [System.Collections.Generic.List[System.IO.FileInfo]]::new()

        foreach ($name in $expectedNames) {
            $candidatePath = Join-Path $dir $name
            if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
                $candidates.Add([System.IO.FileInfo]::new($candidatePath))
            }
        }

        if ($candidates.Count -eq 0) {
            foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter 'u_ex*.log' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
                $candidates.Add($file)
            }
        }

        if ($candidates.Count -eq 0) {
            foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter '*.log' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
                $candidates.Add($file)
            }
        }

        foreach ($file in $candidates) {
            if (-not (Test-W3CLogFileOverlapsTimeWindow -File $file -StartUtc $StartUtc -EndUtc $EndUtc)) {
                continue
            }

            if ($seen.Add($file.FullName)) {
                $selected.Add($file)
            }
        }
    }

    @($selected)
}
