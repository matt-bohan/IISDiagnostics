#Requires -Version 5.1

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

    foreach ($dir in @($LogDirectories)) {
        if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path -LiteralPath $dir -PathType Container)) {
            continue
        }

        $candidates = @(Get-ChildItem -LiteralPath $dir -Filter 'u_ex*.log' -File -ErrorAction SilentlyContinue |
            Sort-Object Name)

        if ($candidates.Count -eq 0) {
            $candidates = @(Get-ChildItem -LiteralPath $dir -Filter '*.log' -File -ErrorAction SilentlyContinue |
                Sort-Object Name)
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
