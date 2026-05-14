#Requires -Version 5.1

function Write-IISPerformanceCounterConsoleReport {
    <#
    .SYNOPSIS
        Writes a colour-grouped console summary for IISDiagnostics.PerformanceCounterSnapshot.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject]$Snapshot,

        [Parameter()]
        [int]$GuidanceMaxLength = 115
    )

    $lineWidth = 68

    function Limit-ConsoleText([string]$Text, [int]$Max) {
        if ([string]::IsNullOrEmpty($Text)) { return '' }
        if ($Text.Length -le $Max) { return $Text }
        return $Text.Substring(0, [math]::Max(0, $Max - 3)) + '...'
    }

    function Write-PerfBanner([string]$Text, [switch]$Double) {
        $char = if ($Double) { '=' } else { '-' }
        $line = $char * $lineWidth
        Write-Host "  $line" -ForegroundColor DarkGray
        if ($Text) { Write-Host "    $Text" -ForegroundColor White }
    }

    function Write-PerfSection([string]$Title) {
        $pad = '-' * [math]::Max(2, $lineWidth - $Title.Length - 5)
        Write-Host ''
        Write-Host "  --- $Title $pad" -ForegroundColor DarkGray
    }

    function Write-PerfLine([string]$Severity, [string]$Text) {
        $badge = switch ($Severity) {
            'Critical' { '[CRIT]' } 'Warning' { '[WARN]' }
            'Info'     { '[INFO]' } default   { '[ OK ]' }
        }
        $colour = switch ($Severity) {
            'Critical' { 'Red'    } 'Warning' { 'Yellow' }
            'Info'     { 'Cyan'   } default   { 'Green'  }
        }
        Write-Host "  $badge  $Text" -ForegroundColor $colour
    }

    $categoryRank = @{
        'HttpSys'       = 1
        'AppPool'       = 2
        'WorkerProcess' = 3
        'WebService'    = 4
        'System'        = 5
        'DotNetRuntime' = 6
        'AspNet'        = 7
        'SqlClient'     = 8
    }

    $measures = @($Snapshot.Measures)
    $crit = @($measures | Where-Object { $_.Severity -eq 'Critical' }).Count
    $warn = @($measures | Where-Object { $_.Severity -eq 'Warning' }).Count
    $info = @($measures | Where-Object { $_.Severity -eq 'Info' }).Count
    $ok   = @($measures | Where-Object { $_.Severity -in 'OK', 'Healthy' }).Count

    $overallColour = switch ($Snapshot.OverallSeverity) {
        'Critical' { 'Red' } 'Warning' { 'Yellow' } 'Info' { 'Cyan' } default { 'Green' }
    }

    Write-Host ''
    Write-PerfBanner -Double
    Write-Host "    IIS performance counters" -ForegroundColor White -NoNewline
    Write-Host "  *  $($Snapshot.ComputerName)  *  $($Snapshot.GeneratedAt.ToString('dd/MM/yyyy HH:mm:ss'))" -ForegroundColor DarkGray
    Write-Host "    Samples: $($Snapshot.MaxSamples)  *  Interval: $($Snapshot.SampleIntervalSeconds)s" -ForegroundColor DarkGray
    Write-PerfBanner -Double

    Write-Host ''
    Write-Host "    OVERALL: " -ForegroundColor DarkGray -NoNewline
    Write-Host $Snapshot.OverallSeverity.ToUpper() -ForegroundColor $overallColour -NoNewline
    Write-Host "  |  $crit critical  |  $warn warning  |  $info info  |  $ok ok" -ForegroundColor DarkGray

    $sortedMeasures = $measures | Sort-Object {
        $key = [string]$_.Category
        if ($categoryRank.ContainsKey($key)) { $categoryRank[$key] } else { 99 }
    }, @{ Expression = 'SeverityRank'; Descending = $true }, Instance, Name

    $currentCategory = $null
    foreach ($m in $sortedMeasures) {
        if ($m.Category -ne $currentCategory) {
            $currentCategory = $m.Category
            Write-PerfSection ($currentCategory.ToUpper())
        }

        $inst = if ($m.Instance) { " [$($m.Instance)]" } else { '' }
        $line1 = "$($m.Name)$inst  =  $($m.FormattedValue)"
        Write-PerfLine -Severity $m.Severity -Text $line1

        $guidance = if ($m.StatusSummary) { $m.StatusSummary } elseif ($m.OkGuidance) { $m.OkGuidance } else { '' }
        if ($guidance) {
            Write-Host "           $(Limit-ConsoleText $guidance $GuidanceMaxLength)" -ForegroundColor DarkGray
        }
        if ($m.WhatToExpect -and $m.Severity -eq 'Info') {
            Write-Host "           Expect: $(Limit-ConsoleText $m.WhatToExpect $GuidanceMaxLength)" -ForegroundColor DarkCyan
        }
        if ($m.RecommendedActions -and $m.Severity -in 'Critical', 'Warning') {
            foreach ($act in ($m.RecommendedActions | Select-Object -First 2)) {
                Write-Host "           -> $act" -ForegroundColor DarkGray
            }
        }
    }

    Write-Host ''
    Write-PerfBanner -Double
    Write-Host '    Tip:  Use -Quiet for automation (no host output). Pipe measures to Format-Table or Format-List.' -ForegroundColor DarkGray
    Write-PerfBanner -Double
    Write-Host ''
}
