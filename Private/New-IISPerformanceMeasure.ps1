function New-IISPerformanceMeasure {
    param(
        [Parameter(Mandatory)]
        [string]$Category,

        [string]$Instance,
        [string]$Name,
        [string]$CounterPath,
        $Value,
        [string]$FormattedValue,
        [string]$Unit,
        [string]$Severity = 'OK',
        [string]$WhatToExpect,
        [string]$OkGuidance,
        [string]$WarningGuidance,
        [string]$CriticalGuidance,
        [string[]]$RecommendedActions
    )

    $rank = switch ($Severity) {
        'Critical' { 4 }
        'Warning'  { 3 }
        'Info'     { 2 }
        default    { 1 }
    }

    $statusSummary = switch ($Severity) {
        'Critical' { $CriticalGuidance }
        'Warning'  { $WarningGuidance }
        'Info'     { $OkGuidance }
        default    { $OkGuidance }
    }

    [pscustomobject]@{
        PSTypeName          = 'IISDiagnostics.PerformanceMeasure'
        Category            = $Category
        Instance            = $Instance
        Name                = $Name
        CounterPath         = $CounterPath
        Value               = $Value
        FormattedValue      = $FormattedValue
        Unit                = $Unit
        Severity            = $Severity
        SeverityRank        = $rank
        WhatToExpect        = $WhatToExpect
        OkGuidance          = $OkGuidance
        WarningGuidance     = $WarningGuidance
        CriticalGuidance    = $CriticalGuidance
        StatusSummary       = $statusSummary
        RecommendedActions  = if ($RecommendedActions) { [string[]]$RecommendedActions } else { @() }
    }
}

function Add-IISPerformanceFinding {
    param(
        [System.Collections.Generic.List[psobject]]$Findings,
        [psobject]$Measure
    )

    if ($Measure.Severity -in 'OK', 'Healthy') {
        return
    }

    $severity = if ($Measure.Severity -eq 'Info') { 'Info' } else { $Measure.Severity }
    $title = if ($Measure.Instance) {
        "$($Measure.Name) - $($Measure.Instance)"
    } else {
        $Measure.Name
    }

    $detail = @(
        "Value: $($Measure.FormattedValue)"
        if ($Measure.StatusSummary) { $Measure.StatusSummary }
        if ($Measure.WhatToExpect) { "Expect: $($Measure.WhatToExpect)" }
    ) -join ' '

    $Findings.Add([pscustomobject]@{
        PSTypeName         = 'IISDiagnostics.PerformanceFinding'
        SeverityRank       = $Measure.SeverityRank
        Severity           = $severity
        Category           = $Measure.Category
        Title              = $title
        Detail             = $detail
        Evidence           = if ($Measure.CounterPath) { $Measure.CounterPath } else { $Measure.FormattedValue }
        RecommendedActions = $Measure.RecommendedActions
        Measure            = $Measure
    })
}
