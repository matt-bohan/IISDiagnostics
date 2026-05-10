function Get-UnknownStatusGuidance {
    param(
        [string]$DisplayCode,
        [bool]$IsSubstatus
    )

    $extra = if ($IsSubstatus) {
        'Compare your IIS log column sc-substatus with documentation for that HTTP family.'
    } else {
        'Confirm the exact three-digit HTTP status from logs or browser dev tools.'
    }

    $likelyUnknown = @(
        'Custom module returned a nonstandard combination',
        'Load balancer mapped errors into uncommon HTTP codes',
        'New framework substatus not yet added to this module'
    )
    $checksUnknown = @(
        'Capture W3C fields: date, time, cs-uri-stem, sc-status, sc-substatus, sc-win32-status, time-taken',
        'Enable Failed Request Tracing for the failing URL pattern',
        'Review HTTPERR log under %SystemRoot%\System32\LogFiles\HTTPERR',
        'If ASP.NET Core, enable stdout logging and check Application event log for ANCM HRESULTs',
        'Validate site bindings, certificates, and recent configuration or deployment changes'
    )
    $refsUnknown = @(
        'https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/www-administration-management/http-status-code'
    )

    [pscustomobject]@{
        PSTypeName                = 'IISDiagnostics.StatusHelp'
        StatusCode                = $DisplayCode
        Title                     = 'Unknown or undocumented status'
        Description               = @(
            'No curated explanation is stored for this code yet.',
            'Use IIS logs (fields sc-status, sc-substatus, sc-win32-status), Failed Request Tracing,',
            'and Windows Event Viewer (WAS, ASP.NET Core Module) to narrow the failure.',
            $extra
        ) -join ' '
        ServerAdminConcern        = 'Medium - Until classified, treat as unknown failure mode and gather diagnostics.'
        ApplicationSupportConcern = 'Medium - Unknown codes may still indicate application defects after infra checks.'
        LikelyCauses              = $likelyUnknown
        Checks                    = $checksUnknown
        SeeAlso                   = $refsUnknown
        LikelyCausesDisplay       = (Format-NumberedLines $likelyUnknown)
        ChecksDisplay             = (Format-NumberedLines $checksUnknown)
        SeeAlsoDisplay            = (($refsUnknown | ForEach-Object { "- $_" }) -join [Environment]::NewLine)
    }
}
function Get-UnknownStatusGuidance {
    param(
        [string]$DisplayCode,
        [bool]$IsSubstatus
    )
    $extra = if ($IsSubstatus) {
        'Compare your IIS log column sc-substatus with documentation for that HTTP family.'
    } else {
        'Confirm the exact three-digit HTTP status from logs or browser dev tools.'
    }

    $likelyUnknown = @(
        'Custom module returned a nonstandard combination',
        'Load balancer mapped errors into uncommon HTTP codes',
        'New framework substatus not yet added to this module'
    )
    $checksUnknown = @(
        'Capture W3C fields: date, time, cs-uri-stem, sc-status, sc-substatus, sc-win32-status, time-taken',
        'Enable Failed Request Tracing for the failing URL pattern',
        'Review HTTPERR log under %SystemRoot%\System32\LogFiles\HTTPERR',
        'If ASP.NET Core, enable stdout logging and check Application event log for ANCM HRESULTs',
        'Validate site bindings, certificates, and recent configuration or deployment changes'
    )
    $refsUnknown = @(
        'https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/www-administration-management/http-status-code'
    )

    [pscustomobject]@{
        PSTypeName                = 'IISDiagnostics.StatusHelp'
        StatusCode                = $DisplayCode
        Title                     = 'Unknown or undocumented status'
        Description               = @(
            'No curated explanation is stored for this code yet.',
            'Use IIS logs (fields sc-status, sc-substatus, sc-win32-status), Failed Request Tracing,',
            'and Windows Event Viewer (WAS, ASP.NET Core Module) to narrow the failure.',
            $extra
        ) -join ' '
        ServerAdminConcern        = 'Medium - Until classified, treat as unknown failure mode and gather diagnostics.'
        ApplicationSupportConcern = 'Medium - Unknown codes may still indicate application defects after infra checks.'
        LikelyCauses              = $likelyUnknown
        Checks                    = $checksUnknown
        SeeAlso                   = $refsUnknown
        LikelyCausesDisplay       = (Format-NumberedLines $likelyUnknown)
        ChecksDisplay             = (Format-NumberedLines $checksUnknown)
        SeeAlsoDisplay            = (($refsUnknown | ForEach-Object { "- $_" }) -join [Environment]::NewLine)
    }
}