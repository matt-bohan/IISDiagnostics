function ConvertTo-StatusResult {
    param(
        [psobject]$Entry,
        [string]$DisplayCode
    )

    $likely = @()
    $checks = @()
    $refs = @()
    if ($null -ne $Entry.likelyCauses) { $likely = @($Entry.likelyCauses) }
    if ($null -ne $Entry.checks) { $checks = @($Entry.checks) }
    if ($null -ne $Entry.seeAlso) { $refs = @($Entry.seeAlso) }

    $seeAlsoText = if ($refs.Count -gt 0) {
        ($refs | ForEach-Object { "- $_" }) -join [Environment]::NewLine
    } else {
        ''
    }

    [pscustomobject]@{
        PSTypeName                = 'IISDiagnostics.StatusHelp'
        StatusCode                = $DisplayCode
        Title                     = [string]$Entry.title
        Description               = [string]$Entry.description
        ServerAdminConcern        = [string]$Entry.serverAdminConcern
        ApplicationSupportConcern = [string]$Entry.applicationSupportConcern
        LikelyCauses              = $likely
        Checks                    = $checks
        SeeAlso                   = $refs
        LikelyCausesDisplay       = (Format-NumberedLines $likely)
        ChecksDisplay             = (Format-NumberedLines $checks)
        SeeAlsoDisplay            = $seeAlsoText
    }
}
function ConvertTo-StatusResult {
    param(
        [psobject]$Entry,
        [string]$DisplayCode
    )
    $likely = @()
    $checks = @()
    $refs = @()
    if ($null -ne $Entry.likelyCauses) { $likely = @($Entry.likelyCauses) }
    if ($null -ne $Entry.checks) { $checks = @($Entry.checks) }
    if ($null -ne $Entry.seeAlso) { $refs = @($Entry.seeAlso) }

    $seeAlsoText = if ($refs.Count -gt 0) {
        ($refs | ForEach-Object { "- $_" }) -join [Environment]::NewLine
    } else {
        ''
    }

    [pscustomobject]@{
        PSTypeName                = 'IISDiagnostics.StatusHelp'
        StatusCode                = $DisplayCode
        Title                     = [string]$Entry.title
        Description               = [string]$Entry.description
        ServerAdminConcern        = [string]$Entry.serverAdminConcern
        ApplicationSupportConcern = [string]$Entry.applicationSupportConcern
        LikelyCauses              = $likely
        Checks                    = $checks
        SeeAlso                   = $refs
        LikelyCausesDisplay       = (Format-NumberedLines $likely)
        ChecksDisplay             = (Format-NumberedLines $checks)
        SeeAlsoDisplay            = $seeAlsoText
    }
}