function Get-IISStatusCodeHelp {
    <#
    .SYNOPSIS
        Describes an HTTP status code or IIS substatus (major.minor) with remediation hints.

    .DESCRIPTION
        Looks up curated guidance for server administrators and application support teams.

    .PARAMETER StatusCode
        A three-digit HTTP status (e.g. 503) or IIS-style substatus as a string (e.g. '500.30').

    .PARAMETER Substatus
        Optional IIS substatus number when passing the HTTP class separately.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [object]$StatusCode,

        [Parameter(Position = 1)]
        [ValidateRange(0, 999)]
        [int]$Substatus
    )

    begin {
        if ($null -eq $script:StatusData) {
            Initialize-StatusData
        }
    }

    process {
        if ($null -eq $StatusCode) {
            throw 'StatusCode cannot be null.'
        }

        if (-not $PSBoundParameters.ContainsKey('Substatus') -and
            ($StatusCode -is [double] -or $StatusCode -is [float] -or $StatusCode -is [decimal])) {
            $asText = $StatusCode.ToString()
            if ($asText -match '\.') {
                throw 'Dotted IIS codes must be passed as a string in quotes (e.g. Get-IISStatusCodeHelp ''500.30'') or split as Get-IISStatusCodeHelp 500 -Substatus 30. Unquoted decimals lose trailing digits (500.30 becomes 500.3).'
            }
        }

        $raw = $StatusCode.ToString().Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) {
            throw 'StatusCode cannot be empty.'
        }

        if ($PSBoundParameters.ContainsKey('Substatus')) {
            if ($raw -notmatch '^([1-5]\d{2})$') {
                throw "When using -Substatus, StatusCode must be a three-digit HTTP class (100-599). Got '$raw'."
            }
            $minorStr = [string]$Substatus
            $display = '{0}.{1}' -f $raw, $minorStr
            $entry = Get-SubstatusEntry -Major $raw -Minor $minorStr
            if ($null -ne $entry) {
                return ConvertTo-StatusResult -Entry $entry -DisplayCode $display
            }
            return Get-UnknownStatusGuidance -DisplayCode $display -IsSubstatus $true
        }

        if ($raw -match '^([1-5]\d{2})\.(\d+)$') {
            $major = $Matches[1]
            $minor = $Matches[2]
            $display = '{0}.{1}' -f $major, $minor
            $entry = Get-SubstatusEntry -Major $major -Minor $minor
            if ($null -ne $entry) {
                return ConvertTo-StatusResult -Entry $entry -DisplayCode $display
            }
            return Get-UnknownStatusGuidance -DisplayCode $display -IsSubstatus $true
        }

        if ($raw -match '^([1-5]\d{2})$') {
            $code = $Matches[1]
            $entry = Get-HttpEntry -Code $code
            if ($null -ne $entry) {
                return ConvertTo-StatusResult -Entry $entry -DisplayCode $code
            }
            return Get-UnknownStatusGuidance -DisplayCode $code -IsSubstatus $false
        }

        throw "Invalid status code '$raw'. Expected a three-digit HTTP status (e.g. 503) or IIS substatus (e.g. 500.30)."
    }
}
