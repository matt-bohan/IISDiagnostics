function Get-IISSiteBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [SupportsWildcards()]
        [string]$SiteName,

        [Parameter()]
        [ValidateRange(0, 3650)]
        [int]$WarnDaysRemaining = 30,

        [Parameter()]
        [switch]$IncludeNonHttps
    )

    # Backward-compatibility shim for older internal calls/scripts.
    # Prefer Get-IISSiteBindingReport going forward.
    IISDiagnostics\Get-IISSiteBindingReport @PSBoundParameters
}
