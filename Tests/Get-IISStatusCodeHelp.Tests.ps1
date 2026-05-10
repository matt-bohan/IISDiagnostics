Describe 'Get-IISStatusCodeHelp' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'returns details for a known HTTP status code' {
        $result = Get-IISStatusCodeHelp 503

        if ($result.PSObject.TypeNames[0] -ne 'IISDiagnostics.StatusHelp') { throw 'Expected IISDiagnostics.StatusHelp result type.' }
        if ($result.StatusCode -ne '503') { throw "Expected StatusCode 503, got '$($result.StatusCode)'." }
        if ($result.Title -ne 'Service Unavailable') { throw "Unexpected title '$($result.Title)'." }
        if ($result.LikelyCauses.Count -le 0) { throw 'Expected one or more likely causes.' }
    }

    It 'returns details for a known IIS substatus code' {
        $result = Get-IISStatusCodeHelp '500.30'

        if ($result.PSObject.TypeNames[0] -ne 'IISDiagnostics.StatusHelp') { throw 'Expected IISDiagnostics.StatusHelp result type.' }
        if ($result.StatusCode -ne '500.30') { throw "Expected StatusCode 500.30, got '$($result.StatusCode)'." }
        if ($result.Title -ne '500.30 - In-process start failure') { throw "Unexpected title '$($result.Title)'." }
    }

    It 'returns unknown guidance for unmapped substatus values' {
        $result = Get-IISStatusCodeHelp '500.999'

        if ($result.StatusCode -ne '500.999') { throw "Expected StatusCode 500.999, got '$($result.StatusCode)'." }
        if ($result.Title -ne 'Unknown or undocumented status') { throw "Unexpected title '$($result.Title)'." }
    }

    It 'throws for dotted numeric values not passed as strings' {
        $threw = $false
        try { Get-IISStatusCodeHelp 500.30 | Out-Null } catch { $threw = $true }
        if (-not $threw) { throw 'Expected Get-IISStatusCodeHelp 500.30 to throw.' }
    }
}
