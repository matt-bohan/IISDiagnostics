function Initialize-StatusData {
    if (-not (Test-Path -LiteralPath $script:DataPath)) {
        throw "Status code data file not found at '$script:DataPath'."
    }

    $raw = Get-Content -LiteralPath $script:DataPath -Raw -Encoding UTF8
    $script:StatusData = $raw | ConvertFrom-Json
}

function Initialize-StatusData {
    if (-not (Test-Path -LiteralPath $script:DataPath)) {
        throw "Status code data file not found at '$script:DataPath'."
    }
    $raw = Get-Content -LiteralPath $script:DataPath -Raw -Encoding UTF8
    # Note: -Depth exists only in PowerShell 6+; omit for Windows PowerShell 5.1 compatibility.
    $script:StatusData = $raw | ConvertFrom-Json
}