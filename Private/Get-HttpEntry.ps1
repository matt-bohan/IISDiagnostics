function Get-HttpEntry {
    param([string]$Code)

    $bucket = $script:StatusData.http
    if ($null -eq $bucket) { return $null }

    $prop = $bucket.PSObject.Properties[$Code]
    if ($null -eq $prop) { return $null }

    $prop.Value
}

function Get-HttpEntry {
    param([string]$Code)
    $bucket = $script:StatusData.http
    if ($null -eq $bucket) { return $null }
    $prop = $bucket.PSObject.Properties[$Code]
    if ($null -eq $prop) { return $null }
    $prop.Value
}
