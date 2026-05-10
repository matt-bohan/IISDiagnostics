function Get-SubstatusEntry {
    param(
        [string]$Major,
        [string]$Minor
    )

    $composite = '{0}.{1}' -f $Major, $Minor
    $bucket = $script:StatusData.substatus
    if ($null -eq $bucket) { return $null }
    $prop = $bucket.PSObject.Properties[$composite]
    if ($null -eq $prop) { return $null }
    $prop.Value
}
