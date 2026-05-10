#Requires -Version 5.1

$script:ModuleRoot = $PSScriptRoot
$script:DataPath = Join-Path $script:ModuleRoot 'Data\StatusCodes.json'
$script:StatusData = $null


# Dot-source private helpers first so they are available to public cmdlets.
Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -File -ErrorAction Stop |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

# Dot-source public cmdlets.
Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -File -ErrorAction Stop |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

Initialize-StatusData

$publicFunctions = @(
    'Get-IISStatusCodeHelp',
    'Get-IISHttpErrLog',
    'Invoke-IISHttpErrAnalysis',
    'Get-IISAppPoolStatus',
    'Get-IISSiteBindingReport',
    'Get-IISSiteSummary',
    'Get-IISW3CLog',
    'Invoke-IISW3CLogAnalysis'
)

Export-ModuleMember -Function $publicFunctions
 




