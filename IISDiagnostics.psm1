#Requires -Version 5.1

$script:ModuleRoot = $PSScriptRoot
$script:DataPath = Join-Path $script:ModuleRoot 'Data\StatusCodes.json'
$script:StatusData = $null


# Dot-source private helpers first so they are available to public cmdlets.
foreach ($privateFile in (Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -File -ErrorAction Stop | Sort-Object Name)) {
    try   { . $privateFile.FullName }
    catch { Write-Error "Failed to load private helper '$($privateFile.Name)': $_" -ErrorAction Continue }
}

# Dot-source public cmdlets.
foreach ($publicFile in (Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -File -ErrorAction Stop | Sort-Object Name)) {
    try   { . $publicFile.FullName }
    catch { Write-Error "Failed to load public function '$($publicFile.Name)': $_" -ErrorAction Continue }
}

Initialize-StatusData

$publicFunctions = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -File -ErrorAction Stop |
    Sort-Object Name |
    ForEach-Object { $_.BaseName })

Export-ModuleMember -Function $publicFunctions
 




