Describe 'Get-IISConfigSummary' {
    BeforeAll {
        $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $manifestPath = Join-Path $repoRoot 'IISDiagnostics.psd1'
        Import-Module $manifestPath -Force
    }

    AfterAll {
        Remove-Module IISDiagnostics -ErrorAction SilentlyContinue
    }

    It 'is exported by the module' {
        $module = Get-Module IISDiagnostics
        if (-not ($module.ExportedCommands.Keys -contains 'Get-IISConfigSummary')) {
            throw 'Expected Get-IISConfigSummary to be exported.'
        }
    }

    It 'returns IISDiagnostics.ConfigSummary with expected properties' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Assert-WebAdminModule  {}

            # Mock IIS:\AppPools enumeration
            Mock Get-ChildItem {
                param($Path)
                if ($Path -eq 'IIS:\AppPools') {
                    return @(
                        [pscustomobject]@{
                            Name            = 'DefaultAppPool'
                            State           = 'Started'
                            ProcessModel    = [pscustomobject]@{
                                IdentityType = 'ApplicationPoolIdentity'
                                UserName     = ''
                            }
                            ManagedPipelineMode    = 'Integrated'
                            ManagedRuntimeVersion  = 'v4.0'
                        }
                    )
                }
                if ($Path -eq 'IIS:\Sites') {
                    return @(
                        [pscustomobject]@{
                            Id              = 1
                            Name            = 'Default Web Site'
                            State           = 'Started'
                            ApplicationPool = 'DefaultAppPool'
                            Bindings        = [pscustomobject]@{
                                Collection = @(
                                    [pscustomobject]@{
                                        Protocol           = 'http'
                                        bindingInformation = '*:80:'
                                    }
                                )
                            }
                        }
                    )
                }
                # Fallback for unexpected paths
                return @()
            }

            Mock Get-IISSiteW3CLogDirectoryRaw {
                return '%SystemDrive%\inetpub\logs\LogFiles\W3SVC1'
            }

            Mock Resolve-W3CSiteLogDirectory {
                return $null   # simulate directory not found on disk
            }

            Mock Expand-IISDiagnosticsLogPath {
                param($Path)
                return $Path -replace '(?i)%SystemDrive%', 'C:'
            }

            Mock Test-Path { return $false }

            Mock Get-HttpErrLogDirectoryCandidates {
                return @('C:\Windows\System32\LogFiles\HTTPERR')
            }

            $result = Get-IISConfigSummary

            if ($result.PSObject.TypeNames[0] -ne 'IISDiagnostics.ConfigSummary') {
                throw "Expected IISDiagnostics.ConfigSummary, got '$($result.PSObject.TypeNames[0])'."
            }

            foreach ($prop in @('ComputerName', 'GeneratedAt', 'AppPools', 'Sites', 'W3CLogPaths', 'HttpErrLogPath')) {
                if (-not $result.PSObject.Properties[$prop]) {
                    throw "Expected property '$prop' on ConfigSummary."
                }
            }
        }
    }

    It 'app pool rows have expected type and properties' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Assert-WebAdminModule  {}

            Mock Get-ChildItem {
                param($Path)
                if ($Path -eq 'IIS:\AppPools') {
                    return @(
                        [pscustomobject]@{
                            Name            = 'TestPool'
                            State           = 'Started'
                            ProcessModel    = [pscustomobject]@{
                                IdentityType = 'ApplicationPoolIdentity'
                                UserName     = ''
                            }
                            ManagedPipelineMode   = 'Integrated'
                            ManagedRuntimeVersion = 'v4.0'
                        }
                    )
                }
                return @()
            }

            Mock Get-IISSiteW3CLogDirectoryRaw { return $null }
            Mock Resolve-W3CSiteLogDirectory   { return $null }
            Mock Expand-IISDiagnosticsLogPath  { param($Path) return $Path }
            Mock Test-Path                     { return $false }
            Mock Get-HttpErrLogDirectoryCandidates { return @() }

            $result = Get-IISConfigSummary

            if ($result.AppPools.Count -ne 1) {
                throw "Expected 1 app pool row, got $($result.AppPools.Count)."
            }

            $pool = $result.AppPools[0]

            if ($pool.PSObject.TypeNames[0] -ne 'IISDiagnostics.ConfigSummary.AppPool') {
                throw "Expected IISDiagnostics.ConfigSummary.AppPool type, got '$($pool.PSObject.TypeNames[0])'."
            }

            if ($pool.Name -ne 'TestPool') {
                throw "Expected pool name 'TestPool', got '$($pool.Name)'."
            }

            if ($pool.State -ne 'Started') {
                throw "Expected pool state 'Started', got '$($pool.State)'."
            }
        }
    }

    It 'site rows have expected type and properties' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Assert-WebAdminModule  {}

            Mock Get-ChildItem {
                param($Path)
                if ($Path -eq 'IIS:\Sites') {
                    return @(
                        [pscustomobject]@{
                            Id              = 2
                            Name            = 'MySite'
                            State           = 'Started'
                            ApplicationPool = 'MyPool'
                            Bindings        = [pscustomobject]@{
                                Collection = @(
                                    [pscustomobject]@{
                                        Protocol           = 'https'
                                        bindingInformation = '*:443:mysite.example.com'
                                    }
                                )
                            }
                        }
                    )
                }
                return @()
            }

            Mock Get-IISSiteW3CLogDirectoryRaw { return $null }
            Mock Resolve-W3CSiteLogDirectory   { return $null }
            Mock Expand-IISDiagnosticsLogPath  { param($Path) return $Path }
            Mock Test-Path                     { return $false }
            Mock Get-HttpErrLogDirectoryCandidates { return @() }

            $result = Get-IISConfigSummary

            if ($result.Sites.Count -ne 1) {
                throw "Expected 1 site row, got $($result.Sites.Count)."
            }

            $site = $result.Sites[0]

            if ($site.PSObject.TypeNames[0] -ne 'IISDiagnostics.ConfigSummary.Site') {
                throw "Expected IISDiagnostics.ConfigSummary.Site type, got '$($site.PSObject.TypeNames[0])'."
            }

            if ($site.SiteName -ne 'MySite') {
                throw "Expected site name 'MySite', got '$($site.SiteName)'."
            }

            if ($site.SiteId -ne 2) {
                throw "Expected site ID 2, got $($site.SiteId)."
            }

            if ($site.ApplicationPool -ne 'MyPool') {
                throw "Expected application pool 'MyPool', got '$($site.ApplicationPool)'."
            }
        }
    }

    It 'W3CLogPaths rows have expected type and properties' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Assert-WebAdminModule  {}

            Mock Get-ChildItem {
                param($Path)
                if ($Path -eq 'IIS:\Sites') {
                    return @(
                        [pscustomobject]@{
                            Id              = 1
                            Name            = 'Default Web Site'
                            State           = 'Started'
                            ApplicationPool = 'DefaultAppPool'
                            Bindings        = [pscustomobject]@{ Collection = @() }
                        }
                    )
                }
                return @()
            }

            $resolvedLogPath = 'C:\inetpub\logs\LogFiles\W3SVC1'

            Mock Get-IISSiteW3CLogDirectoryRaw { return '%SystemDrive%\inetpub\logs\LogFiles' }
            Mock Resolve-W3CSiteLogDirectory   { return $resolvedLogPath }
            Mock Expand-IISDiagnosticsLogPath  { param($Path) return $Path }
            Mock Test-Path                     {
                param($LiteralPath, $PathType)
                return $LiteralPath -eq $resolvedLogPath
            }
            Mock Get-HttpErrLogDirectoryCandidates { return @() }

            $result = Get-IISConfigSummary

            if ($result.W3CLogPaths.Count -ne 1) {
                throw "Expected 1 W3CLogPath row, got $($result.W3CLogPaths.Count)."
            }

            $entry = $result.W3CLogPaths[0]

            if ($entry.PSObject.TypeNames[0] -ne 'IISDiagnostics.ConfigSummary.W3CLogPath') {
                throw "Expected IISDiagnostics.ConfigSummary.W3CLogPath type, got '$($entry.PSObject.TypeNames[0])'."
            }

            if ($entry.ResolvedPath -ne $resolvedLogPath) {
                throw "Expected ResolvedPath '$resolvedLogPath', got '$($entry.ResolvedPath)'."
            }

            if (-not $entry.Exists) {
                throw 'Expected Exists to be true when directory exists on disk.'
            }
        }
    }

    It 'HttpErrLogPath is set when HTTPERR directory exists' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Assert-WebAdminModule  {}
            Mock Get-ChildItem          { return @() }
            Mock Get-IISSiteW3CLogDirectoryRaw { return $null }
            Mock Resolve-W3CSiteLogDirectory   { return $null }
            Mock Expand-IISDiagnosticsLogPath  { param($Path) return $Path }

            Mock Get-HttpErrLogDirectoryCandidates {
                return @('C:\Windows\System32\LogFiles\HTTPERR')
            }

            Mock Test-Path {
                param($LiteralPath, $PathType)
                return ($LiteralPath -eq 'C:\Windows\System32\LogFiles\HTTPERR')
            }

            $result = Get-IISConfigSummary

            if ($result.HttpErrLogPath -ne 'C:\Windows\System32\LogFiles\HTTPERR') {
                throw "Expected HttpErrLogPath 'C:\Windows\System32\LogFiles\HTTPERR', got '$($result.HttpErrLogPath)'."
            }
        }
    }

    It 'resolves SpecificUser identity type and includes UserName' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Assert-WebAdminModule  {}

            Mock Get-ChildItem {
                param($Path)
                if ($Path -eq 'IIS:\AppPools') {
                    return @(
                        [pscustomobject]@{
                            Name         = 'ServicePool'
                            State        = 'Started'
                            ProcessModel = [pscustomobject]@{
                                IdentityType = 'SpecificUser'
                                UserName     = 'DOMAIN\svcAccount'
                            }
                            ManagedPipelineMode   = 'Integrated'
                            ManagedRuntimeVersion = 'v4.0'
                        }
                    )
                }
                return @()
            }

            Mock Get-IISSiteW3CLogDirectoryRaw     { return $null }
            Mock Resolve-W3CSiteLogDirectory        { return $null }
            Mock Expand-IISDiagnosticsLogPath       { param($Path) return $Path }
            Mock Test-Path                          { return $false }
            Mock Get-HttpErrLogDirectoryCandidates  { return @() }

            $result = Get-IISConfigSummary
            $pool   = $result.AppPools[0]

            if ($pool.IdentityType -ne 'SpecificUser') {
                throw "Expected IdentityType 'SpecificUser', got '$($pool.IdentityType)'."
            }

            if ($pool.UserName -ne 'DOMAIN\svcAccount') {
                throw "Expected UserName 'DOMAIN\svcAccount', got '$($pool.UserName)'."
            }
        }
    }

    It 'maps numeric identity type 4 to ApplicationPoolIdentity' {
        InModuleScope IISDiagnostics {
            Mock Assert-ElevatedSession {}
            Mock Assert-WebAdminModule  {}

            Mock Get-ChildItem {
                param($Path)
                if ($Path -eq 'IIS:\AppPools') {
                    return @(
                        [pscustomobject]@{
                            Name         = 'MappedPool'
                            State        = 'Started'
                            ProcessModel = [pscustomobject]@{
                                IdentityType = '4'  # integer form from configuration API
                                UserName     = ''
                            }
                            ManagedPipelineMode   = 'Integrated'
                            ManagedRuntimeVersion = 'v4.0'
                        }
                    )
                }
                return @()
            }

            Mock Get-IISSiteW3CLogDirectoryRaw     { return $null }
            Mock Resolve-W3CSiteLogDirectory        { return $null }
            Mock Expand-IISDiagnosticsLogPath       { param($Path) return $Path }
            Mock Test-Path                          { return $false }
            Mock Get-HttpErrLogDirectoryCandidates  { return @() }

            $result = Get-IISConfigSummary
            $pool   = $result.AppPools[0]

            if ($pool.IdentityType -ne 'ApplicationPoolIdentity') {
                throw "Expected IdentityType 'ApplicationPoolIdentity' after mapping '4', got '$($pool.IdentityType)'."
            }
        }
    }
}
