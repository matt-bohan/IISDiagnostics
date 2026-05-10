#Requires -Version 5.1

function Get-IISSiteConfiguration {
    <#
    .SYNOPSIS
        Returns the configuration of IIS sites - physical path, identity permissions,
        authentication methods, and request filtering limits.

    .DESCRIPTION
        Bridges the gap between IIS log analysis and root-cause diagnosis by surfacing
        configuration that cannot be read from logs alone.

        Common problems that produce errors in W3C and HTTPERR logs but whose cause is
        only visible in configuration:

          Physical path missing or wrong (→ 404, 500)
            The site's root physical path does not exist on disk, or points to the wrong
            location. Common after deployments that move or rename application folders.

          App pool identity has no read access (→ 500, Win32 status 5)
            The worker process cannot read web.config or application files because the
            app pool identity was not granted access to the physical path. Particularly
            common with ApplicationPoolIdentity after a path change.

          Authentication misconfiguration (→ 401.x)
            Windows Authentication enabled but no providers configured, Anonymous
            Authentication disabled on a public-facing site, or both Anonymous and
            Windows Authentication enabled simultaneously without intent.

          Request filtering rejecting legitimate requests (→ 400, 404.x, 413)
            MaxAllowedContentLength too low for file uploads, MaxUrl too short for
            long query strings, or blocked extensions interfering with application routes.

        For each site the output includes:

          Physical path
            Whether the configured path exists, whether it is a UNC path (network-dependent),
            and whether a web.config is present.

          Permission check
            Searches the path ACL for explicit Access Control Entries matching the app pool
            identity. Reports the rights found. Does not resolve group membership chains -
            see the Status and Detail fields for what the check can and cannot confirm.

          Authentication configuration
            State of each IIS authentication module plus ASP.NET Forms Authentication.
            Flags combinations that are often misconfigured.

          Request filtering limits
            Maximum content length, URL length, query string length, and any non-default
            blocked extensions or verbs.

          Notices
            Pre-computed observations that warrant investigation - not assertions of broken
            configuration, but specific conditions worth reviewing.

        Scope: root application of each site only. Virtual directories and sub-applications
        within a site are not included in this release.

    .PARAMETER SiteName
        Name of the site(s) to query. Accepts wildcards. Defaults to all sites.

    .PARAMETER SkipPermissionCheck
        Skip the ACL check on the physical path. Use when the identity cannot be resolved
        (e.g. SpecificUser on a domain account that is not reachable from this server).

    .EXAMPLE
        Get-IISSiteConfiguration

        Configuration for all sites.

    .EXAMPLE
        Get-IISSiteConfiguration -SiteName 'My Web Site'

        Configuration for a specific site.

    .EXAMPLE
        Get-IISSiteConfiguration | Where-Object PhysicalPathStatus -ne 'Exists'

        Sites whose physical path is missing or cannot be verified.

    .EXAMPLE
        Get-IISSiteConfiguration |
            Where-Object { $_.PathPermissions.Status -notin 'OK','NotRequired' }

        Sites where the app pool identity has no confirmed ACE on the physical path.

    .EXAMPLE
        Get-IISSiteConfiguration | Where-Object { $_.Notices.Count -gt 0 } | Format-List

        Full detail for any site with notices.

    .EXAMPLE
        Get-IISSiteConfiguration |
            Select-Object SiteName, PhysicalPathStatus, @{n='Auth';e={ $_.Authentication.EnabledMethods -join ', ' }}, @{n='Notices';e={$_.Notices.Count}}

        Quick summary table.

    .NOTES
        Requires an elevated session and the WebAdministration module.

        The permission check reads explicit ACEs from the path ACL. Access granted via
        NTFS inheritance or Windows group membership is not resolved - the check shows
        what is directly visible in the ACL, not the full effective permissions. Use
        icacls.exe or Get-Acl for a complete view.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [SupportsWildcards()]
        [string]$SiteName,

        [Parameter()]
        [switch]$SkipPermissionCheck
    )

    Assert-ElevatedSession -CmdletName $MyInvocation.MyCommand.Name
    Assert-WebAdminModule  -CmdletName $MyInvocation.MyCommand.Name

    $siteFilter = if ([string]::IsNullOrWhiteSpace($SiteName)) { '*' } else { $SiteName }

    # ------------------------------------------------------------------
    # Helper: read a WebAdministration configuration property safely,
    # returning $null rather than throwing when the property or feature
    # is not present (e.g. Basic Auth module not installed).
    # ------------------------------------------------------------------
    function Get-WebProp {
        param([string]$Filter, [string]$Location, [string]$Name)
        try {
            $val = Get-WebConfigurationProperty `
                        -Filter   $Filter `
                        -PSPath   'IIS:\' `
                        -Location $Location `
                        -Name     $Name `
                        -ErrorAction SilentlyContinue
            if ($null -eq $val) { return $null }
            # ConfigurationAttribute wraps the value - unwrap it
            if ($val.PSObject.Properties['Value']) { return $val.Value }
            return $val
        }
        catch { return $null }
    }

    # ------------------------------------------------------------------
    # Helper: read a collection property (e.g. Windows Auth providers)
    # ------------------------------------------------------------------
    function Get-WebCollection {
        param([string]$Filter, [string]$Location)
        try {
            @(Get-WebConfiguration -Filter $Filter -PSPath 'IIS:\' -Location $Location `
                -ErrorAction SilentlyContinue)
        }
        catch { @() }
    }

    # ------------------------------------------------------------------
    # Enumerate sites
    # ------------------------------------------------------------------
    try {
        $sites = @(Get-ChildItem 'IIS:\Sites' -ErrorAction Stop |
                   Where-Object { $_.Name -like $siteFilter })
    }
    catch {
        $PSCmdlet.ThrowTerminatingError(
            [System.Management.Automation.ErrorRecord]::new(
                [System.InvalidOperationException]::new(
                    "Failed to enumerate sites from IIS:\Sites. Error: $_"),
                'SiteEnumerationFailed',
                [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
                'IIS:\Sites'
            )
        )
    }

    if (-not $sites) {
        Write-Warning "No IIS sites found matching '$siteFilter'."
        return
    }

    # Pre-load all app pools once so we can look up identity by pool name
    $poolMap = @{}
    try {
        Get-ChildItem 'IIS:\AppPools' -ErrorAction SilentlyContinue | ForEach-Object {
            $identityType = try {
                $raw = [string]$_.ProcessModel.IdentityType
                if ($script:IdentityTypeMap -and $script:IdentityTypeMap.ContainsKey($raw)) {
                    $script:IdentityTypeMap[$raw]
                } else { $raw }
            } catch { 'Unknown' }

            $poolMap[$_.Name] = [pscustomobject]@{
                IdentityType = $identityType
                UserName     = try { [string]$_.ProcessModel.UserName } catch { $null }
            }
        }
    }
    catch {
        Write-Verbose "Could not pre-load app pool identities: $_"
    }

    foreach ($site in $sites) {
        $name    = $site.Name
        $siteId  = [int]$site.Id
        $state   = try { [string]$site.State } catch { 'Unknown' }
        $poolName = try { [string]$site.ApplicationPool } catch { $null }

        Write-Verbose "Processing site: $name"

        # ------------------------------------------------------------------
        # Physical path
        # ------------------------------------------------------------------
        $rawPath      = try { [string]$site.PhysicalPath } catch { $null }

        # Expand environment variables (%SystemDrive%, %windir% etc.)
        $expandedPath = if ($rawPath) {
            try { [System.Environment]::ExpandEnvironmentVariables($rawPath) }
            catch { $rawPath }
        } else { $null }

        $isUnc        = $expandedPath -match '^\\\\' -or $expandedPath -match '^//'
        $pathExists   = $false
        $webConfigPresent = $false
        $pathStatus   = 'Unknown'

        if ($expandedPath) {
            if ($isUnc) {
                $pathStatus = 'UncPath'
                try {
                    $pathExists       = Test-Path -LiteralPath $expandedPath -ErrorAction SilentlyContinue
                    $webConfigPresent = Test-Path -LiteralPath (Join-Path $expandedPath 'web.config') -ErrorAction SilentlyContinue
                } catch { }
            }
            else {
                try {
                    $pathExists       = Test-Path -LiteralPath $expandedPath -PathType Container -ErrorAction SilentlyContinue
                    $webConfigPresent = $pathExists -and (Test-Path -LiteralPath (Join-Path $expandedPath 'web.config') -ErrorAction SilentlyContinue)
                    $pathStatus       = if ($pathExists) { 'Exists' } else { 'Missing' }
                } catch {
                    $pathStatus = 'AccessDenied'
                }
            }
        }
        else {
            $pathStatus = 'NotConfigured'
        }

        # ------------------------------------------------------------------
        # Permission check
        # ------------------------------------------------------------------
        $poolInfo     = if ($poolName -and $poolMap.ContainsKey($poolName)) { $poolMap[$poolName] } else { $null }
        $identityType = if ($poolInfo) { $poolInfo.IdentityType } else { 'Unknown' }
        $identityUser = if ($poolInfo) { $poolInfo.UserName     } else { $null }

        $pathPermissions = if ($SkipPermissionCheck) {
            [pscustomobject]@{
                PSTypeName        = 'IISDiagnostics.PathPermissions'
                CheckPerformed    = $false
                Status            = 'Skipped'
                EffectiveIdentity = $null
                AccessRights      = $null
                Detail            = 'Permission check skipped (-SkipPermissionCheck).'
            }
        }
        elseif (-not $pathExists -or $isUnc) {
            [pscustomobject]@{
                PSTypeName        = 'IISDiagnostics.PathPermissions'
                CheckPerformed    = $false
                Status            = if ($isUnc) { 'Skipped' } else { 'PathMissing' }
                EffectiveIdentity = $null
                AccessRights      = $null
                Detail            = if ($isUnc) {
                    'UNC path - permission check not performed. Verify network share permissions manually.'
                } else {
                    'Physical path does not exist - permission check not applicable.'
                }
            }
        }
        elseif ($identityType -eq 'Unknown') {
            [pscustomobject]@{
                PSTypeName        = 'IISDiagnostics.PathPermissions'
                CheckPerformed    = $false
                Status            = 'CheckFailed'
                EffectiveIdentity = $null
                AccessRights      = $null
                Detail            = "Could not determine the identity type for pool '$poolName'."
            }
        }
        else {
            Get-PathPermissionsForIdentity `
                -Path         $expandedPath `
                -IdentityType $identityType `
                -UserName     $identityUser `
                -PoolName     $poolName
        }

        # ------------------------------------------------------------------
        # Authentication configuration
        # ------------------------------------------------------------------
        $anonEnabled  = Get-WebProp 'system.webServer/security/authentication/anonymousAuthentication' $name 'enabled'
        $anonUser     = Get-WebProp 'system.webServer/security/authentication/anonymousAuthentication' $name 'userName'
        $winEnabled   = Get-WebProp 'system.webServer/security/authentication/windowsAuthentication'   $name 'enabled'
        $basicEnabled = Get-WebProp 'system.webServer/security/authentication/basicAuthentication'     $name 'enabled'
        $digestEnabled = Get-WebProp 'system.webServer/security/authentication/digestAuthentication'   $name 'enabled'
        $certEnabled   = Get-WebProp 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication' $name 'enabled'

        # Windows Auth providers (order matters - Negotiate before NTLM = Kerberos first)
        $winProviders = @(Get-WebCollection `
            'system.webServer/security/authentication/windowsAuthentication/providers/add' $name |
            ForEach-Object { try { [string]$_.Value } catch { [string]$_.Name } } |
            Where-Object { $_ })

        # ASP.NET Forms Auth (system.web, not system.webServer)
        $formsAuthMode = Get-WebProp 'system.web/authentication' $name 'mode'
        $formsEnabled  = ($formsAuthMode -eq 'Forms')

        $enabledMethods = [System.Collections.Generic.List[string]]::new()
        if ($anonEnabled  -eq $true) { $enabledMethods.Add('Anonymous') }
        if ($winEnabled   -eq $true) { $enabledMethods.Add('Windows') }
        if ($basicEnabled -eq $true) { $enabledMethods.Add('Basic') }
        if ($digestEnabled -eq $true) { $enabledMethods.Add('Digest') }
        if ($certEnabled   -eq $true) { $enabledMethods.Add('ClientCertificate') }
        if ($formsEnabled)            { $enabledMethods.Add('Forms (ASP.NET)') }

        $auth = [pscustomobject]@{
            PSTypeName              = 'IISDiagnostics.AuthConfig'
            AnonymousEnabled        = $anonEnabled  -eq $true
            AnonymousUser           = if ($anonUser) { [string]$anonUser } else { $null }
            WindowsAuthEnabled      = $winEnabled   -eq $true
            WindowsAuthProviders    = $winProviders
            BasicAuthEnabled        = $basicEnabled -eq $true
            DigestAuthEnabled       = $digestEnabled -eq $true
            ClientCertEnabled       = $certEnabled   -eq $true
            FormsAuthEnabled        = $formsEnabled
            EnabledMethods          = $enabledMethods.ToArray()
        }

        # ------------------------------------------------------------------
        # Request filtering
        # ------------------------------------------------------------------
        $maxContentLength = Get-WebProp 'system.webServer/security/requestFiltering/requestLimits' $name 'maxAllowedContentLength'
        $maxUrl           = Get-WebProp 'system.webServer/security/requestFiltering/requestLimits' $name 'maxUrl'
        $maxQueryString   = Get-WebProp 'system.webServer/security/requestFiltering/requestLimits' $name 'maxQueryString'

        $blockedExtensions = @(Get-WebCollection `
            'system.webServer/security/requestFiltering/fileExtensions/add' $name |
            Where-Object { try { -not [bool]$_.allowed } catch { $false } } |
            ForEach-Object { try { [string]$_.fileExtension } catch { $null } } |
            Where-Object { $_ })

        $blockedVerbs = @(Get-WebCollection `
            'system.webServer/security/requestFiltering/verbs/add' $name |
            Where-Object { try { -not [bool]$_.allowed } catch { $false } } |
            ForEach-Object { try { [string]$_.verb } catch { $null } } |
            Where-Object { $_ })

        $maxAllowedContentLengthBytes = try { [long]$maxContentLength } catch { $null }
        $maxUrlLength = try { [int]$maxUrl } catch { $null }
        $maxQueryStringLength = try { [int]$maxQueryString } catch { $null }

        $requestFiltering = [pscustomobject] @{
            PSTypeName                  = 'IISDiagnostics.RequestFilteringConfig'
            MaxAllowedContentLengthBytes = $maxAllowedContentLengthBytes
            MaxUrlLength                = $maxUrlLength
            MaxQueryStringLength        = $maxQueryStringLength
            BlockedExtensions           = $blockedExtensions
            BlockedVerbs                = $blockedVerbs
        }

        # ------------------------------------------------------------------
        # Notices
        # ------------------------------------------------------------------
        $notices = [System.Collections.Generic.List[string]]::new()

        # Physical path
        if ($pathStatus -eq 'Missing') {
            $notices.Add(
                "Physical path '$expandedPath' does not exist on disk. " +
                "All requests will fail with a 404 or 500. " +
                "Verify the path is correct and the directory has been created."
            )
        }
        elseif ($pathStatus -eq 'NotConfigured') {
            $notices.Add("No physical path is configured for this site.")
        }
        elseif ($pathStatus -eq 'UncPath') {
            $state_str = if ($pathExists) { 'reachable' } else { 'not reachable from this server' }
            $notices.Add(
                "Physical path is a UNC path ($expandedPath) - $state_str. " +
                "UNC paths depend on network availability and require the app pool identity " +
                "to have access to the network share. Verify share permissions separately."
            )
        }

        if ($pathExists -and -not $webConfigPresent) {
            $notices.Add(
                "No web.config found in '$expandedPath'. " +
                "This is expected for static file sites but unusual for ASP.NET applications. " +
                "Verify the application was deployed correctly."
            )
        }

        # Permissions
        if ($pathPermissions.Status -eq 'NoExplicitAce') {
            $notices.Add(
                "No explicit ACE found for the app pool identity ($($pathPermissions.EffectiveIdentity)) on '$expandedPath'. " +
                "Access may be granted via inheritance or group membership - run " +
                "icacls '$expandedPath' to check effective permissions. " +
                "If the site is returning 500 errors with Win32 status 5, " +
                "grant the identity at least Read & Execute access."
            )
        }
        elseif ($pathPermissions.Status -eq 'ExplicitDeny') {
            $notices.Add(
                "Explicit Deny ACE found for '$($pathPermissions.EffectiveIdentity)' on '$expandedPath'. " +
                "This will prevent the worker process from reading application files regardless " +
                "of any Allow entries. Remove the Deny ACE or change the identity."
            )
        }

        # Authentication
        if ($enabledMethods.Count -eq 0) {
            $notices.Add(
                "No authentication methods are enabled. All requests will receive a 401 response. " +
                "Enable at least Anonymous Authentication for public sites or Windows Authentication " +
                "for intranet applications."
            )
        }

        if ($auth.WindowsAuthEnabled -and $auth.AnonymousEnabled) {
            $notices.Add(
                "Both Windows Authentication and Anonymous Authentication are enabled. " +
                "IIS will use Anonymous Authentication by default. Windows Authentication " +
                "will only activate when the application challenges with 401. " +
                "This is intentional for mixed-mode applications but unintentional for " +
                "pure intranet sites - disable Anonymous Authentication if all users should authenticate."
            )
        }

        if ($auth.WindowsAuthEnabled -and $winProviders.Count -eq 0) {
            $notices.Add(
                "Windows Authentication is enabled but no providers are configured. " +
                "Authentication will fail for all requests. " +
                "Add 'Negotiate' (for Kerberos/NTLM) or 'NTLM' as a provider in IIS Manager."
            )
        }

        if ($auth.WindowsAuthEnabled -and $winProviders.Count -gt 0) {
            $first = $winProviders[0]
            if ($first -ne 'Negotiate') {
                $notices.Add(
                    "Windows Authentication provider order: $($winProviders -join ', '). " +
                    "'Negotiate' is not first in the list. " +
                    "Kerberos (via Negotiate) is preferred over NTLM for security and performance. " +
                    "Consider moving 'Negotiate' to the top of the providers list."
                )
            }
        }

        if ($auth.BasicAuthEnabled) {
            $notices.Add(
                "Basic Authentication is enabled. Credentials are sent as Base64-encoded plaintext " +
                "and must be protected by HTTPS. Verify this site has a valid HTTPS binding."
            )
        }

        # Request filtering
        if ($requestFiltering.MaxAllowedContentLengthBytes -and
            $requestFiltering.MaxAllowedContentLengthBytes -lt 1048576) {
            $mb = [math]::Round($requestFiltering.MaxAllowedContentLengthBytes / 1MB, 2)
            $notices.Add(
                "MaxAllowedContentLength is set to $($requestFiltering.MaxAllowedContentLengthBytes) bytes ($mb MB). " +
                "Requests with bodies larger than this will receive a 413 or 404.13. " +
                "The IIS default is 30 MB (31457280). Increase if the application handles file uploads."
            )
        }

        if ($requestFiltering.MaxUrlLength -and $requestFiltering.MaxUrlLength -lt 2048) {
            $notices.Add(
                "MaxUrl is set to $($requestFiltering.MaxUrlLength) characters. " +
                "Requests with longer URLs will receive a 404.14. " +
                "The IIS default is 4096. Some web frameworks generate long URLs for deep routes."
            )
        }

        if ($blockedExtensions.Count -gt 0) {
            $notices.Add(
                "Request filtering is blocking the following file extensions: $($blockedExtensions -join ', '). " +
                "Requests for these extensions will receive a 404.7. " +
                "Verify these are intentional blocks and not causing application errors."
            )
        }

        if ($blockedVerbs.Count -gt 0) {
            $notices.Add(
                "Request filtering is blocking the following HTTP verbs: $($blockedVerbs -join ', '). " +
                "Requests using these methods will receive a 404.6. " +
                "REST APIs commonly require PUT, DELETE, and PATCH."
            )
        }

        # ------------------------------------------------------------------
        # Emit
        # ------------------------------------------------------------------
        [pscustomobject]@{
            PSTypeName            = 'IISDiagnostics.SiteConfiguration'
            SiteName              = $name
            SiteId                = $siteId
            SiteState             = $state
            AppPoolName           = $poolName
            IdentityType          = $identityType
            IdentityUserName      = $identityUser
            PhysicalPath          = $expandedPath
            PhysicalPathRaw       = $rawPath
            PhysicalPathStatus    = $pathStatus
            WebConfigPresent      = $webConfigPresent
            PathPermissions       = $pathPermissions
            Authentication        = $auth
            RequestFiltering      = $requestFiltering
            Notices               = $notices.ToArray()
        }
    }
}