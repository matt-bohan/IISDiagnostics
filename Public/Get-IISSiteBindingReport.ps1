#Requires -Version 5.1

function Get-IISSiteBindingReport {
    <#
    .SYNOPSIS
        Returns IIS site bindings enriched with SSL certificate details, expiry status,
        SNI configuration, and wildcard detection.

    .DESCRIPTION
        Enumerates sites and their bindings from the IIS:\Sites drive, then for each HTTPS
        binding resolves the bound certificate through HTTP.sys's SSL binding table
        (IIS:\SslBindings) into the machine certificate store.

        For each binding, the output includes:

          Binding configuration
            Protocol, IP address, port, hostname, site name and ID, site state.

          SSL / TLS details (HTTPS bindings only)
            Whether the binding uses SNI (Server Name Indication) or is IP-based.
            Whether it uses the IIS Central Certificate Store.
            The raw sslFlags value for reference.

          Certificate details
            Thumbprint, subject, issuer, expiry date, days remaining.
            Subject Alternative Names (SANs) from the certificate extension.
            Whether the certificate is a wildcard (CN or any SAN starts with *.).

          Expiry status
            Valid        - certificate is present and not near expiry
            ExpiringSoon - within -WarnDaysRemaining days of expiry (default: 30)
            Expired      - certificate has already expired
            NoCertificate - HTTPS binding exists but no certificate could be resolved
            NotHttps     - non-HTTPS binding, no certificate applicable

          Notices
            Pre-computed observations used by Invoke-IISDiagnosticSweep. Populated when
            a certificate is expired, expiring soon, missing from a live binding, or when
            a wildcard certificate is bound (noted as informational, not a problem).

        Certificate stores searched (in order):
            Cert:\LocalMachine\My          (Personal - most common for IIS)
            Cert:\LocalMachine\WebHosting  (IIS Web Hosting store)

    .PARAMETER SiteName
        Name of the IIS site to query. Accepts wildcards. Defaults to all sites.

    .PARAMETER WarnDaysRemaining
        Number of days before expiry at which a certificate is flagged as ExpiringSoon.
        Default: 30. Set to 0 to suppress expiry warnings.

    .PARAMETER IncludeNonHttps
        Include HTTP, net.tcp, and other non-HTTPS bindings in the output.
        By default, non-HTTPS bindings are included but their certificate fields are
        empty and ExpiryStatus is NotHttps.

    .EXAMPLE
        Get-IISSiteBindingReport

        Returns all bindings for all sites.

    .EXAMPLE
        Get-IISSiteBindingReport -SiteName 'Default Web Site'

        Returns bindings for a specific site.

    .EXAMPLE
        Get-IISSiteBindingReport | Where-Object ExpiryStatus -eq 'ExpiringSoon'

        Returns bindings whose certificate expires within 30 days.

    .EXAMPLE
        Get-IISSiteBindingReport -WarnDaysRemaining 60 |
            Where-Object ExpiryStatus -in 'ExpiringSoon','Expired' |
            Select-Object SiteName, HostName, CertExpiry, DaysUntilExpiry

        Certificate expiry report with a 60-day warning horizon.

    .EXAMPLE
        Get-IISSiteBindingReport | Where-Object IsWildcard | Select-Object SiteName, CertSubject, SubjectAltNames

        Lists all wildcard certificate bindings.

    .NOTES
        Requires an elevated session and the WebAdministration module.
        The WebAdministration module is installed with the IIS Management tools feature:
          Install-WindowsFeature -Name Web-Scripting-Tools
    #>
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

    Assert-ElevatedSession -CmdletName $MyInvocation.MyCommand.Name
    Assert-WebAdminModule  -CmdletName $MyInvocation.MyCommand.Name

    # Treat absent, empty, or whitespace-only SiteName as "all sites"
    $siteFilter = if ([string]::IsNullOrWhiteSpace($SiteName)) { '*' } else { $SiteName }

    # ------------------------------------------------------------------
    # Build SSL binding lookup table from IIS:\SslBindings
    #
    # HTTP.sys maintains one entry per bound certificate, keyed by
    # either "ip!port" (IP-based) or "ip!port!hostname" (SNI).
    # We index by both formats so HTTPS binding lookups are O(1).
    #
    # sslFlags meaning (bitmask):
    #   0 = IP-based SSL
    #   1 = SNI (Server Name Indication)
    #   2 = Central Certificate Store
    #   3 = SNI + Central Certificate Store
    # ------------------------------------------------------------------
    $sslBindingMap = @{}

    try {
        $sslBindings = @(Get-ChildItem 'IIS:\SslBindings' -ErrorAction Stop)
        foreach ($ssl in $sslBindings) {
            $ip       = if ([string]::IsNullOrWhiteSpace($ssl.IPAddress) -or $ssl.IPAddress -eq '0.0.0.0') { '0.0.0.0' } else { $ssl.IPAddress }
            $port     = $ssl.Port
            $sniHost  = try { [string]$ssl.Host } catch { '' }

            # Store under both key formats; the site binding lookup will try both
            $ipPortKey = "$ip!$port"
            $sniKey    = "$ip!$port!$sniHost"

            $entry = @{
                Thumbprint         = [string]$ssl.Thumbprint
                Store              = [string]$ssl.Store
                Host               = $sniHost
                IsSni              = (-not [string]::IsNullOrWhiteSpace($sniHost))
            }

            $sslBindingMap[$ipPortKey] = $entry
            if ($entry.IsSni) { $sslBindingMap[$sniKey] = $entry }
        }
        Write-Verbose "Loaded $($sslBindingMap.Count) SSL binding(s) from IIS:\SslBindings."
    }
    catch {
        Write-Warning "Could not read IIS:\SslBindings: $_. Certificate details will not be available."
    }

    # ------------------------------------------------------------------
    # Certificate store lookup helper
    # Searches Personal then WebHosting store by thumbprint.
    # Returns $null if not found.
    # ------------------------------------------------------------------
    $certCache = @{}

    function Resolve-Certificate([string]$Thumbprint) {
        if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
        $clean = $Thumbprint.ToUpperInvariant() -replace '\s', ''

        if ($certCache.ContainsKey($clean)) { return $certCache[$clean] }

        $cert = $null
        foreach ($store in @('My', 'WebHosting')) {
            $storePath = "Cert:\LocalMachine\$store"
            if (-not (Test-Path $storePath)) { continue }
            $cert = Get-ChildItem $storePath -ErrorAction SilentlyContinue |
                    Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $clean } |
                    Select-Object -First 1
            if ($cert) { break }
        }

        $certCache[$clean] = $cert   # cache $null too so we don't re-query missing certs
        return $cert
    }

    # ------------------------------------------------------------------
    # SAN extraction helper
    # The Subject Alternative Names extension OID is 2.5.29.17.
    # The formatted value looks like: "DNS Name=www.example.com\r\nDNS Name=example.com"
    # ------------------------------------------------------------------
    function Get-SubjectAltNames([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
        if (-not $Cert) { return @() }
        try {
            $sanExt = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
            if (-not $sanExt) { return @() }

            # AsnEncodedData.Format(multiline: $false) returns comma-separated on some OS versions,
            # newline-separated on others. Split on both and normalise.
            $formatted = $sanExt.Format($false)
            $entries   = $formatted -split '[,\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

            # Entries are like "DNS Name=www.example.com" - extract the value portion
            return @($entries | ForEach-Object {
                if ($_ -match '=(.+)$') { $Matches[1].Trim() } else { $_ }
            } | Where-Object { $_ })
        }
        catch {
            Write-Verbose "  SAN extraction failed: $_"
            return @()
        }
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
                    "Failed to enumerate sites from IIS:\Sites. " +
                    "Verify IIS is installed and running. Error: $_"),
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

    Write-Verbose "Processing $($sites.Count) site(s)."

    foreach ($site in $sites) {
        $siteName  = $site.Name
        $siteId    = [int]$site.Id
        $siteState = try { [string]$site.State } catch { 'Unknown' }

        Write-Verbose "Site: $siteName (ID: $siteId, State: $siteState)"

        # Bindings are stored as a collection on the site object
        $bindings = try {
            @($site.Bindings.Collection)
        }
        catch {
            Write-Warning "  Could not read bindings for site '$siteName': $_"
            continue
        }

        foreach ($binding in $bindings) {
            # Binding information string format: "ip:port:hostname"
            $bindingInfo = [string]$binding.BindingInformation
            $protocol    = [string]$binding.Protocol

            # Parse the binding information string
            $ip       = $null
            $port     = $null
            $hostName = $null

            if ($bindingInfo -match '^([^:]*):(\d+):(.*)$') {
                $ip       = if ([string]::IsNullOrWhiteSpace($Matches[1])) { '*' } else { $Matches[1] }
                $port     = [int]$Matches[2]
                $hostName = if ([string]::IsNullOrWhiteSpace($Matches[3])) { $null } else { $Matches[3] }
            }
            else {
                # Non-TCP bindings (net.tcp, net.pipe) have different formats - record what we have
                $ip   = $null
                $port = $null
            }

            $isHttps = ($protocol -eq 'https')

            # Non-HTTPS - emit if IncludeNonHttps or if the caller wants everything
            if (-not $isHttps) {
                if (-not $IncludeNonHttps) { continue }

                [pscustomobject]@{
                    PSTypeName          = 'IISDiagnostics.SiteBinding'
                    SiteName            = $siteName
                    SiteId              = $siteId
                    SiteState           = $siteState
                    Protocol            = $protocol
                    IPAddress           = $ip
                    Port                = $port
                    HostName            = $hostName
                    IsSni               = $false
                    IsCentralCertStore  = $false
                    SslFlags            = $null
                    CertThumbprint      = $null
                    CertSubject         = $null
                    CertIssuer          = $null
                    CertExpiry          = $null
                    DaysUntilExpiry     = $null
                    ExpiryStatus        = 'NotHttps'
                    IsWildcard          = $false
                    SubjectAltNames     = @()
                    Notices             = @()
                }
                continue
            }

            # ------------------------------------------------------------------
            # HTTPS binding - resolve SSL flags and look up the certificate
            # ------------------------------------------------------------------
            $rawSslFlags     = try { [int]$binding.SslFlags } catch { 0 }
            $isSni           = ($rawSslFlags -band 1) -ne 0
            $isCentralStore  = ($rawSslFlags -band 2) -ne 0

            # Build the lookup keys for IIS:\SslBindings
            # Normalise IP: IIS stores '*' as an address, HTTP.sys uses 0.0.0.0
            $lookupIp = if ($ip -eq '*' -or [string]::IsNullOrWhiteSpace($ip)) { '0.0.0.0' } else { $ip }

            $sslEntry = $null
            if ($isSni -and $hostName) {
                $sniLookup = "$lookupIp!$port!$hostName"
                if ($sslBindingMap.ContainsKey($sniLookup)) {
                    $sslEntry = $sslBindingMap[$sniLookup]
                }
            }
            # Fall through to IP-based lookup if SNI lookup missed or binding is IP-based
            if (-not $sslEntry) {
                $ipLookup = "$lookupIp!$port"
                if ($sslBindingMap.ContainsKey($ipLookup)) {
                    $sslEntry = $sslBindingMap[$ipLookup]
                }
            }

            $thumbprint = if ($sslEntry) { $sslEntry.Thumbprint } else { $null }
            $cert       = Resolve-Certificate -Thumbprint $thumbprint

            # ------------------------------------------------------------------
            # Certificate properties
            # ------------------------------------------------------------------
            $certSubject  = $null
            $certIssuer   = $null
            $certExpiry   = $null
            $daysLeft     = $null
            $isWildcard   = $false
            $sans         = @()
            $expiryStatus = 'NoCertificate'

            if ($cert) {
                $certSubject = $cert.Subject
                $certIssuer  = $cert.Issuer
                $certExpiry  = $cert.NotAfter
                $daysLeft    = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0)
                $sans        = Get-SubjectAltNames -Cert $cert

                # Wildcard detection - CN starts with *. or any SAN does
                $cnMatch    = $certSubject -match 'CN=(\*\.[^,]+)'
                $isWildcard = $cnMatch -or ($sans | Where-Object { $_ -like '*.*' -and $_ -match '^\*\.' }).Count -gt 0

                $expiryStatus = if ($daysLeft -lt 0) { 'Expired' }
                                elseif ($WarnDaysRemaining -gt 0 -and $daysLeft -le $WarnDaysRemaining) { 'ExpiringSoon' }
                                else { 'Valid' }
            }
            elseif ($thumbprint) {
                # Thumbprint recorded in SSL bindings but cert not found in any store
                $expiryStatus = 'NoCertificate'
            }

            # ------------------------------------------------------------------
            # Notices
            # ------------------------------------------------------------------
            $notices = [System.Collections.Generic.List[string]]::new()

            switch ($expiryStatus) {
                'Expired' {
                    $notices.Add(
                        "Certificate expired $([math]::Abs($daysLeft)) day(s) ago " +
                        "($($certExpiry.ToString('dd/MM/yyyy'))). " +
                        "HTTPS connections to this binding will fail with a certificate error."
                    )
                }
                'ExpiringSoon' {
                    $notices.Add(
                        "Certificate expires in $daysLeft day(s) on $($certExpiry.ToString('dd/MM/yyyy')). " +
                        "Plan renewal before expiry to avoid service disruption."
                    )
                }
                'NoCertificate' {
                    if ($thumbprint) {
                        $notices.Add(
                            "HTTPS binding references thumbprint $thumbprint but no matching certificate " +
                            "was found in Cert:\LocalMachine\My or Cert:\LocalMachine\WebHosting. " +
                            "HTTPS connections will fail. Verify the certificate is installed on this server."
                        )
                    }
                    elseif ($siteState -eq 'Started') {
                        $notices.Add(
                            "HTTPS binding on port $port has no certificate bound. " +
                            "HTTPS connections will fail. Bind a certificate via IIS Manager or " +
                            "netsh http add sslcert."
                        )
                    }
                }
            }

            if ($isWildcard) {
                $sans_preview = if ($sans.Count -gt 0) { " (SANs: $($sans -join ', '))" } else { '' }
                $notices.Add(
                    "Wildcard certificate bound: $certSubject$sans_preview. " +
                    "Confirm the wildcard covers the intended hostnames for this binding."
                )
            }

            if ($isSni -and -not $hostName) {
                $notices.Add(
                    "Binding has SNI flag set (sslFlags=1) but no hostname is configured. " +
                    "SNI requires a hostname; without one HTTP.sys will not match SNI ClientHello " +
                    "messages correctly. Review the binding configuration in IIS Manager."
                )
            }

            if (-not $isSni -and $hostName -and $isHttps) {
                # Has a hostname but SNI is not set - unusual, may cause cert selection issues
                # when multiple HTTPS bindings share the same port
                $notices.Add(
                    "HTTPS binding has a hostname ('$hostName') but SNI is not enabled. " +
                    "On servers with multiple HTTPS sites on the same port, SNI is required " +
                    "for correct certificate selection per hostname."
                )
            }

            # ------------------------------------------------------------------
            # Emit
            # ------------------------------------------------------------------
            Write-Verbose "  Binding: $protocol $ip`:$port`:$hostName - $expiryStatus"

            [pscustomobject]@{
                PSTypeName         = 'IISDiagnostics.SiteBinding'
                SiteName           = $siteName
                SiteId             = $siteId
                SiteState          = $siteState
                Protocol           = $protocol
                IPAddress          = $ip
                Port               = $port
                HostName           = $hostName
                IsSni              = $isSni
                IsCentralCertStore = $isCentralStore
                SslFlags           = $rawSslFlags
                CertThumbprint     = $thumbprint
                CertSubject        = $certSubject
                CertIssuer         = $certIssuer
                CertExpiry         = $certExpiry
                DaysUntilExpiry    = $daysLeft
                ExpiryStatus       = $expiryStatus
                IsWildcard         = $isWildcard
                SubjectAltNames    = $sans
                Notices            = $notices.ToArray()
            }
        }
    }
}