#Requires -Version 5.1

function Get-IISSiteSummary {
    <#
    .SYNOPSIS
        Returns a one-row-per-site summary of IIS site state, bindings, and certificate health.

    .DESCRIPTION
        Calls Get-IISSiteBindingReport internally and collapses the per-binding results into a
        single IISDiagnostics.SiteSummary object per site, showing:

          - Site name, ID, and current state
          - Application pool name
          - Number of HTTP and HTTPS bindings
          - Worst certificate expiry status across all HTTPS bindings
          - The nearest (soonest-expiring) certificate and its days remaining
          - Total notice count across all bindings
          - A flat list of all notices for pipeline use or detail view

        Designed for a quick health check across all sites on a server before drilling
        into per-binding detail with Get-IISSiteBindingReport.

    .PARAMETER SiteName
        Name of the site(s) to summarise. Accepts wildcards. Defaults to all sites.

    .PARAMETER WarnDaysRemaining
        Passed through to Get-IISSiteBindingReport. Certificates expiring within this many days
        are flagged as ExpiringSoon. Default: 30.

    .EXAMPLE
        Get-IISSiteSummary

        One-line summary of every site on the server.

    .EXAMPLE
        Get-IISSiteSummary | Where-Object WorstCertStatus -ne 'Valid'

        Shows only sites with certificate problems or no HTTPS bindings.

    .EXAMPLE
        Get-IISSiteSummary | Sort-Object NearestExpiry | Format-Table

        Sites sorted by certificate expiry date - quickest expiring first.

    .EXAMPLE
        Get-IISSiteSummary | Where-Object NoticeCount -gt 0 |
            ForEach-Object { $_.Notices | ForEach-Object { "$($_.SiteName): $_" } }

        Prints every notice across all sites with the site name prepended.

    .NOTES
        Requires an elevated session and the WebAdministration module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [SupportsWildcards()]
        [string]$SiteName,

        [Parameter()]
        [ValidateRange(0, 3650)]
        [int]$WarnDaysRemaining = 30
    )

    Assert-ElevatedSession -CmdletName $MyInvocation.MyCommand.Name
    Assert-WebAdminModule  -CmdletName $MyInvocation.MyCommand.Name

    $siteFilter = if ([string]::IsNullOrWhiteSpace($SiteName)) { '*' } else { $SiteName }

    # Severity rank for rolling up worst status across bindings
    $statusRank = @{
        'Expired'        = 5
        'NoCertificate'  = 4
        'ExpiringSoon'   = 3
        'Valid'          = 2
        'NotHttps'       = 1
        'Unknown'        = 0
    }

    Write-Verbose "Collecting binding data for sites matching '$siteFilter'..."

    # Use module-qualified name to avoid colliding with the built-in WebAdministration cmdlet.
    $allBindings = @(IISDiagnostics\Get-IISSiteBindingReport -SiteName $siteFilter `
                                                             -WarnDaysRemaining $WarnDaysRemaining `
                                                             -IncludeNonHttps `
                                                             -Verbose:$false)

    if (-not $allBindings) {
        Write-Warning "No bindings found for sites matching '$siteFilter'."
        return
    }

    # App pool name lives on the site object, not the binding - fetch once
    $poolBySiteId = @{}
    try {
        Get-ChildItem 'IIS:\Sites' -ErrorAction Stop | ForEach-Object {
            $poolBySiteId[[int]$_.Id] = try { [string]$_.ApplicationPool } catch { $null }
        }
    }
    catch {
        Write-Verbose "Could not read app pool names from IIS:\Sites: $_"
    }

    $allBindings | Group-Object SiteName | ForEach-Object {
        $group    = $_.Group
        $first    = $group[0]
        $siteId   = $first.SiteId
        $poolName = $poolBySiteId[$siteId]

        $httpsBindings = @($group | Where-Object Protocol -eq 'https')
        $httpBindings  = @($group | Where-Object Protocol -eq 'http')
        $otherBindings = @($group | Where-Object { $_.Protocol -notin 'http','https' })

        # Roll up worst cert status
        $worstStatus = 'NotHttps'
        $worstRank   = 1
        foreach ($b in $httpsBindings) {
            $rank = if ($statusRank.ContainsKey($b.ExpiryStatus)) { $statusRank[$b.ExpiryStatus] } else { 0 }
            if ($rank -gt $worstRank) {
                $worstRank   = $rank
                $worstStatus = $b.ExpiryStatus
            }
        }

        # Find nearest-expiring certificate (soonest to expire = smallest DaysUntilExpiry)
        $nearestBinding = $httpsBindings |
            Where-Object { $null -ne $_.DaysUntilExpiry } |
            Sort-Object DaysUntilExpiry |
            Select-Object -First 1

        $nearestExpiry  = if ($nearestBinding) { $nearestBinding.CertExpiry }     else { $null }
        $nearestDays    = if ($nearestBinding) { $nearestBinding.DaysUntilExpiry } else { $null }
        $nearestSubject = if ($nearestBinding) { $nearestBinding.CertSubject }     else { $null }

        # Flatten all notices, tagging each with its binding address for context
        $allNotices = [System.Collections.Generic.List[pscustomobject]]::new()
        foreach ($b in $group) {
            foreach ($notice in $b.Notices) {
                $addr = "$($b.Protocol)://$($b.IPAddress):$($b.Port)$(if ($b.HostName) { "/$($b.HostName)" })"
                $allNotices.Add([pscustomobject]@{
                    SiteName = $b.SiteName
                    Binding  = $addr
                    Notice   = $notice
                })
            }
        }

        [pscustomobject]@{
            PSTypeName        = 'IISDiagnostics.SiteSummary'
            SiteName          = $first.SiteName
            SiteId            = $siteId
            SiteState         = $first.SiteState
            ApplicationPool   = $poolName
            HttpBindings      = $httpBindings.Count
            HttpsBindings     = $httpsBindings.Count
            OtherBindings     = $otherBindings.Count
            WorstCertStatus   = if ($httpsBindings.Count -gt 0) { $worstStatus } else { 'NoHttps' }
            NearestExpiry     = $nearestExpiry
            NearestExpiryDays = $nearestDays
            NearestCertSubject= $nearestSubject
            NoticeCount       = $allNotices.Count
            Notices           = $allNotices.ToArray()
        }
    } | Sort-Object SiteName
}