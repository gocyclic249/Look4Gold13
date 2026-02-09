function Search-BreachInfo {
    <#
    .SYNOPSIS
        Searches free breach/compromise information sources for keywords.
    .DESCRIPTION
        Checks publicly available breach databases, security blogs, and
        disclosure feeds for mentions of keywords. Uses Google to search
        known security blogs and breach reporting sites.
    .PARAMETER Keywords
        Array of keywords to search for.
    .PARAMETER DaysBack
        Number of days back to filter results.
    .EXAMPLE
        Search-BreachInfo -Keywords @("acme-corp") -DaysBack 90
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [Parameter()]
        [int]$DaysBack = 30
    )

    $results = @()

    # Security blogs and breach reporting sites to search via Google
    $breachSites = @(
        'haveibeenpwned.com',
        'krebsonsecurity.com',
        'bleepingcomputer.com',
        'threatpost.com',
        'securityweek.com',
        'therecord.media',
        'databreaches.net',
        'breachdirectory.org',
        'cybernews.com',
        'hackread.com',
        'securityaffairs.com'
    )

    foreach ($keyword in $Keywords) {
        $encodedKeyword = [System.Uri]::EscapeDataString("`"$keyword`"")

        # --- Have I Been Pwned (free API - breach list only) ---
        try {
            # HIBP free endpoint lists all known breaches - check if keyword matches any
            $hibpUri = "https://haveibeenpwned.com/api/v3/breaches"
            Write-Verbose "[BreachInfo] Checking HIBP breach list for '$keyword'..."

            $hibpResponse = Invoke-RestMethod -Uri $hibpUri -Method Get `
                -Headers @{ 'User-Agent' = 'Look4Gold13-AU13-Scanner' } `
                -TimeoutSec 15 -ErrorAction Stop

            $matches = $hibpResponse | Where-Object {
                $_.Name -match [regex]::Escape($keyword) -or
                $_.Title -match [regex]::Escape($keyword) -or
                $_.Domain -match [regex]::Escape($keyword) -or
                $_.Description -match [regex]::Escape($keyword)
            }

            foreach ($breach in $matches) {
                $results += New-AU13Result `
                    -Source 'HIBP-Breach' `
                    -Keyword $keyword `
                    -Title "Breach: $($breach.Title) ($($breach.BreachDate))" `
                    -Url "https://haveibeenpwned.com/PwnedWebsites#$($breach.Name)" `
                    -Snippet "Domain: $($breach.Domain) | Records: $($breach.PwnCount) | Data: $($breach.DataClasses -join ', ')" `
                    -DateFound $breach.BreachDate `
                    -Severity 'Critical'
            }
        }
        catch {
            Write-Warning "[BreachInfo] HIBP check error: $($_.Exception.Message)"
        }

        # --- Google searches across security blogs ---
        $siteQueries = $breachSites | ForEach-Object {
            "site:$_ $encodedKeyword"
        }

        # Combined multi-site search
        $combinedSites = ($breachSites | ForEach-Object { "site:$_" }) -join ' OR '
        $combinedUrl = "https://www.google.com/search?q=$encodedKeyword+($([System.Uri]::EscapeDataString($combinedSites)))&tbs=qdr:d$DaysBack"

        $results += New-AU13Result `
            -Source 'BreachBlogs-Combined' `
            -Keyword $keyword `
            -Title "MANUAL: Security blogs search for '$keyword'" `
            -Url $combinedUrl `
            -Snippet "Combined search across $($breachSites.Count) security/breach sites" `
            -Severity 'Manual-Review'

        # Individual site searches for more targeted review
        foreach ($site in @('haveibeenpwned.com', 'krebsonsecurity.com', 'bleepingcomputer.com')) {
            $siteUrl = "https://www.google.com/search?q=site:$site+$encodedKeyword&tbs=qdr:d$DaysBack"
            $results += New-AU13Result `
                -Source "BreachBlog-$site" `
                -Keyword $keyword `
                -Title "MANUAL: Search $site for '$keyword'" `
                -Url $siteUrl `
                -Snippet "Search $site for keyword mentions" `
                -Severity 'Manual-Review'
        }

        Start-Sleep -Milliseconds 300
    }

    Write-Host "[BreachInfo] Found $($results.Count) results/links" -ForegroundColor Cyan
    return $results
}
