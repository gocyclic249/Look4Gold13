<#
.SYNOPSIS
    Look4Gold13 - AU-13 Compliance Scanner (Single-file edition)
.DESCRIPTION
    Scans multiple sources for unauthorized disclosure of organizational
    information per NIST SP 800-53 AU-13.

    Sources: DuckDuckGo, Paste Sites, GitHub, Breach/Security Blogs

    After scanning, sends results per keyword to a GenAI API (Ask Sage)
    for summarization. The AI summary is embedded in the HTML report.

    Two modes:
      Interactive (default) - prompts for all settings
      Silent (-Silent)      - uses flags and defaults, no prompts
.EXAMPLE
    .\Look4Gold13.ps1
    # Interactive mode - prompts for everything
.EXAMPLE
    .\Look4Gold13.ps1 -Silent -GitHubToken "ghp_xxxx" -DaysBack 60
    # Silent mode - no prompts, uses flags
.EXAMPLE
    .\Look4Gold13.ps1 -Silent -DaysBack 7 -Sources GitHub,Breach
    # Silent mode with specific sources (reads tokens from env vars)
#>
param(
    [switch]$Silent,

    [string]$KeywordFile,

    [int]$DaysBack,

    [string]$OutputFile,

    [string]$ConfigFile,

    [ValidateSet('DuckDuckGo', 'Paste', 'GitHub', 'Breach')]
    [string[]]$Sources,

    [string]$GitHubToken
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-DateFilter {
    param(
        [Parameter(Mandatory)]
        [int]$DaysBack,

        [ValidateSet('GitHub', 'Unix')]
        [string]$Format = 'GitHub'
    )

    $targetDate = (Get-Date).AddDays(-$DaysBack)

    switch ($Format) {
        'GitHub' { return $targetDate.ToString('yyyy-MM-dd') }
        'Unix'   { return [int][double]::Parse((Get-Date $targetDate -UFormat %s)) }
    }
}

function New-AU13Result {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Keyword,
        [Parameter(Mandatory)][string]$Title,
        [string]$Url = '',
        [string]$Snippet = '',
        [string]$DateFound = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        [string]$Severity = 'Review'
    )

    [PSCustomObject]@{
        ScanTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Source        = $Source
        Keyword       = $Keyword
        Title         = $Title
        Url           = $Url
        Snippet       = ($Snippet -replace '\s+', ' ').Trim()
        DateFound     = $DateFound
        Severity      = $Severity
    }
}

function Import-AU13Keywords {
    param(
        [string]$Path
    )

    if (-not $Path) {
        $Path = Join-Path $PSScriptRoot "keywords.txt"
    }

    if (-not (Test-Path $Path)) {
        Write-Error "Keywords file not found at '$Path'. Copy config/keywords.example.txt to '$Path' and add your keywords."
        return @()
    }

    $keywords = Get-Content -Path $Path |
        Where-Object { $_ -and $_.Trim() -and -not $_.Trim().StartsWith('#') } |
        ForEach-Object { $_.Trim() }

    if ($keywords.Count -eq 0) {
        Write-Warning "Keywords file is empty or contains only comments: $Path"
        return @()
    }

    Write-Verbose "Loaded $($keywords.Count) keywords from $Path"
    return $keywords
}

function Import-AU13Config {
    param(
        [string]$Path
    )

    if (-not $Path) {
        $Path = Join-Path $PSScriptRoot "config/au13-config.json"
    }

    # Default config values
    $defaults = @{
        genai = @{
            endpoint         = 'https://api.genai.army.mil/server/query'
            tokenEnvVar      = 'GENAI_API_TOKEN'
            model            = 'google-claude-45-sonnet'
            persona          = 5
            temperature      = 0.7
            limit_references = 5
            live             = 1
        }
        search = @{
            daysBack     = 30
            delaySeconds = 2
            sources      = @('DuckDuckGo', 'Paste', 'GitHub', 'Breach')
        }
    }

    if (Test-Path $Path) {
        try {
            $fileConfig = Get-Content -Path $Path -Raw | ConvertFrom-Json

            # Merge genai settings
            if ($fileConfig.genai) {
                foreach ($prop in $fileConfig.genai.PSObject.Properties) {
                    $defaults.genai[$prop.Name] = $prop.Value
                }
            }

            # Merge search settings
            if ($fileConfig.search) {
                foreach ($prop in $fileConfig.search.PSObject.Properties) {
                    $defaults.search[$prop.Name] = $prop.Value
                }
            }

            Write-Verbose "Loaded config from $Path"
        }
        catch {
            Write-Warning "Failed to parse config file '$Path': $($_.Exception.Message). Using defaults."
        }
    }
    else {
        Write-Verbose "No config file at '$Path'. Using defaults."
    }

    return $defaults
}

# ============================================================================
# SEARCH FUNCTIONS
# ============================================================================

function Search-DuckDuckGo {
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [int]$DaysBack = 30,

        [int]$DelaySeconds = 2
    )

    $results = @()

    # DuckDuckGo dork templates — DDG supports site: and filetype: operators
    $dorkTemplates = @(
        '"{keyword}" site:pastebin.com',
        '"{keyword}" site:github.com',
        '"{keyword}" site:trello.com',
        '"{keyword}" site:paste.ee',
        '"{keyword}" site:dpaste.org',
        '"{keyword}" filetype:pdf',
        '"{keyword}" filetype:xlsx',
        '"{keyword}" filetype:csv',
        '"{keyword}" filetype:doc',
        '"{keyword}" filetype:conf',
        '"{keyword}" filetype:log',
        '"{keyword}" filetype:sql',
        '"{keyword}" filetype:env'
    )

    Write-Host "[DuckDuckGo] Searching via HTML lite endpoint..." -ForegroundColor Cyan

    foreach ($keyword in $Keywords) {
        Write-Host "[DuckDuckGo] Checking dorks for '$keyword'..." -ForegroundColor Gray
        foreach ($template in $dorkTemplates) {
            $query = $template -replace '\{keyword\}', $keyword
            $encodedQuery = [System.Uri]::EscapeDataString($query)
            $ddgUrl = "https://html.duckduckgo.com/html/?q=$encodedQuery"

            try {
                $webResponse = Invoke-WebRequest -Uri $ddgUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop -Headers @{
                    'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
                $html = $webResponse.Content

                # DDG lite returns result links in <a class="result__a"> tags
                if ($html -match 'No results' -or $html -match 'No more results' -or $html -notmatch 'result__a') {
                    Write-Host "  [No Results] $query" -ForegroundColor DarkGray
                }
                else {
                    # Extract result links from DDG HTML
                    $linkMatches = [regex]::Matches($html, 'class="result__a" href="([^"]+)"[^>]*>([^<]+)<')

                    if ($linkMatches.Count -gt 0) {
                        Write-Host "  [Results: $($linkMatches.Count)] $query" -ForegroundColor Green
                        foreach ($match in $linkMatches) {
                            $resultUrl = $match.Groups[1].Value
                            $resultTitle = $match.Groups[2].Value.Trim()

                            # DDG sometimes wraps URLs in a redirect — extract the real URL
                            if ($resultUrl -match 'uddg=([^&]+)') {
                                $resultUrl = [System.Uri]::UnescapeDataString($Matches[1])
                            }

                            $results += New-AU13Result `
                                -Source 'DuckDuckGo' `
                                -Keyword $keyword `
                                -Title $resultTitle `
                                -Url $resultUrl `
                                -Snippet "Found via DuckDuckGo dork: $query" `
                                -Severity 'Review'
                        }
                    }
                    else {
                        Write-Host "  [Parse Error] $query - could not extract links" -ForegroundColor DarkYellow
                    }
                }
            }
            catch {
                Write-Host "  [Error] $query - $($_.Exception.Message)" -ForegroundColor DarkYellow
            }

            Start-Sleep -Seconds $DelaySeconds
        }
    }

    Write-Host "[DuckDuckGo] Found $($results.Count) results" -ForegroundColor Cyan
    return $results
}

function Search-PasteSites {
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [int]$DaysBack = 30
    )

    $results = @()
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)

    foreach ($keyword in $Keywords) {
        try {
            $encodedKeyword = [System.Uri]::EscapeDataString($keyword)
            $uri = "https://psbdmp.ws/api/v3/search/$encodedKeyword"

            Write-Verbose "[PasteSites] Querying psbdmp.ws for '$keyword'..."
            $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 30 -ErrorAction Stop

            if ($response -and $response.Count -gt 0) {
                foreach ($paste in $response) {
                    $pasteDate = $null
                    if ($paste.time) {
                        try {
                            $pasteDate = [DateTimeOffset]::FromUnixTimeSeconds($paste.time).DateTime
                        }
                        catch {
                            $pasteDate = Get-Date
                        }
                    }

                    if ($pasteDate -and $pasteDate -lt $cutoffDate) { continue }

                    $pasteUrl = "https://pastebin.com/$($paste.id)"
                    $results += New-AU13Result `
                        -Source 'Pastebin' `
                        -Keyword $keyword `
                        -Title "Paste: $($paste.id)" `
                        -Url $pasteUrl `
                        -Snippet ($paste.text | Select-Object -First 1) `
                        -DateFound $(if ($pasteDate) { $pasteDate.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }) `
                        -Severity 'High'
                }
            }
        }
        catch {
            if ($_.Exception.Message -match '404') {
                Write-Verbose "[PasteSites] No psbdmp.ws results for '$keyword'"
            }
            else {
                Write-Warning "[PasteSites] psbdmp.ws error for '$keyword': $($_.Exception.Message)"
            }
        }

        $pasteSites = @(
            @{ Name = 'Pastebin';  Url = "https://html.duckduckgo.com/html/?q=site:pastebin.com+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'Paste.ee';  Url = "https://html.duckduckgo.com/html/?q=site:paste.ee+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'Ghostbin';  Url = "https://html.duckduckgo.com/html/?q=site:ghostbin.com+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'Dpaste';    Url = "https://html.duckduckgo.com/html/?q=site:dpaste.org+%22$([System.Uri]::EscapeDataString($keyword))%22" }
        )

        Write-Host "[PasteSites] Manual search URLs for '$keyword':" -ForegroundColor Gray
        foreach ($site in $pasteSites) {
            Write-Host "  $($site.Name): $($site.Url)" -ForegroundColor DarkGray
        }

        Start-Sleep -Milliseconds 300
    }

    Write-Host "[PasteSites] Found $($results.Count) results/links" -ForegroundColor Cyan
    return $results
}

function Invoke-GitHubSearch {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [string]$SearchType = 'search',
        [int]$MaxRetries = 2
    )

    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method Get -TimeoutSec 30 -ErrorAction Stop

            # Check rate limit remaining from response headers
            $remaining = $response.Headers['X-RateLimit-Remaining']
            $resetEpoch = $response.Headers['X-RateLimit-Reset']
            if ($remaining -and [int]$remaining -le 2) {
                $resetTime = [DateTimeOffset]::FromUnixTimeSeconds([long]$resetEpoch).LocalDateTime
                $waitSec = [math]::Max(1, ($resetTime - (Get-Date)).TotalSeconds)
                Write-Host "[GitHub] Rate limit low ($remaining left). Waiting $([math]::Ceiling($waitSec))s for reset..." -ForegroundColor Yellow
                Start-Sleep -Seconds ([math]::Ceiling($waitSec))
            }

            return ($response.Content | ConvertFrom-Json)
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            if ($statusCode -eq 401) {
                Write-Warning "[GitHub] Authentication failed. Check your GitHub token."
                return $null
            }
            elseif ($statusCode -eq 403 -or ($_.Exception.Message -match '403')) {
                if ($attempt -lt $MaxRetries) {
                    # Check Retry-After header, default to 60s
                    $retryAfter = 60
                    if ($_.Exception.Response.Headers) {
                        try {
                            $ra = $_.Exception.Response.Headers | Where-Object { $_.Key -eq 'Retry-After' }
                            if ($ra) { $retryAfter = [int]$ra.Value[0] }
                        } catch {}
                    }
                    Write-Host "[GitHub] Rate limited on $SearchType (attempt $($attempt + 1)/$($MaxRetries + 1)). Waiting ${retryAfter}s..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $retryAfter
                }
                else {
                    Write-Warning "[GitHub] Rate limited on $SearchType after $($MaxRetries + 1) attempts. Skipping."
                    return $null
                }
            }
            else {
                Write-Warning "[GitHub] $SearchType error: $($_.Exception.Message)"
                return $null
            }
        }
    }
    return $null
}

function Search-GitHubExposure {
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [int]$DaysBack = 30,

        [Parameter(Mandatory)]
        [string]$GitHubToken
    )

    $results = @()
    $dateFilter = Get-DateFilter -DaysBack $DaysBack -Format 'GitHub'

    $headers = @{
        'Accept'        = 'application/vnd.github.v3+json'
        'User-Agent'    = 'Look4Gold13-AU13-Scanner'
        'Authorization' = "token $GitHubToken"
    }

    foreach ($keyword in $Keywords) {
        $encodedKeyword = [System.Uri]::EscapeDataString("`"$keyword`"")

        # --- Code search (most restrictive rate limit - ~10 req/min) ---
        $codeUri = "https://api.github.com/search/code?q=$encodedKeyword&sort=indexed&order=desc&per_page=10"
        Write-Verbose "[GitHub] Code search for '$keyword'..."

        $codeResponse = Invoke-GitHubSearch -Uri $codeUri -Headers $headers -SearchType "code search for '$keyword'"

        if ($codeResponse -and $codeResponse.items) {
            foreach ($item in $codeResponse.items) {
                $results += New-AU13Result `
                    -Source 'GitHub-Code' `
                    -Keyword $keyword `
                    -Title "$($item.repository.full_name) - $($item.name)" `
                    -Url $item.html_url `
                    -Snippet "File: $($item.path) in repo $($item.repository.full_name)" `
                    -Severity 'High'
            }
            Write-Verbose "[GitHub] Code search returned $($codeResponse.total_count) total results"
        }

        Start-Sleep -Seconds 12

        # --- Commits search ---
        $commitUri = "https://api.github.com/search/commits?q=$encodedKeyword+committer-date:>$dateFilter&sort=committer-date&order=desc&per_page=20"
        Write-Verbose "[GitHub] Commit search for '$keyword'..."

        $commitHeaders = $headers.Clone()
        $commitHeaders['Accept'] = 'application/vnd.github.cloak-preview+json'

        $commitResponse = Invoke-GitHubSearch -Uri $commitUri -Headers $commitHeaders -SearchType "commit search for '$keyword'"

        if ($commitResponse -and $commitResponse.items) {
            foreach ($item in $commitResponse.items) {
                $commitDate = if ($item.commit.committer.date) { $item.commit.committer.date } else { '' }
                $results += New-AU13Result `
                    -Source 'GitHub-Commit' `
                    -Keyword $keyword `
                    -Title "$($item.repository.full_name) - $($item.commit.message | Select-Object -First 1)" `
                    -Url $item.html_url `
                    -Snippet "Commit by $($item.commit.committer.name) on $commitDate" `
                    -DateFound $commitDate `
                    -Severity 'High'
            }
        }

        Start-Sleep -Seconds 12

        # --- Issues search ---
        $issueUri = "https://api.github.com/search/issues?q=$encodedKeyword+created:>$dateFilter&sort=created&order=desc&per_page=20"
        Write-Verbose "[GitHub] Issue search for '$keyword'..."

        $issueResponse = Invoke-GitHubSearch -Uri $issueUri -Headers $headers -SearchType "issue search for '$keyword'"

        if ($issueResponse -and $issueResponse.items) {
            foreach ($item in $issueResponse.items) {
                $results += New-AU13Result `
                    -Source 'GitHub-Issue' `
                    -Keyword $keyword `
                    -Title "$($item.title)" `
                    -Url $item.html_url `
                    -Snippet ($item.body | Select-Object -First 1) `
                    -DateFound $item.created_at `
                    -Severity 'Medium'
            }
        }

        Start-Sleep -Seconds 12
    }

    Write-Host "[GitHub] Found $($results.Count) results" -ForegroundColor Cyan
    return $results
}

function Search-BreachInfo {
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [int]$DaysBack = 30
    )

    $results = @()

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

        # --- DuckDuckGo searches across security blogs ---
        $combinedSites = ($breachSites | ForEach-Object { "site:$_" }) -join ' OR '
        $combinedUrl = "https://html.duckduckgo.com/html/?q=$encodedKeyword+($([System.Uri]::EscapeDataString($combinedSites)))"

        $results += New-AU13Result `
            -Source 'BreachBlogs-Combined' `
            -Keyword $keyword `
            -Title "MANUAL: Security blogs search for '$keyword'" `
            -Url $combinedUrl `
            -Snippet "Combined search across $($breachSites.Count) security/breach sites" `
            -Severity 'Manual-Review'

        foreach ($site in @('haveibeenpwned.com', 'krebsonsecurity.com', 'bleepingcomputer.com')) {
            $siteUrl = "https://html.duckduckgo.com/html/?q=site:$site+$encodedKeyword"
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

# ============================================================================
# GENAI SUMMARIZATION
# ============================================================================

function Invoke-GenAISummary {
    param(
        [Parameter(Mandatory)]
        [string]$Keyword,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [hashtable]$GenAIConfig
    )

    $token = [System.Environment]::GetEnvironmentVariable($GenAIConfig.tokenEnvVar)
    if (-not $token) {
        return "GenAI summary unavailable - $($GenAIConfig.tokenEnvVar) environment variable not set."
    }

    $headers = @{
        'x-access-tokens' = $token
        'Content-Type'    = 'application/json'
    }

    # Build a concise summary of findings for the AI
    $resultSummary = $Results | ForEach-Object {
        "- [$($_.Severity)] $($_.Source): $($_.Title) | URL: $($_.Url) | $($_.Snippet)"
    }
    $resultText = $resultSummary -join "`n"

    $prompt = @"
You are an AU-13 compliance analyst. Analyze the following scan results for the keyword "$Keyword" and provide:
1. A brief risk assessment (1-2 sentences)
2. Key findings summary (bullet points)
3. Recommended actions

Scan Results:
$resultText
"@

    $body = @{
        message          = $prompt
        persona          = $GenAIConfig.persona
        model            = $GenAIConfig.model
        temperature      = $GenAIConfig.temperature
        limit_references = $GenAIConfig.limit_references
        live             = $GenAIConfig.live
    } | ConvertTo-Json -Depth 3

    try {
        Write-Host "[GenAI] Summarizing results for '$Keyword'..." -ForegroundColor Cyan
        $response = Invoke-RestMethod -Uri $GenAIConfig.endpoint `
            -Method Post `
            -Headers $headers `
            -Body $body `
            -TimeoutSec 300

        Start-Sleep -Seconds 3

        if ($response.message) {
            return $response.message
        }
        else {
            return "GenAI returned an empty response."
        }
    }
    catch {
        Write-Warning "[GenAI] Error summarizing '$Keyword': $($_.Exception.Message)"
        return "GenAI summary failed: $($_.Exception.Message)"
    }
}

# ============================================================================
# HTML REPORT EXPORT
# ============================================================================

function Export-AU13Html {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [string]$OutputPath,

        [string[]]$Keywords,

        [int]$DaysBack,

        [string[]]$Sources,

        [hashtable]$AISummaries = @{}
    )

    if (-not $OutputPath) {
        $outputDir = Join-Path $PSScriptRoot "Output"
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $OutputPath = Join-Path $outputDir "AU13_Scan_$timestamp.html"
    }

    $parentDir = Split-Path -Parent $OutputPath
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    $scanTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Build severity summary
    $grouped = $Results | Group-Object -Property Severity
    $severitySummaryHtml = ""
    foreach ($group in $grouped | Sort-Object Name) {
        $color = switch ($group.Name) {
            'Critical'      { '#dc3545' }
            'High'          { '#c71585' }
            'Medium'        { '#ffc107' }
            'Review'        { '#17a2b8' }
            'Manual-Review' { '#6c757d' }
            default         { '#333' }
        }
        $severitySummaryHtml += "        <span class=`"severity-badge`" style=`"background:$color;`">$($group.Name): $($group.Count)</span>`n"
    }

    # Build per-keyword result blocks
    $keywordBlocks = ""
    $resultsByKeyword = $Results | Group-Object -Property Keyword

    foreach ($kwGroup in $resultsByKeyword) {
        $kw = [System.Web.HttpUtility]::HtmlEncode($kwGroup.Name)
        $count = $kwGroup.Count

        $listItems = ""
        foreach ($r in $kwGroup.Group) {
            $title = [System.Web.HttpUtility]::HtmlEncode($r.Title)
            $url   = [System.Web.HttpUtility]::HtmlEncode($r.Url)
            $src   = [System.Web.HttpUtility]::HtmlEncode($r.Source)
            $sev   = $r.Severity
            $snip  = [System.Web.HttpUtility]::HtmlEncode($r.Snippet)

            $sevColor = switch ($sev) {
                'Critical'      { '#dc3545' }
                'High'          { '#c71585' }
                'Medium'        { '#ffc107' }
                'Review'        { '#17a2b8' }
                'Manual-Review' { '#6c757d' }
                default         { '#333' }
            }

            if ($url) {
                $listItems += "            <li><a href=`"$url`" target=`"_blank`">$title</a> &mdash; <em>$src</em> <span class=`"severity-badge`" style=`"background:$sevColor;`">$sev</span><br><small>$snip</small></li>`n"
            }
            else {
                $listItems += "            <li>$title &mdash; <em>$src</em> <span class=`"severity-badge`" style=`"background:$sevColor;`">$sev</span><br><small>$snip</small></li>`n"
            }
        }

        # AI Summary block for this keyword
        $aiBlock = ""
        if ($AISummaries.ContainsKey($kwGroup.Name)) {
            $aiText = [System.Web.HttpUtility]::HtmlEncode($AISummaries[$kwGroup.Name]) -replace "`n", "<br>"
            $aiBlock = @"
            <div class="ai-summary">
                <h3>AI Analysis</h3>
                <div class="ai-content">$aiText</div>
            </div>
"@
        }

        $keywordBlocks += @"
        <div class="query-block">
            <h2>Query: &quot;$kw&quot;</h2>
            <p class="result-count">Result Count: $count</p>
            <ul>
$listItems
            </ul>
$aiBlock
        </div>

"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AU-13 Scan Report - $scanTime</title>
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
        .container { max-width: 960px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 6px; box-shadow: 0 1px 4px rgba(0,0,0,.1); }
        h1 { color: #1a1a2e; border-bottom: 3px solid #e2b714; padding-bottom: 10px; }
        .scan-meta { background: #f8f9fa; padding: 12px 16px; border-radius: 4px; margin-bottom: 20px; font-size: 0.95em; }
        .scan-meta strong { color: #1a1a2e; }
        .severity-summary { margin-bottom: 24px; }
        .severity-badge { display: inline-block; color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 0.85em; margin-right: 6px; }
        .query-block { border: 1px solid #dee2e6; border-radius: 6px; padding: 16px 20px; margin-bottom: 18px; }
        .query-block h2 { margin-top: 0; color: #1a1a2e; font-size: 1.15em; }
        .result-count { font-weight: bold; color: #555; }
        .query-block ul { list-style: none; padding-left: 0; }
        .query-block li { padding: 8px 0; border-bottom: 1px solid #eee; }
        .query-block li:last-child { border-bottom: none; }
        .query-block a { color: #0d6efd; text-decoration: none; }
        .query-block a:hover { text-decoration: underline; }
        .query-block small { color: #777; }
        .ai-summary { background: #f0f4ff; border-left: 4px solid #4a6cf7; padding: 12px 16px; margin-top: 12px; border-radius: 0 4px 4px 0; }
        .ai-summary h3 { margin: 0 0 8px 0; color: #4a6cf7; font-size: 0.95em; }
        .ai-content { font-size: 0.9em; line-height: 1.5; color: #444; }
        .footer { margin-top: 30px; text-align: center; font-size: 0.85em; color: #999; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AU-13 Compliance Scan Report</h1>

        <div class="scan-meta">
            <strong>Scan Date:</strong> $scanTime<br>
            <strong>Keywords Scanned:</strong> $($Keywords.Count)<br>
            <strong>Days Back:</strong> $DaysBack<br>
            <strong>Sources:</strong> $($Sources -join ', ')<br>
            <strong>Total Results:</strong> $($Results.Count)
        </div>

        <div class="severity-summary">
$severitySummaryHtml
        </div>

$keywordBlocks

        <div class="footer">
            Generated by Look4Gold13 - AU-13 Compliance Scanner
        </div>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Report exported to: $OutputPath" -ForegroundColor Green
    return $OutputPath
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

$banner = @"

    +-------------------------------------------------+
    |     Look4Gold13 - AU-13 Compliance Scanner      |
    |     Monitoring for Information Disclosure        |
    +-------------------------------------------------+

"@
Write-Host $banner -ForegroundColor Yellow

# --- Load config file ---
$config = Import-AU13Config -Path $ConfigFile

# --- Resolve GitHub Token (REQUIRED) ---
if (-not $GitHubToken) {
    $GitHubToken = $env:GITHUB_TOKEN
}

if (-not $GitHubToken) {
    if ($Silent) {
        Write-Error "GitHub token is required. Provide -GitHubToken or set `$env:GITHUB_TOKEN."
        exit 1
    }
    else {
        Write-Host "A GitHub Personal Access Token is required for GitHub searches." -ForegroundColor Yellow
        Write-Host "  (Create one at https://github.com/settings/tokens with 'public_repo' scope)" -ForegroundColor Gray
        $GitHubToken = Read-Host "Paste your GitHub token"
        if (-not $GitHubToken) {
            Write-Error "No token provided. Cannot continue."
            exit 1
        }
    }
}

# --- Resolve GenAI Token ---
$genaiToken = [System.Environment]::GetEnvironmentVariable($config.genai.tokenEnvVar)
if (-not $genaiToken) {
    if ($Silent) {
        Write-Warning "GenAI token not found in `$env:$($config.genai.tokenEnvVar). AI summaries will be skipped."
    }
    else {
        Write-Host "GenAI API token enables AI-powered summarization of results." -ForegroundColor Yellow
        Write-Host "  (Get one from Ask Sage: Settings > Account > Manage API Keys)" -ForegroundColor Gray
        $genaiInput = Read-Host "Paste your GenAI API token (or press Enter to skip)"
        if ($genaiInput) {
            [System.Environment]::SetEnvironmentVariable($config.genai.tokenEnvVar, $genaiInput, "Process")
        }
    }
}

# --- Resolve remaining parameters ---
if ($Silent) {
    if (-not $DaysBack)    { $DaysBack = $config.search.daysBack }
    if (-not $Sources)     { $Sources = $config.search.sources }
    if (-not $KeywordFile) { $KeywordFile = Join-Path $PSScriptRoot "keywords.txt" }
}
else {
    if (-not $KeywordFile) {
        $defaultKw = Join-Path $PSScriptRoot "keywords.txt"
        $input = Read-Host "Keywords file path [$defaultKw]"
        $KeywordFile = if ($input) { $input } else { $defaultKw }
    }

    if (-not $DaysBack) {
        $input = Read-Host "Days back to search [$($config.search.daysBack)]"
        $DaysBack = if ($input) { [int]$input } else { $config.search.daysBack }
    }

    if (-not $Sources) {
        Write-Host "Available sources: DuckDuckGo, Paste, GitHub, Breach" -ForegroundColor Gray
        $input = Read-Host "Sources to scan (comma-separated) [All]"
        $Sources = if ($input) {
            $input -split ',' | ForEach-Object { $_.Trim() }
        }
        else {
            $config.search.sources
        }
    }

    if (-not $OutputFile) {
        $defaultOut = Join-Path (Join-Path $PSScriptRoot "Output") "AU13_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $input = Read-Host "Output file path [$defaultOut]"
        $OutputFile = if ($input) { $input } else { $defaultOut }
    }
}

# --- Load keywords ---
$keywords = Import-AU13Keywords -Path $KeywordFile

if (-not $keywords -or $keywords.Count -eq 0) {
    Write-Error "No keywords loaded. Create a keywords.txt file with your monitoring terms."
    Write-Host "  Hint: Copy config/keywords.example.txt to keywords.txt and add your keywords." -ForegroundColor Yellow
    exit 1
}

Write-Host "Scan Configuration:" -ForegroundColor White
Write-Host "  Keywords:  $($keywords.Count) loaded" -ForegroundColor Gray
Write-Host "  Days Back: $DaysBack" -ForegroundColor Gray
Write-Host "  Sources:   $($Sources -join ', ')" -ForegroundColor Gray
Write-Host "  GenAI:     $(if ([System.Environment]::GetEnvironmentVariable($config.genai.tokenEnvVar)) { 'Enabled' } else { 'Disabled (no token)' })" -ForegroundColor Gray
Write-Host ""

$allResults = @()

# --- DuckDuckGo ---
if ('DuckDuckGo' -in $Sources) {
    Write-Host "=== Scanning DuckDuckGo... ===" -ForegroundColor White
    $ddgResults = Search-DuckDuckGo -Keywords $keywords -DaysBack $DaysBack -DelaySeconds $config.search.delaySeconds
    $allResults += $ddgResults
    Write-Host ""
}

# --- Paste Sites ---
if ('Paste' -in $Sources) {
    Write-Host "=== Scanning Paste Sites... ===" -ForegroundColor White
    $pasteResults = Search-PasteSites -Keywords $keywords -DaysBack $DaysBack
    $allResults += $pasteResults
    Write-Host ""
}

# --- GitHub ---
if ('GitHub' -in $Sources) {
    Write-Host "=== Scanning GitHub... ===" -ForegroundColor White
    $githubResults = Search-GitHubExposure -Keywords $keywords -DaysBack $DaysBack -GitHubToken $GitHubToken
    $allResults += $githubResults
    Write-Host ""
}

# --- Breach Info ---
if ('Breach' -in $Sources) {
    Write-Host "=== Scanning Breach Sources... ===" -ForegroundColor White
    $breachResults = Search-BreachInfo -Keywords $keywords -DaysBack $DaysBack
    $allResults += $breachResults
    Write-Host ""
}

# --- Summary ---
Write-Host "=== Scan Complete ===" -ForegroundColor Green
Write-Host ""

if ($allResults.Count -eq 0) {
    Write-Host "No results found across any sources." -ForegroundColor Green
    exit 0
}

# Print summary by severity
$grouped = $allResults | Group-Object -Property Severity
Write-Host "Results Summary:" -ForegroundColor White
foreach ($group in $grouped | Sort-Object Name) {
    $color = switch ($group.Name) {
        'Critical'      { 'Red' }
        'High'          { 'Magenta' }
        'Medium'        { 'Yellow' }
        'Review'        { 'Cyan' }
        'Manual-Review' { 'Gray' }
        default         { 'White' }
    }
    Write-Host "  [$($group.Name)]: $($group.Count)" -ForegroundColor $color
}
Write-Host "  Total: $($allResults.Count)" -ForegroundColor White
Write-Host ""

# --- GenAI Summarization (per keyword) ---
$aiSummaries = @{}
$genaiTokenCheck = [System.Environment]::GetEnvironmentVariable($config.genai.tokenEnvVar)
if ($genaiTokenCheck) {
    Write-Host "=== Running GenAI Analysis... ===" -ForegroundColor White
    $resultsByKeyword = $allResults | Group-Object -Property Keyword

    foreach ($kwGroup in $resultsByKeyword) {
        $summary = Invoke-GenAISummary -Keyword $kwGroup.Name -Results $kwGroup.Group -GenAIConfig $config.genai
        $aiSummaries[$kwGroup.Name] = $summary
    }
    Write-Host ""
}
else {
    Write-Host "[GenAI] Skipped - no API token configured." -ForegroundColor DarkGray
}

# Export HTML
$reportPath = Export-AU13Html -Results $allResults -OutputPath $OutputFile -Keywords $keywords -DaysBack $DaysBack -Sources $Sources -AISummaries $aiSummaries

# Display high-severity hits in console
$highSev = $allResults | Where-Object { $_.Severity -in @('Critical', 'High') }
if ($highSev) {
    Write-Host ""
    Write-Host "!! HIGH SEVERITY FINDINGS !!" -ForegroundColor Red
    foreach ($finding in $highSev) {
        Write-Host "  [$($finding.Source)] $($finding.Keyword): $($finding.Title)" -ForegroundColor Red
        if ($finding.Url) {
            Write-Host "    URL: $($finding.Url)" -ForegroundColor DarkRed
        }
    }
}
