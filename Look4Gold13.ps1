<#
.SYNOPSIS
    Look4Gold13 - AU-13 Compliance Scanner (Single-file edition)
.DESCRIPTION
    Scans multiple sources for unauthorized disclosure of organizational
    information per NIST SP 800-53 AU-13.

    Sources: DuckDuckGo, Paste Sites, Breach/Security Blogs

    After scanning, sends results per keyword to a GenAI API (Ask Sage)
    for summarization. The AI summary is embedded in the HTML report.

    Two modes:
      Interactive (default) - prompts for all settings
      Silent (-Silent)      - uses flags and defaults, no prompts
.EXAMPLE
    .\Look4Gold13.ps1
    # Interactive mode - prompts for everything
.EXAMPLE
    .\Look4Gold13.ps1 -Silent -DaysBack 60
    # Silent mode - no prompts, uses flags
.EXAMPLE
    .\Look4Gold13.ps1 -Silent -DaysBack 7 -Sources DuckDuckGo,Breach
    # Silent mode with specific sources
.EXAMPLE
    .\Look4Gold13.ps1 -UseProxy
    # Route DDG searches through Menlo Security (gov computers)
.EXAMPLE
    .\Look4Gold13.ps1 -Silent -UseProxy
    # Silent mode through Menlo Security proxy
#>
param(
    [switch]$Silent,

    [string]$KeywordFile,

    [int]$DaysBack,

    [string]$OutputFile,

    [string]$ConfigFile,

    [ValidateSet('DuckDuckGo', 'Paste', 'Breach')]
    [string[]]$Sources,

    [switch]$UseProxy
)

# ============================================================================
# TLS CONFIGURATION
# ============================================================================

# Force TLS 1.2 — fixes "The underlying connection was closed" errors
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Invoke-WebRequestWithRetry {
    param(
        [Parameter(Mandatory)][hashtable]$RequestParams,
        [int]$MaxRetries = 3,
        [int]$BaseDelaySeconds = 2
    )

    for ($attempt = 1; $attempt -le ($MaxRetries + 1); $attempt++) {
        try {
            return Invoke-WebRequest @RequestParams
        }
        catch {
            $isRetryable = $_.Exception.Message -match 'connection was closed' -or
                           $_.Exception.Message -match 'Unable to connect' -or
                           $_.Exception.Message -match 'timed out' -or
                           $_.Exception.Message -match '429' -or
                           $_.Exception.Message -match '503'

            if ($isRetryable -and $attempt -le $MaxRetries) {
                $delay = $BaseDelaySeconds * [math]::Pow(2, $attempt - 1)
                Write-Host "  [Retry $attempt/$MaxRetries] Waiting ${delay}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
            else {
                throw
            }
        }
    }
}

function Invoke-RestMethodWithRetry {
    param(
        [Parameter(Mandatory)][hashtable]$RequestParams,
        [int]$MaxRetries = 3,
        [int]$BaseDelaySeconds = 2
    )

    for ($attempt = 1; $attempt -le ($MaxRetries + 1); $attempt++) {
        try {
            return Invoke-RestMethod @RequestParams
        }
        catch {
            $isRetryable = $_.Exception.Message -match 'connection was closed' -or
                           $_.Exception.Message -match 'Unable to connect' -or
                           $_.Exception.Message -match 'timed out' -or
                           $_.Exception.Message -match '429' -or
                           $_.Exception.Message -match '503'

            if ($isRetryable -and $attempt -le $MaxRetries) {
                $delay = $BaseDelaySeconds * [math]::Pow(2, $attempt - 1)
                Write-Host "  [Retry $attempt/$MaxRetries] Waiting ${delay}s..." -ForegroundColor Yellow
                Start-Sleep -Seconds $delay
            }
            else {
                throw
            }
        }
    }
}

function Get-ProxiedUrl {
    param(
        [Parameter(Mandatory)][string]$Url,
        [string]$ProxyBase
    )

    if ($ProxyBase) {
        return "$ProxyBase/$Url"
    }
    return $Url
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
            delaySeconds = 3
            sources      = @('DuckDuckGo', 'Paste', 'Breach')
            webProxyBase = 'https://safe.menlosecurity.com'
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

        [int]$DelaySeconds = 2,

        [string]$ProxyBase = ''
    )

    $results = @()

    # Grouped dork queries — combines related site:/filetype: with OR to reduce
    # request count while keeping queries short enough for DDG's HTML lite endpoint.
    # DDG rejects queries that are too long once URL-encoded (especially through proxies).
    $dorkGroups = @(
        @{ Label = 'Paste sites (1/2)'; Query = 'site:pastebin.com OR site:paste.ee OR site:dpaste.org' },
        @{ Label = 'Paste sites (2/2)'; Query = 'site:rentry.co OR site:justpaste.it OR site:controlc.com OR site:privatebin.net' },
        @{ Label = 'Code/project';      Query = 'site:github.com OR site:trello.com' },
        @{ Label = 'Documents';         Query = 'filetype:pdf OR filetype:xlsx OR filetype:csv OR filetype:doc' },
        @{ Label = 'Config/sensitive';  Query = 'filetype:conf OR filetype:log OR filetype:sql OR filetype:env' }
    )

    Write-Host "[DuckDuckGo] Searching via HTML lite endpoint ($($dorkGroups.Count) queries/keyword)..." -ForegroundColor Cyan

    foreach ($keyword in $Keywords) {
        Write-Host "[DuckDuckGo] Searching for '$keyword'..." -ForegroundColor Gray

        foreach ($group in $dorkGroups) {
            $query = "`"$keyword`" $($group.Query)"
            $encodedQuery = [System.Uri]::EscapeDataString($query)
            $ddgUrl = Get-ProxiedUrl -Url "https://html.duckduckgo.com/html/?q=$encodedQuery" -ProxyBase $ProxyBase

            try {
                $reqParams = @{
                    Uri             = $ddgUrl
                    UseBasicParsing = $true
                    TimeoutSec      = 15
                    ErrorAction     = 'Stop'
                    Headers         = @{
                        'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                    }
                }
                $webResponse = Invoke-WebRequestWithRetry -RequestParams $reqParams -MaxRetries 3 -BaseDelaySeconds $DelaySeconds
                $html = $webResponse.Content

                # Detect DDG CAPTCHA/bot block (HTTP 202 with "select all squares")
                if ($webResponse.StatusCode -eq 202 -or $html -match 'anomaly-modal' -or $html -match 'cc=botnet') {
                    Write-Host "  [CAPTCHA] DDG rate limit hit - pausing 30s before continuing..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 30
                    # Retry once after cooldown
                    $webResponse = Invoke-WebRequest @reqParams
                    $html = $webResponse.Content
                    if ($webResponse.StatusCode -eq 202 -or $html -match 'anomaly-modal') {
                        Write-Host "  [CAPTCHA] Still blocked - skipping remaining dorks for '$keyword'" -ForegroundColor Red
                        break
                    }
                }

                # Detect DDG "query too long" error
                if ($html -match 'too long') {
                    Write-Host "  [Query Too Long] $($group.Label) - DDG rejected query length" -ForegroundColor DarkYellow
                }
                # DDG lite returns result links in <a class="result__a"> tags
                elseif ($html -match 'No results' -or $html -match 'No more results' -or $html -notmatch 'result__a') {
                    Write-Host "  [No Results] $($group.Label)" -ForegroundColor DarkGray
                }
                else {
                    # Extract result links from DDG HTML
                    $linkMatches = [regex]::Matches($html, 'class="result__a" href="([^"]+)"[^>]*>([^<]+)<')

                    if ($linkMatches.Count -gt 0) {
                        Write-Host "  [Results: $($linkMatches.Count)] $($group.Label)" -ForegroundColor Green
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
                                -Snippet "Found via DuckDuckGo: $($group.Label) dork" `
                                -Severity 'Review'
                        }
                    }
                    else {
                        Write-Host "  [Parse Error] $($group.Label) - could not extract links" -ForegroundColor DarkYellow
                    }
                }
            }
            catch {
                Write-Host "  [Error] $($group.Label) - $($_.Exception.Message)" -ForegroundColor DarkYellow
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

        [int]$DaysBack = 30,

        [string]$ProxyBase = ''
    )

    $results = @()
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)

    foreach ($keyword in $Keywords) {
        try {
            $encodedKeyword = [System.Uri]::EscapeDataString($keyword)
            $uri = "https://psbdmp.ws/api/v3/search/$encodedKeyword"

            Write-Verbose "[PasteSites] Querying psbdmp.ws for '$keyword'..."
            $reqParams = @{
                Uri         = $uri
                Method      = 'Get'
                TimeoutSec  = 15
                ErrorAction = 'Stop'
            }
            $response = Invoke-RestMethodWithRetry -RequestParams $reqParams -MaxRetries 1 -BaseDelaySeconds 3

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

        $ddgBase = Get-ProxiedUrl -Url "https://html.duckduckgo.com/html/" -ProxyBase $ProxyBase
        $pasteSites = @(
            @{ Name = 'Pastebin';     Url = "${ddgBase}?q=site:pastebin.com+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'Paste.ee';     Url = "${ddgBase}?q=site:paste.ee+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'Ghostbin';     Url = "${ddgBase}?q=site:ghostbin.com+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'Dpaste';       Url = "${ddgBase}?q=site:dpaste.org+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'Rentry';       Url = "${ddgBase}?q=site:rentry.co+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'JustPaste.it'; Url = "${ddgBase}?q=site:justpaste.it+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'ControlC';     Url = "${ddgBase}?q=site:controlc.com+%22$([System.Uri]::EscapeDataString($keyword))%22" },
            @{ Name = 'PrivateBin';   Url = "${ddgBase}?q=site:privatebin.net+%22$([System.Uri]::EscapeDataString($keyword))%22" }
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

function Search-BreachInfo {
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [int]$DaysBack = 30,

        [string]$ProxyBase = ''
    )

    $results = @()

    $breachSites = @(
        'haveibeenpwned.com',
        'krebsonsecurity.com',
        'bleepingcomputer.com',
        'securityweek.com',
        'therecord.media',
        'databreaches.net',
        'breachdirectory.org',
        'cybernews.com',
        'hackread.com',
        'securityaffairs.com',
        'darkreading.com',
        'thehackernews.com',
        'schneier.com',
        'grahamcluley.com',
        'csoonline.com',
        'infosecurity-magazine.com',
        'arstechnica.com',
        'reddit.com/r/netsec',
        'reddit.com/r/cybersecurity'
    )

    foreach ($keyword in $Keywords) {
        $encodedKeyword = [System.Uri]::EscapeDataString("`"$keyword`"")

        # --- DuckDuckGo searches across security blogs ---
        $combinedSites = ($breachSites | ForEach-Object { "site:$_" }) -join ' OR '
        $combinedUrl = Get-ProxiedUrl -Url "https://html.duckduckgo.com/html/?q=$encodedKeyword+($([System.Uri]::EscapeDataString($combinedSites)))" -ProxyBase $ProxyBase

        $results += New-AU13Result `
            -Source 'BreachBlogs-Combined' `
            -Keyword $keyword `
            -Title "MANUAL: Security blogs search for '$keyword'" `
            -Url $combinedUrl `
            -Snippet "Combined search across $($breachSites.Count) security/breach sites" `
            -Severity 'Manual-Review'

        foreach ($site in @('haveibeenpwned.com', 'krebsonsecurity.com', 'bleepingcomputer.com')) {
            $siteUrl = Get-ProxiedUrl -Url "https://html.duckduckgo.com/html/?q=site:$site+$encodedKeyword" -ProxyBase $ProxyBase
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

# --- Resolve web proxy (Menlo Security) ---
$proxyBase = ''
if ($UseProxy) {
    $proxyBase = $config.search.webProxyBase
}
elseif (-not $Silent) {
    Write-Host "Government networks may require Menlo Security web isolation proxy." -ForegroundColor Yellow
    $input = Read-Host "Are you on a government computer that uses Menlo Security? (y/N)"
    if ($input -match '^[Yy]') {
        $proxyBase = $config.search.webProxyBase
        Write-Host ""
        Write-Host "  Before continuing, make sure you are logged into Menlo Security:" -ForegroundColor Cyan
        Write-Host "    1. Open a browser and go to: $($config.search.webProxyBase)" -ForegroundColor Gray
        Write-Host "    2. Log in if prompted (usually only required after a reboot)" -ForegroundColor Gray
        Write-Host "    3. Once the page loads, you're good to go" -ForegroundColor Gray
        Write-Host ""
        Read-Host "Press Enter once you've confirmed Menlo Security is accessible"
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
        Write-Host "Available sources: DuckDuckGo, Paste, Breach" -ForegroundColor Gray
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
Write-Host "  Proxy:     $(if ($proxyBase) { $proxyBase } else { 'Direct (no proxy)' })" -ForegroundColor Gray
Write-Host "  GenAI:     $(if ([System.Environment]::GetEnvironmentVariable($config.genai.tokenEnvVar)) { 'Enabled' } else { 'Disabled (no token)' })" -ForegroundColor Gray
Write-Host ""

$allResults = @()

# --- DuckDuckGo ---
if ('DuckDuckGo' -in $Sources) {
    Write-Host "=== Scanning DuckDuckGo... ===" -ForegroundColor White
    $ddgResults = Search-DuckDuckGo -Keywords $keywords -DaysBack $DaysBack -DelaySeconds $config.search.delaySeconds -ProxyBase $proxyBase
    $allResults += $ddgResults
    Write-Host ""
}

# --- Paste Sites ---
if ('Paste' -in $Sources) {
    Write-Host "=== Scanning Paste Sites... ===" -ForegroundColor White
    $pasteResults = Search-PasteSites -Keywords $keywords -DaysBack $DaysBack -ProxyBase $proxyBase
    $allResults += $pasteResults
    Write-Host ""
}

# --- Breach Info ---
if ('Breach' -in $Sources) {
    Write-Host "=== Scanning Breach Sources... ===" -ForegroundColor White
    $breachResults = Search-BreachInfo -Keywords $keywords -DaysBack $DaysBack -ProxyBase $proxyBase
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
