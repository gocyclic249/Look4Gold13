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
            model            = 'google-gemini-2.5-pro'
            persona          = 5
            temperature      = 0.7
            limit_references = 5
            live             = 1
        }
        search = @{
            daysBack     = 30
            delaySeconds = 4
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

        [int]$DelaySeconds = 4,

        [string]$ProxyBase = '',

        [ref]$CaptchaState
    )

    $results = @()
    $seenUrls = @{}  # Dedup across queries

    # Broad contextual queries first (most effective — DDG returns top results from any site).
    # Then targeted site: queries for high-priority sites that may not surface in broad search.
    # Finally filetype: queries for document exposure.
    $dorks = @(
        # Broad: catches breach news, HIBP, security articles, etc.
        @{ Label = 'Breach/leak mentions'; Dork = 'breach data leak exposed' },
        # Broad: paste site and credential exposure
        @{ Label = 'Paste/credential';     Dork = 'pastebin paste credential dump' },
        # Broad: code and project exposure
        @{ Label = 'Code exposure';        Dork = 'github code exposed repository' },
        # Targeted: high-priority sites that may not surface in broad search
        @{ Label = 'Pastebin';             Dork = 'site:pastebin.com' },
        @{ Label = 'GitHub';               Dork = 'site:github.com' },
        # Document exposure
        @{ Label = 'PDF files';            Dork = 'filetype:pdf' },
        @{ Label = 'Excel files';          Dork = 'filetype:xlsx' },
        @{ Label = 'Word docs';            Dork = 'filetype:doc' },
        @{ Label = 'CSV files';            Dork = 'filetype:csv' }
    )

    Write-Host "[DuckDuckGo] Searching via HTML lite endpoint ($($dorks.Count) queries/keyword, ${DelaySeconds}s delay)..." -ForegroundColor Cyan

    foreach ($keyword in $Keywords) {
        Write-Host "[DuckDuckGo] Searching for '$keyword'..." -ForegroundColor Gray

        foreach ($dork in $dorks) {
            # Check shared CAPTCHA state — skip if blocked by prior searches
            if ($CaptchaState -and $CaptchaState.Value.Blocked) {
                Write-Host "  [Blocked] Skipping remaining dorks (CAPTCHA)" -ForegroundColor Red
                break
            }

            $query = "`"$keyword`" $($dork.Dork)"
            $encodedQuery = [System.Uri]::EscapeDataString($query)
            $ddgUrl = Get-ProxiedUrl -Url "https://html.duckduckgo.com/html/?q=$encodedQuery" -ProxyBase $ProxyBase

            $currentDelay = if ($CaptchaState) { $CaptchaState.Value.CurrentDelay } else { $DelaySeconds }

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
                $webResponse = Invoke-WebRequestWithRetry -RequestParams $reqParams -MaxRetries 3 -BaseDelaySeconds $currentDelay
                $html = $webResponse.Content

                # Detect DDG CAPTCHA/bot block (HTTP 202 with "select all squares")
                if ($webResponse.StatusCode -eq 202 -or $html -match 'anomaly-modal' -or $html -match 'cc=botnet') {
                    Write-Host "  [CAPTCHA] DDG rate limit hit - pausing 30s before continuing..." -ForegroundColor Yellow
                    if ($CaptchaState) {
                        $CaptchaState.Value.HitCount++
                        $CaptchaState.Value.CurrentDelay = [math]::Min(10, $CaptchaState.Value.CurrentDelay + 2)
                    }
                    Start-Sleep -Seconds 30
                    # Retry once after cooldown
                    $webResponse = Invoke-WebRequest @reqParams
                    $html = $webResponse.Content
                    if ($webResponse.StatusCode -eq 202 -or $html -match 'anomaly-modal') {
                        Write-Host "  [CAPTCHA] Still blocked - skipping remaining dorks for '$keyword'" -ForegroundColor Red
                        if ($CaptchaState) { $CaptchaState.Value.Blocked = $true }
                        break
                    }
                }

                # Detect DDG "query too long" error
                if ($html -match 'too long') {
                    Write-Host "  [Query Too Long] $($dork.Label) - DDG rejected query length" -ForegroundColor DarkYellow
                }
                else {
                    # Try multiple regex patterns to extract results — Menlo proxy
                    # may rewrite CSS class names, so fall back to URL patterns.
                    $linkMatches = [regex]::Matches($html, 'class="result__a" href="([^"]+)"[^>]*>([^<]+)<')
                    if ($linkMatches.Count -eq 0) {
                        # Fallback: match DDG redirect links by uddg= parameter
                        $linkMatches = [regex]::Matches($html, 'href="([^"]*uddg=[^"]+)"[^>]*>([^<]+)<')
                    }
                    if ($linkMatches.Count -eq 0) {
                        # Fallback: match any duckduckgo.com/l/ redirect links
                        $linkMatches = [regex]::Matches($html, 'href="([^"]*duckduckgo\.com/l/[^"]+)"[^>]*>([^<]+)<')
                    }

                    if ($linkMatches.Count -gt 0) {
                        $newCount = 0
                        foreach ($match in $linkMatches) {
                            $resultUrl = $match.Groups[1].Value
                            $resultTitle = $match.Groups[2].Value.Trim()

                            # DDG wraps URLs in a redirect — extract the real URL
                            if ($resultUrl -match 'uddg=([^&]+)') {
                                $resultUrl = [System.Uri]::UnescapeDataString($Matches[1])
                            }

                            # Dedup by URL
                            $urlKey = "$keyword|$resultUrl"
                            if ($seenUrls.ContainsKey($urlKey)) { continue }
                            $seenUrls[$urlKey] = $true
                            $newCount++

                            $results += New-AU13Result `
                                -Source 'DuckDuckGo' `
                                -Keyword $keyword `
                                -Title $resultTitle `
                                -Url $resultUrl `
                                -Snippet "DDG search: $ddgUrl" `
                                -Severity 'Review'
                        }
                        Write-Host "  [Results: $newCount new] $($dork.Label)" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  [No Results] $($dork.Label)" -ForegroundColor DarkGray
                    }
                }
            }
            catch {
                Write-Host "  [Error] $($dork.Label) - $($_.Exception.Message)" -ForegroundColor DarkYellow
            }

            Start-Sleep -Seconds $currentDelay
        }
    }

    Write-Host "[DuckDuckGo] Found $($results.Count) unique results" -ForegroundColor Cyan
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

    foreach ($keyword in $Keywords) {
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
    }

    Write-Host "[PasteSites] Manual links printed above (paste sites also covered by DuckDuckGo scan)" -ForegroundColor Cyan
    return $results
}

function Search-BreachInfo {
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [int]$DaysBack = 30,

        [int]$DelaySeconds = 4,

        [string]$ProxyBase = '',

        [ref]$CaptchaState
    )

    $results = @()
    $seenUrls = @{}  # Dedup across queries

    # Broad contextual queries first, then targeted high-priority breach sites.
    $breachDorks = @(
        # Broad: general breach/leak news — catches HIBP, BleepingComputer, SecurityWeek, etc.
        @{ Label = 'Breach/leak news';    Dork = 'breach data leak compromised' },
        # Broad: ransomware and attack news
        @{ Label = 'Ransomware/attacks';  Dork = 'ransomware attack security incident' },
        # Broad: credential/dark web exposure
        @{ Label = 'Credential exposure'; Dork = 'credential stolen dark web' },
        # Targeted: highest-priority breach sites that may not surface in broad search
        @{ Label = 'Have I Been Pwned';   Dork = 'site:haveibeenpwned.com' },
        @{ Label = 'DataBreaches.net';    Dork = 'site:databreaches.net' }
    )

    Write-Host "[BreachInfo] Searching $($breachDorks.Count) queries/keyword, ${DelaySeconds}s delay..." -ForegroundColor Cyan

    foreach ($keyword in $Keywords) {
        Write-Host "[BreachInfo] Searching for '$keyword'..." -ForegroundColor Gray

        foreach ($dork in $breachDorks) {
            # Check shared CAPTCHA state — skip if blocked by prior searches
            if ($CaptchaState -and $CaptchaState.Value.Blocked) {
                Write-Host "  [Blocked] Skipping remaining dorks (CAPTCHA)" -ForegroundColor Red
                break
            }

            $query = "`"$keyword`" $($dork.Dork)"
            $encodedQuery = [System.Uri]::EscapeDataString($query)
            $ddgUrl = Get-ProxiedUrl -Url "https://html.duckduckgo.com/html/?q=$encodedQuery" -ProxyBase $ProxyBase

            $currentDelay = if ($CaptchaState) { $CaptchaState.Value.CurrentDelay } else { $DelaySeconds }

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
                $webResponse = Invoke-WebRequestWithRetry -RequestParams $reqParams -MaxRetries 3 -BaseDelaySeconds $currentDelay
                $html = $webResponse.Content

                # Detect CAPTCHA
                if ($webResponse.StatusCode -eq 202 -or $html -match 'anomaly-modal' -or $html -match 'cc=botnet') {
                    Write-Host "  [CAPTCHA] DDG rate limit hit - pausing 30s..." -ForegroundColor Yellow
                    if ($CaptchaState) {
                        $CaptchaState.Value.HitCount++
                        $CaptchaState.Value.CurrentDelay = [math]::Min(10, $CaptchaState.Value.CurrentDelay + 2)
                    }
                    Start-Sleep -Seconds 30
                    $webResponse = Invoke-WebRequest @reqParams
                    $html = $webResponse.Content
                    if ($webResponse.StatusCode -eq 202 -or $html -match 'anomaly-modal') {
                        Write-Host "  [CAPTCHA] Still blocked - skipping remaining dorks for '$keyword'" -ForegroundColor Red
                        if ($CaptchaState) { $CaptchaState.Value.Blocked = $true }
                        break
                    }
                }

                if ($html -match 'too long') {
                    Write-Host "  [Query Too Long] $($dork.Label)" -ForegroundColor DarkYellow
                }
                else {
                    # Try multiple regex patterns — Menlo proxy may rewrite CSS classes
                    $linkMatches = [regex]::Matches($html, 'class="result__a" href="([^"]+)"[^>]*>([^<]+)<')
                    if ($linkMatches.Count -eq 0) {
                        $linkMatches = [regex]::Matches($html, 'href="([^"]*uddg=[^"]+)"[^>]*>([^<]+)<')
                    }
                    if ($linkMatches.Count -eq 0) {
                        $linkMatches = [regex]::Matches($html, 'href="([^"]*duckduckgo\.com/l/[^"]+)"[^>]*>([^<]+)<')
                    }

                    if ($linkMatches.Count -gt 0) {
                        $newCount = 0
                        foreach ($match in $linkMatches) {
                            $resultUrl = $match.Groups[1].Value
                            $resultTitle = $match.Groups[2].Value.Trim()

                            if ($resultUrl -match 'uddg=([^&]+)') {
                                $resultUrl = [System.Uri]::UnescapeDataString($Matches[1])
                            }

                            # Dedup by URL
                            $urlKey = "$keyword|$resultUrl"
                            if ($seenUrls.ContainsKey($urlKey)) { continue }
                            $seenUrls[$urlKey] = $true
                            $newCount++

                            $results += New-AU13Result `
                                -Source "BreachBlog" `
                                -Keyword $keyword `
                                -Title $resultTitle `
                                -Url $resultUrl `
                                -Snippet "DDG search: $ddgUrl" `
                                -Severity 'High'
                        }
                        Write-Host "  [Results: $newCount new] $($dork.Label)" -ForegroundColor Green
                    }
                    else {
                        Write-Host "  [No Results] $($dork.Label)" -ForegroundColor DarkGray
                    }
                }
            }
            catch {
                Write-Host "  [Error] $($dork.Label) - $($_.Exception.Message)" -ForegroundColor DarkYellow
            }

            Start-Sleep -Seconds $currentDelay
        }
    }

    Write-Host "[BreachInfo] Found $($results.Count) unique results" -ForegroundColor Cyan
    return $results
}

# ============================================================================
# GENAI SUMMARIZATION
# ============================================================================

function Invoke-GenAISummary {
    param(
        [Parameter(Mandatory)]
        [string]$Keyword,

        [AllowEmptyCollection()]
        [PSCustomObject[]]$Results = @(),

        [Parameter(Mandatory)]
        [hashtable]$GenAIConfig
    )

    $token = [System.Environment]::GetEnvironmentVariable($GenAIConfig.tokenEnvVar)
    if (-not $token) {
        return @{
            Message    = "GenAI summary unavailable - $($GenAIConfig.tokenEnvVar) environment variable not set."
            References = @()
        }
    }

    $headers = @{
        'x-access-tokens' = $token
        'Content-Type'    = 'application/json'
    }

    # Build different prompts depending on whether we have scan results
    if ($Results -and $Results.Count -gt 0) {
        $resultSummary = $Results | ForEach-Object {
            "- [$($_.Severity)] $($_.Source): $($_.Title) | URL: $($_.Url) | $($_.Snippet)"
        }
        $resultText = $resultSummary -join "`n"

        $prompt = @"
You are an AU-13 compliance analyst. Analyze the following scan results for the keyword "$Keyword" and provide:
1. A brief risk assessment (1-2 sentences)
2. Key findings summary (bullet points)
3. Recommended actions
4. Additional sources: Search the web for any additional public disclosures, data breaches, paste site leaks, or security incidents related to "$Keyword" that are NOT already in the scan results below. List each additional source with its URL and a brief description.

Scan Results:
$resultText
"@
    }
    else {
        $prompt = @"
You are an AU-13 compliance analyst. The automated scan found NO results for "$Keyword" on monitored sites (paste sites, GitHub, breach databases, security news).

Using your live search capability, search the web for any public disclosures, data breaches, paste site leaks, credential dumps, or security incidents related to "$Keyword". Provide:
1. A brief risk assessment (1-2 sentences)
2. Any findings from your search (with source URLs for each finding)
3. Recommended actions

If you find evidence of compromise or disclosure, list each source with its full URL.
"@
    }

    $body = @{
        message          = $prompt
        persona          = $GenAIConfig.persona
        model            = $GenAIConfig.model
        temperature      = $GenAIConfig.temperature
        limit_references = $GenAIConfig.limit_references
        live             = $GenAIConfig.live
    } | ConvertTo-Json -Depth 3

    try {
        $action = if ($Results -and $Results.Count -gt 0) { "Summarizing" } else { "Searching for" }
        Write-Host "[GenAI] $action '$Keyword'..." -ForegroundColor Cyan
        $response = Invoke-RestMethodWithRetry -RequestParams @{
            Uri         = $GenAIConfig.endpoint
            Method      = 'Post'
            Headers     = $headers
            Body        = $body
            TimeoutSec  = 300
            ErrorAction = 'Stop'
        } -MaxRetries 2 -BaseDelaySeconds 3

        Start-Sleep -Seconds 3

        # Capture both message and references from API response
        $refs = @()
        if ($response.references) {
            $refs = @($response.references)
            Write-Host "[GenAI] Received $($refs.Count) reference(s) for '$Keyword'" -ForegroundColor Gray
        }

        if ($response.message) {
            return @{
                Message    = $response.message
                References = $refs
            }
        }
        else {
            return @{
                Message    = "GenAI returned an empty response."
                References = $refs
            }
        }
    }
    catch {
        Write-Warning "[GenAI] Error for '$Keyword': $($_.Exception.Message)"
        return @{
            Message    = "GenAI summary failed: $($_.Exception.Message)"
            References = @()
        }
    }
}

# ============================================================================
# HTML REPORT EXPORT
# ============================================================================

function Export-AU13Html {
    param(
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Results = @(),

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

    # Build per-keyword result blocks — include ALL keywords (even those with 0 DDG
    # results) so GenAI summaries are always shown.
    $keywordBlocks = ""

    # Combine keywords from results + keywords from AI summaries to cover all
    $allKeywordNames = @()
    if ($Results -and $Results.Count -gt 0) {
        $allKeywordNames += @($Results | ForEach-Object { $_.Keyword } | Select-Object -Unique)
    }
    foreach ($aiKey in $AISummaries.Keys) {
        if ($aiKey -notin $allKeywordNames) { $allKeywordNames += $aiKey }
    }
    # Also include any keywords passed to the function
    foreach ($inputKw in $Keywords) {
        if ($inputKw -notin $allKeywordNames) { $allKeywordNames += $inputKw }
    }

    foreach ($kwName in $allKeywordNames) {
        $kw = [System.Web.HttpUtility]::HtmlEncode($kwName)
        $kwResults = @($Results | Where-Object { $_.Keyword -eq $kwName })
        $count = $kwResults.Count

        $listItems = ""
        foreach ($r in $kwResults) {
            $title = [System.Web.HttpUtility]::HtmlEncode($r.Title)
            $url   = [System.Web.HttpUtility]::HtmlEncode($r.Url)
            $src   = [System.Web.HttpUtility]::HtmlEncode($r.Source)
            $sev   = $r.Severity

            # Render DDG search URLs as clickable links in the snippet
            if ($r.Snippet -match '^DDG search: (.+)$') {
                $searchUrl = [System.Web.HttpUtility]::HtmlEncode($Matches[1])
                $snip = "Found via: <a href=`"$searchUrl`" target=`"_blank`">DDG search</a>"
            }
            else {
                $snip = [System.Web.HttpUtility]::HtmlEncode($r.Snippet)
            }

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
        if ($AISummaries.ContainsKey($kwName)) {
            $aiData = $AISummaries[$kwName]

            if ($aiData -is [hashtable]) {
                $aiText = [System.Web.HttpUtility]::HtmlEncode($aiData.Message) -replace "`n", "<br>"

                # Render AI references as clickable source links
                $refsHtml = ""
                if ($aiData.References -and $aiData.References.Count -gt 0) {
                    $refsHtml = "<h4>Sources Found by AI</h4><ul class=`"ai-refs`">"
                    foreach ($ref in $aiData.References) {
                        if ($ref -is [string]) {
                            $refEnc = [System.Web.HttpUtility]::HtmlEncode($ref)
                            if ($ref -match '^https?://') {
                                $refsHtml += "<li><a href=`"$refEnc`" target=`"_blank`">$refEnc</a></li>"
                            }
                            else {
                                $refsHtml += "<li>$refEnc</li>"
                            }
                        }
                        elseif ($ref.url) {
                            $refUrlEnc = [System.Web.HttpUtility]::HtmlEncode($ref.url)
                            $refTitleEnc = if ($ref.title) { [System.Web.HttpUtility]::HtmlEncode($ref.title) } else { $refUrlEnc }
                            $refsHtml += "<li><a href=`"$refUrlEnc`" target=`"_blank`">$refTitleEnc</a></li>"
                        }
                        elseif ($ref.source) {
                            $refSrcEnc = [System.Web.HttpUtility]::HtmlEncode($ref.source)
                            if ($ref.source -match '^https?://') {
                                $refsHtml += "<li><a href=`"$refSrcEnc`" target=`"_blank`">$refSrcEnc</a></li>"
                            }
                            else {
                                $refsHtml += "<li>$refSrcEnc</li>"
                            }
                        }
                        else {
                            $refStr = [System.Web.HttpUtility]::HtmlEncode(($ref | ConvertTo-Json -Compress))
                            $refsHtml += "<li>$refStr</li>"
                        }
                    }
                    $refsHtml += "</ul>"
                }

                $aiBlock = @"
            <div class="ai-summary">
                <h3>AI Analysis</h3>
                <div class="ai-content">$aiText</div>
                $refsHtml
            </div>
"@
            }
            else {
                # Legacy: plain string format
                $aiText = [System.Web.HttpUtility]::HtmlEncode($aiData) -replace "`n", "<br>"
                $aiBlock = @"
            <div class="ai-summary">
                <h3>AI Analysis</h3>
                <div class="ai-content">$aiText</div>
            </div>
"@
            }
        }

        # Show result list or "no DDG results" message
        $resultSection = ""
        if ($count -gt 0) {
            $resultSection = @"
            <p class="result-count">Result Count: $count</p>
            <ul>
$listItems
            </ul>
"@
        }
        else {
            $resultSection = "            <p class=`"result-count`" style=`"color:#999;`">No results from DDG scans</p>"
        }

        $keywordBlocks += @"
        <div class="query-block">
            <h2>Query: &quot;$kw&quot;</h2>
$resultSection
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
        .ai-summary h4 { margin: 12px 0 6px 0; color: #333; font-size: 0.9em; }
        .ai-refs { padding-left: 20px; margin: 4px 0; list-style: disc; }
        .ai-refs li { font-size: 0.85em; color: #555; padding: 2px 0; }
        .ai-refs a { color: #0d6efd; }
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

# Shared CAPTCHA state across all DDG-based searches — if DuckDuckGo scanning
# triggers CAPTCHA, the escalated delay carries over to BreachInfo queries.
$captchaState = @{ HitCount = 0; CurrentDelay = $config.search.delaySeconds; Blocked = $false }

# --- DuckDuckGo ---
if ('DuckDuckGo' -in $Sources) {
    Write-Host "=== Scanning DuckDuckGo... ===" -ForegroundColor White
    $ddgResults = Search-DuckDuckGo -Keywords $keywords -DaysBack $DaysBack -DelaySeconds $config.search.delaySeconds -ProxyBase $proxyBase -CaptchaState ([ref]$captchaState)
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
    $breachResults = Search-BreachInfo -Keywords $keywords -DaysBack $DaysBack -DelaySeconds $config.search.delaySeconds -ProxyBase $proxyBase -CaptchaState ([ref]$captchaState)
    $allResults += $breachResults
    Write-Host ""
}

# --- Summary ---
Write-Host "=== Scan Complete ===" -ForegroundColor Green
Write-Host ""

if ($allResults.Count -eq 0) {
    Write-Host "No results found from DDG scans. GenAI will search independently." -ForegroundColor Yellow
}
else {
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
}
Write-Host ""

# --- GenAI Summarization (per keyword — runs for ALL keywords, even with 0 DDG results) ---
$aiSummaries = @{}
$genaiTokenCheck = [System.Environment]::GetEnvironmentVariable($config.genai.tokenEnvVar)
if ($genaiTokenCheck) {
    Write-Host "=== Running GenAI Analysis... ===" -ForegroundColor White

    foreach ($kw in $keywords) {
        $kwResults = @($allResults | Where-Object { $_.Keyword -eq $kw })
        $summary = Invoke-GenAISummary -Keyword $kw -Results $kwResults -GenAIConfig $config.genai
        $aiSummaries[$kw] = $summary

        # Add GenAI-discovered references as scan results
        if ($summary -is [hashtable] -and $summary.References -and $summary.References.Count -gt 0) {
            foreach ($ref in $summary.References) {
                $refUrl = ''
                $refTitle = 'AI-discovered source'
                if ($ref -is [string] -and $ref -match '^https?://') {
                    $refUrl = $ref
                }
                elseif ($ref.url) {
                    $refUrl = $ref.url
                    if ($ref.title) { $refTitle = $ref.title }
                }
                elseif ($ref.source) {
                    $refUrl = $ref.source
                }
                if ($refUrl) {
                    $allResults += New-AU13Result `
                        -Source 'GenAI-Live' `
                        -Keyword $kw `
                        -Title $refTitle `
                        -Url $refUrl `
                        -Snippet "Found by Ask Sage live search" `
                        -Severity 'Review'
                }
            }
        }
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
