<#
.SYNOPSIS
    Look4Gold13 - AU-13 Publicly Available Content Scanner
.DESCRIPTION
    Searches DuckDuckGo for keywords combined with search dorks to find
    publicly exposed information (NIST SP 800-53 AU-13 compliance).
    Uses aggressive rate-limit evasion: UA rotation, session rotation,
    randomized timing, and query parameter variation.
.EXAMPLE
    .\Look4Gold13.ps1 -MaxDorks 4
    .\Look4Gold13.ps1 -MaxDorks 1 -BaseDelay 90
    .\Look4Gold13.ps1 -Silent
#>
param(
    [string]$KeywordFile,
    [int]$MaxDorks       = 0,       # 0 = all dorks; N = use first N only
    [int]$BaseDelay      = 60,      # Base seconds between requests
    [int]$MinJitter      = 5,       # Min additional random seconds
    [int]$MaxJitter      = 15,      # Max additional random seconds
    [switch]$VerboseOutput,         # Extra debug output
    [string]$OutputFile,            # Custom path for CSV export
    [switch]$NoExport,              # Suppress file export
    [switch]$Silent                 # Suppress all console output
)

# ============================================================================
# SILENT MODE — suppress all console output when -Silent is set
# ============================================================================
if ($Silent) {
    function Write-Host { <# silenced #> }
}

# ============================================================================
# TLS CONFIGURATION
# ============================================================================
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
Add-Type -AssemblyName System.Web

# ============================================================================
# BROWSER PROFILE POOL
# Each profile pairs a User-Agent with its correct Sec-CH-UA headers.
# Firefox does NOT send Sec-CH-UA headers; Chrome/Edge do.
# ============================================================================
$Script:BrowserProfiles = @(
    # Chrome 131 on Windows
    @{
        UA       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        SecCHUA  = '"Not A(Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"'
        Platform = '"Windows"'
        IsChrome = $true
    }
    # Chrome 132 on Windows
    @{
        UA       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
        SecCHUA  = '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"'
        Platform = '"Windows"'
        IsChrome = $true
    }
    # Chrome 131 on macOS
    @{
        UA       = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        SecCHUA  = '"Not A(Brand";v="8", "Chromium";v="131", "Google Chrome";v="131"'
        Platform = '"macOS"'
        IsChrome = $true
    }
    # Chrome 132 on macOS
    @{
        UA       = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
        SecCHUA  = '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"'
        Platform = '"macOS"'
        IsChrome = $true
    }
    # Firefox 134 on Windows
    @{
        UA       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0'
        SecCHUA  = $null
        Platform = $null
        IsChrome = $false
    }
    # Firefox 133 on Windows
    @{
        UA       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0'
        SecCHUA  = $null
        Platform = $null
        IsChrome = $false
    }
    # Firefox 134 on macOS
    @{
        UA       = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0'
        SecCHUA  = $null
        Platform = $null
        IsChrome = $false
    }
    # Edge 131 on Windows
    @{
        UA       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
        SecCHUA  = '"Not A(Brand";v="8", "Chromium";v="131", "Microsoft Edge";v="131"'
        Platform = '"Windows"'
        IsChrome = $true
    }
    # Edge 132 on Windows
    @{
        UA       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0'
        SecCHUA  = '"Not A(Brand";v="8", "Chromium";v="132", "Microsoft Edge";v="132"'
        Platform = '"Windows"'
        IsChrome = $true
    }
    # Edge 131 on macOS
    @{
        UA       = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0'
        SecCHUA  = '"Not A(Brand";v="8", "Chromium";v="131", "Microsoft Edge";v="131"'
        Platform = '"macOS"'
        IsChrome = $true
    }
)

# DDG parameter variation pools
$Script:DdgRegions = @('us-en', 'uk-en', 'au-en', 'ca-en', 'wt-wt')
$Script:DdgDateFilters = @('none', 'w', 'm')   # none=anytime, w=past week, m=past month
$Script:RefererPool = @(
    'none'
    'https://duckduckgo.com/'
    'https://html.duckduckgo.com/'
    'https://start.duckduckgo.com/'
)

# ============================================================================
# RATE-LIMIT EVASION FUNCTIONS
# ============================================================================

function Get-RandomIdentity {
    <# Returns a fresh set of headers + WebRequestSession for one request. #>

    $profile = Get-Random -InputObject $Script:BrowserProfiles

    # Slight Accept-Language variation
    $langQuality = Get-Random -Minimum 5 -Maximum 10

    $headers = [ordered]@{
        'User-Agent'                = $profile.UA
        'Accept'                    = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
        'Accept-Language'           = "en-US,en;q=0.$langQuality"
        'Accept-Encoding'           = 'gzip, deflate'
        'Upgrade-Insecure-Requests' = '1'
        'DNT'                       = '1'
    }

    # Chrome/Edge send Sec-CH-UA headers; Firefox does NOT
    if ($profile.IsChrome) {
        $headers['Sec-CH-UA']          = $profile.SecCHUA
        $headers['Sec-CH-UA-Mobile']   = '?0'
        $headers['Sec-CH-UA-Platform'] = $profile.Platform
        $headers['Sec-Fetch-Dest']     = 'document'
        $headers['Sec-Fetch-Mode']     = 'navigate'
        $headers['Sec-Fetch-Site']     = (Get-Random -InputObject @('none', 'same-origin'))
        $headers['Sec-Fetch-User']     = '?1'
    }

    $referer = Get-Random -InputObject $Script:RefererPool
    if ($referer -ne 'none') { $headers['Referer'] = $referer }

    # Fresh session = fresh cookie jar = no tracking between requests
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    return @{
        Headers    = $headers
        WebSession = $session
        BrowserTag = if ($profile.IsChrome) { $profile.UA -replace '.*?(Chrome|Edg)/(\d+).*', '$1/$2' } else { $profile.UA -replace '.*?(Firefox)/(\d+).*', '$1/$2' }
    }
}

function Get-RandomDelay {
    param(
        [int]$BaseSeconds = 30,
        [int]$MinJitter   = 5,
        [int]$MaxJitter   = 15
    )
    $jitter = Get-Random -Minimum $MinJitter -Maximum ($MaxJitter + 1)
    return $BaseSeconds + $jitter
}

function Build-DdgUrl {
    param(
        [Parameter(Mandatory)][string]$Keyword,
        [Parameter(Mandatory)][string]$Dork
    )
    $query = "`"$Keyword`" $Dork"
    $encodedQuery = [System.Uri]::EscapeDataString($query)
    $url = "https://html.duckduckgo.com/html/?q=$encodedQuery"

    # Random region parameter
    $region = Get-Random -InputObject $Script:DdgRegions
    if ($region -ne 'wt-wt') { $url += "&kl=$region" }

    # Random date filter
    $dateFilter = Get-Random -InputObject $Script:DdgDateFilters
    if ($dateFilter -ne 'none') { $url += "&df=$dateFilter" }

    return $url
}

# ============================================================================
# CAPTCHA DETECTION
# ============================================================================

function Test-CaptchaResponse {
    param(
        [Parameter(Mandatory)]$WebResponse,
        [Parameter(Mandatory)][string]$Html
    )

    if ($WebResponse.StatusCode -eq 202) {
        return @{ IsCaptcha = $true; Reason = 'HTTP 202 response' }
    }
    if ($Html -match 'anomaly-modal') {
        return @{ IsCaptcha = $true; Reason = 'anomaly-modal in HTML' }
    }
    if ($Html -match 'cc=botnet') {
        return @{ IsCaptcha = $true; Reason = 'cc=botnet parameter' }
    }
    if ($Html -match 'Please try again') {
        return @{ IsCaptcha = $true; Reason = '"Please try again" message' }
    }
    if ($Html -match 'automated requests') {
        return @{ IsCaptcha = $true; Reason = '"automated requests" warning' }
    }
    return @{ IsCaptcha = $false; Reason = '' }
}

# ============================================================================
# CONFIG LOADING
# ============================================================================

function Import-Keywords {
    param([string]$Path)

    if (-not $Path) {
        $Path = Join-Path (Join-Path $PSScriptRoot 'config') 'keywords.txt'
    }

    if (-not (Test-Path $Path)) {
        Write-Error "Keywords file not found: '$Path'. Copy config/keywords.example.txt to config/keywords.txt and add your terms."
        exit 1
    }

    $keywords = @(Get-Content -Path $Path |
        Where-Object { $_ -and $_.Trim() -and -not $_.Trim().StartsWith('#') } |
        ForEach-Object { $_.Trim() })

    if ($keywords.Count -eq 0) {
        Write-Error "Keywords file is empty or contains only comments: $Path"
        exit 1
    }

    Write-Host "  Loaded $($keywords.Count) keyword(s) from $Path" -ForegroundColor DarkGray
    return $keywords
}

function Import-Sources {
    param(
        [string]$Path,
        [int]$MaxDorks       = 0
    )

    if (-not $Path) {
        $Path = Join-Path (Join-Path $PSScriptRoot 'config') 'sources.json'
    }

    if (-not (Test-Path $Path)) {
        Write-Error "Sources file not found: '$Path'"
        exit 1
    }

    $sources = Get-Content -Path $Path -Raw | ConvertFrom-Json

    # Load breach dorks first so they run before DDG gets blocked
    $dorks = @()
    if ($sources.breachDorks) {
        $dorks += @($sources.breachDorks | ForEach-Object {
            @{ Label = $_.label; Dork = $_.dork }
        })
    }

    $dorks += @($sources.ddgDorks | ForEach-Object {
        @{ Label = $_.label; Dork = $_.dork }
    })

    if ($MaxDorks -gt 0 -and $MaxDorks -lt $dorks.Count) {
        $dorks = $dorks[0..($MaxDorks - 1)]
    }

    Write-Host "  Loaded $($dorks.Count) dork(s) from $Path" -ForegroundColor DarkGray
    return $dorks
}

# ============================================================================
# DORK GROUPING
# ============================================================================

function Group-Dorks {
    <# Groups flat dork array into combined OR query groups by type. #>
    param([Parameter(Mandatory)][array]$Dorks)

    $siteGroup  = @{ GroupLabel = 'Sites'; Dorks = @(); Labels = @(); Mappings = @() }
    $textGroups = @()

    foreach ($d in $Dorks) {
        if ($d.Dork -match '^site:(.+)$') {
            $siteGroup.Dorks   += $d.Dork
            $siteGroup.Labels  += $d.Label
            $domain = ($Matches[1] -replace '\.', '\.') -replace '/', '\/'
            $siteGroup.Mappings += @{ Label = $d.Label; Pattern = $domain }
        }
        else {
            $textGroups += @{
                GroupLabel   = $d.Label
                Dorks        = @($d.Dork)
                Labels       = @($d.Label)
                Mappings     = @(@{ Label = $d.Label; Pattern = '.' })
                CombinedDork = $d.Dork
            }
        }
    }

    $groups = @()

    if ($siteGroup.Dorks.Count -gt 0) {
        if ($siteGroup.Dorks.Count -eq 1) {
            $siteGroup['CombinedDork'] = $siteGroup.Dorks[0]
        } else {
            $siteGroup['CombinedDork'] = '(' + ($siteGroup.Dorks -join ' OR ') + ')'
        }
        $groups += $siteGroup
    }

    $groups += $textGroups

    return $groups
}

# ============================================================================
# RESULT PARSING
# ============================================================================

function Parse-DdgResults {
    param(
        [Parameter(Mandatory)][string]$Html,
        [Parameter(Mandatory)][string]$Keyword,
        [string]$GroupLabel = '',
        [array]$DorkMappings = @()
    )

    $results = @()

    if ($Html -match 'too long') {
        Write-Host "  [Query Too Long] DDG rejected query length" -ForegroundColor DarkYellow
        return $results
    }

    # Build snippet lookup: raw href -> snippet text
    $snippetLookup = @{}
    $snippetMatches = [regex]::Matches($Html,
        '(?s)class="result__a"[^>]*href="([^"]+)"[^>]*>.*?class="result__snippet"[^>]*>(.*?)</(?:a|span)>')
    foreach ($sm in $snippetMatches) {
        $rawHref = $sm.Groups[1].Value
        $rawSnippet = ($sm.Groups[2].Value -replace '<[^>]+>', '').Trim()
        if ($rawHref -and $rawSnippet) {
            $snippetLookup[$rawHref] = $rawSnippet
        }
    }
    # Also try reversed attribute order
    $snippetMatches2 = [regex]::Matches($Html,
        '(?s)href="([^"]+)"[^>]*class="result__a"[^>]*>.*?class="result__snippet"[^>]*>(.*?)</(?:a|span)>')
    foreach ($sm in $snippetMatches2) {
        $rawHref = $sm.Groups[1].Value
        $rawSnippet = ($sm.Groups[2].Value -replace '<[^>]+>', '').Trim()
        if ($rawHref -and -not $snippetLookup.ContainsKey($rawHref)) {
            $snippetLookup[$rawHref] = $rawSnippet
        }
    }

    # Tier 1: DDG native result__a links (handles both attribute orders)
    $linkMatches = [regex]::Matches($Html,
        '<a\b((?:[^>]*\bclass="result__a"[^>]*\bhref="([^"]+)"|[^>]*\bhref="([^"]+)"[^>]*\bclass="result__a")[^>]*)>([^<]+)<')

    # Tier 2: uddg= redirect links
    if ($linkMatches.Count -eq 0) {
        $linkMatches = [regex]::Matches($Html, 'href="([^"]*uddg=[^"]+)"[^>]*>([^<]+)<')
    }

    # Tier 3: duckduckgo.com/l/ redirect links
    if ($linkMatches.Count -eq 0) {
        $linkMatches = [regex]::Matches($Html, 'href="([^"]*duckduckgo\.com/l/[^"]+)"[^>]*>([^<]+)<')
    }

    foreach ($match in $linkMatches) {
        # Extract URL and title from the correct regex groups
        if ($match.Groups.Count -ge 5 -and $match.Groups[4].Value) {
            $resultUrl = if ($match.Groups[2].Value) { $match.Groups[2].Value } else { $match.Groups[3].Value }
            $resultTitle = $match.Groups[4].Value.Trim()
        } else {
            $resultUrl = $match.Groups[1].Value
            $resultTitle = $match.Groups[2].Value.Trim()
        }

        if (-not $resultTitle -or -not $resultUrl) { continue }

        # Unwrap DDG redirect (uddg= parameter)
        if ($resultUrl -match 'uddg=([^&]+)') {
            $resultUrl = [System.Uri]::UnescapeDataString($Matches[1])
        }

        # Strip remaining DDG wrapper
        if ($resultUrl -match '^(//|https?://)duckduckgo\.com') {
            if ($resultUrl -match 'uddg=([^&]+)') {
                $resultUrl = [System.Uri]::UnescapeDataString($Matches[1])
            } else {
                continue
            }
        }

        # Normalize scheme
        if ($resultUrl -match '^//') { $resultUrl = 'https:' + $resultUrl }
        if ($resultUrl -notmatch '^https?://') { $resultUrl = 'https://' + $resultUrl }

        # Infer specific dork label from URL using mappings
        $inferredLabel = $GroupLabel
        if ($DorkMappings.Count -gt 0) {
            foreach ($mapping in $DorkMappings) {
                if ($resultUrl -match $mapping.Pattern) {
                    $inferredLabel = $mapping.Label
                    break
                }
            }
        }

        # Look up snippet using raw href from match groups
        $rawSnippet = ''
        $rawHref = if ($match.Groups[2].Value) { $match.Groups[2].Value }
                   elseif ($match.Groups[3].Value) { $match.Groups[3].Value }
                   else { $match.Groups[1].Value }
        if ($rawHref -and $snippetLookup.ContainsKey($rawHref)) {
            $rawSnippet = $snippetLookup[$rawHref]
        }

        $results += [PSCustomObject]@{
            Keyword = $Keyword
            Title   = $resultTitle
            Url     = $resultUrl
            Dork    = $inferredLabel
            Summary = $rawSnippet
        }
    }

    return $results
}

# ============================================================================
# CORE SEARCH FUNCTION
# ============================================================================

function Invoke-DdgSearch {
    param(
        [Parameter(Mandatory)][string]$Keyword,
        [Parameter(Mandatory)][string]$Dork,
        [Parameter(Mandatory)][string]$GroupLabel,
        [Parameter(Mandatory)][ref]$CaptchaState,
        [array]$DorkMappings = @(),
        [switch]$VerboseOutput
    )

    # 1. Fresh identity for this request
    $identity = Get-RandomIdentity

    # 2. Build URL with randomized params
    $url = Build-DdgUrl -Keyword $Keyword -Dork $Dork

    # Debug: show browser profile, group info, and search parameters
    $dbgReferer = if ($identity.Headers['Referer']) { $identity.Headers['Referer'] } else { '(none)' }
    $dbgRegion = if ($url -match 'kl=([^&]+)') { $Matches[1] } else { 'wt-wt' }
    $dbgDateFilter = if ($url -match 'df=([^&]+)') { $Matches[1] } else { 'none' }
    $dbgSecFetchSite = if ($identity.Headers['Sec-Fetch-Site']) { $identity.Headers['Sec-Fetch-Site'] } else { 'n/a' }
    Write-Host ""
    Write-Host "    [DEBUG] Group: $GroupLabel | Browser: $($identity.BrowserTag) | Referer: $dbgReferer" -ForegroundColor DarkGray
    Write-Host "    [DEBUG] Region: $dbgRegion | DateFilter: $dbgDateFilter | SecFetchSite: $dbgSecFetchSite" -ForegroundColor DarkGray
    Write-Host "    [DEBUG] UA: $($identity.Headers['User-Agent'])" -ForegroundColor DarkGray
    Write-Host "    [DEBUG] Query: $Dork" -ForegroundColor DarkGray

    # 3. Make the request
    $reqParams = @{
        Uri             = $url
        UseBasicParsing = $true
        TimeoutSec      = 20
        ErrorAction     = 'Stop'
        Headers         = $identity.Headers
        WebSession      = $identity.WebSession
    }

    $webResponse = $null
    try {
        $webResponse = Invoke-WebRequest @reqParams
    } catch {
        # Network-level retry with backoff (max 3 attempts)
        $retryable = $_.Exception.Message -match 'connection was closed|Unable to connect|timed out|ConnectFailure'
        if ($retryable) {
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                $retryDelay = 5 * [math]::Pow(2, $attempt - 1)
                Write-Host "    [Retry $attempt/3] Network error, waiting ${retryDelay}s..." -ForegroundColor DarkYellow
                Start-Sleep -Seconds $retryDelay
                try {
                    $identity = Get-RandomIdentity
                    $reqParams.Headers = $identity.Headers
                    $reqParams.WebSession = $identity.WebSession
                    $webResponse = Invoke-WebRequest @reqParams
                    break
                } catch {
                    if ($attempt -eq 3) { throw }
                }
            }
        } else {
            throw
        }
    }

    $html = $webResponse.Content

    # 4. CAPTCHA check
    $captchaCheck = Test-CaptchaResponse -WebResponse $webResponse -Html $html
    if ($captchaCheck.IsCaptcha) {
        $CaptchaState.Value.HitCount++
        $CaptchaState.Value.ConsecutiveHits++
        $CaptchaState.Value.LastHitTime = Get-Date

        # Exponential backoff: 60s, 120s, 240s, 480s (capped)
        $backoffSeconds = [int](60 * [math]::Pow(2, [math]::Min($CaptchaState.Value.ConsecutiveHits - 1, 3)))
        Write-Host ""
        Write-Host "  [CAPTCHA] $($captchaCheck.Reason)" -ForegroundColor Red
        Write-Host "  [CAPTCHA] Backoff: ${backoffSeconds}s (consecutive hit #$($CaptchaState.Value.ConsecutiveHits))" -ForegroundColor Red
        Start-Sleep -Seconds $backoffSeconds

        # Retry once with completely fresh identity + rebuilt URL
        $identity = Get-RandomIdentity
        $url = Build-DdgUrl -Keyword $Keyword -Dork $Dork
        $reqParams.Uri = $url
        $reqParams.Headers = $identity.Headers
        $reqParams.WebSession = $identity.WebSession

        try {
            $webResponse = Invoke-WebRequest @reqParams
            $html = $webResponse.Content
        } catch {
            $CaptchaState.Value.Blocked = $true
            Write-Host "  [CAPTCHA] Retry failed with error - halting DDG searches" -ForegroundColor Red
            return @{ Results = @(); CaptchaBlocked = $true }
        }

        $retryCheck = Test-CaptchaResponse -WebResponse $webResponse -Html $html
        if ($retryCheck.IsCaptcha) {
            $CaptchaState.Value.Blocked = $true
            Write-Host "  [CAPTCHA] Still blocked after retry - halting DDG searches" -ForegroundColor Red
            return @{ Results = @(); CaptchaBlocked = $true }
        }

        # Retry succeeded
        Write-Host "  [CAPTCHA] Retry succeeded - resuming" -ForegroundColor Green
        $CaptchaState.Value.ConsecutiveHits = 0
    } else {
        $CaptchaState.Value.ConsecutiveHits = 0
    }

    # 5. Parse results
    $results = Parse-DdgResults -Html $html -Keyword $Keyword -GroupLabel $GroupLabel -DorkMappings $DorkMappings

    # 6. Debug: save HTML if no results and verbose
    if ($results.Count -eq 0 -and $VerboseOutput) {
        $debugFile = Join-Path $PSScriptRoot "debug_ddg_$($GroupLabel -replace '[^a-zA-Z0-9]','_').html"
        $html | Out-File -FilePath $debugFile -Encoding utf8
        Write-Host "    [Debug] No results - HTML saved to $debugFile" -ForegroundColor DarkGray
    }

    return @{ Results = $results; CaptchaBlocked = $false }
}

# ============================================================================
# ASK SAGE AGI QUERY
# ============================================================================

function Invoke-AskSageQuery {
    <# Sends a single query to the Ask Sage API using keywords and scan results.
       Returns the parsed response or $null on failure. #>
    param(
        [Parameter(Mandatory)][array]$Keywords,
        [Parameter(Mandatory)][string]$ApiKey,
        [array]$ScanResults = @()
    )

    $uri = "https://api.genai.army.mil/server/query"

    $headers = @{
        "Content-Type"     = "application/json"
        "x-access-tokens"  = $ApiKey
    }

    $searchText = $Keywords -join ', '
    $days = 30

    # Build context from scan results if available
    $scanContext = ""
    if ($ScanResults.Count -gt 0) {
        $scanContext = "`n`nThe following links were discovered during an initial scan. Use them as a starting point and search broadly for additional related information:`n"
        foreach ($r in $ScanResults) {
            $scanContext += "- $($r.Url)`n"
        }
    }

    $body = @{
        message     = @"
Please search for any recent cyber security news, breaches, leaks, vulnerabilities, ransomware, or other notable events related to $searchText in the last $days days. Search broadly across the internet — do not limit yourself to specific sites. Provide a link to every article or site referenced. For each entry, assess the severity as Critical, High, Medium, Low, or Informational based on the potential impact. Format response as JSON array. Use the following format for each entry:
{
  "date_published":
  "source_site":
  "category":
  "severity":
  "title":
  "summary":
  "link":
}$scanContext
"@
        persona     = 5
        model       = "google-gemini-2.5-pro"
        temperature = 0.7
        live        = 2
    } | ConvertTo-Json -Depth 3

    Write-Host "[Ask Sage] Sending AGI query for: $searchText" -ForegroundColor Cyan
    Write-Host "[Ask Sage] This may take a moment (live web search enabled)..." -ForegroundColor DarkGray

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body
        Write-Host "[Ask Sage] Response received." -ForegroundColor Green
        return $response
    } catch {
        Write-Host "[Ask Sage] ERROR: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response) {
            Write-Host "[Ask Sage] HTTP Status: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
        }
        return $null
    }
}

# ============================================================================
# MAIN
# ============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor White
Write-Host " Look4Gold13 - AU-13 DDG Scanner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor White
Write-Host ""

# Load config
Write-Host "[Loading configuration]" -ForegroundColor White
$keywords = Import-Keywords -Path $KeywordFile
$dorks = Import-Sources -MaxDorks $MaxDorks

# Group dorks by type (site:, text) to reduce query count
$dorkGroups = @(Group-Dorks -Dorks $dorks)

$totalQueries = $keywords.Count * $dorkGroups.Count
$avgDelay = $BaseDelay + [math]::Floor(($MinJitter + $MaxJitter) / 2)
$estimatedMinutes = [math]::Ceiling(($totalQueries * $avgDelay) / 60)

Write-Host ""
Write-Host "[Scan parameters]" -ForegroundColor White
Write-Host "  Keywords:  $($keywords.Count)" -ForegroundColor Gray
Write-Host "  Dorks:     $($dorks.Count) (grouped into $($dorkGroups.Count) queries)" -ForegroundColor Gray
Write-Host "  Queries:   $totalQueries total ($($dorks.Count) dorks combined via OR)" -ForegroundColor Gray
Write-Host "  Delay:     ${BaseDelay}s base + ${MinJitter}-${MaxJitter}s jitter" -ForegroundColor Gray
Write-Host "  Est. time: ~${estimatedMinutes} minutes" -ForegroundColor Gray
Write-Host ""

# Group listing
Write-Host "[Query groups]" -ForegroundColor White
foreach ($g in $dorkGroups) {
    Write-Host "  [$($g.GroupLabel)] $($g.Dorks.Count) dork(s): $($g.Labels -join ', ')" -ForegroundColor DarkGray
}
Write-Host ""

# CAPTCHA state tracker
$captchaState = @{
    HitCount        = 0
    ConsecutiveHits = 0
    Blocked         = $false
    LastHitTime     = $null
}

# Results collector + dedup set
$allResults = @()
$seenUrls = @{}

# Open DDG in a new minimized browser window to prime the session
$ddgProcess = $null
$ddgBrowserName = $null
try {
    Write-Host "[Browser] Opening DuckDuckGo to prime session..." -ForegroundColor DarkGray

    # Detect default browser and launch with --new-window so it doesn't open as a tab
    $browserPath = $null
    $browserArgs = @()
    try {
        $progId = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -ErrorAction Stop).ProgId
        $command = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$progId\shell\open\command" -ErrorAction Stop).'(default)'
        if ($command -match '"([^"]+)"') {
            $browserPath = $Matches[1]
        }
    } catch { }

    # Snapshot browser PIDs before launch so we can find the new window later
    $preBrowserPIDs = @()
    if ($browserPath -and (Test-Path $browserPath)) {
        $ddgBrowserName = [System.IO.Path]::GetFileNameWithoutExtension($browserPath)
        $preBrowserPIDs = @(Get-Process -Name $ddgBrowserName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        $browserArgs = @('--new-window', 'https://html.duckduckgo.com/html/')
        $ddgProcess = Start-Process -FilePath $browserPath -ArgumentList $browserArgs -WindowStyle Minimized -PassThru
    } else {
        $ddgProcess = Start-Process "https://html.duckduckgo.com/html/" -PassThru
    }

    Start-Sleep -Seconds 3

    # Find any new browser PIDs that appeared (Chromium merges into existing process)
    if ($ddgBrowserName) {
        $postBrowserPIDs = @(Get-Process -Name $ddgBrowserName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        $Script:NewBrowserPIDs = @($postBrowserPIDs | Where-Object { $_ -notin $preBrowserPIDs })
    }

    # Minimize the window via Win32 for the fallback path
    if ($ddgProcess -and -not $ddgProcess.HasExited) {
        try {
            Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@
            if ($ddgProcess.MainWindowHandle -ne [IntPtr]::Zero) {
                [Win32]::ShowWindow($ddgProcess.MainWindowHandle, 6) | Out-Null  # 6 = SW_MINIMIZE
            }
        } catch { }
    }
} catch {
    Write-Host "[Browser] Could not open DuckDuckGo: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

$queryNum = 0
$scanStart = Get-Date

Write-Host "[Starting scan at $($scanStart.ToString('HH:mm:ss'))]" -ForegroundColor Cyan
Write-Host ""

foreach ($keyword in $keywords) {
    Write-Host "[Keyword] '$keyword'" -ForegroundColor White

    if ($captchaState.Blocked) {
        Write-Host "  [BLOCKED] CAPTCHA block active - skipping remaining keywords" -ForegroundColor Red
        break
    }

    foreach ($group in $dorkGroups) {
        $queryNum++

        if ($captchaState.Blocked) {
            Write-Host "  [BLOCKED] Skipping $($group.GroupLabel)" -ForegroundColor Red
            continue
        }

        Write-Host "  [$queryNum/$totalQueries] $($group.GroupLabel) ($($group.Dorks.Count) dorks)..." -ForegroundColor Gray -NoNewline

        try {
            $searchResult = Invoke-DdgSearch `
                -Keyword $keyword `
                -Dork $group.CombinedDork `
                -GroupLabel $group.GroupLabel `
                -CaptchaState ([ref]$captchaState) `
                -DorkMappings $group.Mappings `
                -VerboseOutput:$VerboseOutput

            if ($searchResult.CaptchaBlocked) {
                Write-Host " BLOCKED" -ForegroundColor Red
                break
            }

            # Dedup and collect
            $newCount = 0
            foreach ($r in $searchResult.Results) {
                $urlKey = "$($r.Keyword)|$($r.Url)"
                if (-not $seenUrls.ContainsKey($urlKey)) {
                    $seenUrls[$urlKey] = $true
                    $allResults += $r
                    $newCount++
                }
            }

            $color = if ($newCount -gt 0) { 'Green' } else { 'DarkGray' }
            Write-Host " $newCount new result(s)" -ForegroundColor $color

        } catch {
            Write-Host " ERROR: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }

        # Random delay before next query (skip after last query)
        $isLastQuery = ($queryNum -eq $totalQueries)
        if (-not $isLastQuery -and -not $captchaState.Blocked) {
            $delay = Get-RandomDelay -BaseSeconds $BaseDelay -MinJitter $MinJitter -MaxJitter $MaxJitter
            Write-Host "  [Wait] ${delay}s before next query..." -ForegroundColor DarkGray
            Start-Sleep -Seconds $delay
        }
    }

    Write-Host ""
}

# ============================================================================
# RESULTS SUMMARY
# ============================================================================
$scanEnd = Get-Date
$elapsed = $scanEnd - $scanStart

Write-Host "========================================" -ForegroundColor White
Write-Host " SCAN COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor White
Write-Host "  Duration:       $($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host "  Queries run:    $queryNum / $totalQueries" -ForegroundColor White
Write-Host "  Total results:  $($allResults.Count)" -ForegroundColor White

$captchaColor = if ($captchaState.HitCount -gt 0) { 'Yellow' } else { 'Green' }
Write-Host "  CAPTCHA hits:   $($captchaState.HitCount)" -ForegroundColor $captchaColor

$blockedColor = if ($captchaState.Blocked) { 'Red' } else { 'Green' }
Write-Host "  Blocked:        $($captchaState.Blocked)" -ForegroundColor $blockedColor
Write-Host "========================================" -ForegroundColor White
Write-Host ""

# Print results grouped by keyword
if ($allResults.Count -gt 0) {
    Write-Host "[Results by keyword]" -ForegroundColor Cyan
    Write-Host ""

    foreach ($keyword in $keywords) {
        $kwResults = @($allResults | Where-Object { $_.Keyword -eq $keyword })
        if ($kwResults.Count -eq 0) { continue }

        Write-Host "  [$keyword] - $($kwResults.Count) result(s)" -ForegroundColor White
        foreach ($r in $kwResults) {
            Write-Host "    [$($r.Dork)] $($r.Title)" -ForegroundColor Gray
            Write-Host "      $($r.Url)" -ForegroundColor DarkCyan
            if ($r.Summary) {
                $preview = if ($r.Summary.Length -gt 100) { $r.Summary.Substring(0, 100) + '...' } else { $r.Summary }
                Write-Host "      $preview" -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }
} else {
    Write-Host "[No results found]" -ForegroundColor DarkYellow
    Write-Host ""
}

# Export results to CSV
if ($allResults.Count -gt 0 -and -not $NoExport) {
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
        $OutputFile = Join-Path $PSScriptRoot "Look4Gold13_Results_$timestamp.csv"
    }
    if ($OutputFile -notmatch '\.csv$') {
        $OutputFile += '.csv'
    }

    try {
        $allResults | Select-Object Title, Summary, Url |
            Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Host "[CSV export] $($allResults.Count) results saved to:" -ForegroundColor Cyan
        Write-Host "  $OutputFile" -ForegroundColor White
    } catch {
        Write-Host "[CSV export] FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
}

# Ask Sage AGI query (runs once, only if API key env var is set)
$sageItems = @()
$sageApiKey = $env:ASK_SAGE_API_KEY
if ($sageApiKey) {
    Write-Host "========================================" -ForegroundColor White
    Write-Host " ASK SAGE AGI ANALYSIS" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor White
    Write-Host ""

    $sageResponse = Invoke-AskSageQuery -Keywords $keywords -ApiKey $sageApiKey -ScanResults $allResults

    if ($sageResponse) {
        # Extract the AGI message and attempt to parse the JSON array from it
        $sageRaw = if ($sageResponse.message) { $sageResponse.message } else { $sageResponse | ConvertTo-Json -Depth 5 }
        Write-Host "[Ask Sage] Response received." -ForegroundColor Cyan

        # Try to extract JSON array from the response (may be wrapped in markdown code fences)
        $sageItems = @()
        $jsonText = $sageRaw
        # Strip markdown code fences if present
        if ($jsonText -match '(?s)```(?:json)?\s*(\[[\s\S]*\])\s*```') {
            $jsonText = $Matches[1]
        } elseif ($jsonText -match '(?s)(\[\s*\{[\s\S]*\}\s*\])') {
            $jsonText = $Matches[1]
        }
        try {
            $parsed = $jsonText | ConvertFrom-Json
            # Ensure we always have an array (ConvertFrom-Json unwraps single-item arrays)
            $sageItems = @($parsed)
        } catch {
            Write-Host "[Ask Sage] Could not parse JSON from response, saving raw" -ForegroundColor DarkYellow
        }

        # Build proper JSON output
        $sageTimestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
        $sagePath = Join-Path $PSScriptRoot "Look4Gold13_AGI_$sageTimestamp.json"

        $sageJsonObj = @{
            metadata = @{
                tool       = "Look4Gold13"
                generated  = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                keywords   = $keywords
                model      = "google-gemini-2.5-pro"
            }
            results = $sageItems
        }

        $sageJsonObj | ConvertTo-Json -Depth 10 | Out-File -FilePath $sagePath -Encoding UTF8
        Write-Host "[Ask Sage] $($sageItems.Count) result(s) saved to:" -ForegroundColor Cyan
        Write-Host "  $sagePath" -ForegroundColor White
    }
    Write-Host ""
} else {
    Write-Host "[Ask Sage] Skipped - ASK_SAGE_API_KEY environment variable not set" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# HTML REPORT
# ============================================================================
if (($allResults.Count -gt 0 -or ($sageItems -and $sageItems.Count -gt 0)) -and -not $NoExport) {
    $reportTimestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    $reportPath = Join-Path $PSScriptRoot "Look4Gold13_Report_$reportTimestamp.html"

    $severityColors = @{
        'Critical'      = '#dc3545'
        'High'          = '#fd7e14'
        'Medium'        = '#ffc107'
        'Low'           = '#28a745'
        'Informational' = '#6c757d'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Look4Gold13 Report - $reportTimestamp</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; padding: 2rem; }
  h1 { color: #e94560; margin-bottom: 0.5rem; }
  .subtitle { color: #888; margin-bottom: 2rem; }
  h2 { color: #0f3460; background: #e94560; display: inline-block; padding: 0.4rem 1rem; border-radius: 4px; margin: 2rem 0 1rem; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
  th { background: #16213e; color: #e94560; text-align: left; padding: 0.6rem 0.8rem; border-bottom: 2px solid #0f3460; }
  td { padding: 0.6rem 0.8rem; border-bottom: 1px solid #2a2a4a; vertical-align: top; }
  tr:hover { background: #16213e; }
  a { color: #53a8e2; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .severity { padding: 0.2rem 0.6rem; border-radius: 3px; font-size: 0.8rem; font-weight: bold; color: #fff; display: inline-block; }
  .summary { color: #aaa; font-size: 0.9rem; }
  .stats { color: #888; margin-bottom: 1rem; }
  .section-empty { color: #666; font-style: italic; margin-bottom: 2rem; }
</style>
</head>
<body>
<h1>Look4Gold13 - AU-13 Report</h1>
<p class="subtitle">Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Keywords: $($keywords -join ', ')</p>
<p class="stats">Scan duration: $($elapsed.ToString('hh\:mm\:ss')) | Queries: $queryNum / $totalQueries | CAPTCHA hits: $($captchaState.HitCount)</p>
"@

    # --- AGI Results Section ---
    $html += "`n<h2>AGI Intelligence (Ask Sage)</h2>`n"
    if ($sageItems -and @($sageItems).Count -gt 0) {
        $html += "<table>`n<tr><th>Severity</th><th>Title</th><th>Category</th><th>Source</th><th>Summary</th></tr>`n"
        foreach ($item in @($sageItems)) {
            # Safely read each property, defaulting to empty string
            $sev        = if ($item.severity)    { "$($item.severity)" }    else { 'Informational' }
            $itemTitle  = if ($item.title)        { "$($item.title)" }      else { '' }
            $itemCat    = if ($item.category)     { "$($item.category)" }   else { '' }
            $itemSite   = if ($item.source_site)  { "$($item.source_site)" } else { '' }
            $itemLink   = if ($item.link)         { "$($item.link)" }       else { '' }
            $itemSum    = if ($item.summary)       { "$($item.summary)" }   else { '' }

            $sevColor = if ($severityColors.ContainsKey($sev)) { $severityColors[$sev] } else { '#6c757d' }

            # Build source cell: linked if we have a URL, plain text otherwise
            $sourceCell = ''
            if ($itemLink) {
                $encodedHref = [System.Web.HttpUtility]::HtmlAttributeEncode($itemLink)
                $sourceCell = "<a href=`"$encodedHref`" target=`"_blank`">$([System.Web.HttpUtility]::HtmlEncode($itemSite))</a>"
            } else {
                $sourceCell = [System.Web.HttpUtility]::HtmlEncode($itemSite)
            }

            $html += "<tr>"
            $html += "<td><span class=`"severity`" style=`"background:$sevColor`">$([System.Web.HttpUtility]::HtmlEncode($sev))</span></td>"
            $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($itemTitle))</td>"
            $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($itemCat))</td>"
            $html += "<td>$sourceCell</td>"
            $html += "<td class=`"summary`">$([System.Web.HttpUtility]::HtmlEncode($itemSum))</td>"
            $html += "</tr>`n"
        }
        $html += "</table>`n"
    } else {
        $html += "<p class=`"section-empty`">No AGI results available (API key not set or query returned no data).</p>`n"
    }

    # --- Dork Results Section ---
    $html += "<h2>Search Dork Results</h2>`n"
    if ($allResults.Count -gt 0) {
        $html += "<table><tr><th>Keyword</th><th>Dork</th><th>Title</th><th>URL</th><th>Summary</th></tr>`n"
        foreach ($r in $allResults) {
            $html += "<tr>"
            $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($r.Keyword))</td>"
            $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($r.Dork))</td>"
            $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($r.Title))</td>"
            $encodedUrl = [System.Web.HttpUtility]::HtmlAttributeEncode($r.Url)
            $html += "<td><a href=`"$encodedUrl`" target=`"_blank`">$([System.Web.HttpUtility]::HtmlEncode($r.Url))</a></td>"
            $rawSummary = if ($r.Summary) { "$($r.Summary)" } else { '' }
            $summaryText = if ($rawSummary.Length -gt 200) { $rawSummary.Substring(0, 200) + '...' } else { $rawSummary }
            $html += "<td class=`"summary`">$([System.Web.HttpUtility]::HtmlEncode($summaryText))</td>"
            $html += "</tr>`n"
        }
        $html += "</table>`n"
    } else {
        $html += "<p class=`"section-empty`">No dork results found.</p>`n"
    }

    $html += "</body></html>"

    try {
        $html | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Host "[HTML Report] Saved to:" -ForegroundColor Cyan
        Write-Host "  $reportPath" -ForegroundColor White
    } catch {
        Write-Host "[HTML Report] FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
}

# Close the DDG browser window we opened at start
$ddgClosed = $false
# Try the original process handle first
if ($ddgProcess -and -not $ddgProcess.HasExited) {
    try {
        $ddgProcess.CloseMainWindow() | Out-Null
        if (-not $ddgProcess.WaitForExit(5000)) { $ddgProcess.Kill() }
        $ddgClosed = $true
    } catch { }
}
# If the process merged (Chromium), kill the new PIDs we tracked
if (-not $ddgClosed -and $Script:NewBrowserPIDs -and $Script:NewBrowserPIDs.Count -gt 0) {
    try {
        foreach ($pid in $Script:NewBrowserPIDs) {
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
        $ddgClosed = $true
    } catch { }
}
# Last resort: find any window with DuckDuckGo in the title
if (-not $ddgClosed -and $ddgBrowserName) {
    try {
        Get-Process -Name $ddgBrowserName -ErrorAction SilentlyContinue |
            Where-Object { $_.MainWindowTitle -match 'DuckDuckGo' } |
            ForEach-Object { $_.CloseMainWindow() | Out-Null }
        $ddgClosed = $true
    } catch { }
}
if ($ddgClosed) {
    Write-Host "[Browser] DuckDuckGo window closed." -ForegroundColor DarkGray
}

Write-Host "Done." -ForegroundColor Green
