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
    .\Look4Gold13.ps1 -MaxDorks 1 -BaseDelay 45
    .\Look4Gold13.ps1 -IncludeBreach
#>
param(
    [string]$KeywordFile,
    [int]$MaxDorks       = 0,       # 0 = all dorks; N = use first N only
    [int]$BaseDelay      = 30,      # Base seconds between requests
    [int]$MinJitter      = 5,       # Min additional random seconds
    [int]$MaxJitter      = 15,      # Max additional random seconds
    [switch]$IncludeBreach,         # Also run breach dorks
    [switch]$VerboseOutput          # Extra debug output
)

# ============================================================================
# TLS CONFIGURATION
# ============================================================================
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

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
$Script:DdgDateFilters = @('', 'w', 'm')   # blank=anytime, w=past week, m=past month
$Script:RefererPool = @(
    $null
    'https://duckduckgo.com/'
    'https://html.duckduckgo.com/'
    'https://start.duckduckgo.com/'
)

# ============================================================================
# RATE-LIMIT EVASION FUNCTIONS
# ============================================================================

function Get-RandomIdentity {
    <# Returns a fresh set of headers + WebRequestSession for one request. #>

    $profile = $Script:BrowserProfiles | Get-Random

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

    $referer = $Script:RefererPool | Get-Random
    if ($referer) { $headers['Referer'] = $referer }

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
    $region = $Script:DdgRegions | Get-Random
    if ($region -ne 'wt-wt') { $url += "&kl=$region" }

    # Random date filter
    $dateFilter = $Script:DdgDateFilters | Get-Random
    if ($dateFilter) { $url += "&df=$dateFilter" }

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
        $Path = Join-Path $PSScriptRoot 'config' 'keywords.txt'
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
        [int]$MaxDorks       = 0,
        [switch]$IncludeBreach
    )

    if (-not $Path) {
        $Path = Join-Path $PSScriptRoot 'config' 'sources.json'
    }

    if (-not (Test-Path $Path)) {
        Write-Error "Sources file not found: '$Path'"
        exit 1
    }

    $sources = Get-Content -Path $Path -Raw | ConvertFrom-Json

    $dorks = @($sources.ddgDorks | ForEach-Object {
        @{ Label = $_.label; Dork = $_.dork }
    })

    if ($IncludeBreach -and $sources.breachDorks) {
        $dorks += @($sources.breachDorks | ForEach-Object {
            @{ Label = $_.label; Dork = $_.dork }
        })
    }

    if ($MaxDorks -gt 0 -and $MaxDorks -lt $dorks.Count) {
        $dorks = $dorks[0..($MaxDorks - 1)]
    }

    Write-Host "  Loaded $($dorks.Count) dork(s) from $Path" -ForegroundColor DarkGray
    return $dorks
}

# ============================================================================
# RESULT PARSING
# ============================================================================

function Parse-DdgResults {
    param(
        [Parameter(Mandatory)][string]$Html,
        [Parameter(Mandatory)][string]$Keyword,
        [string]$DorkLabel = ''
    )

    $results = @()

    if ($Html -match 'too long') {
        Write-Host "  [Query Too Long] DDG rejected query length" -ForegroundColor DarkYellow
        return $results
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

        $results += [PSCustomObject]@{
            Keyword = $Keyword
            Title   = $resultTitle
            Url     = $resultUrl
            Dork    = $DorkLabel
            Found   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
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
        [Parameter(Mandatory)][string]$DorkLabel,
        [Parameter(Mandatory)][ref]$CaptchaState,
        [switch]$VerboseOutput
    )

    # 1. Fresh identity for this request
    $identity = Get-RandomIdentity
    if ($VerboseOutput) {
        Write-Host "    [ID] $($identity.BrowserTag)" -ForegroundColor DarkGray
    }

    # 2. Build URL with randomized params
    $url = Build-DdgUrl -Keyword $Keyword -Dork $Dork
    if ($VerboseOutput) {
        Write-Host "    [URL] $url" -ForegroundColor DarkGray
    }

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
    $results = Parse-DdgResults -Html $html -Keyword $Keyword -DorkLabel $DorkLabel

    # 6. Debug: save HTML if no results and verbose
    if ($results.Count -eq 0 -and $VerboseOutput) {
        $debugFile = Join-Path $PSScriptRoot "debug_ddg_$($DorkLabel -replace '[^a-zA-Z0-9]','_').html"
        $html | Out-File -FilePath $debugFile -Encoding utf8
        Write-Host "    [Debug] No results - HTML saved to $debugFile" -ForegroundColor DarkGray
    }

    return @{ Results = $results; CaptchaBlocked = $false }
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
$dorks = Import-Sources -MaxDorks $MaxDorks -IncludeBreach:$IncludeBreach

$totalQueries = $keywords.Count * $dorks.Count
$avgDelay = $BaseDelay + [math]::Floor(($MinJitter + $MaxJitter) / 2)
$estimatedMinutes = [math]::Ceiling(($totalQueries * $avgDelay) / 60)

Write-Host ""
Write-Host "[Scan parameters]" -ForegroundColor White
Write-Host "  Keywords:  $($keywords.Count)" -ForegroundColor Gray
Write-Host "  Dorks:     $($dorks.Count)" -ForegroundColor Gray
Write-Host "  Queries:   $totalQueries total" -ForegroundColor Gray
Write-Host "  Delay:     ${BaseDelay}s base + ${MinJitter}-${MaxJitter}s jitter" -ForegroundColor Gray
Write-Host "  Est. time: ~${estimatedMinutes} minutes" -ForegroundColor Gray
Write-Host ""

# Dork listing
Write-Host "[Active dorks]" -ForegroundColor White
foreach ($d in $dorks) {
    Write-Host "  - $($d.Label): $($d.Dork)" -ForegroundColor DarkGray
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

    foreach ($dork in $dorks) {
        $queryNum++

        if ($captchaState.Blocked) {
            Write-Host "  [BLOCKED] Skipping $($dork.Label)" -ForegroundColor Red
            continue
        }

        Write-Host "  [$queryNum/$totalQueries] $($dork.Label)..." -ForegroundColor Gray -NoNewline

        try {
            $searchResult = Invoke-DdgSearch `
                -Keyword $keyword `
                -Dork $dork.Dork `
                -DorkLabel $dork.Label `
                -CaptchaState ([ref]$captchaState) `
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
        }
        Write-Host ""
    }
} else {
    Write-Host "[No results found]" -ForegroundColor DarkYellow
    Write-Host ""
}

Write-Host "Done." -ForegroundColor Green
