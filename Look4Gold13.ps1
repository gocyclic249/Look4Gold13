<#
.SYNOPSIS
    Look4Gold13 - AU-13 PAC Scanner + CVE Monitor with NIST AU-2/AU-3 Audit Logging
.DESCRIPTION
    Searches DuckDuckGo for keywords combined with search dorks to find
    publicly exposed information (NIST SP 800-53 AU-13 compliance).
    Queries the NIST NVD API for CVEs matching each keyword.
    Uses aggressive rate-limit evasion: UA rotation, session rotation,
    randomized timing, and query parameter variation.

    Generates NIST AU-2/AU-3 compliant audit logs (NDJSON) that record
    every significant event with who/what/when/where/outcome fields.

    For each keyword the scan runs:  dork searches -> CVE lookup -> Ask Sage AGI query.
    This per-keyword flow gives the AGI focused context from that keyword's
    dork and CVE results rather than mixing all keywords into one query.
.EXAMPLE
    .\Look4Gold13.ps1 -MaxDorks 4
    .\Look4Gold13.ps1 -MaxDorks 1 -BaseDelay 150
    .\Look4Gold13.ps1 -DaysBack 14
    .\Look4Gold13.ps1 -Silent
    .\Look4Gold13.ps1 -AgiOnly
    .\Look4Gold13.ps1 -CveOnly
    .\Look4Gold13.ps1 -NoCve
#>
param(
    [string]$KeywordFile,
    [int]$MaxDorks       = 0,       # 0 = all dorks; N = use first N only
    [int]$BaseDelay      = 120,     # Base seconds between requests
    [int]$MinJitter      = 5,       # Min additional random seconds
    [int]$MaxJitter      = 15,      # Max additional random seconds
    [int]$DaysBack       = 7,       # Lookback period in days (CVE + GenAI)
    [switch]$VerboseOutput,         # Extra debug output
    [string]$OutputFile,            # Custom path for HTML report
    [switch]$NoExport,              # Suppress file export
    [switch]$Silent,                # Suppress all console output
    [switch]$AgiOnly,               # Skip dork scanning, run AGI only
    [switch]$CveOnly,               # Skip dork scanning AND AGI, run only CVE lookup
    [switch]$NoCve,                 # Disable CVE lookup (dorks + AGI only)
    [int]$CveMaxResults  = 100,     # Max CVE results per keyword
    [string]$AuditLogFile,          # Custom path for NIST audit log
    [switch]$NoAuditLog             # Disable audit logging
)

# ============================================================================
# PARAMETER VALIDATION
# ============================================================================
if ($CveOnly -and $AgiOnly) {
    Write-Error "-CveOnly and -AgiOnly cannot be used together."
    exit 1
}
if ($CveOnly -and $NoCve) {
    Write-Error "-CveOnly and -NoCve cannot be used together."
    exit 1
}

# ============================================================================
# SILENT MODE — suppress all console output when -Silent is set
# ============================================================================
if ($Silent) {
    function Write-Host { <# silenced #> }
}

# ============================================================================
# NIST AU-2/AU-3 AUDIT LOGGING
# ============================================================================
# AU-2: Defines auditable events (see event type catalog below)
# AU-3: Each record contains: (a) event type, (b) timestamp, (c) where,
#        (d) source function, (e) outcome, (f) subject identity
#
# Event Types:
#   AUDIT_LOG_INIT, SCAN_START, SCAN_COMPLETE, CONFIG_LOAD, CONFIG_ERROR,
#   KEYWORD_START, KEYWORD_COMPLETE, DORK_QUERY, CAPTCHA_DETECTED,
#   CAPTCHA_BLOCKED, CVE_QUERY_START, CVE_QUERY_COMPLETE, CVE_QUERY_ERROR,
#   GENAI_QUERY, GENAI_RESPONSE, GENAI_ERROR, PERSONA_LOOKUP,
#   DATA_EXPORT, EXPORT_ERROR, NETWORK_ERROR, BROWSER_OPEN, BROWSER_CLOSE
# ============================================================================

$Script:AuditLogPath = $null
$Script:AuditLogEntries = [System.Collections.ArrayList]::new()

function Write-AuditLog {
    param(
        [Parameter(Mandatory)][string]$EventType,      # AU-3(a): type of event
        [Parameter(Mandatory)][string]$Source,          # AU-3(d): source function/module
        [Parameter(Mandatory)][string]$Outcome,         # AU-3(e): Success|Failure|Warning
        [string]$Message = '',                          # Human-readable description
        [string]$Subject = '',                          # AU-3(f): identity/subject
        [hashtable]$Details = @{}                       # Additional structured data
    )

    if (-not $Script:AuditLogPath) { return }

    $record = [ordered]@{
        timestamp       = (Get-Date -Format 'o')                            # AU-3(b): when (ISO 8601 w/ timezone)
        event_type      = $EventType                                        # AU-3(a): what
        source_system   = 'Look4Gold13'                                     # AU-3(c): where - system
        source_host     = $env:COMPUTERNAME                                 # AU-3(c): where - host
        source_function = $Source                                           # AU-3(d): source
        outcome         = $Outcome                                          # AU-3(e): outcome
        subject         = if ($Subject) { $Subject } else { $env:USERNAME } # AU-3(f): identity
        message         = $Message
        details         = $Details
    }

    # Store in memory for later export
    [void]$Script:AuditLogEntries.Add($record)

    # Append to NDJSON file (one JSON object per line)
    try {
        $json = $record | ConvertTo-Json -Depth 5 -Compress
        $json | Out-File -FilePath $Script:AuditLogPath -Append -Encoding UTF8
    } catch {
        Write-Warning "Audit log write failed: $($_.Exception.Message)"
    }
}

# Initialize audit log path
if (-not $NoAuditLog) {
    if ($AuditLogFile) {
        $Script:AuditLogPath = $AuditLogFile
    } else {
        $auditTimestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
        $Script:AuditLogPath = Join-Path $PSScriptRoot "Look4Gold13_Audit_$auditTimestamp.jsonl"
    }
    Write-AuditLog -EventType 'AUDIT_LOG_INIT' -Source 'Main' -Outcome 'Success' `
        -Message "Audit log initialized at $($Script:AuditLogPath)"
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
    <# Groups flat dork array into combined OR query groups by type.
       Site dorks are batched (max 5 per group) to avoid DDG query length limits. #>
    param([Parameter(Mandatory)][array]$Dorks)

    $siteDorks  = @()
    $textGroups = @()

    foreach ($d in $Dorks) {
        if ($d.Dork -match '^site:(.+)$') {
            $domain = ($Matches[1] -replace '\.', '\.') -replace '/', '\/'
            $siteDorks += @{ Dork = $d.Dork; Label = $d.Label; Pattern = $domain }
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

    # Split site dorks into batches of 5 to keep query URLs short
    $batchSize = 5
    if ($siteDorks.Count -gt 0) {
        for ($i = 0; $i -lt $siteDorks.Count; $i += $batchSize) {
            $end = [math]::Min($i + $batchSize - 1, $siteDorks.Count - 1)
            $batch = $siteDorks[$i..$end]

            $batchGroup = @{
                GroupLabel = "Sites $([math]::Floor($i / $batchSize) + 1)"
                Dorks      = @($batch | ForEach-Object { $_.Dork })
                Labels     = @($batch | ForEach-Object { $_.Label })
                Mappings   = @($batch | ForEach-Object { @{ Label = $_.Label; Pattern = $_.Pattern } })
            }

            if ($batchGroup.Dorks.Count -eq 1) {
                $batchGroup['CombinedDork'] = $batchGroup.Dorks[0]
            } else {
                $batchGroup['CombinedDork'] = '(' + ($batchGroup.Dorks -join ' OR ') + ')'
            }
            $groups += $batchGroup
        }
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
        $debugDir = if ($Script:ScanOutputDir) { $Script:ScanOutputDir } else { $PSScriptRoot }
        $debugFile = Join-Path $debugDir "debug_ddg_$($GroupLabel -replace '[^a-zA-Z0-9]','_').html"
        $html | Out-File -FilePath $debugFile -Encoding utf8
        Write-Host "    [Debug] No results - HTML saved to $debugFile" -ForegroundColor DarkGray
    }

    return @{ Results = $results; CaptchaBlocked = $false }
}

# ============================================================================
# ASK SAGE AGI QUERY  (called once per keyword during the main scan loop)
# ============================================================================

function Get-AskSagePersonaId {
    <# Looks up the "Look4Gold13" persona by name via the Ask Sage API.
       Returns the persona ID if found, otherwise falls back to 5 (ISSO).
       Called once before the per-keyword loop. #>
    param(
        [Parameter(Mandatory)][string]$ApiKey
    )

    $uri     = "https://api.genai.army.mil/server/get-personas"
    $headers = @{
        "Content-Type"    = "application/json"
        "x-access-tokens" = $ApiKey
    }

    try {
        $personas = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers
        $match = $personas.response | Where-Object { $_.name -eq "Look4Gold13" }
        if ($match) {
            Write-Host "[Ask Sage] Using custom persona 'Look4Gold13' (ID: $($match.id))" -ForegroundColor Cyan
            Write-AuditLog -EventType 'PERSONA_LOOKUP' -Source 'Get-AskSagePersonaId' -Outcome 'Success' `
                -Message "Custom persona 'Look4Gold13' found (ID: $($match.id))" -Details @{ persona_id = [int]$match.id }
            return [int]$match.id
        }
    } catch {
        Write-Host "[Ask Sage] WARNING: Could not retrieve personas: $($_.Exception.Message)" -ForegroundColor DarkYellow
        Write-AuditLog -EventType 'PERSONA_LOOKUP' -Source 'Get-AskSagePersonaId' -Outcome 'Failure' `
            -Message "Could not retrieve personas: $($_.Exception.Message)"
    }

    Write-Host "[Ask Sage] Custom persona 'Look4Gold13' not found - falling back to ISSO (ID: 5)" -ForegroundColor DarkYellow
    Write-AuditLog -EventType 'PERSONA_LOOKUP' -Source 'Get-AskSagePersonaId' -Outcome 'Warning' `
        -Message "Custom persona not found, falling back to ISSO (ID: 5)" -Details @{ persona_id = 5 }
    return 5
}

function Invoke-AskSageQuery {
    <# Sends a per-keyword query to the Ask Sage API (Gemini 2.5 Flash, live web search).
       Includes any dork-discovered URLs and CVE findings as context for that keyword.
       Returns the parsed response or $null on failure. #>
    param(
        [Parameter(Mandatory)][array]$Keywords,
        [Parameter(Mandatory)][string]$ApiKey,
        [array]$ScanResults = @(),
        [array]$CveResults  = @(),
        [int]$PersonaId = 5,
        [int]$DaysBack  = 7
    )

    $uri = "https://api.genai.army.mil/server/query"

    $headers = @{
        "Content-Type"     = "application/json"
        "x-access-tokens"  = $ApiKey
    }

    $searchText = $Keywords -join ', '

    # Build context from scan results if available
    $scanContext = ""
    if ($ScanResults.Count -gt 0) {
        $scanContext = "`n`nThe following links were discovered during an initial scan. Use them as a starting point and search broadly for additional related information:`n"
        foreach ($r in $ScanResults) {
            $scanContext += "- $($r.Url)`n"
        }
    }

    # Build context from CVE results if available
    $cveContext = ""
    if ($CveResults.Count -gt 0) {
        $cveContext = "`n`nThe following CVEs were found in the NIST NVD database related to this keyword:`n"
        foreach ($cve in ($CveResults | Select-Object -First 20)) {
            $descPreview = if ($cve.Description.Length -gt 150) { $cve.Description.Substring(0, 150) + '...' } else { $cve.Description }
            $cveContext += "- $($cve.CveId) (CVSS: $($cve.CvssScore), $($cve.Severity)): $descPreview`n"
        }
    }

    $body = @{
        message     = @"
Search broadly across the internet for any recent cybersecurity news, breaches, leaks, vulnerabilities, ransomware, or other notable events related to $searchText in the last $DaysBack days. Include events specifically tied to information disclosure risks (e.g., unauthorized data exposure, sensitive information leaks, or monitoring failures under NIST AU-13). Use multiple search variations to cover government sources (e.g., NIST, CISA), industry reports, security blogs, and mainstream news. Provide a link to every article or site referenced. For each entry, assess the severity as Critical, High, Medium, Low, or Informational based on the potential impact to information systems, considering factors like scope of disclosure, affected entities, exploitability, and compliance implications.

Respond with ONLY a JSON array, no other text before or after it. Use this exact format for each entry:
[
  {
    "date_published": "YYYY-MM-DD",
    "source_site": "example.com",
    "category": "Vulnerability|Breach|Ransomware|Leak|Informational|Disclosure",
    "severity": "Critical|High|Medium|Low|Informational",
    "title": "Short descriptive title",
    "summary": "Brief summary of the event, including any ties to information disclosure or AU-13 monitoring",
    "link": "https://full-url-to-source"
  }
]$scanContext$cveContext
"@
        persona     = $PersonaId
        model       = "google-gemini-2.5-flash"
        temperature = 0.7
        live        = 2
    } | ConvertTo-Json -Depth 3

    Write-Host "[Ask Sage] Sending AGI query for: $searchText" -ForegroundColor Cyan
    Write-Host "[Ask Sage] This may take a moment (live web search enabled)..." -ForegroundColor DarkGray

    Write-AuditLog -EventType 'GENAI_QUERY' -Source 'Invoke-AskSageQuery' -Outcome 'Success' `
        -Subject $searchText -Message "Sending GenAI query with $($ScanResults.Count) dork URLs and $($CveResults.Count) CVEs as context" `
        -Details @{ dork_context_count = $ScanResults.Count; cve_context_count = $CveResults.Count; days_back = $DaysBack }

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body
        Write-Host "[Ask Sage] Response received." -ForegroundColor Green
        Write-AuditLog -EventType 'GENAI_RESPONSE' -Source 'Invoke-AskSageQuery' -Outcome 'Success' `
            -Subject $searchText -Message "GenAI response received"
        return $response
    } catch {
        Write-Host "[Ask Sage] ERROR: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response) {
            Write-Host "[Ask Sage] HTTP Status: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
        }
        Write-AuditLog -EventType 'GENAI_ERROR' -Source 'Invoke-AskSageQuery' -Outcome 'Failure' `
            -Subject $searchText -Message "GenAI API error: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================================
# NVD CVE SEARCH
# ============================================================================

$Script:NvdLastRequestTime = $null

function Wait-NvdRateLimit {
    <# Enforces NVD API rate limits by sleeping if needed.
       Without API key: 5 requests per 30s (6s gap).
       With API key:   50 requests per 30s (0.6s gap). #>
    $minGap = if ($env:NVD_API_KEY) { 0.6 } else { 6.0 }
    if ($Script:NvdLastRequestTime) {
        $elapsed = ((Get-Date) - $Script:NvdLastRequestTime).TotalSeconds
        if ($elapsed -lt $minGap) {
            $sleepTime = [math]::Ceiling($minGap - $elapsed)
            Start-Sleep -Seconds $sleepTime
        }
    }
    $Script:NvdLastRequestTime = Get-Date
}

function Invoke-NvdCveSearch {
    <# Queries the NIST NVD API v2.0 for CVEs matching a keyword.
       Supports pagination and optional API key for higher rate limits.
       Returns an array of CVE result objects. #>
    param(
        [Parameter(Mandatory)][string]$Keyword,
        [int]$DaysBack       = 7,
        [int]$MaxResults     = 100,
        [switch]$VerboseOutput
    )

    $baseUri = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    $endDate = Get-Date
    $startDate = $endDate.AddDays(-$DaysBack)
    $pubStart = $startDate.ToString('yyyy-MM-ddTHH:mm:ss.fff')
    $pubEnd   = $endDate.ToString('yyyy-MM-ddTHH:mm:ss.fff')

    $headers = @{ 'Accept' = 'application/json' }
    if ($env:NVD_API_KEY) {
        $headers['apiKey'] = $env:NVD_API_KEY
    }

    $allCves = @()
    $startIndex = 0
    $pageSize = 100
    $totalResults = 0
    $pageNum = 0

    do {
        $pageNum++
        Wait-NvdRateLimit

        $uri = "$baseUri`?keywordSearch=$([System.Uri]::EscapeDataString($Keyword))" +
               "&pubStartDate=$pubStart&pubEndDate=$pubEnd" +
               "&resultsPerPage=$pageSize&startIndex=$startIndex"

        if ($VerboseOutput) {
            Write-Host "    [NVD] Page $pageNum (startIndex=$startIndex)..." -ForegroundColor DarkGray
        }

        try {
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 30

            $totalResults = $response.totalResults
            if ($VerboseOutput) {
                Write-Host "    [NVD] Total available: $totalResults" -ForegroundColor DarkGray
            }

            foreach ($vuln in $response.vulnerabilities) {
                $cve = $vuln.cve

                # Extract English description
                $desc = ($cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value
                if (-not $desc) { $desc = ($cve.descriptions | Select-Object -First 1).value }

                # Extract CVSS score and severity (v3.1 -> v3.0 -> v2.0 fallback)
                $cvssScore = $null
                $cvssSeverity = 'Informational'

                if ($cve.metrics.cvssMetricV31) {
                    $cvssScore = $cve.metrics.cvssMetricV31[0].cvssData.baseScore
                    $cvssSeverity = $cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
                } elseif ($cve.metrics.cvssMetricV30) {
                    $cvssScore = $cve.metrics.cvssMetricV30[0].cvssData.baseScore
                    $cvssSeverity = $cve.metrics.cvssMetricV30[0].cvssData.baseSeverity
                } elseif ($cve.metrics.cvssMetricV2) {
                    $cvssScore = $cve.metrics.cvssMetricV2[0].cvssData.baseScore
                    $cvssSeverity = $cve.metrics.cvssMetricV2[0].baseSeverity
                }

                # Map NVD severity to Look4Gold13 severity levels
                $mappedSeverity = switch ($cvssSeverity) {
                    'CRITICAL' { 'Critical' }
                    'HIGH'     { 'High' }
                    'MEDIUM'   { 'Medium' }
                    'LOW'      { 'Low' }
                    default    { 'Informational' }
                }

                # Get first reference URL or build NVD link
                $link = "https://nvd.nist.gov/vuln/detail/$($cve.id)"
                if ($cve.references -and $cve.references.Count -gt 0) {
                    $primaryRef = $cve.references[0].url
                    if ($primaryRef) { $link = $primaryRef }
                }

                $allCves += [PSCustomObject]@{
                    Keyword     = $Keyword
                    CveId       = $cve.id
                    Severity    = $mappedSeverity
                    CvssScore   = if ($cvssScore) { $cvssScore } else { 'N/A' }
                    Published   = ($cve.published -replace 'T.*', '')
                    Description = $desc
                    Link        = $link
                    NvdLink     = "https://nvd.nist.gov/vuln/detail/$($cve.id)"
                    Source      = 'NIST NVD'
                }
            }

            Write-AuditLog -EventType 'CVE_QUERY_PAGE' -Source 'Invoke-NvdCveSearch' -Outcome 'Success' `
                -Subject $Keyword -Message "NVD page $pageNum returned $($response.vulnerabilities.Count) CVEs" `
                -Details @{ startIndex = $startIndex; pageResults = $response.vulnerabilities.Count; totalResults = $totalResults }

            $startIndex += $pageSize
        } catch {
            Write-Host "    [NVD] ERROR: $($_.Exception.Message)" -ForegroundColor Red
            Write-AuditLog -EventType 'CVE_QUERY_ERROR' -Source 'Invoke-NvdCveSearch' -Outcome 'Failure' `
                -Subject $Keyword -Message "NVD API error: $($_.Exception.Message)" `
                -Details @{ page = $pageNum; startIndex = $startIndex }
            break
        }
    } while ($startIndex -lt $totalResults -and $startIndex -lt $MaxResults)

    return $allCves
}

# ============================================================================
# MAIN
# ============================================================================

Write-Host ""
Write-Host "========================================" -ForegroundColor White
Write-Host " Look4Gold13 - AU-13 PAC + CVE Scanner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor White
Write-Host ""

# Load config
Write-Host "[Loading configuration]" -ForegroundColor White
$keywords = Import-Keywords -Path $KeywordFile

Write-AuditLog -EventType 'CONFIG_LOAD' -Source 'Import-Keywords' -Outcome 'Success' `
    -Message "Loaded $($keywords.Count) keyword(s)" -Details @{ keyword_count = $keywords.Count }

$allResults = @()
$allCveResults = [ordered]@{}
$queryNum = 0
$totalQueries = 0
$captchaState = @{ HitCount = 0; ConsecutiveHits = 0; Blocked = $false; LastHitTime = $null }
$scanStart = Get-Date
$elapsed = New-TimeSpan
$allSageResults = [ordered]@{}

# Create per-scan output directory: Outputs/Scan_<date_time>/
$scanFolderName = "Scan_$(Get-Date -Format 'yyyy-MM-dd_HHmm')"
$Script:ScanOutputDir = Join-Path (Join-Path $PSScriptRoot 'Outputs') $scanFolderName
if (-not $NoExport) {
    try {
        New-Item -Path $Script:ScanOutputDir -ItemType Directory -Force | Out-Null
        Write-Host "  Output folder: $($Script:ScanOutputDir)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  WARNING: Could not create output folder, falling back to script root" -ForegroundColor DarkYellow
        $Script:ScanOutputDir = $PSScriptRoot
    }
} else {
    $Script:ScanOutputDir = $PSScriptRoot
}

# Move the NDJSON audit log into the output directory (if logging is active and not custom path)
if ($Script:AuditLogPath -and -not $AuditLogFile -and -not $NoExport) {
    $oldAuditPath = $Script:AuditLogPath
    $Script:AuditLogPath = Join-Path $Script:ScanOutputDir (Split-Path $oldAuditPath -Leaf)
    # Move any early entries already written to old location
    if (Test-Path $oldAuditPath) {
        try {
            Move-Item -Path $oldAuditPath -Destination $Script:AuditLogPath -Force
        } catch {
            # If move fails, just continue with new path
        }
    }
}

if (-not $AgiOnly -and -not $CveOnly) {

$dorks = Import-Sources -MaxDorks $MaxDorks

Write-AuditLog -EventType 'CONFIG_LOAD' -Source 'Import-Sources' -Outcome 'Success' `
    -Message "Loaded $($dorks.Count) dork(s)" -Details @{ dork_count = $dorks.Count }

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
Write-Host "  DaysBack:  $DaysBack day(s)" -ForegroundColor Gray
Write-Host "  CVE:       $(if ($NoCve) { 'Disabled' } else { 'Enabled' })" -ForegroundColor Gray
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
$Script:NewBrowserPIDs = @()
try {
    Write-Host "[Browser] Opening DuckDuckGo to prime session..." -ForegroundColor DarkGray

    # Load Win32 window management functions (used for minimize + close)
    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class Win32Window {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    public const int SW_MINIMIZE = 6;
    public const int SW_HIDE = 0;
    public const uint WM_CLOSE = 0x0010;
}
"@
    } catch {
        # Type may already be loaded from a previous run
    }

    # Detect default browser from registry
    $browserPath = $null
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

        # Chromium browsers: --window-position and --window-size force minimized appearance
        # --new-window prevents merging into existing tabs
        $browserArgs = @(
            '--new-window',
            '--window-position=-32000,-32000',
            '--window-size=1,1',
            'https://html.duckduckgo.com/html/'
        )
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

    # Force-minimize via Win32 -- handles both the launched process and any merged windows
    try {
        # Minimize the original process window if it has one
        if ($ddgProcess -and -not $ddgProcess.HasExited -and $ddgProcess.MainWindowHandle -ne [IntPtr]::Zero) {
            [Win32Window]::ShowWindow($ddgProcess.MainWindowHandle, [Win32Window]::SW_MINIMIZE) | Out-Null
        }
        # Also minimize any newly spawned browser windows
        foreach ($newPid in $Script:NewBrowserPIDs) {
            try {
                $proc = Get-Process -Id $newPid -ErrorAction SilentlyContinue
                if ($proc -and $proc.MainWindowHandle -ne [IntPtr]::Zero) {
                    [Win32Window]::ShowWindow($proc.MainWindowHandle, [Win32Window]::SW_MINIMIZE) | Out-Null
                }
            } catch { }
        }
    } catch { }

    Write-Host "[Browser] DDG session primed (minimized)." -ForegroundColor DarkGray
    Write-AuditLog -EventType 'BROWSER_OPEN' -Source 'Main' -Outcome 'Success' `
        -Message "DDG browser window opened for session priming"
} catch {
    Write-Host "[Browser] Could not open DuckDuckGo: $($_.Exception.Message)" -ForegroundColor DarkYellow
    Write-AuditLog -EventType 'BROWSER_OPEN' -Source 'Main' -Outcome 'Failure' `
        -Message "Could not open DDG browser: $($_.Exception.Message)"
}

} # end if (-not $AgiOnly -and -not $CveOnly) setup

# CveOnly mode scan parameters
if ($CveOnly) {
    Write-Host ""
    Write-Host "[Scan parameters]" -ForegroundColor White
    Write-Host "  Mode:      CVE-only (no dork scanning, no GenAI)" -ForegroundColor Gray
    Write-Host "  Keywords:  $($keywords.Count)" -ForegroundColor Gray
    Write-Host "  DaysBack:  $DaysBack day(s)" -ForegroundColor Gray
    Write-Host ""
}

# Resolve persona once before the per-keyword loop
$sageApiKey = $env:ASK_SAGE_API_KEY
$personaId = 5
if ($sageApiKey) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor White
    Write-Host " ASK SAGE AGI ANALYSIS (per-keyword)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor White
    Write-Host ""
    $personaId = Get-AskSagePersonaId -ApiKey $sageApiKey
} else {
    Write-Host "[Ask Sage] Skipped - ASK_SAGE_API_KEY environment variable not set" -ForegroundColor DarkGray
    Write-Host ""
}

$queryNum = 0
$scanStart = Get-Date

Write-AuditLog -EventType 'SCAN_START' -Source 'Main' -Outcome 'Success' `
    -Message "Scan initiated with $($keywords.Count) keyword(s)" `
    -Details @{
        keyword_count = $keywords.Count
        parameters    = @{
            AgiOnly       = [bool]$AgiOnly
            CveOnly       = [bool]$CveOnly
            NoCve         = [bool]$NoCve
            DaysBack      = $DaysBack
            MaxDorks      = $MaxDorks
            BaseDelay     = $BaseDelay
            CveMaxResults = $CveMaxResults
        }
    }

Write-Host "[Starting scan at $($scanStart.ToString('HH:mm:ss'))]" -ForegroundColor Cyan
Write-Host ""

foreach ($keyword in $keywords) {
    Write-Host "[Keyword] '$keyword'" -ForegroundColor White
    Write-AuditLog -EventType 'KEYWORD_START' -Source 'Main' -Outcome 'Success' `
        -Subject $keyword -Message "Processing keyword: $keyword"

    # --- Dork searches for this keyword ---
    if (-not $AgiOnly -and -not $CveOnly -and -not $captchaState.Blocked) {
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
    } elseif (-not $AgiOnly -and -not $CveOnly) {
        Write-Host "  [BLOCKED] CAPTCHA block active - skipping dork searches" -ForegroundColor Red
        Write-AuditLog -EventType 'CAPTCHA_BLOCKED' -Source 'Main' -Outcome 'Warning' `
            -Subject $keyword -Message "Dork searches skipped due to CAPTCHA block"
    }

    # --- CVE lookup for this keyword ---
    if (-not $NoCve) {
        Write-Host "  [NVD] Searching CVEs for '$keyword' (last $DaysBack days)..." -ForegroundColor Cyan
        Write-AuditLog -EventType 'CVE_QUERY_START' -Source 'Invoke-NvdCveSearch' -Outcome 'Success' `
            -Subject $keyword -Message "Starting NVD CVE search" `
            -Details @{ days_back = $DaysBack; max_results = $CveMaxResults }

        $cveResults = Invoke-NvdCveSearch -Keyword $keyword -DaysBack $DaysBack `
            -MaxResults $CveMaxResults -VerboseOutput:$VerboseOutput
        $allCveResults[$keyword] = $cveResults

        $cveColor = if ($cveResults.Count -gt 0) { 'Green' } else { 'DarkGray' }
        Write-Host "  [NVD] $($cveResults.Count) CVE(s) found for '$keyword'" -ForegroundColor $cveColor

        Write-AuditLog -EventType 'CVE_QUERY_COMPLETE' -Source 'Invoke-NvdCveSearch' -Outcome 'Success' `
            -Subject $keyword -Message "NVD search complete: $($cveResults.Count) CVE(s) found" `
            -Details @{ cve_count = $cveResults.Count }
    }

    # --- AGI query for this keyword ---
    if ($sageApiKey -and -not $CveOnly) {
        $kwDorkResults = @($allResults | Where-Object { $_.Keyword -eq $keyword })
        $kwCveResults = if ($allCveResults.Contains($keyword)) { @($allCveResults[$keyword]) } else { @() }
        $sageResponse = Invoke-AskSageQuery -Keywords @($keyword) -ApiKey $sageApiKey `
            -ScanResults $kwDorkResults -CveResults $kwCveResults -PersonaId $personaId -DaysBack $DaysBack

        if ($sageResponse) {
            $sageRaw = if ($sageResponse.message) { $sageResponse.message } else { $sageResponse | ConvertTo-Json -Depth 5 }
            $jsonText = $sageRaw
            if ($jsonText -match '(?s)```(?:json)?\s*(\[[\s\S]*\])\s*```') {
                $jsonText = $Matches[1]
            } elseif ($jsonText -match '(?s)(\[\s*\{[\s\S]*\}\s*\])') {
                $jsonText = $Matches[1]
            }
            try {
                $parsed = $jsonText | ConvertFrom-Json
                $allSageResults[$keyword] = @($parsed)
                Write-Host "  [Ask Sage] $(@($parsed).Count) finding(s) for '$keyword'" -ForegroundColor Green
                Write-AuditLog -EventType 'GENAI_RESPONSE' -Source 'Main' -Outcome 'Success' `
                    -Subject $keyword -Message "Parsed $(@($parsed).Count) GenAI finding(s)"
            } catch {
                Write-Host "  [Ask Sage] Could not parse JSON for '$keyword'" -ForegroundColor DarkYellow
                $allSageResults[$keyword] = @()
                Write-AuditLog -EventType 'GENAI_ERROR' -Source 'Main' -Outcome 'Failure' `
                    -Subject $keyword -Message "Could not parse GenAI JSON response"
            }
        } else {
            $allSageResults[$keyword] = @()
        }
    }

    Write-AuditLog -EventType 'KEYWORD_COMPLETE' -Source 'Main' -Outcome 'Success' `
        -Subject $keyword -Message "Keyword processing complete"

    Write-Host ""
}

# ============================================================================
# RESULTS SUMMARY
# ============================================================================
$scanEnd = Get-Date
$elapsed = $scanEnd - $scanStart

# Count CVE results
$totalCves = 0
if ($allCveResults.Count -gt 0) {
    $totalCves = ($allCveResults.Keys | ForEach-Object { $allCveResults[$_].Count } | Measure-Object -Sum).Sum
}

Write-Host "========================================" -ForegroundColor White
Write-Host " SCAN COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor White
Write-Host "  Duration:       $($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor White
if (-not $AgiOnly -and -not $CveOnly) {
    Write-Host "  Queries run:    $queryNum / $totalQueries" -ForegroundColor White
    Write-Host "  Dork results:   $($allResults.Count)" -ForegroundColor White
    $captchaColor = if ($captchaState.HitCount -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host "  CAPTCHA hits:   $($captchaState.HitCount)" -ForegroundColor $captchaColor
    $blockedColor = if ($captchaState.Blocked) { 'Red' } else { 'Green' }
    Write-Host "  Blocked:        $($captchaState.Blocked)" -ForegroundColor $blockedColor
}
if (-not $NoCve) {
    $cveColor = if ($totalCves -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host "  CVEs found:     $totalCves" -ForegroundColor $cveColor
}
Write-Host "========================================" -ForegroundColor White
Write-Host ""

# Print dork results grouped by keyword
if (-not $AgiOnly -and -not $CveOnly -and $allResults.Count -gt 0) {
    Write-Host "[Dork Results by keyword]" -ForegroundColor Cyan
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
}

# Print CVE results grouped by keyword
if (-not $NoCve -and $totalCves -gt 0) {
    Write-Host "[CVE Results by keyword]" -ForegroundColor Cyan
    Write-Host ""
    foreach ($keyword in $keywords) {
        $kwCves = if ($allCveResults.Contains($keyword)) { @($allCveResults[$keyword]) } else { @() }
        if ($kwCves.Count -eq 0) { continue }
        Write-Host "  [$keyword] - $($kwCves.Count) CVE(s)" -ForegroundColor White
        foreach ($cve in $kwCves) {
            Write-Host "    [$($cve.Severity)] $($cve.CveId) (CVSS: $($cve.CvssScore))" -ForegroundColor Gray
            Write-Host "      $($cve.NvdLink)" -ForegroundColor DarkCyan
            if ($cve.Description) {
                $preview = if ($cve.Description.Length -gt 100) { $cve.Description.Substring(0, 100) + '...' } else { $cve.Description }
                Write-Host "      $preview" -ForegroundColor DarkGray
            }
        }
        Write-Host ""
    }
}

# Flatten per-keyword AGI results (tagged with keyword)
$sageItems = @()
if ($allSageResults.Count -gt 0) {
    foreach ($kw in $allSageResults.Keys) {
        foreach ($item in $allSageResults[$kw]) {
            $item | Add-Member -NotePropertyName 'keyword' -NotePropertyValue $kw -Force
            $sageItems += $item
        }
    }
}

# Flatten per-keyword CVE results
$cveFlatResults = @()
if ($allCveResults.Count -gt 0) {
    foreach ($kw in $allCveResults.Keys) {
        $cveFlatResults += @($allCveResults[$kw])
    }
}

# ============================================================================
# NIST AUDIT LOG EXPORT (JSON + CSV)
# ============================================================================
Write-AuditLog -EventType 'SCAN_COMPLETE' -Source 'Main' -Outcome 'Success' `
    -Message "Scan complete" `
    -Details @{
        duration_seconds = [math]::Round($elapsed.TotalSeconds, 1)
        dork_results     = $allResults.Count
        cve_results      = $totalCves
        sage_findings    = $sageItems.Count
    }

if ($Script:AuditLogEntries.Count -gt 0 -and -not $NoExport) {
    $auditTimestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'

    # NIST Audit Log - JSON format
    $auditJsonPath = Join-Path $Script:ScanOutputDir "Look4Gold13_Audit_$auditTimestamp.json"
    try {
        $auditJsonObj = @{
            metadata = @{
                tool          = "Look4Gold13"
                log_standard  = "NIST SP 800-53 AU-2/AU-3"
                generated     = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                scan_duration = $elapsed.ToString('hh\:mm\:ss')
                keywords      = $keywords
                days_back     = $DaysBack
                total_events  = $Script:AuditLogEntries.Count
            }
            audit_events = @($Script:AuditLogEntries)
        }
        $auditJsonObj | ConvertTo-Json -Depth 10 | Out-File -FilePath $auditJsonPath -Encoding UTF8
        Write-Host "[NIST Audit Log] JSON saved to:" -ForegroundColor Cyan
        Write-Host "  $auditJsonPath" -ForegroundColor White
        Write-AuditLog -EventType 'DATA_EXPORT' -Source 'Main' -Outcome 'Success' `
            -Message "NIST audit log exported (JSON)" -Details @{ path = $auditJsonPath }
    } catch {
        Write-Host "[NIST Audit Log] JSON export FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }

    # NIST Audit Log - CSV/Excel format
    $auditCsvPath = Join-Path $Script:ScanOutputDir "Look4Gold13_Audit_$auditTimestamp.csv"
    try {
        $csvRows = @()
        foreach ($entry in $Script:AuditLogEntries) {
            $csvRows += [PSCustomObject]@{
                Timestamp      = $entry.timestamp
                EventType      = $entry.event_type
                SourceSystem   = $entry.source_system
                SourceHost     = $entry.source_host
                SourceFunction = $entry.source_function
                Outcome        = $entry.outcome
                Subject        = $entry.subject
                Message        = $entry.message
                Details        = ($entry.details | ConvertTo-Json -Depth 5 -Compress)
            }
        }
        $csvRows | Export-Csv -Path $auditCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "[NIST Audit Log] CSV (Excel) saved to:" -ForegroundColor Cyan
        Write-Host "  $auditCsvPath" -ForegroundColor White
        Write-AuditLog -EventType 'DATA_EXPORT' -Source 'Main' -Outcome 'Success' `
            -Message "NIST audit log exported (CSV)" -Details @{ path = $auditCsvPath }
    } catch {
        Write-Host "[NIST Audit Log] CSV export FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
}

# ============================================================================
# HTML REPORT (with collapsible CVE and Dork sections)
# ============================================================================
$hasCveResults = $totalCves -gt 0
$hasAnyContent = ($allResults.Count -gt 0 -or $sageItems.Count -gt 0 -or $hasCveResults)

if ($hasAnyContent -and -not $NoExport) {
    $reportTimestamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    if ($OutputFile) {
        $reportPath = $OutputFile
        if ($reportPath -notmatch '\.html?$') { $reportPath += '.html' }
    } else {
        $reportPath = Join-Path $Script:ScanOutputDir "Look4Gold13_Report_$reportTimestamp.html"
    }

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
  h3 { color: #53a8e2; margin: 1.2rem 0 0.6rem; border-bottom: 1px solid #2a2a4a; padding-bottom: 0.3rem; }
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
  .keyword-section { margin-bottom: 2.5rem; padding: 1rem; border: 1px solid #2a2a4a; border-radius: 6px; background: #16213e22; }
  /* Collapsible sections */
  details { margin-bottom: 1rem; }
  summary { cursor: pointer; color: #53a8e2; font-size: 1.1rem; font-weight: 600; padding: 0.5rem 0; border-bottom: 1px solid #2a2a4a; user-select: none; }
  summary:hover { color: #e94560; }
  summary::marker { color: #e94560; }
  details[open] summary { margin-bottom: 0.5rem; }
  .count-badge { background: #0f3460; color: #53a8e2; padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.8rem; margin-left: 0.5rem; }
</style>
</head>
<body>
<h1>Look4Gold13 - AU-13 PAC + CVE Report</h1>
<p class="subtitle">Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Keywords: $($keywords -join ', ') | DaysBack: $DaysBack</p>
<p class="stats">Scan duration: $($elapsed.ToString('hh\:mm\:ss')) | Dork queries: $queryNum / $totalQueries | CVEs: $totalCves | CAPTCHA hits: $($captchaState.HitCount)</p>
"@

    # --- Per-keyword sections ---
    foreach ($keyword in $keywords) {
        $kwSage  = if ($allSageResults.Contains($keyword)) { @($allSageResults[$keyword]) } else { @() }
        $kwDorks = @($allResults | Where-Object { $_.Keyword -eq $keyword })
        $kwCves  = if ($allCveResults.Contains($keyword)) { @($allCveResults[$keyword]) } else { @() }

        $html += "`n<div class=`"keyword-section`">"
        $html += "`n<h2>$([System.Web.HttpUtility]::HtmlEncode($keyword))</h2>`n"

        # AGI findings for this keyword (always expanded)
        $html += "<h3>AGI Intelligence (Ask Sage)</h3>`n"
        if ($kwSage.Count -gt 0) {
            $html += "<table>`n<tr><th>Severity</th><th>Title</th><th>Category</th><th>Source</th><th>Summary</th></tr>`n"
            foreach ($item in $kwSage) {
                $sev        = if ($item.severity)    { "$($item.severity)" }    else { 'Informational' }
                $itemTitle  = if ($item.title)        { "$($item.title)" }      else { '' }
                $itemCat    = if ($item.category)     { "$($item.category)" }   else { '' }
                $itemSite   = if ($item.source_site)  { "$($item.source_site)" } else { '' }
                $itemLink   = if ($item.link)         { "$($item.link)" }       else { '' }
                $itemSum    = if ($item.summary)       { "$($item.summary)" }   else { '' }

                $sevColor = if ($severityColors.ContainsKey($sev)) { $severityColors[$sev] } else { '#6c757d' }

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
            $html += "<p class=`"section-empty`">No AGI results for this keyword.</p>`n"
        }

        # CVE results for this keyword (collapsible)
        $html += "<details$(if ($kwCves.Count -gt 0 -and $kwCves.Count -le 10) { ' open' })>`n"
        $html += "<summary>NIST NVD CVE Results (Last $DaysBack Days) <span class=`"count-badge`">$($kwCves.Count)</span></summary>`n"
        if ($kwCves.Count -gt 0) {
            $html += "<table>`n<tr><th>Severity</th><th>CVE ID</th><th>CVSS</th><th>Published</th><th>Description</th></tr>`n"
            foreach ($cve in $kwCves) {
                $sevColor = if ($severityColors.ContainsKey($cve.Severity)) { $severityColors[$cve.Severity] } else { '#6c757d' }
                $descPreview = if ($cve.Description.Length -gt 200) { $cve.Description.Substring(0, 200) + '...' } else { $cve.Description }
                $html += "<tr>"
                $html += "<td><span class=`"severity`" style=`"background:$sevColor`">$([System.Web.HttpUtility]::HtmlEncode($cve.Severity))</span></td>"
                $nvdHref = [System.Web.HttpUtility]::HtmlAttributeEncode($cve.NvdLink)
                $html += "<td><a href=`"$nvdHref`" target=`"_blank`">$([System.Web.HttpUtility]::HtmlEncode($cve.CveId))</a></td>"
                $html += "<td>$($cve.CvssScore)</td>"
                $html += "<td>$([System.Web.HttpUtility]::HtmlEncode($cve.Published))</td>"
                $html += "<td class=`"summary`">$([System.Web.HttpUtility]::HtmlEncode($descPreview))</td>"
                $html += "</tr>`n"
            }
            $html += "</table>`n"
        } else {
            $html += "<p class=`"section-empty`">No CVEs found for this keyword in the last $DaysBack days.</p>`n"
        }
        $html += "</details>`n"

        # Dork results for this keyword (collapsible)
        $html += "<details$(if ($kwDorks.Count -gt 0 -and $kwDorks.Count -le 10) { ' open' })>`n"
        $html += "<summary>Search Dork Results <span class=`"count-badge`">$($kwDorks.Count)</span></summary>`n"
        if ($kwDorks.Count -gt 0) {
            $html += "<table><tr><th>Dork</th><th>Title</th><th>URL</th><th>Summary</th></tr>`n"
            foreach ($r in $kwDorks) {
                $html += "<tr>"
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
            $html += "<p class=`"section-empty`">No dork results for this keyword.</p>`n"
        }
        $html += "</details>`n"

        $html += "</div>`n"
    }

    $html += "</body></html>"

    try {
        $html | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Host "[HTML Report] Saved to:" -ForegroundColor Cyan
        Write-Host "  $reportPath" -ForegroundColor White
        Write-AuditLog -EventType 'DATA_EXPORT' -Source 'Main' -Outcome 'Success' `
            -Message "HTML report exported" -Details @{ path = $reportPath }
    } catch {
        Write-Host "[HTML Report] FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-AuditLog -EventType 'EXPORT_ERROR' -Source 'Main' -Outcome 'Failure' `
            -Message "HTML report export failed: $($_.Exception.Message)"
    }
    Write-Host ""
}

# Close the DDG browser window we opened at start
$ddgClosed = $false

# Strategy 1: Close original process via CloseMainWindow + Kill fallback
if ($ddgProcess -and -not $ddgProcess.HasExited) {
    try {
        $ddgProcess.CloseMainWindow() | Out-Null
        if (-not $ddgProcess.WaitForExit(3000)) {
            $ddgProcess.Kill()
        }
        $ddgClosed = $true
    } catch { }
}

# Strategy 2: Kill any new PIDs that appeared when we launched the browser
# (Chromium-based browsers merge into an existing process, so the original PID may not own the window)
if ($Script:NewBrowserPIDs -and $Script:NewBrowserPIDs.Count -gt 0) {
    foreach ($bpid in $Script:NewBrowserPIDs) {
        try {
            $proc = Get-Process -Id $bpid -ErrorAction SilentlyContinue
            if ($proc -and -not $proc.HasExited) {
                # Try Win32 WM_CLOSE first (graceful)
                if ($proc.MainWindowHandle -ne [IntPtr]::Zero) {
                    try { [Win32Window]::PostMessage($proc.MainWindowHandle, [Win32Window]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null } catch { }
                    Start-Sleep -Milliseconds 500
                }
                # Force-kill if still alive
                if (-not $proc.HasExited) {
                    Stop-Process -Id $bpid -Force -ErrorAction SilentlyContinue
                }
                $ddgClosed = $true
            }
        } catch { }
    }
}

# Strategy 3: Find any browser window with DuckDuckGo in the title
if (-not $ddgClosed -and $ddgBrowserName) {
    try {
        Get-Process -Name $ddgBrowserName -ErrorAction SilentlyContinue |
            Where-Object { $_.MainWindowTitle -match 'DuckDuckGo' } |
            ForEach-Object {
                try {
                    if ($_.MainWindowHandle -ne [IntPtr]::Zero) {
                        [Win32Window]::PostMessage($_.MainWindowHandle, [Win32Window]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
                    }
                } catch { }
            }
        $ddgClosed = $true
    } catch { }
}

if ($ddgClosed) {
    Write-Host "[Browser] DuckDuckGo window closed." -ForegroundColor DarkGray
    Write-AuditLog -EventType 'BROWSER_CLOSE' -Source 'Main' -Outcome 'Success' `
        -Message "DDG browser window closed"
}

Write-Host "Done." -ForegroundColor Green
