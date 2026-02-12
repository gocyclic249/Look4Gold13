
<#
.SYNOPSIS
    Look4Gold13 - AU-13 Compliance Scanner (Single-file edition)
.DESCRIPTION
    Scans multiple sources for unauthorized disclosure of organizational
    information per NIST SP 800-53 AU-13.

    Sources: DuckDuckGo (including paste sites), Breach/Security Blogs,
             NIST NVD CVE Database, AskSage Live Search

    After scanning, sends results per keyword to a GenAI API (Ask Sage)
    for summarization. The AI summary is embedded in the HTML report.

    On government networks where web scraping is blocked (Menlo Security,
    CAPTCHAs), automatically uses AskSage API for live web searches instead.
    NIST NVD CVE search works on all networks (direct .gov API access).

    Optional: Set $env:NVD_API_KEY for faster NVD queries (50 req/30s vs 5 req/30s).
    Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

    Three modes:
      Web UI (default)     - browser-based dashboard at localhost (when GenAI token available)
      Interactive          - prompts for all settings (when no GenAI token)
      Silent (-Silent)     - uses flags and defaults, no prompts
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
.EXAMPLE
    .\Look4Gold13.ps1 -WebUI
    # Launch browser-based dashboard (uses AskSage for searches)
.EXAMPLE
    .\Look4Gold13.ps1 -WebUI -UseProxy
    # Web UI mode on government network
#>
param(
    [switch]$Silent,

    [string]$KeywordFile,

    [int]$DaysBack,

    [string]$OutputFile,

    [string]$ConfigFile,

    [ValidateSet('DuckDuckGo', 'Breach')]
    [string[]]$Sources,

    [switch]$UseProxy,

    [switch]$WebUI
)

# ============================================================================
# TLS CONFIGURATION
# ============================================================================

# Enable TLS 1.2 + 1.3 (if available) for browser-like TLS negotiation
# Browsers negotiate TLS 1.3; security proxies like Menlo may flag TLS 1.2-only clients
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} catch {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-EnvVar {
    param([string]$Name)
    foreach ($scope in 'Process', 'User', 'Machine') {
        $val = [System.Environment]::GetEnvironmentVariable($Name, $scope)
        if ($val) { return $val }
    }
    return $null
}

function ConvertFrom-Markdown {
    param([string]$Text)
    if (-not $Text) { return '' }

    $lines = $Text -split "`n"
    $html = New-Object System.Text.StringBuilder
    $inList = $false
    $inCodeBlock = $false

    foreach ($line in $lines) {
        # Fenced code blocks
        if ($line -match '^```') {
            if ($inCodeBlock) {
                [void]$html.Append('</code></pre>')
                $inCodeBlock = $false
            } else {
                if ($inList) { [void]$html.Append('</ul>'); $inList = $false }
                [void]$html.Append('<pre><code>')
                $inCodeBlock = $true
            }
            continue
        }
        if ($inCodeBlock) {
            [void]$html.AppendLine([System.Web.HttpUtility]::HtmlEncode($line))
            continue
        }

        # Close list if current line is not a list item
        if ($inList -and $line -notmatch '^\s*[-*]\s') {
            [void]$html.Append('</ul>')
            $inList = $false
        }

        # Blank lines
        if ($line -match '^\s*$') { continue }

        # Headers
        if ($line -match '^####\s+(.+)') {
            [void]$html.Append("<h6>$([System.Web.HttpUtility]::HtmlEncode($Matches[1]))</h6>")
            continue
        }
        if ($line -match '^###\s+(.+)') {
            [void]$html.Append("<h5>$([System.Web.HttpUtility]::HtmlEncode($Matches[1]))</h5>")
            continue
        }
        if ($line -match '^##\s+(.+)') {
            [void]$html.Append("<h4>$([System.Web.HttpUtility]::HtmlEncode($Matches[1]))</h4>")
            continue
        }
        if ($line -match '^#\s+(.+)') {
            [void]$html.Append("<h3>$([System.Web.HttpUtility]::HtmlEncode($Matches[1]))</h3>")
            continue
        }

        # Unordered list items
        if ($line -match '^\s*[-*]\s+(.+)') {
            if (-not $inList) { [void]$html.Append('<ul>'); $inList = $true }
            $itemText = $Matches[1]
            $itemText = [System.Web.HttpUtility]::HtmlEncode($itemText)
            $itemText = $itemText -replace '\*\*(.+?)\*\*', '<strong>$1</strong>'
            $itemText = $itemText -replace '`(.+?)`', '<code>$1</code>'
            [void]$html.Append("<li>$itemText</li>")
            continue
        }

        # Regular paragraph — apply inline formatting
        $escaped = [System.Web.HttpUtility]::HtmlEncode($line)
        $escaped = $escaped -replace '\*\*(.+?)\*\*', '<strong>$1</strong>'
        $escaped = $escaped -replace '`(.+?)`', '<code>$1</code>'
        [void]$html.Append("<p>$escaped</p>")
    }

    if ($inList) { [void]$html.Append('</ul>') }
    if ($inCodeBlock) { [void]$html.Append('</code></pre>') }

    # Replace severity tags like [HIGH], [CRITICAL] with styled badges
    $sevColors = @{
        'CRITICAL'      = '#dc3545'
        'HIGH'          = '#c71585'
        'MEDIUM'        = '#ffc107'
        'REVIEW'        = '#17a2b8'
        'MANUAL-REVIEW' = '#6c757d'
        'LOW'           = '#28a745'
    }
    $result = $html.ToString()
    foreach ($tag in $sevColors.Keys) {
        $color = $sevColors[$tag]
        $result = $result -replace "\[$tag\]", "<span class=`"severity-badge`" style=`"background:$color;`">$tag</span>"
    }

    return $result
}

function Invoke-WebRequestWithRetry {
    param(
        [Parameter(Mandatory)][hashtable]$RequestParams,
        [int]$MaxRetries = 5,
        [int]$BaseDelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le ($MaxRetries + 1); $attempt++) {
        try {
            return Invoke-WebRequest @RequestParams
        }
        catch {
            $isRetryable = $_.Exception.Message -match 'connection was closed' -or
                           $_.Exception.Message -match 'Unable to connect' -or
                           $_.Exception.Message -match 'timed out' -or
                           $_.Exception.Message -match '(403|429|503)'

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
        [int]$MaxRetries = 5,
        [int]$BaseDelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le ($MaxRetries + 1); $attempt++) {
        try {
            return Invoke-RestMethod @RequestParams
        }
        catch {
            $isRetryable = $_.Exception.Message -match 'connection was closed' -or
                           $_.Exception.Message -match 'Unable to connect' -or
                           $_.Exception.Message -match 'timed out' -or
                           $_.Exception.Message -match '(403|429|503)'

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

function Test-MenloInterstitial {
    param([string]$Html)
    if (-not $Html) { return $false }
    # Menlo "Proceed with Caution" page has a proceed-link element and Menlo branding
    return ($Html -match 'id\s*=\s*"?proceed-link' -or
            ($Html -match 'Proceed with Caution' -and $Html -match 'menlosecurity'))
}

function Test-MenloSafeView {
    param([string]$Html)
    if (-not $Html) { return $false }
    # Only flag SafeView as a problem when it has NO DDG search content.
    # SafeView WITH content (result__a links, uddg= params) is GOOD — Menlo rendered the DDG page
    # and our existing regex chain can parse it. Only empty SafeView shells are a problem.
    $isSafeView = ($Html -match 'sv_role\s*=\s*"main"' -or $Html -match 'safeview-info')
    $hasContent = ($Html -match 'result__a' -or $Html -match 'uddg=')
    return ($isSafeView -and -not $hasContent)
}

function Invoke-DdgRequestWithMenloHandling {
    param(
        [Parameter(Mandatory)][string]$DirectUrl,
        [string]$ProxyBase,
        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,
        [ref]$CaptchaState,
        [int]$DelaySeconds = 5,
        [string]$DorkLabel = ''
    )

    # Determine request URL (proxied or direct)
    $requestUrl = Get-ProxiedUrl -Url $DirectUrl -ProxyBase $ProxyBase
    $displayUrl = $requestUrl  # Always the proxied URL for report links
    $currentDelay = if ($CaptchaState) { $CaptchaState.Value.CurrentDelay } else { $DelaySeconds }

    # Browser-like headers to prevent Menlo Security from showing interstitial
    # Menlo serves SafeView-rendered DDG results to browsers but shows "Proceed with Caution"
    # to non-browser clients that lack standard headers
    $baseReqParams = @{
        UseBasicParsing = $true
        TimeoutSec      = 15
        ErrorAction     = 'Stop'
        Headers         = @{
            'User-Agent'                = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
            'Accept'                    = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
            'Accept-Language'           = 'en-US,en;q=0.9'
            'Accept-Encoding'           = 'gzip, deflate'
            'Sec-CH-UA'                 = '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"'
            'Sec-CH-UA-Mobile'          = '?0'
            'Sec-CH-UA-Platform'        = '"Windows"'
            'Sec-Fetch-Dest'            = 'document'
            'Sec-Fetch-Mode'            = 'navigate'
            'Sec-Fetch-Site'            = 'none'
            'Sec-Fetch-User'            = '?1'
            'Upgrade-Insecure-Requests' = '1'
            'DNT'                       = '1'
        }
    }
    if ($WebSession) {
        $baseReqParams['WebSession'] = $WebSession
    }

    # --- Attempt 1: Request through proxy (or direct if no proxy) ---
    $reqParams = $baseReqParams.Clone()
    $reqParams['Uri'] = $requestUrl

    $webResponse = Invoke-WebRequestWithRetry -RequestParams $reqParams -MaxRetries 5 -BaseDelaySeconds $currentDelay
    $html = $webResponse.Content

    # --- Check: Menlo Interstitial ("Proceed with Caution") ---
    if ($ProxyBase -and (Test-MenloInterstitial -Html $html)) {
        Write-Host "  [Menlo] Interstitial detected for $DorkLabel - retrying with session cookies..." -ForegroundColor Yellow
        $debugFile = Join-Path $PSScriptRoot "menlo_interstitial_debug.html"
        $html | Out-File -FilePath $debugFile -Encoding UTF8
        Start-Sleep -Seconds 2
        # Retry same proxied URL — WebSession now carries cookies Menlo set
        $webResponse = Invoke-WebRequestWithRetry -RequestParams $reqParams -MaxRetries 2 -BaseDelaySeconds 3
        $html = $webResponse.Content

        # If still interstitial, cookie approach did not work — fall back to direct
        if (Test-MenloInterstitial -Html $html) {
            Write-Host "  [Menlo] Interstitial persists - falling back to direct URL..." -ForegroundColor Yellow
            $reqParams['Uri'] = $DirectUrl
            $webResponse = Invoke-WebRequestWithRetry -RequestParams $reqParams -MaxRetries 3 -BaseDelaySeconds $currentDelay
            $html = $webResponse.Content
        }
    }

    # --- Check: Menlo SafeView (thin JS shell, no usable content) ---
    if ($ProxyBase -and (Test-MenloSafeView -Html $html)) {
        Write-Host "  [Menlo] SafeView JS shell detected - falling back to direct URL..." -ForegroundColor Yellow
        $debugFile = Join-Path $PSScriptRoot "menlo_safeview_debug.html"
        $html | Out-File -FilePath $debugFile -Encoding UTF8
        $reqParams['Uri'] = $DirectUrl
        $webResponse = Invoke-WebRequestWithRetry -RequestParams $reqParams -MaxRetries 3 -BaseDelaySeconds $currentDelay
        $html = $webResponse.Content
    }

    # --- Check: DDG CAPTCHA ---
    $captchaDetected = $false
    if ($webResponse.StatusCode -eq 202 -or $html -match 'anomaly-modal' -or $html -match 'cc=botnet') {
        Write-Host "  [CAPTCHA] DDG rate limit hit - pausing 30s..." -ForegroundColor Yellow
        if ($CaptchaState) {
            $CaptchaState.Value.HitCount++
            $CaptchaState.Value.CurrentDelay = [math]::Min(10, $CaptchaState.Value.CurrentDelay + 2)
        }
        Start-Sleep -Seconds 30
        # Retry once after cooldown
        $webResponse = Invoke-WebRequest @reqParams
        $html = $webResponse.Content
        if ($webResponse.StatusCode -eq 202 -or $html -match 'anomaly-modal') {
            $captchaDetected = $true
            if ($CaptchaState) { $CaptchaState.Value.Blocked = $true }
        }
    }

    return @{
        Html           = $html
        Response       = $webResponse
        CaptchaBlocked = $captchaDetected
        RequestUrl     = $reqParams['Uri']
        DisplayUrl     = $displayUrl
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
        $Path = Join-Path $PSScriptRoot "config/keywords.txt"
    }

    if (-not (Test-Path $Path)) {
        Write-Error "Keywords file not found at '$Path'. Copy config/keywords.example.txt to config/keywords.txt and add your keywords."
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
            delaySeconds = 5
            sources      = @('DuckDuckGo', 'Breach')
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

function Import-AU13Sources {
    param(
        [string]$Path
    )

    if (-not $Path) {
        $Path = Join-Path $PSScriptRoot "config/sources.json"
    }

    # --- Hardcoded defaults (ultimate fallback) ---
    $defaults = @{
        ddgDorks = @(
            @{ Label = 'Code exposure';    Dork = 'github code exposed repository' },
            @{ Label = 'Pastebin';         Dork = 'site:pastebin.com' },
            @{ Label = 'GitHub';           Dork = 'site:github.com' },
            @{ Label = 'GitHub Gist';      Dork = 'site:gist.github.com' },
            @{ Label = 'Reddit';           Dork = 'site:reddit.com' },
            @{ Label = 'Dropbox (public)'; Dork = 'site:dropbox.com/s/' },
            @{ Label = 'Google Docs';      Dork = 'site:docs.google.com' },
            @{ Label = 'Archive.org';      Dork = 'site:archive.org' },
            @{ Label = 'Paste.ee';         Dork = 'site:paste.ee' },
            @{ Label = 'Ghostbin';         Dork = 'site:ghostbin.com' },
            @{ Label = 'Dpaste';           Dork = 'site:dpaste.org' },
            @{ Label = 'Rentry';           Dork = 'site:rentry.co' },
            @{ Label = 'JustPaste.it';     Dork = 'site:justpaste.it' },
            @{ Label = 'ControlC';         Dork = 'site:controlc.com' },
            @{ Label = 'PrivateBin';       Dork = 'site:privatebin.net' },
            @{ Label = '0bin';             Dork = 'site:0bin.net' },
            @{ Label = 'Hastebin';         Dork = 'site:hastebin.com' },
            @{ Label = 'Ideone';           Dork = 'site:ideone.com' },
            @{ Label = 'PDF files';        Dork = 'filetype:pdf' },
            @{ Label = 'Excel files';      Dork = 'filetype:xlsx' },
            @{ Label = 'Word docs';        Dork = 'filetype:doc' },
            @{ Label = 'CSV files';        Dork = 'filetype:csv' }
        )
        breachDorks = @(
            @{ Label = 'Breach/leak news';    Dork = 'breach data leak compromised' },
            @{ Label = 'Ransomware/attacks';  Dork = 'ransomware attack security incident' },
            @{ Label = 'Credential exposure'; Dork = 'credential stolen dark web' },
            @{ Label = 'Have I Been Pwned';   Dork = 'site:haveibeenpwned.com' },
            @{ Label = 'DataBreaches.net';    Dork = 'site:databreaches.net' },
            @{ Label = 'BleepingComputer';    Dork = 'site:bleepingcomputer.com' },
            @{ Label = 'KrebsOnSecurity';     Dork = 'site:krebsonsecurity.com' },
            @{ Label = 'BreachForums (agg)';  Dork = 'breachforums breach leaked database' }
        )
    }

    if (Test-Path $Path) {
        try {
            $fileConfig = Get-Content -Path $Path -Raw | ConvertFrom-Json

            # Full replacement per section: if user provides the key with
            # a non-empty array, it completely replaces the default.
            if ($fileConfig.ddgDorks -and $fileConfig.ddgDorks.Count -gt 0) {
                $defaults.ddgDorks = @($fileConfig.ddgDorks | ForEach-Object {
                    @{ Label = $_.label; Dork = $_.dork }
                })
            }

            if ($fileConfig.breachDorks -and $fileConfig.breachDorks.Count -gt 0) {
                $defaults.breachDorks = @($fileConfig.breachDorks | ForEach-Object {
                    @{ Label = $_.label; Dork = $_.dork }
                })
            }

            Write-Verbose "Loaded search sources from $Path"
        }
        catch {
            Write-Warning "Failed to parse sources file '$Path': $($_.Exception.Message). Using defaults."
        }
    }
    else {
        Write-Verbose "No sources file at '$Path'. Using built-in defaults."
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

        [int]$DelaySeconds = 5,

        [string]$ProxyBase = '',

        [ref]$CaptchaState,

        [array]$Dorks = @(),

        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession
    )

    $results = @()
    $seenUrls = @{}  # Dedup across queries

    $proxyNote = if ($ProxyBase) { ' (via Menlo proxy with session cookies)' } else { '' }
    Write-Host "[DuckDuckGo] Searching via HTML lite endpoint ($($Dorks.Count) queries/keyword, ${DelaySeconds}s delay)$proxyNote..." -ForegroundColor Cyan

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
            $directUrl = "https://html.duckduckgo.com/html/?q=$encodedQuery"
            $currentDelay = if ($CaptchaState) { $CaptchaState.Value.CurrentDelay } else { $DelaySeconds }

            try {
                $requestResult = Invoke-DdgRequestWithMenloHandling `
                    -DirectUrl $directUrl `
                    -ProxyBase $ProxyBase `
                    -WebSession $WebSession `
                    -CaptchaState $CaptchaState `
                    -DelaySeconds $currentDelay `
                    -DorkLabel $dork.Label

                $html = $requestResult.Html
                $ddgUrl = $requestResult.DisplayUrl

                if ($requestResult.CaptchaBlocked) {
                    Write-Host "  [CAPTCHA] Still blocked - skipping remaining dorks for '$keyword'" -ForegroundColor Red
                    break
                }

                # Detect DDG "query too long" error
                if ($html -match 'too long') {
                    Write-Host "  [Query Too Long] $($dork.Label) - DDG rejected query length" -ForegroundColor DarkYellow
                }
                else {
                    # Robust regex for class="result__a" with flexible attribute order
                    $linkMatches = [regex]::Matches($html, '<a\b((?:[^>]*\bclass="result__a"[^>]*\bhref="([^"]+)"|[^>]*\bhref="([^"]+)"[^>]*\bclass="result__a")[^>]*)>([^<]+)<')

                    if ($linkMatches.Count -eq 0) {
                        # Fallback 1: match DDG redirect links by uddg= parameter
                        $linkMatches = [regex]::Matches($html, 'href="([^"]*uddg=[^"]+)"[^>]*>([^<]+)<')
                    }

                    if ($linkMatches.Count -eq 0) {
                        # Fallback 2: match any duckduckgo.com/l/ redirect links
                        $linkMatches = [regex]::Matches($html, 'href="([^"]*duckduckgo\.com/l/[^"]+)"[^>]*>([^<]+)<')
                    }

                    if ($linkMatches.Count -eq 0 -and $ProxyBase) {
                        # Proxy-specific fallback: match links rewritten by proxy (classes may be prefixed, links start with proxy base)
                        $linkMatches = [regex]::Matches($html, 'class="[^"]*result__a" href="([^"]+)"[^>]*>([^<]+)<')
                        if ($linkMatches.Count -eq 0) {
                            # Even broader: any href starting with proxy base + https://
                            $linkMatches = [regex]::Matches($html, 'href="' + [regex]::Escape($ProxyBase) + '/https?://([^"]+)"[^>]*>([^<]+)<')
                        }
                    }

                    if ($linkMatches.Count -gt 0) {
                        $newCount = 0
                        foreach ($match in $linkMatches) {
                            # Handle robust regex groups (href in group 2 or 3, title in 4)
                            if ($match.Groups.Count -ge 5 -and $match.Groups[4].Value) {
                                $resultUrl = if ($match.Groups[2].Value) { $match.Groups[2].Value } else { $match.Groups[3].Value }
                                $resultTitle = $match.Groups[4].Value.Trim()
                            } else {
                                $resultUrl = $match.Groups[1].Value
                                $resultTitle = $match.Groups[2].Value.Trim()
                            }

                            # For proxy, strip proxy base from URL
                            if ($ProxyBase -and $resultUrl -match [regex]::Escape($ProxyBase + '/') + '(.*)') {
                                $resultUrl = $Matches[1]
                                if ($resultUrl -notmatch '^https?://') { $resultUrl = 'https://' + $resultUrl }
                            }

                            # Skip results with empty titles (mandatory param)
                            if (-not $resultTitle) { continue }

                            # DDG wraps URLs in a redirect — extract the real URL
                            # Handle both & and &amp; as parameter separators
                            if ($resultUrl -match 'uddg=([^&]+)') {
                                $resultUrl = [System.Uri]::UnescapeDataString($Matches[1])
                            }
                            # Strip any remaining DDG redirect wrapper
                            if ($resultUrl -match '^(//|https?://)duckduckgo\.com') {
                                if ($resultUrl -match 'uddg=([^&]+)') {
                                    $resultUrl = [System.Uri]::UnescapeDataString($Matches[1])
                                } else { continue }
                            }
                            # Ensure valid scheme
                            if ($resultUrl -match '^//') { $resultUrl = 'https:' + $resultUrl }
                            if ($resultUrl -notmatch '^https?://') { $resultUrl = 'https://' + $resultUrl }

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
                        $debugFile = Join-Path $PSScriptRoot "debug_ddg_$($dork.Label -replace '[^a-zA-Z0-9]','_').html"
                        Write-Host "  [Debug] Saving HTML to $debugFile" -ForegroundColor Yellow
                        $html | Out-File -FilePath $debugFile -Encoding UTF8
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

function Search-BreachInfo {
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [int]$DaysBack = 30,

        [int]$DelaySeconds = 5,

        [string]$ProxyBase = '',

        [ref]$CaptchaState,

        [array]$BreachDorks = @(),

        [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession
    )

    $results = @()
    $seenUrls = @{}  # Dedup across queries

    $proxyNote = if ($ProxyBase) { ' (via Menlo proxy with session cookies)' } else { '' }
    Write-Host "[BreachInfo] Searching $($BreachDorks.Count) queries/keyword, ${DelaySeconds}s delay$proxyNote..." -ForegroundColor Cyan

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
            $directUrl = "https://html.duckduckgo.com/html/?q=$encodedQuery"
            $currentDelay = if ($CaptchaState) { $CaptchaState.Value.CurrentDelay } else { $DelaySeconds }

            try {
                $requestResult = Invoke-DdgRequestWithMenloHandling `
                    -DirectUrl $directUrl `
                    -ProxyBase $ProxyBase `
                    -WebSession $WebSession `
                    -CaptchaState $CaptchaState `
                    -DelaySeconds $currentDelay `
                    -DorkLabel $dork.Label

                $html = $requestResult.Html
                $ddgUrl = $requestResult.DisplayUrl

                if ($requestResult.CaptchaBlocked) {
                    Write-Host "  [CAPTCHA] Still blocked - skipping remaining dorks for '$keyword'" -ForegroundColor Red
                    break
                }

                if ($html -match 'too long') {
                    Write-Host "  [Query Too Long] $($dork.Label)" -ForegroundColor DarkYellow
                }
                else {
                    # Robust regex for class="result__a" with flexible attribute order
                    $linkMatches = [regex]::Matches($html, '<a\b((?:[^>]*\bclass="result__a"[^>]*\bhref="([^"]+)"|[^>]*\bhref="([^"]+)"[^>]*\bclass="result__a")[^>]*)>([^<]+)<')

                    if ($linkMatches.Count -eq 0) {
                        # Fallback 1: match DDG redirect links by uddg= parameter
                        $linkMatches = [regex]::Matches($html, 'href="([^"]*uddg=[^"]+)"[^>]*>([^<]+)<')
                    }

                    if ($linkMatches.Count -eq 0) {
                        # Fallback 2: match any duckduckgo.com/l/ redirect links
                        $linkMatches = [regex]::Matches($html, 'href="([^"]*duckduckgo\.com/l/[^"]+)"[^>]*>([^<]+)<')
                    }

                    if ($linkMatches.Count -eq 0 -and $ProxyBase) {
                        # Proxy-specific fallback: match links rewritten by proxy (classes may be prefixed)
                        $linkMatches = [regex]::Matches($html, 'class="[^"]*result__a" href="([^"]+)"[^>]*>([^<]+)<')
                        if ($linkMatches.Count -eq 0) {
                            # Broader: any href starting with proxy base + https://
                            $linkMatches = [regex]::Matches($html, 'href="' + [regex]::Escape($ProxyBase) + '/https?://([^"]+)"[^>]*>([^<]+)<')
                        }
                    }

                    if ($linkMatches.Count -gt 0) {
                        $newCount = 0
                        foreach ($match in $linkMatches) {
                            # Handle robust regex groups (href in group 2 or 3, title in 4)
                            if ($match.Groups.Count -ge 5 -and $match.Groups[4].Value) {
                                $resultUrl = if ($match.Groups[2].Value) { $match.Groups[2].Value } else { $match.Groups[3].Value }
                                $resultTitle = $match.Groups[4].Value.Trim()
                            } else {
                                $resultUrl = $match.Groups[1].Value
                                $resultTitle = $match.Groups[2].Value.Trim()
                            }

                            # DDG wraps URLs in a redirect — extract the real URL
                            # Handle both & and &amp; as parameter separators
                            if ($resultUrl -match 'uddg=([^&]+)') {
                                $resultUrl = [System.Uri]::UnescapeDataString($Matches[1])
                            }
                            # Strip any remaining DDG redirect wrapper
                            if ($resultUrl -match '^(//|https?://)duckduckgo\.com') {
                                if ($resultUrl -match 'uddg=([^&]+)') {
                                    $resultUrl = [System.Uri]::UnescapeDataString($Matches[1])
                                } else { continue }
                            }
                            # Ensure valid scheme
                            if ($resultUrl -match '^//') { $resultUrl = 'https:' + $resultUrl }
                            if ($resultUrl -notmatch '^https?://') { $resultUrl = 'https://' + $resultUrl }

                            # Skip results with empty titles
                            if (-not $resultTitle) { continue }

                            # Dedup by URL
                            $urlKey = "$keyword|$resultUrl"
                            if ($seenUrls.ContainsKey($urlKey)) { continue }
                            $seenUrls[$urlKey] = $true
                            $newCount++

                            # Extract domain name for source label
                            $sourceName = try { ([System.Uri]$resultUrl).Host -replace '^www\.' } catch { 'Breach' }

                            $results += New-AU13Result `
                                -Source $sourceName `
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
                        $debugFile = Join-Path $PSScriptRoot "debug_ddg_$($dork.Label -replace '[^a-zA-Z0-9]','_').html"
                        Write-Host "  [Debug] Saving HTML to $debugFile" -ForegroundColor Yellow
                        $html | Out-File -FilePath $debugFile -Encoding UTF8
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
# NIST NVD CVE SEARCH
# ============================================================================

function Search-NvdCve {
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [int]$DaysBack = 30,

        [string]$ApiKey = ''
    )

    $baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    $delaySeconds = if ([string]::IsNullOrEmpty($ApiKey)) { 7 } else { 0.8 }

    if ([string]::IsNullOrEmpty($ApiKey)) {
        Write-Host "[NVD] No API key - using public rate (${delaySeconds}s delay)" -ForegroundColor Gray
    } else {
        Write-Host "[NVD] API key detected - using fast rate" -ForegroundColor Green
    }

    $pubStartDate = (Get-Date).AddDays(-$DaysBack).ToString('yyyy-MM-ddT00:00:00.000')
    $pubEndDate = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.000')

    $results = @()

    foreach ($keyword in $Keywords) {
        Write-Host "[NVD] Searching for '$keyword'..." -ForegroundColor Gray
        $startIndex = 0
        $totalResults = 0

        do {
            $queryParts = @(
                "keywordSearch=$([System.Uri]::EscapeDataString($keyword))",
                "resultsPerPage=2000",
                "startIndex=$startIndex",
                "pubStartDate=$pubStartDate",
                "pubEndDate=$pubEndDate"
            )
            $uri = $baseUrl + '?' + ($queryParts -join '&')

            $headers = @{}
            if (-not [string]::IsNullOrEmpty($ApiKey)) {
                $headers['apiKey'] = $ApiKey
            }

            try {
                $requestParams = @{
                    Uri             = $uri
                    Method          = 'Get'
                    ContentType     = 'application/json'
                    UseBasicParsing = $true
                }
                if ($headers.Count -gt 0) {
                    $requestParams['Headers'] = $headers
                }

                $response = Invoke-RestMethod @requestParams

                if ($startIndex -eq 0) {
                    $totalResults = $response.totalResults
                    Write-Host "[NVD] Found $totalResults CVE(s) for '$keyword'" -ForegroundColor Gray
                }

                foreach ($vuln in $response.vulnerabilities) {
                    $cveId = $vuln.cve.id
                    $description = ($vuln.cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value
                    if (-not $description) { $description = 'No description available' }

                    # Map CVSS score to severity
                    $severity = 'Review'
                    $cvssScore = $null
                    if ($vuln.cve.metrics.cvssMetricV31) {
                        $cvssScore = $vuln.cve.metrics.cvssMetricV31[0].cvssData.baseScore
                    } elseif ($vuln.cve.metrics.cvssMetricV2) {
                        $cvssScore = $vuln.cve.metrics.cvssMetricV2[0].cvssData.baseScore
                    }
                    if ($cvssScore) {
                        $severity = if ($cvssScore -ge 9.0) { 'Critical' }
                                    elseif ($cvssScore -ge 7.0) { 'High' }
                                    elseif ($cvssScore -ge 4.0) { 'Medium' }
                                    else { 'Review' }
                    }

                    $truncDesc = if ($description.Length -gt 300) { $description.Substring(0, 300) + '...' } else { $description }
                    $title = "$cveId$(if ($cvssScore) { " (CVSS: $cvssScore)" } else { '' })"

                    $results += New-AU13Result `
                        -Source 'NVD-CVE' `
                        -Keyword $keyword `
                        -Title $title `
                        -Url "https://nvd.nist.gov/vuln/detail/$cveId" `
                        -Snippet $truncDesc `
                        -Severity $severity
                }

                $startIndex += $response.vulnerabilities.Count
            }
            catch {
                Write-Warning "[NVD] Error fetching CVEs for '$keyword': $($_.Exception.Message)"
                break
            }

            if ($startIndex -lt $totalResults) {
                Start-Sleep -Seconds $delaySeconds
            }
        } while ($startIndex -lt $totalResults)
    }

    Write-Host "[NVD] Search complete: $($results.Count) CVE(s) found" -ForegroundColor Gray
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

    $token = Get-EnvVar $GenAIConfig.tokenEnvVar
    if (-not $token) {
        return @{
            Message    = "GenAI summary unavailable - $($GenAIConfig.tokenEnvVar) environment variable not set."
            References = @()
        }
    }

    $isOpenAI = $GenAIConfig.apiType -eq 'openai-compatible'

    # Set auth headers based on API type (Content-Type must be set via
    # -ContentType param, not headers — PowerShell silently ignores it in headers)
    if ($isOpenAI) {
        $headers = @{
            'Authorization' = "Bearer $token"
        }
    }
    else {
        $headers = @{
            'x-access-tokens' = $token
        }
    }

    # Build different prompts depending on whether we have scan results
    if ($Results -and $Results.Count -gt 0) {
        $resultSummary = $Results | ForEach-Object {
            "- [$($_.Severity)] $($_.Source): $($_.Title) | URL: $($_.Url) | $($_.Snippet)"
        }
        $resultText = $resultSummary -join "`n"

        $prompt = @"
You are an AU-13 compliance analyst, specializing in NIST SP 800-53 AU-13: monitoring for unauthorized disclosure of organizational information (e.g., data breaches, leaks on paste sites, GitHub, or security blogs). Analyze the provided scan results for the keyword "$Keyword". Base your response strictly on the results and any additional live web searches. Focus on events from the last $DaysBack days. Provide your output in Markdown format with the following sections:

### 1. Risk Assessment
A brief assessment (1-2 sentences) of the overall risk level, using severity levels like Critical, High, Medium, or Low.

### 2. Key Findings
Bullet-point summary of the most important findings from the scan results, including any suggested severity.

### 3. Recommended Actions
Bullet-point list of practical, compliance-focused actions (e.g., investigate, notify stakeholders).

### 4. Additional Sources
Use live web search to find any NEW public disclosures, data breaches, paste site leaks, or security incidents related to "$Keyword" that are NOT in the scan results below (check by URL and content). If none found, state "No additional sources identified." Otherwise, list each as:
- **Title/Description**: Brief summary (1 sentence).
- **URL**: Full link.
- **Date**: Approximate date of the event.
Scan Results:
$resultText
"@
    }
    else {
        $prompt = @"
You are an AU-13 compliance analyst, specializing in NIST SP 800-53 AU-13: monitoring for unauthorized disclosure of organizational information (e.g., data breaches, leaks on paste sites, GitHub, or security blogs). The automated scan found NO results for "$Keyword" on monitored sites (paste sites, GitHub, breach databases, security news). Use your live web search capability to check for any public disclosures, data breaches, paste site leaks, credential dumps, or security incidents related to "$Keyword" from the last $DaysBack days. Base your response strictly on search findings—do not hallucinate. If no evidence found, explicitly state so. Provide your output in Markdown format with the following sections:

### 1. Risk Assessment
A brief assessment (1-2 sentences) of the overall risk level, using severity levels like Critical, High, Medium, or Low.

### 2. Key Findings
Bullet-point summary of any findings from your search (with source URLs inline). If none, state "No findings from live search."

### 3. Recommended Actions
Bullet-point list of practical, compliance-focused actions (e.g., continue monitoring).

### 4. Additional Sources
List each finding as:
- **Title/Description**: Brief summary (1 sentence).
- **URL**: Full link.
- **Date**: Approximate date of the event.
If none, state "No additional sources identified."
"@
    }

    # Build request body based on API type
    if ($isOpenAI) {
        # OpenAI-compatible format (Grok, OpenAI, etc.)
        $body = @{
            model       = $GenAIConfig.model
            messages    = @(
                @{ role = 'system'; content = 'You are an AU-13 compliance analyst specializing in NIST SP 800-53 AU-13.' }
                @{ role = 'user';   content = $prompt }
            )
            temperature = $GenAIConfig.temperature
        } | ConvertTo-Json -Depth 4
    }
    else {
        # Ask Sage format
        $body = @{
            message          = $prompt
            persona          = $GenAIConfig.persona
            model            = $GenAIConfig.model
            temperature      = $GenAIConfig.temperature
            limit_references = $GenAIConfig.limit_references
            live             = $GenAIConfig.live
        } | ConvertTo-Json -Depth 3
    }

    try {
        $action = if ($Results -and $Results.Count -gt 0) { "Summarizing" } else { "Searching for" }
        $apiLabel = if ($isOpenAI) { $GenAIConfig.model } else { "Ask Sage" }
        Write-Host "[GenAI] $action '$Keyword' via $apiLabel..." -ForegroundColor Cyan
        $response = Invoke-RestMethodWithRetry -RequestParams @{
            Uri         = $GenAIConfig.endpoint
            Method      = 'Post'
            Headers     = $headers
            Body        = [System.Text.Encoding]::UTF8.GetBytes($body)
            ContentType = 'application/json; charset=utf-8'
            TimeoutSec  = 300
            ErrorAction = 'Stop'
        } -MaxRetries 2 -BaseDelaySeconds 3

        Start-Sleep -Seconds 3

        # Parse response based on API type
        $refs = @()
        $messageText = $null

        if ($isOpenAI) {
            # OpenAI-compatible: response.choices[0].message.content
            if ($response.choices -and $response.choices.Count -gt 0) {
                $messageText = $response.choices[0].message.content
            }
        }
        else {
            # Ask Sage: response.message, response.references
            $messageText = $response.message
            if ($response.references) {
                $refs = @($response.references)
                Write-Host "[GenAI] Received $($refs.Count) reference(s) for '$Keyword'" -ForegroundColor Gray
            }
        }

        if ($messageText) {
            return @{
                Message    = $messageText
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
# ASKSAGE WEB SEARCH (replaces DDG scraping on government networks)
# ============================================================================

function Get-AskSageSearchCategories {
    return @(
        @{
            Id          = 'paste_sites'
            Label       = 'Paste Sites'
            Description = 'Paste-sharing sites where data leaks are commonly posted'
            Sites       = 'pastebin.com, paste.ee, ghostbin.com, dpaste.org, rentry.co, justpaste.it, controlc.com, privatebin.net, 0bin.net, hastebin.com'
        },
        @{
            Id          = 'code_repos'
            Label       = 'Code Repositories'
            Description = 'Code hosting platforms where credentials or source code may be exposed'
            Sites       = 'github.com, gist.github.com, gitlab.com, bitbucket.org, ideone.com'
        },
        @{
            Id          = 'documents'
            Label       = 'Document Exposure'
            Description = 'Publicly accessible documents (PDF, Excel, Word, CSV)'
            Sites       = 'docs.google.com, dropbox.com, scribd.com'
        },
        @{
            Id          = 'breach_db'
            Label       = 'Breach Databases'
            Description = 'Breach notification sites and databases'
            Sites       = 'haveibeenpwned.com, databreaches.net, dehashed.com'
        },
        @{
            Id          = 'security_news'
            Label       = 'Security News'
            Description = 'Security news sites reporting on breaches and incidents'
            Sites       = 'bleepingcomputer.com, krebsonsecurity.com, therecord.media, securityweek.com'
        },
        @{
            Id          = 'forums_social'
            Label       = 'Forums & Social'
            Description = 'Discussion forums and social media'
            Sites       = 'reddit.com, archive.org, medium.com'
        }
    )
}

function Invoke-AskSageSearch {
    param(
        [Parameter(Mandatory)][string]$Keyword,
        [Parameter(Mandatory)][hashtable]$Category,
        [Parameter(Mandatory)][hashtable]$GenAIConfig,
        [int]$DaysBack = 30
    )

    $token = Get-EnvVar $GenAIConfig.tokenEnvVar
    if (-not $token) { return @() }

    $isOpenAI = $GenAIConfig.apiType -eq 'openai-compatible'

    if ($isOpenAI) {
        $headers = @{ 'Authorization' = "Bearer $token" }
    } else {
        $headers = @{ 'x-access-tokens' = $token }
    }

    $prompt = @"
As part of NIST SP 800-53 AU-13 compliance monitoring, search for any unauthorized disclosure of information related to "$Keyword".

Focus area: $($Category.Label) — look for "$Keyword" on sites like $($Category.Sites).

Look for: leaked credentials, API keys, source code, sensitive documents, data breaches, PII exposure, and security incidents from the last $DaysBack days.

If you find any results, respond with ONLY a JSON array in this format:
[{"url":"https://...","title":"...","severity":"Critical|High|Medium|Review","snippet":"..."}]

Severity guide: Critical = active credential/data exposure, High = sensitive code/docs, Medium = potential exposure mentions, Review = general references.

If nothing is found, respond with exactly: []

Important: Only include real findings with real, verifiable URLs. Do not fabricate results.
"@

    if ($isOpenAI) {
        $body = @{
            model       = $GenAIConfig.model
            messages    = @(
                @{ role = 'system'; content = 'You are a web search tool for AU-13 compliance. Return only JSON arrays of findings.' }
                @{ role = 'user';   content = $prompt }
            )
            temperature = 0.3
        } | ConvertTo-Json -Depth 4
    } else {
        $body = @{
            message          = $prompt
            persona          = $GenAIConfig.persona
            model            = $GenAIConfig.model
            temperature      = 0.3
            limit_references = $GenAIConfig.limit_references
            live             = $GenAIConfig.live
        } | ConvertTo-Json -Depth 3
    }

    try {
        Write-Host "  [AskSage] Searching $($Category.Label) for '$Keyword'..." -ForegroundColor Cyan
        $response = Invoke-RestMethodWithRetry -RequestParams @{
            Uri         = $GenAIConfig.endpoint
            Method      = 'Post'
            Headers     = $headers
            Body        = [System.Text.Encoding]::UTF8.GetBytes($body)
            ContentType = 'application/json; charset=utf-8'
            TimeoutSec  = 300
            ErrorAction = 'Stop'
        } -MaxRetries 2 -BaseDelaySeconds 3

        Start-Sleep -Seconds 2

        # Extract message text
        $messageText = $null
        if ($isOpenAI) {
            if ($response.choices -and $response.choices.Count -gt 0) {
                $messageText = $response.choices[0].message.content
            }
        } else {
            $messageText = $response.message
        }

        if (-not $messageText) { return @() }

        # Parse JSON from response (handle markdown code blocks)
        $jsonText = $messageText
        if ($jsonText -match '(?s)```(?:json)?\s*(\[[\s\S]*?\])\s*```') {
            $jsonText = $Matches[1].Trim()
        } elseif ($jsonText -match '(?s)(\[[\s\S]*?\])') {
            $jsonText = $Matches[1].Trim()
        } else {
            # No JSON array found — try to extract URLs from plain text
            $results = @()
            $urlMatches = [regex]::Matches($messageText, 'https?://[^\s\)\"<>]+')
            foreach ($m in $urlMatches) {
                $results += New-AU13Result `
                    -Source "AskSage-$($Category.Label)" `
                    -Keyword $Keyword `
                    -Title "AI-discovered finding" `
                    -Url $m.Value `
                    -Snippet "Found by AskSage live search on $($Category.Label)" `
                    -Severity 'Review'
            }
            if ($results.Count -gt 0) {
                Write-Host "    Found $($results.Count) result(s) (text-parsed)" -ForegroundColor Gray
            }
            return $results
        }

        # Parse the JSON array
        try {
            $findings = $jsonText | ConvertFrom-Json
        } catch {
            Write-Host "    Failed to parse JSON response" -ForegroundColor Yellow
            return @()
        }

        if (-not $findings -or $findings.Count -eq 0) { return @() }

        $results = @()
        foreach ($f in $findings) {
            if (-not $f.url -or $f.url -notmatch '^https?://') { continue }
            $sev = switch ($f.severity) {
                'Critical' { 'Critical' }
                'High'     { 'High' }
                'Medium'   { 'Medium' }
                default    { 'Review' }
            }
            $results += New-AU13Result `
                -Source "AskSage-$($Category.Label)" `
                -Keyword $Keyword `
                -Title $(if ($f.title) { $f.title } else { 'AI-discovered finding' }) `
                -Url $f.url `
                -Snippet $(if ($f.snippet) { $f.snippet } else { "Found on $($Category.Label)" }) `
                -Severity $sev
        }

        Write-Host "    Found $($results.Count) result(s)" -ForegroundColor $(if ($results.Count -gt 0) { 'Green' } else { 'Gray' })
        return $results
    }
    catch {
        Write-Warning "  [AskSage] Search error for $($Category.Label)/$Keyword : $($_.Exception.Message)"
        return @()
    }
}

function Search-WithAskSage {
    param(
        [Parameter(Mandatory)][string[]]$Keywords,
        [int]$DaysBack = 30,
        [Parameter(Mandatory)][hashtable]$GenAIConfig
    )

    $categories = Get-AskSageSearchCategories
    $allResults = @()

    foreach ($kw in $Keywords) {
        Write-Host "[AskSage] Searching for '$kw' across $($categories.Count) categories..." -ForegroundColor White
        foreach ($cat in $categories) {
            $catResults = Invoke-AskSageSearch -Keyword $kw -Category $cat -GenAIConfig $GenAIConfig -DaysBack $DaysBack
            $allResults += $catResults
            Start-Sleep -Seconds 1
        }
    }

    Write-Host "[AskSage] Total: $($allResults.Count) results found" -ForegroundColor Cyan
    return $allResults
}

# ============================================================================
# WEB UI SERVER
# ============================================================================

function Get-WebUIHtml {
    return @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Look4Gold13 - AU-13 Compliance Scanner</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--accent:#3b82f6;--accent2:#8b5cf6;--danger:#ef4444;--warn:#f59e0b;--success:#22c55e;--text:#f1f5f9;--muted:#94a3b8;--dim:#475569}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.container{max-width:1200px;margin:0 auto;padding:24px}
.header{text-align:center;padding:32px 0;border-bottom:1px solid var(--border);margin-bottom:24px}
.header h1{font-size:2rem;background:linear-gradient(135deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.header p{color:var(--muted);margin-top:8px;font-size:0.95rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px}
.card h2{font-size:1.15rem;margin-bottom:16px;color:var(--text);display:flex;align-items:center;gap:8px}
.badge{display:inline-block;padding:2px 10px;border-radius:9999px;font-size:0.75rem;font-weight:600}
.badge-blue{background:#1e3a5f;color:#60a5fa}
.badge-green{background:#14532d;color:#4ade80}
.badge-yellow{background:#422006;color:#fbbf24}
.config-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px}
.config-item{background:var(--bg);padding:12px 16px;border-radius:8px;border:1px solid var(--border)}
.config-item label{font-size:0.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em}
.config-item .value{font-size:1rem;margin-top:4px;font-weight:500}
.btn{padding:10px 24px;border:none;border-radius:8px;font-size:0.9rem;font-weight:600;cursor:pointer;transition:all 0.2s}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#2563eb}
.btn-primary:disabled{background:var(--dim);cursor:not-allowed}
.btn-success{background:var(--success);color:#fff}
.btn-success:hover{background:#16a34a}
.btn-danger{background:var(--danger);color:#fff}
.btn-row{display:flex;gap:12px;flex-wrap:wrap}
.progress-outer{background:var(--bg);border-radius:8px;height:28px;overflow:hidden;margin:12px 0;border:1px solid var(--border)}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width 0.5s ease;display:flex;align-items:center;justify-content:center;font-size:0.75rem;font-weight:600;min-width:40px}
.progress-text{color:var(--muted);font-size:0.85rem;margin-top:4px}
.results-table{width:100%;border-collapse:collapse;font-size:0.85rem}
.results-table th{text-align:left;padding:10px 12px;background:var(--bg);color:var(--muted);font-weight:600;text-transform:uppercase;font-size:0.7rem;letter-spacing:0.05em;border-bottom:1px solid var(--border)}
.results-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
.results-table tr:hover{background:rgba(59,130,246,0.05)}
.results-table a{color:var(--accent);text-decoration:none;word-break:break-all}
.results-table a:hover{text-decoration:underline}
.sev{padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;text-transform:uppercase}
.sev-critical{background:#7f1d1d;color:#fca5a5}
.sev-high{background:#78350f;color:#fbbf24}
.sev-medium{background:#713f12;color:#fde68a}
.sev-review{background:#1e3a5f;color:#93c5fd}
.ai-summary{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px;line-height:1.6;font-size:0.9rem}
.ai-summary h3{color:var(--accent);margin-bottom:8px}
.ai-summary h4{color:var(--muted);margin:12px 0 4px}
.ai-summary ul{padding-left:20px;margin:4px 0}
.ai-summary li{margin:4px 0}
.ai-summary a{color:var(--accent)}
.log-area{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;max-height:200px;overflow-y:auto;font-family:'Cascadia Code','Fira Code',monospace;font-size:0.8rem;color:var(--muted);line-height:1.5}
.empty-state{text-align:center;padding:40px;color:var(--dim)}
.hidden{display:none!important}
.kw-tag{display:inline-flex;align-items:center;gap:6px;background:var(--bg);border:1px solid var(--border);padding:4px 12px;border-radius:6px;margin:2px 4px;font-size:0.85rem}
.kw-del{background:none;border:none;color:var(--danger);cursor:pointer;font-size:1rem;padding:0 2px;line-height:1;opacity:0.7}
.kw-del:hover{opacity:1}
.kw-input-row{display:flex;gap:8px;margin-top:10px;align-items:center}
.kw-input-row input{flex:1;padding:8px 12px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--text);font-size:0.85rem;max-width:300px}
.kw-input-row input:focus{outline:none;border-color:var(--accent)}
.btn-sm{padding:6px 14px;font-size:0.8rem}
.kw-save-status{font-size:0.8rem;margin-left:8px;color:var(--success)}
.btn-shutdown{background:var(--dim);color:var(--text);padding:8px 16px;border:none;border-radius:8px;font-size:0.8rem;cursor:pointer;margin-top:24px}
.btn-shutdown:hover{background:var(--danger)}
.footer{text-align:center;padding:20px 0;border-top:1px solid var(--border);margin-top:24px}
.stats-row{display:flex;gap:16px;flex-wrap:wrap;margin-top:12px}
.stat{background:var(--bg);padding:8px 16px;border-radius:8px;border:1px solid var(--border);text-align:center;min-width:80px}
.stat .num{font-size:1.5rem;font-weight:700}
.stat .lbl{font-size:0.7rem;color:var(--muted);text-transform:uppercase}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Look4Gold13</h1>
    <p>NIST SP 800-53 AU-13 Compliance Scanner &mdash; Unauthorized Disclosure Monitoring</p>
  </div>

  <div class="card" id="config-card">
    <h2>Scan Configuration</h2>
    <div class="config-grid" id="config-grid"></div>
    <div style="margin-top:12px">
      <strong style="font-size:0.8rem;color:var(--muted)">KEYWORDS</strong>
      <div id="keywords-display" style="margin-top:6px"></div>
      <div class="kw-input-row">
        <input type="text" id="kw-input" placeholder="Add keyword..." onkeydown="if(event.key==='Enter')addKeyword()">
        <button class="btn btn-primary btn-sm" onclick="addKeyword()">Add</button>
        <button class="btn btn-success btn-sm" onclick="saveKeywords()">Save Keywords</button>
        <span id="kw-save-status" class="kw-save-status"></span>
      </div>
    </div>
    <div class="btn-row" style="margin-top:20px">
      <button class="btn btn-primary" id="btn-scan" onclick="startScan()">Start Scan</button>
      <button class="btn btn-danger hidden" id="btn-stop" onclick="stopScan()">Stop</button>
    </div>
  </div>

  <div class="card hidden" id="progress-card">
    <h2>Scan Progress</h2>
    <div class="progress-outer"><div class="progress-fill" id="progress-fill" style="width:0%">0%</div></div>
    <div class="progress-text" id="progress-text">Initializing...</div>
    <div class="log-area" id="log-area"></div>
  </div>

  <div class="card hidden" id="results-card">
    <h2>Findings <span class="badge badge-blue" id="result-count">0</span></h2>
    <div class="stats-row" id="stats-row"></div>
    <div style="overflow-x:auto;margin-top:16px">
      <table class="results-table">
        <thead><tr><th>Severity</th><th>Source</th><th>Keyword</th><th>Title</th><th>URL</th></tr></thead>
        <tbody id="results-body"></tbody>
      </table>
    </div>
    <div class="empty-state" id="no-results">No findings yet. Start a scan to begin searching.</div>
  </div>

  <div class="card hidden" id="summary-card">
    <h2>AI Analysis</h2>
    <div id="ai-summaries"></div>
  </div>

  <div class="card hidden" id="report-card">
    <h2>Report</h2>
    <div class="btn-row">
      <button class="btn btn-success" onclick="generateReport()">Generate HTML Report</button>
    </div>
    <p id="report-status" style="margin-top:12px;color:var(--muted);font-size:0.85rem"></p>
  </div>

  <div class="footer">
    <button class="btn-shutdown" onclick="shutdownServer()">Shutdown Server</button>
  </div>
</div>
<script>
let config={},allResults=[],scanning=false,stopped=false;
async function loadConfig(){
  try{const r=await fetch('/api/config');config=await r.json();renderConfig()}
  catch(e){log('Failed to load config: '+e.message)}
}
function renderConfig(){
  const g=document.getElementById('config-grid');
  const engineLabel=config.searchMode==='standard'?'DDG + Breach + NVD (Direct)':'AskSage + NVD (Live)';
  g.innerHTML=[
    {l:'Days Back',v:config.daysBack},
    {l:'Sources',v:config.categories?.length||0},
    {l:'Search Engine',v:engineLabel},
    {l:'AI Model',v:config.model||'N/A'}
  ].map(i=>`<div class="config-item"><label>${i.l}</label><div class="value">${i.v}</div></div>`).join('');
  renderKeywordEditor();
}
function renderKeywordEditor(){
  const kd=document.getElementById('keywords-display');
  const kws=config.keywords||[];
  kd.innerHTML=kws.map((k,i)=>`<span class="kw-tag">${esc(k)}<button class="kw-del" onclick="removeKeyword(${i})" title="Remove">&times;</button></span>`).join('');
}
function addKeyword(){
  const inp=document.getElementById('kw-input');
  const v=inp.value.trim();
  if(!v)return;
  if(!config.keywords)config.keywords=[];
  if(!config.keywords.includes(v)){config.keywords.push(v);renderKeywordEditor()}
  inp.value='';inp.focus();
  document.getElementById('kw-save-status').textContent='(unsaved changes)';
  document.getElementById('kw-save-status').style.color='var(--warn)';
}
function removeKeyword(idx){
  if(!config.keywords)return;
  config.keywords.splice(idx,1);
  renderKeywordEditor();
  document.getElementById('kw-save-status').textContent='(unsaved changes)';
  document.getElementById('kw-save-status').style.color='var(--warn)';
}
async function saveKeywords(){
  const st=document.getElementById('kw-save-status');
  st.textContent='Saving...';st.style.color='var(--muted)';
  try{
    const r=await fetch('/api/keywords',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({keywords:config.keywords||[]})});
    const res=await r.json();
    if(res.saved){st.textContent='Saved!';st.style.color='var(--success)';config.keywords=res.keywords}
    else{st.textContent='Error: '+(res.error||'unknown');st.style.color='var(--danger)'}
  }catch(e){st.textContent='Error: '+e.message;st.style.color='var(--danger)'}
  setTimeout(()=>{st.textContent=''},3000);
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function log(msg){
  const la=document.getElementById('log-area');
  const t=new Date().toLocaleTimeString();
  la.innerHTML+=`<div>[${t}] ${esc(msg)}</div>`;
  la.scrollTop=la.scrollHeight;
}
function show(id){document.getElementById(id).classList.remove('hidden')}
function hide(id){document.getElementById(id).classList.add('hidden')}
function updateProgress(done,total,text){
  const pct=total>0?Math.round((done/total)*100):0;
  const pf=document.getElementById('progress-fill');
  pf.style.width=pct+'%';pf.textContent=pct+'%';
  document.getElementById('progress-text').textContent=text;
}
function renderResults(){
  const tb=document.getElementById('results-body');
  const nr=document.getElementById('no-results');
  document.getElementById('result-count').textContent=allResults.length;
  if(allResults.length===0){nr.style.display='block';tb.innerHTML='';return}
  nr.style.display='none';
  tb.innerHTML=allResults.map(r=>{
    const sc=r.Severity.toLowerCase();
    return`<tr><td><span class="sev sev-${sc}">${esc(r.Severity)}</span></td><td>${esc(r.Source)}</td><td>${esc(r.Keyword)}</td><td>${esc(r.Title)}</td><td><a href="${esc(r.Url)}" target="_blank" rel="noopener">${esc(r.Url)}</a></td></tr>`;
  }).join('');
  const sev={Critical:0,High:0,Medium:0,Review:0};
  allResults.forEach(r=>{sev[r.Severity]=(sev[r.Severity]||0)+1});
  document.getElementById('stats-row').innerHTML=Object.entries(sev).filter(([,v])=>v>0).map(([k,v])=>`<div class="stat"><div class="num">${v}</div><div class="lbl">${k}</div></div>`).join('');
}
function renderMarkdown(md){
  if(!md)return'';
  return md.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/^### (.+)$/gm,'<h4>$1</h4>')
    .replace(/^## (.+)$/gm,'<h3>$1</h3>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,'<em>$1</em>')
    .replace(/^- (.+)$/gm,'<li>$1</li>')
    .replace(/(<li>.*<\/li>)/gs,'<ul>$1</ul>')
    .replace(/(https?:\/\/[^\s<]+)/g,'<a href="$1" target="_blank">$1</a>')
    .replace(/\n/g,'<br>');
}
async function startScan(){
  if(scanning)return;scanning=true;stopped=false;
  allResults=[];
  document.getElementById('btn-scan').disabled=true;
  show('btn-stop');show('progress-card');show('results-card');
  document.getElementById('log-area').innerHTML='';
  document.getElementById('ai-summaries').innerHTML='';
  hide('summary-card');hide('report-card');
  renderResults();
  const cats=config.categories||[];
  const kws=config.keywords||[];
  const total=kws.length*cats.length;
  let done=0;
  const modeLabel=config.searchMode==='standard'?'Standard (DDG+Breach+NVD)':'AskSage+NVD';
  log('Starting scan ['+modeLabel+']: '+kws.length+' keywords x '+cats.length+' sources = '+total+' searches');
  for(const kw of kws){
    if(stopped)break;
    for(const cat of cats){
      if(stopped)break;
      updateProgress(done,total,`Searching ${cat.Label} for "${kw}"...`);
      log(`Searching ${cat.Label} for "${kw}"...`);
      try{
        const r=await fetch('/api/search',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({keyword:kw,categoryId:cat.Id})});
        if(!r.ok){log('Search error: HTTP '+r.status);done++;continue}
        const res=await r.json();
        if(res&&res.length>0){allResults.push(...res);log(`  Found ${res.length} result(s)`);renderResults()}
        else{log('  No results')}
      }catch(e){log('  Error: '+e.message)}
      done++;
    }
  }
  if(!stopped){
    updateProgress(total,total,'Search complete. Running AI analysis...');
    log('Running AI analysis for each keyword...');
    show('summary-card');
    for(const kw of kws){
      if(stopped)break;
      log(`Analyzing "${kw}"...`);
      try{
        const r=await fetch('/api/summarize',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({keyword:kw})});
        const s=await r.json();
        if(s&&s.Message){
          const d=document.createElement('div');d.className='ai-summary';
          d.innerHTML=`<h3>${esc(kw)}</h3><div>${renderMarkdown(s.Message)}</div>`;
          document.getElementById('ai-summaries').appendChild(d);
          if(s.References&&s.References.length>0){
            s.References.forEach(ref=>{
              const url=typeof ref==='string'?ref:(ref.url||ref.source||'');
              if(url&&url.match(/^https?:\/\//)){
                allResults.push({Source:'GenAI-Live',Keyword:kw,Title:ref.title||'AI reference',Url:url,Snippet:'Found by AI analysis',Severity:'Review'});
              }
            });
            renderResults();
          }
          log(`  Analysis complete for "${kw}"`);
        }
      }catch(e){log('  Analysis error: '+e.message)}
    }
    updateProgress(total,total,'Scan complete!');
    log('Scan complete. '+allResults.length+' total findings.');
    show('report-card');
  }else{
    updateProgress(done,total,'Scan stopped by user.');
    log('Scan stopped.');
    if(allResults.length>0)show('report-card');
  }
  scanning=false;
  document.getElementById('btn-scan').disabled=false;
  hide('btn-stop');
}
function stopScan(){stopped=true;log('Stopping scan...')}
async function generateReport(){
  const rs=document.getElementById('report-status');
  rs.textContent='Generating report...';
  try{
    const r=await fetch('/api/report',{method:'POST'});
    const res=await r.json();
    if(res.path){
      rs.innerHTML='Report saved: <strong>'+esc(res.path)+'</strong><br><span style="color:var(--muted)">Server will shut down in 5 seconds...</span>';
      setTimeout(async()=>{try{await fetch('/api/stop',{method:'POST'})}catch(e){}},5000);
    }
    else{rs.textContent='Report generation failed'}
  }catch(e){rs.textContent='Error: '+e.message}
}
async function shutdownServer(){
  if(!confirm('Shut down the Look4Gold13 server?'))return;
  try{await fetch('/api/stop',{method:'POST'})}catch(e){}
  document.body.innerHTML='<div style="text-align:center;padding:80px;color:#94a3b8;font-family:system-ui"><h2>Server stopped</h2><p>You can close this tab.</p></div>';
}
loadConfig();
</script>
</body>
</html>
'@
}

function Start-AU13WebServer {
    param(
        [hashtable]$Config,
        [hashtable]$SourcesConfig,
        [string[]]$Keywords,
        [int]$DaysBack,
        [string]$OutputFile,
        [string]$KeywordFilePath,
        [string]$SearchMode = 'asksage',
        [string]$ProxyBase = ''
    )

    # Find an available port
    $tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $tcpListener.Start()
    $port = $tcpListener.LocalEndpoint.Port
    $tcpListener.Stop()

    $prefix = "http://localhost:$port/"
    $httpListener = New-Object System.Net.HttpListener
    $httpListener.Prefixes.Add($prefix)
    $httpListener.Start()

    $modeLabel = if ($SearchMode -eq 'standard') { 'Standard (DDG + Breach + NVD)' } else { 'AskSage + NVD' }
    Write-Host ""
    Write-Host "  Look4Gold13 Web UI running at: $prefix" -ForegroundColor Green
    Write-Host "  Search mode: $modeLabel" -ForegroundColor Green
    Write-Host "  Press Ctrl+C to stop the server." -ForegroundColor Gray
    Write-Host ""

    # Open default browser
    Start-Process $prefix

    $allResults = [System.Collections.ArrayList]::new()
    $aiSummaries = @{}

    # --- Search mode setup ---
    if ($SearchMode -eq 'standard') {
        $categories = @(
            @{ Id = 'duckduckgo'; Label = 'DuckDuckGo'; Description = 'Web search via DuckDuckGo' },
            @{ Id = 'breach'; Label = 'Breach Sources'; Description = 'Breach/leak data search' }
        )
        $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $captchaState = @{ HitCount = 0; CurrentDelay = $Config.search.delaySeconds; Blocked = $false }
    } else {
        $categories = Get-AskSageSearchCategories
    }
    # NVD available in all modes
    $categories += @{ Id = 'nvd'; Label = 'NIST NVD CVEs'; Description = 'NIST National Vulnerability Database' }

    try {
        while ($httpListener.IsListening) {
            $context = $httpListener.GetContext()
            $request = $context.Request
            $response = $context.Response

            $path = $request.Url.LocalPath
            $method = $request.HttpMethod

            try {
                switch -Regex ("$method $path") {
                    '^GET /$' {
                        $html = Get-WebUIHtml
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                        $response.ContentType = 'text/html; charset=utf-8'
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    }
                    '^GET /api/config$' {
                        $json = @{
                            keywords   = $Keywords
                            daysBack   = $DaysBack
                            categories = $categories
                            model      = $Config.genai.model
                            searchMode = $SearchMode
                        } | ConvertTo-Json -Depth 4
                        Send-WebResponse -Response $response -Json $json
                    }
                    '^POST /api/search$' {
                        $bodyText = Read-WebRequestBody -Request $request
                        $params = $bodyText | ConvertFrom-Json
                        $results = @()

                        if ($params.categoryId -eq 'nvd') {
                            # NVD CVE search (works in all modes, always direct)
                            $nvdApiKey = Get-EnvVar 'NVD_API_KEY'
                            $results = Search-NvdCve -Keywords @($params.keyword) -DaysBack $DaysBack -ApiKey $(if ($nvdApiKey) { $nvdApiKey } else { '' })
                        }
                        elseif ($SearchMode -eq 'standard') {
                            # Standard DDG/Breach web scraping
                            if ($params.categoryId -eq 'duckduckgo') {
                                $results = Search-DuckDuckGo -Keywords @($params.keyword) -DaysBack $DaysBack -DelaySeconds $Config.search.delaySeconds -ProxyBase $ProxyBase -CaptchaState ([ref]$captchaState) -Dorks $SourcesConfig.ddgDorks -WebSession $webSession
                            }
                            elseif ($params.categoryId -eq 'breach') {
                                $results = Search-BreachInfo -Keywords @($params.keyword) -DaysBack $DaysBack -DelaySeconds $Config.search.delaySeconds -ProxyBase $ProxyBase -CaptchaState ([ref]$captchaState) -BreachDorks $SourcesConfig.breachDorks -WebSession $webSession
                            }
                        }
                        else {
                            # AskSage mode
                            $cat = $categories | Where-Object { $_.Id -eq $params.categoryId } | Select-Object -First 1
                            if ($cat) {
                                $results = Invoke-AskSageSearch -Keyword $params.keyword -Category $cat -GenAIConfig $Config.genai -DaysBack $DaysBack
                            }
                        }

                        foreach ($r in $results) { [void]$allResults.Add($r) }
                        $resultsJson = @($results) | ForEach-Object {
                            @{
                                Source   = $_.Source
                                Keyword  = $_.Keyword
                                Title    = $_.Title
                                Url      = $_.Url
                                Snippet  = $_.Snippet
                                Severity = $_.Severity
                            }
                        }
                        Send-WebResponse -Response $response -Json (ConvertTo-Json @($resultsJson) -Depth 3)
                    }
                    '^POST /api/summarize$' {
                        $bodyText = Read-WebRequestBody -Request $request
                        $params = $bodyText | ConvertFrom-Json
                        $kwResults = @($allResults | Where-Object { $_.Keyword -eq $params.keyword })
                        $summary = Invoke-GenAISummary -Keyword $params.keyword -Results $kwResults -GenAIConfig $Config.genai
                        $aiSummaries[$params.keyword] = $summary

                        # Add references as results
                        if ($summary -is [hashtable] -and $summary.References -and $summary.References.Count -gt 0) {
                            foreach ($ref in $summary.References) {
                                $refUrl = ''
                                $refTitle = 'AI-discovered source'
                                if ($ref -is [string] -and $ref -match '^https?://') { $refUrl = $ref }
                                elseif ($ref.url) { $refUrl = $ref.url; if ($ref.title) { $refTitle = $ref.title } }
                                elseif ($ref.source) { $refUrl = $ref.source }
                                if ($refUrl) {
                                    [void]$allResults.Add((New-AU13Result -Source 'GenAI-Live' -Keyword $params.keyword -Title $refTitle -Url $refUrl -Snippet "Found by AI analysis" -Severity 'Review'))
                                }
                            }
                        }

                        $summaryJson = @{
                            Message    = $summary.Message
                            References = @($summary.References)
                        } | ConvertTo-Json -Depth 3
                        Send-WebResponse -Response $response -Json $summaryJson
                    }
                    '^POST /api/report$' {
                        $reportSources = if ($SearchMode -eq 'standard') { @('DuckDuckGo','Breach','NVD') } else { @('AskSage','NVD') }
                        $reportPath = Export-AU13Html -Results @($allResults) -OutputPath $OutputFile -Keywords $Keywords -DaysBack $DaysBack -Sources $reportSources -AISummaries $aiSummaries
                        Send-WebResponse -Response $response -Json (@{ path = $reportPath } | ConvertTo-Json)
                    }
                    '^POST /api/keywords$' {
                        $bodyText = Read-WebRequestBody -Request $request
                        $params = $bodyText | ConvertFrom-Json
                        $newKeywords = @($params.keywords | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() })
                        if ($newKeywords.Count -eq 0) {
                            Send-WebResponse -Response $response -Json '{"error":"No valid keywords provided"}'
                        } else {
                            $newKeywords | Set-Content -Path $KeywordFilePath -Encoding UTF8
                            $Keywords = $newKeywords
                            Send-WebResponse -Response $response -Json (ConvertTo-Json @{ keywords = $newKeywords; saved = $true })
                        }
                    }
                    '^POST /api/stop$' {
                        Send-WebResponse -Response $response -Json '{"status":"stopped"}'
                        $response.Close()
                        $httpListener.Stop()
                        return
                    }
                    default {
                        $response.StatusCode = 404
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes('{"error":"Not found"}')
                        $response.ContentType = 'application/json'
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    }
                }
            }
            catch {
                Write-Warning "[WebUI] Request error: $($_.Exception.Message)"
                try {
                    $errJson = @{ error = $_.Exception.Message } | ConvertTo-Json
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($errJson)
                    $response.StatusCode = 500
                    $response.ContentType = 'application/json'
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                } catch {}
            }
            finally {
                try { $response.Close() } catch {}
            }
        }
    }
    finally {
        try { $httpListener.Close() } catch {}
        Write-Host "[WebUI] Server stopped." -ForegroundColor Yellow
    }
}

function Send-WebResponse {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [string]$Json
    )
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($Json)
    $Response.ContentType = 'application/json; charset=utf-8'
    $Response.ContentLength64 = $buffer.Length
    $Response.Headers.Add('Cache-Control', 'no-cache')
    $Response.OutputStream.Write($buffer, 0, $buffer.Length)
}

function Read-WebRequestBody {
    param([System.Net.HttpListenerRequest]$Request)
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    $body = $reader.ReadToEnd()
    $reader.Close()
    return $body
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

            # Extract clean display URL (domain + path, no query string noise)
            $displayUrl = try {
                $uri = [System.Uri]$r.Url
                $path = if ($uri.AbsolutePath -and $uri.AbsolutePath -ne '/') { $uri.AbsolutePath } else { '' }
                if ($path.Length -gt 60) { $path = $path.Substring(0, 57) + '...' }
                [System.Web.HttpUtility]::HtmlEncode("$($uri.Host)$path")
            } catch { $url }

            # Build snippet: show DDG search link if available
            $snip = ""
            if ($r.Snippet -match '^DDG search: (.+)$') {
                $searchUrl = [System.Web.HttpUtility]::HtmlEncode($Matches[1])
                $snip = "<a href=`"$searchUrl`" target=`"_blank`" class=`"ddg-link`">View DDG search</a>"
            }
            elseif ($r.Snippet) {
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

            # Use title as link text; fall back to domain if title looks like a URL
            $linkText = if ($title -match '^https?://') { $displayUrl } else { $title }

            if ($url) {
                $listItems += @"
            <li>
                <div class="result-header"><a href="$url" target="_blank">$linkText</a> <span class="severity-badge" style="background:$sevColor;">$sev</span></div>
                <div class="result-meta"><span class="result-source">$src</span> <span class="result-url">$displayUrl</span></div>
                $(if ($snip) { "<div class=`"result-snippet`">$snip</div>" })
            </li>

"@
            }
            else {
                $listItems += @"
            <li>
                <div class="result-header">$linkText <span class="severity-badge" style="background:$sevColor;">$sev</span></div>
                <div class="result-meta"><span class="result-source">$src</span></div>
                $(if ($snip) { "<div class=`"result-snippet`">$snip</div>" })
            </li>

"@
            }
        }

        # AI Summary block for this keyword
        $aiBlock = ""
        if ($AISummaries.ContainsKey($kwName)) {
            $aiData = $AISummaries[$kwName]

            if ($aiData -is [hashtable]) {
                $aiText = ConvertFrom-Markdown $aiData.Message

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
                $aiText = ConvertFrom-Markdown $aiData
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
$aiBlock
$resultSection
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
        .query-block li { padding: 10px 0; border-bottom: 1px solid #eee; }
        .query-block li:last-child { border-bottom: none; }
        .query-block a { color: #0d6efd; text-decoration: none; }
        .query-block a:hover { text-decoration: underline; }
        .result-header { font-size: 1em; }
        .result-header a { font-weight: 500; }
        .result-meta { font-size: 0.82em; color: #666; margin-top: 2px; }
        .result-source { color: #555; font-weight: 500; }
        .result-url { color: #0a7; }
        .result-snippet { font-size: 0.82em; color: #777; margin-top: 2px; }
        .ddg-link { font-size: 0.82em; color: #888; }
        .ddg-link:hover { color: #0d6efd; }
        .ai-summary { background: #f0f4ff; border-left: 4px solid #4a6cf7; padding: 12px 16px; margin-top: 12px; border-radius: 0 4px 4px 0; }
        .ai-summary h3 { margin: 0 0 8px 0; color: #4a6cf7; font-size: 0.95em; }
        .ai-content { font-size: 0.9em; line-height: 1.6; color: #444; }
        .ai-content h3, .ai-content h4, .ai-content h5, .ai-content h6 { color: #1a1a2e; margin: 14px 0 6px 0; }
        .ai-content h3 { font-size: 1.05em; } .ai-content h4 { font-size: 0.95em; } .ai-content h5 { font-size: 0.9em; } .ai-content h6 { font-size: 0.85em; }
        .ai-content p { margin: 6px 0; }
        .ai-content ul { padding-left: 22px; margin: 6px 0; }
        .ai-content li { padding: 2px 0; }
        .ai-content code { background: #e8ecf1; padding: 1px 5px; border-radius: 3px; font-size: 0.9em; }
        .ai-content pre { background: #1e1e2e; color: #cdd6f4; padding: 12px 16px; border-radius: 4px; overflow-x: auto; margin: 8px 0; }
        .ai-content pre code { background: none; padding: 0; color: inherit; }
        .ai-content strong { color: #333; }
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

# --- Load search sources ---
$sourcesConfig = Import-AU13Sources

# --- Resolve GenAI Token ---
$genaiToken = Get-EnvVar $config.genai.tokenEnvVar
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
    $userInput = Read-Host "Are you on a government computer that uses Menlo Security? (y/N)"
    if ($userInput -match '^[Yy]') {
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

# --- Resolve keyword file path (needed by all modes) ---
if (-not $KeywordFile) { $KeywordFile = Join-Path $PSScriptRoot "config/keywords.txt" }

# --- Default to Web UI mode when GenAI token is available ---
if (-not $Silent -and -not $WebUI) {
    $genaiToken = Get-EnvVar $config.genai.tokenEnvVar
    if ($genaiToken) {
        $WebUI = $true
    }
}

# --- Resolve remaining parameters ---
if ($Silent) {
    if (-not $DaysBack)    { $DaysBack = $config.search.daysBack }
    if (-not $Sources)     { $Sources = $config.search.sources }
}
elseif ($WebUI) {
    # Web UI mode — use defaults, skip interactive prompts
    if (-not $DaysBack)    { $DaysBack = $config.search.daysBack }
    if (-not $Sources)     { $Sources = $config.search.sources }
    if (-not $OutputFile) {
        $OutputFile = Join-Path (Join-Path $PSScriptRoot "Output") "AU13_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    }
}
else {
    # Interactive CLI mode
    if (-not $DaysBack) {
        $userInput = Read-Host "Days back to search [$($config.search.daysBack)]"
        $DaysBack = if ($userInput) { [int]$userInput } else { $config.search.daysBack }
    }

    if (-not $Sources) {
        Write-Host "Available sources: DuckDuckGo, Breach" -ForegroundColor Gray
        $userInput = Read-Host "Sources to scan (comma-separated) [All]"
        $Sources = if ($userInput) {
            $userInput -split ',' | ForEach-Object { $_.Trim() }
        }
        else {
            $config.search.sources
        }
    }

    if (-not $OutputFile) {
        $defaultOut = Join-Path (Join-Path $PSScriptRoot "Output") "AU13_Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $userInput = Read-Host "Output file path [$defaultOut]"
        $OutputFile = if ($userInput) { $userInput } else { $defaultOut }
    }
}

# --- Load keywords ---
$keywords = Import-AU13Keywords -Path $KeywordFile

if (-not $keywords -or $keywords.Count -eq 0) {
    Write-Error "No keywords loaded. Create a config/keywords.txt file with your monitoring terms."
    Write-Host "  Hint: Copy config/keywords.example.txt to config/keywords.txt and add your keywords." -ForegroundColor Yellow
    exit 1
}

Write-Host "Scan Configuration:" -ForegroundColor White
Write-Host "  Keywords:  $($keywords.Count) loaded" -ForegroundColor Gray
Write-Host "  Days Back: $DaysBack" -ForegroundColor Gray
Write-Host "  Sources:   $($Sources -join ', ')" -ForegroundColor Gray
Write-Host "  Proxy:     $(if ($proxyBase) { $proxyBase } else { 'Direct (no proxy)' })" -ForegroundColor Gray
$genaiStatus = if (Get-EnvVar $config.genai.tokenEnvVar) {
    $apiName = if ($config.genai.apiType -eq 'openai-compatible') { "$($config.genai.model)" } else { "Ask Sage ($($config.genai.model))" }
    "Enabled - $apiName"
} else { 'Disabled (no token)' }
Write-Host "  GenAI:     $genaiStatus" -ForegroundColor Gray
Write-Host "  Mode:      $(if ($WebUI) { 'Web UI' } else { 'CLI' })" -ForegroundColor Gray
Write-Host ""

# ============================================================================
# WEB UI MODE — launches browser-based dashboard
# ============================================================================
if ($WebUI) {
    # Determine search mode: proxy = AskSage (gov network), no proxy = standard DDG/Breach
    $webSearchMode = if ($proxyBase) { 'asksage' } else { 'standard' }

    if ($webSearchMode -eq 'asksage') {
        $genaiToken = Get-EnvVar $config.genai.tokenEnvVar
        if (-not $genaiToken) {
            Write-Error "Web UI on government network requires a GenAI API token. Set `$env:$($config.genai.tokenEnvVar) or run in interactive mode first."
            exit 1
        }
    }

    $searchModeLabel = if ($webSearchMode -eq 'asksage') { 'AskSage (gov network via Menlo proxy)' } else { 'Standard (DDG + Breach + NVD direct)' }
    Write-Host "Launching Web UI... [Search: $searchModeLabel]" -ForegroundColor Cyan
    Start-AU13WebServer -Config $config -SourcesConfig $sourcesConfig -Keywords $keywords -DaysBack $DaysBack -OutputFile $OutputFile -KeywordFilePath $KeywordFile -SearchMode $webSearchMode -ProxyBase $proxyBase
    exit 0
}

# ============================================================================
# CLI MODE — traditional command-line scan
# ============================================================================

$allResults = @()

# If on government network (proxy), use AskSage for searching instead of DDG
$useAskSageSearch = $false
if ($proxyBase) {
    $genaiToken = Get-EnvVar $config.genai.tokenEnvVar
    if ($genaiToken) {
        $useAskSageSearch = $true
        Write-Host "[Gov Network] Web scraping unavailable through Menlo Security." -ForegroundColor Yellow
        Write-Host "[Gov Network] Using AskSage API for web searches instead." -ForegroundColor Green
        Write-Host ""
    }
}

if ($useAskSageSearch) {
    # --- AskSage-powered search (government network) ---
    Write-Host "=== Scanning via AskSage Live Search... ===" -ForegroundColor White
    $askSageResults = Search-WithAskSage -Keywords $keywords -DaysBack $DaysBack -GenAIConfig $config.genai
    $allResults += $askSageResults
    Write-Host ""
} else {
    # --- Traditional DDG/Breach scraping (home/direct network) ---

    # Shared CAPTCHA state across all DDG-based searches
    $captchaState = @{ HitCount = 0; CurrentDelay = $config.search.delaySeconds; Blocked = $false }

    # Shared web session — persists cookies across all searches
    $webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    # Warm up session through Menlo proxy to pre-establish cookies before search queries
    if ($proxyBase) {
    Write-Host "[Menlo] Warming up session through proxy..." -ForegroundColor Gray
    try {
        $warmupUrl = Get-ProxiedUrl -Url "https://html.duckduckgo.com/html/" -ProxyBase $proxyBase
        $warmupParams = @{
            Uri             = $warmupUrl
            UseBasicParsing = $true
            TimeoutSec      = 15
            ErrorAction     = 'Stop'
            WebSession      = $webSession
            Headers         = @{
                'User-Agent'                = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
                'Accept'                    = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
                'Accept-Language'           = 'en-US,en;q=0.9'
                'Accept-Encoding'           = 'gzip, deflate'
                'Sec-CH-UA'                 = '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"'
                'Sec-CH-UA-Mobile'          = '?0'
                'Sec-CH-UA-Platform'        = '"Windows"'
                'Sec-Fetch-Dest'            = 'document'
                'Sec-Fetch-Mode'            = 'navigate'
                'Sec-Fetch-Site'            = 'none'
                'Sec-Fetch-User'            = '?1'
                'Upgrade-Insecure-Requests' = '1'
                'DNT'                       = '1'
            }
        }
        $warmupResponse = Invoke-WebRequest @warmupParams
        if (Test-MenloInterstitial -Html $warmupResponse.Content) {
            Write-Host "[Menlo] Interstitial received on warmup - cookies captured, retrying..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            $warmupResponse = Invoke-WebRequest @warmupParams
            if (Test-MenloInterstitial -Html $warmupResponse.Content) {
                Write-Host "[Menlo] Interstitial persists - will use per-request fallback to direct." -ForegroundColor Yellow
            } else {
                Write-Host "[Menlo] Session established through proxy." -ForegroundColor Green
            }
        } else {
            Write-Host "[Menlo] Session established through proxy." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[Menlo] Warmup failed: $($_.Exception.Message). Continuing..." -ForegroundColor Yellow
    }
    Start-Sleep -Seconds 2
}

# --- DuckDuckGo ---
if ('DuckDuckGo' -in $Sources) {
    Write-Host "=== Scanning DuckDuckGo... ===" -ForegroundColor White
    $ddgResults = Search-DuckDuckGo -Keywords $keywords -DaysBack $DaysBack -DelaySeconds $config.search.delaySeconds -ProxyBase $proxyBase -CaptchaState ([ref]$captchaState) -Dorks $sourcesConfig.ddgDorks -WebSession $webSession
    $allResults += $ddgResults
    Write-Host ""
}

# --- Breach Info ---
if ('Breach' -in $Sources) {
    Write-Host "=== Scanning Breach Sources... ===" -ForegroundColor White
    $breachResults = Search-BreachInfo -Keywords $keywords -DaysBack $DaysBack -DelaySeconds $config.search.delaySeconds -ProxyBase $proxyBase -CaptchaState ([ref]$captchaState) -BreachDorks $sourcesConfig.breachDorks -WebSession $webSession
    $allResults += $breachResults
    Write-Host ""
}

} # end else (traditional DDG/Breach scraping)

# --- NVD CVE Search (works on all networks, always direct) ---
Write-Host "=== Searching NIST NVD for CVEs... ===" -ForegroundColor White
$nvdApiKey = Get-EnvVar 'NVD_API_KEY'
$nvdResults = Search-NvdCve -Keywords $keywords -DaysBack $DaysBack -ApiKey $(if ($nvdApiKey) { $nvdApiKey } else { '' })
$allResults += $nvdResults
Write-Host ""

# --- Cross-source deduplication (keep highest severity per keyword+URL) ---
$sevRank = @{ 'Critical' = 4; 'High' = 3; 'Medium' = 2; 'Review' = 1; 'Manual-Review' = 0 }
$dedupMap = @{}
foreach ($r in $allResults) {
    $key = "$($r.Keyword)|$($r.Url)"
    if ($dedupMap.ContainsKey($key)) {
        $existingRank = $sevRank[$dedupMap[$key].Severity]
        $newRank = $sevRank[$r.Severity]
        if ($newRank -gt $existingRank) { $dedupMap[$key] = $r }
    } else {
        $dedupMap[$key] = $r
    }
}
$dupeCount = $allResults.Count - $dedupMap.Count
$allResults = @($dedupMap.Values)
if ($dupeCount -gt 0) {
    Write-Host "[Dedup] Removed $dupeCount duplicate results across sources" -ForegroundColor Gray
}

# --- Summary ---
Write-Host "=== Scan Complete ===" -ForegroundColor Green
Write-Host ""

if ($allResults.Count -eq 0) {
    Write-Host "No results found from web scans. GenAI will search independently." -ForegroundColor Yellow
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
$genaiTokenCheck = Get-EnvVar $config.genai.tokenEnvVar
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
Export-AU13Html -Results $allResults -OutputPath $OutputFile -Keywords $keywords -DaysBack $DaysBack -Sources $Sources -AISummaries $aiSummaries | Out-Null

