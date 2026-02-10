function Search-GoogleDorks {
    <#
    .SYNOPSIS
        Searches Google using dork queries for each keyword.
    .DESCRIPTION
        Constructs Google Custom Search API queries to find public exposure
        of keywords. Requires a free Google Custom Search API key and
        Search Engine ID (cx) for automated results. Without API creds,
        generates dork URLs for manual browser use.
    .PARAMETER Keywords
        Array of keywords to search for.
    .PARAMETER DaysBack
        Number of days back to restrict results.
    .PARAMETER ApiKey
        Google Custom Search API key (free tier: 100 queries/day).
    .PARAMETER SearchEngineId
        Google Custom Search Engine ID (cx).
    .PARAMETER DorkTemplates
        Custom dork templates. Use {keyword} as placeholder.
    .EXAMPLE
        Search-GoogleDorks -Keywords @("acme","secret-project") -DaysBack 30
    .EXAMPLE
        Search-GoogleDorks -Keywords $kw -ApiKey $key -SearchEngineId $cx -DaysBack 7
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [Parameter()]
        [int]$DaysBack = 30,

        [Parameter()]
        [string]$ApiKey,

        [Parameter()]
        [string]$SearchEngineId,

        [Parameter()]
        [string[]]$DorkTemplates
    )

    $results = @()

    # Default dork templates targeting common disclosure sites
    if (-not $DorkTemplates) {
        $DorkTemplates = @(
            '"{keyword}"',
            '"{keyword}" site:pastebin.com',
            '"{keyword}" site:github.com',
            '"{keyword}" site:trello.com',
            '"{keyword}" site:paste.ee',
            '"{keyword}" site:dpaste.org',
            '"{keyword}" site:rentry.co',
            '"{keyword}" site:justpaste.it',
            '"{keyword}" site:controlc.com',
            '"{keyword}" site:privatebin.net',
            '"{keyword}" filetype:pdf',
            '"{keyword}" filetype:xlsx',
            '"{keyword}" filetype:csv',
            '"{keyword}" filetype:doc',
            '"{keyword}" filetype:conf',
            '"{keyword}" filetype:log',
            '"{keyword}" filetype:sql',
            '"{keyword}" filetype:env'
        )
    }

    $dateRestrict = Get-DateFilter -DaysBack $DaysBack -Format 'Google'

    if ($ApiKey -and $SearchEngineId) {
        # Automated mode using Google Custom Search JSON API
        Write-Host "[Google] Running automated API search..." -ForegroundColor Cyan

        foreach ($keyword in $Keywords) {
            foreach ($template in $DorkTemplates) {
                $query = $template -replace '\{keyword\}', $keyword
                $encodedQuery = [System.Uri]::EscapeDataString($query)
                $uri = "https://www.googleapis.com/customsearch/v1?key=$ApiKey&cx=$SearchEngineId&q=$encodedQuery&dateRestrict=$dateRestrict&num=10"

                try {
                    $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop

                    if ($response.items) {
                        foreach ($item in $response.items) {
                            $results += New-AU13Result `
                                -Source 'Google' `
                                -Keyword $keyword `
                                -Title $item.title `
                                -Url $item.link `
                                -Snippet $item.snippet `
                                -Severity 'Review'
                        }
                    }

                    # Respect rate limits
                    Start-Sleep -Milliseconds 500
                }
                catch {
                    Write-Warning "[Google] API error for query '$query': $($_.Exception.Message)"
                }
            }
        }
    }
    else {
        # Manual mode - fetch dork URLs and check for results
        Write-Host "[Google] No API key configured. Checking dork URLs directly..." -ForegroundColor Yellow
        Write-Host "[Google] Tip: Get a free API key at https://developers.google.com/custom-search/v1/introduction" -ForegroundColor Yellow

        foreach ($keyword in $Keywords) {
            Write-Host "[Google] Checking dorks for '$keyword'..." -ForegroundColor Gray
            foreach ($template in $DorkTemplates) {
                $query = $template -replace '\{keyword\}', $keyword
                $encodedQuery = [System.Uri]::EscapeDataString($query)
                $dorkUrl = "https://www.google.com/search?q=$encodedQuery&tbs=qdr:d$DaysBack"

                try {
                    $webResponse = Invoke-WebRequest -Uri $dorkUrl -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop -Headers @{
                        'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                    }
                    $html = $webResponse.Content

                    if ($html -match 'did not match any documents' -or $html -match 'No results found') {
                        Write-Host "  [No Results] $query" -ForegroundColor DarkGray
                    }
                    else {
                        Write-Host "  [Results Found] $query" -ForegroundColor Green
                        $results += New-AU13Result `
                            -Source 'Google-Dork' `
                            -Keyword $keyword `
                            -Title "Dork Hit: $query" `
                            -Url $dorkUrl `
                            -Snippet "Google returned results for this dork query - review in browser" `
                            -Severity 'Review'
                    }
                }
                catch {
                    Write-Host "  [Error] $query - $($_.Exception.Message)" -ForegroundColor DarkYellow
                }

                # Delay between requests to avoid rate limiting
                Start-Sleep -Seconds 2
            }
        }
    }

    Write-Host "[Google] Found $($results.Count) results/dorks" -ForegroundColor Cyan
    return $results
}
