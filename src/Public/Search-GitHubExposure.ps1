function Search-GitHubExposure {
    <#
    .SYNOPSIS
        Searches GitHub for public exposure of keywords.
    .DESCRIPTION
        Uses the GitHub Search API (code and issues) to find public
        repositories, code, commits, and issues containing keywords.
        Works unauthenticated (10 req/min) or with a token (30 req/min).
    .PARAMETER Keywords
        Array of keywords to search for.
    .PARAMETER DaysBack
        Number of days back to filter results.
    .PARAMETER GitHubToken
        Optional GitHub personal access token for higher rate limits.
    .EXAMPLE
        Search-GitHubExposure -Keywords @("acme-internal") -DaysBack 14
    .EXAMPLE
        Search-GitHubExposure -Keywords $kw -GitHubToken $env:GITHUB_TOKEN -DaysBack 7
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [Parameter()]
        [int]$DaysBack = 30,

        [Parameter()]
        [string]$GitHubToken
    )

    $results = @()
    $dateFilter = Get-DateFilter -DaysBack $DaysBack -Format 'GitHub'

    $headers = @{
        'Accept'     = 'application/vnd.github.v3+json'
        'User-Agent' = 'Look4Gold13-AU13-Scanner'
    }
    if ($GitHubToken) {
        $headers['Authorization'] = "token $GitHubToken"
    }

    foreach ($keyword in $Keywords) {
        $encodedKeyword = [System.Uri]::EscapeDataString("`"$keyword`"")

        # --- Code search ---
        try {
            $codeUri = "https://api.github.com/search/code?q=$encodedKeyword&sort=indexed&order=desc&per_page=20"
            Write-Verbose "[GitHub] Code search for '$keyword'..."

            $codeResponse = Invoke-RestMethod -Uri $codeUri -Headers $headers -Method Get -TimeoutSec 20 -ErrorAction Stop

            if ($codeResponse.items) {
                foreach ($item in $codeResponse.items) {
                    $results += New-AU13Result `
                        -Source 'GitHub-Code' `
                        -Keyword $keyword `
                        -Title "$($item.repository.full_name) - $($item.name)" `
                        -Url $item.html_url `
                        -Snippet "File: $($item.path) in repo $($item.repository.full_name)" `
                        -Severity 'High'
                }
            }

            Write-Verbose "[GitHub] Code search returned $($codeResponse.total_count) total results"
        }
        catch {
            if ($_.Exception.Message -match '403') {
                Write-Warning "[GitHub] Rate limited on code search. Consider using -GitHubToken for higher limits."
            }
            else {
                Write-Warning "[GitHub] Code search error for '$keyword': $($_.Exception.Message)"
            }
        }

        # Rate limit pause
        Start-Sleep -Seconds 6

        # --- Commits search ---
        try {
            $commitUri = "https://api.github.com/search/commits?q=$encodedKeyword+committer-date:>$dateFilter&sort=committer-date&order=desc&per_page=20"
            Write-Verbose "[GitHub] Commit search for '$keyword'..."

            $commitHeaders = $headers.Clone()
            $commitHeaders['Accept'] = 'application/vnd.github.cloak-preview+json'

            $commitResponse = Invoke-RestMethod -Uri $commitUri -Headers $commitHeaders -Method Get -TimeoutSec 20 -ErrorAction Stop

            if ($commitResponse.items) {
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
        }
        catch {
            if ($_.Exception.Message -match '403') {
                Write-Warning "[GitHub] Rate limited on commit search."
            }
            else {
                Write-Warning "[GitHub] Commit search error for '$keyword': $($_.Exception.Message)"
            }
        }

        # Rate limit pause
        Start-Sleep -Seconds 6

        # --- Issues search (captures discussions, bug reports, etc.) ---
        try {
            $issueUri = "https://api.github.com/search/issues?q=$encodedKeyword+created:>$dateFilter&sort=created&order=desc&per_page=20"
            Write-Verbose "[GitHub] Issue search for '$keyword'..."

            $issueResponse = Invoke-RestMethod -Uri $issueUri -Headers $headers -Method Get -TimeoutSec 20 -ErrorAction Stop

            if ($issueResponse.items) {
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
        }
        catch {
            if ($_.Exception.Message -match '403') {
                Write-Warning "[GitHub] Rate limited on issue search."
            }
            else {
                Write-Warning "[GitHub] Issue search error for '$keyword': $($_.Exception.Message)"
            }
        }

        Start-Sleep -Seconds 6
    }

    Write-Host "[GitHub] Found $($results.Count) results" -ForegroundColor Cyan
    return $results
}
