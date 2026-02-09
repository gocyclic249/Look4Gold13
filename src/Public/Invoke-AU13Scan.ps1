function Invoke-AU13Scan {
    <#
    .SYNOPSIS
        Runs a full AU-13 compliance scan across all configured sources.
    .DESCRIPTION
        Orchestrates keyword searches across Google (dorks), paste sites,
        GitHub, and breach/security blogs. Exports results to CSV.

        Sources scanned:
        - Google Dorks (automated with API key, or generates manual URLs)
        - Paste Sites (Pastebin via psbdmp.ws + Google-indexed paste sites)
        - GitHub (code, commits, and issues via GitHub Search API)
        - Breach Info (HIBP breach database + security blog searches)
    .PARAMETER KeywordFile
        Path to the keywords file. Defaults to ./keywords.txt
    .PARAMETER DaysBack
        How many days back to search. Default 30.
    .PARAMETER OutputFile
        Path for CSV output. Auto-generated if not specified.
    .PARAMETER Sources
        Which sources to scan. Default: all. Options: Google, Paste, GitHub, Breach
    .PARAMETER GoogleApiKey
        Optional Google Custom Search API key.
    .PARAMETER GoogleSearchEngineId
        Optional Google Custom Search Engine ID.
    .PARAMETER GitHubToken
        Optional GitHub personal access token.
    .EXAMPLE
        Invoke-AU13Scan -DaysBack 30
    .EXAMPLE
        Invoke-AU13Scan -DaysBack 7 -Sources Google,GitHub
    .EXAMPLE
        Invoke-AU13Scan -DaysBack 90 -GitHubToken $env:GITHUB_TOKEN -OutputFile "./my-report.csv"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$KeywordFile,

        [Parameter()]
        [int]$DaysBack = 30,

        [Parameter()]
        [string]$OutputFile,

        [Parameter()]
        [ValidateSet('Google', 'Paste', 'GitHub', 'Breach')]
        [string[]]$Sources = @('Google', 'Paste', 'GitHub', 'Breach'),

        [Parameter()]
        [string]$GoogleApiKey,

        [Parameter()]
        [string]$GoogleSearchEngineId,

        [Parameter()]
        [string]$GitHubToken
    )

    $banner = @"

    ╔══════════════════════════════════════════════════╗
    ║     Look4Gold13 - AU-13 Compliance Scanner      ║
    ║     Monitoring for Information Disclosure        ║
    ╚══════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Yellow

    # Load keywords
    $keywords = if ($KeywordFile) {
        Import-AU13Keywords -Path $KeywordFile
    }
    else {
        Import-AU13Keywords
    }

    if (-not $keywords -or $keywords.Count -eq 0) {
        Write-Error "No keywords loaded. Create a keywords.txt file with your monitoring terms."
        Write-Host "  Hint: Copy config/keywords.example.txt to keywords.txt and add your keywords." -ForegroundColor Yellow
        return
    }

    Write-Host "Scan Configuration:" -ForegroundColor White
    Write-Host "  Keywords:  $($keywords.Count) loaded" -ForegroundColor Gray
    Write-Host "  Days Back: $DaysBack" -ForegroundColor Gray
    Write-Host "  Sources:   $($Sources -join ', ')" -ForegroundColor Gray
    Write-Host ""

    $allResults = @()

    # --- Google Dorks ---
    if ('Google' -in $Sources) {
        Write-Host "═══ Scanning Google Dorks... ═══" -ForegroundColor White
        $googleParams = @{
            Keywords = $keywords
            DaysBack = $DaysBack
        }
        if ($GoogleApiKey)        { $googleParams['ApiKey'] = $GoogleApiKey }
        if ($GoogleSearchEngineId) { $googleParams['SearchEngineId'] = $GoogleSearchEngineId }

        $googleResults = Search-GoogleDorks @googleParams
        $allResults += $googleResults
        Write-Host ""
    }

    # --- Paste Sites ---
    if ('Paste' -in $Sources) {
        Write-Host "═══ Scanning Paste Sites... ═══" -ForegroundColor White
        $pasteResults = Search-PasteSites -Keywords $keywords -DaysBack $DaysBack
        $allResults += $pasteResults
        Write-Host ""
    }

    # --- GitHub ---
    if ('GitHub' -in $Sources) {
        Write-Host "═══ Scanning GitHub... ═══" -ForegroundColor White
        $ghParams = @{
            Keywords = $keywords
            DaysBack = $DaysBack
        }
        if ($GitHubToken) { $ghParams['GitHubToken'] = $GitHubToken }

        $githubResults = Search-GitHubExposure @ghParams
        $allResults += $githubResults
        Write-Host ""
    }

    # --- Breach Info ---
    if ('Breach' -in $Sources) {
        Write-Host "═══ Scanning Breach Sources... ═══" -ForegroundColor White
        $breachResults = Search-BreachInfo -Keywords $keywords -DaysBack $DaysBack
        $allResults += $breachResults
        Write-Host ""
    }

    # --- Summary ---
    Write-Host "═══ Scan Complete ═══" -ForegroundColor Green
    Write-Host ""

    if ($allResults.Count -eq 0) {
        Write-Host "No results found across any sources." -ForegroundColor Green
        return
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

    # Export CSV
    $reportPath = Export-AU13Report -Results $allResults -OutputPath $OutputFile

    # Also display high-severity hits in the console
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

    return $allResults
}
