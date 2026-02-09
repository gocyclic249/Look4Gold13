function Search-PasteSites {
    <#
    .SYNOPSIS
        Searches public paste sites for keyword exposure.
    .DESCRIPTION
        Queries free paste-search APIs (psbdmp.ws and IntelX paste search)
        for occurrences of keywords in public pastes.
    .PARAMETER Keywords
        Array of keywords to search for.
    .PARAMETER DaysBack
        Number of days back to filter results.
    .EXAMPLE
        Search-PasteSites -Keywords @("acme-corp","internal-tool") -DaysBack 30
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Keywords,

        [Parameter()]
        [int]$DaysBack = 30
    )

    $results = @()
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)

    foreach ($keyword in $Keywords) {
        # --- psbdmp.ws (free Pastebin dump search) ---
        try {
            $encodedKeyword = [System.Uri]::EscapeDataString($keyword)
            $uri = "https://psbdmp.ws/api/v3/search/$encodedKeyword"

            Write-Verbose "[PasteSites] Querying psbdmp.ws for '$keyword'..."
            $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 15 -ErrorAction Stop

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

                    # Filter by date if we got one
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
            Write-Warning "[PasteSites] psbdmp.ws error for '$keyword': $($_.Exception.Message)"
        }

        # --- Fallback: generate manual search URLs for other paste sites ---
        $pasteSites = @(
            @{ Name = 'Pastebin';  Url = "https://www.google.com/search?q=site:pastebin.com+%22$([System.Uri]::EscapeDataString($keyword))%22&tbs=qdr:d$DaysBack" },
            @{ Name = 'Paste.ee';  Url = "https://www.google.com/search?q=site:paste.ee+%22$([System.Uri]::EscapeDataString($keyword))%22&tbs=qdr:d$DaysBack" },
            @{ Name = 'Ghostbin';  Url = "https://www.google.com/search?q=site:ghostbin.com+%22$([System.Uri]::EscapeDataString($keyword))%22&tbs=qdr:d$DaysBack" },
            @{ Name = 'Dpaste';    Url = "https://www.google.com/search?q=site:dpaste.org+%22$([System.Uri]::EscapeDataString($keyword))%22&tbs=qdr:d$DaysBack" }
        )

        foreach ($site in $pasteSites) {
            $results += New-AU13Result `
                -Source "PasteSearch-$($site.Name)" `
                -Keyword $keyword `
                -Title "MANUAL: Search $($site.Name) for '$keyword'" `
                -Url $site.Url `
                -Snippet "Google-indexed paste search - open URL to review" `
                -Severity 'Manual-Review'
        }

        Start-Sleep -Milliseconds 300
    }

    Write-Host "[PasteSites] Found $($results.Count) results/links" -ForegroundColor Cyan
    return $results
}
