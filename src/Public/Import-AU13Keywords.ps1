function Import-AU13Keywords {
    <#
    .SYNOPSIS
        Imports keywords from the AU-13 keywords file.
    .DESCRIPTION
        Reads keywords from a text file (one per line). Ignores comments (#) and blank lines.
        The keywords file is gitignored to prevent accidental disclosure.
    .PARAMETER Path
        Path to the keywords file. Defaults to ./keywords.txt in the module root.
    .EXAMPLE
        $keywords = Import-AU13Keywords
    .EXAMPLE
        $keywords = Import-AU13Keywords -Path "C:\SecureShare\my-keywords.txt"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path
    )

    if (-not $Path) {
        # Default: look in the project root (parent of src/)
        $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $Path = Join-Path $projectRoot "keywords.txt"
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
