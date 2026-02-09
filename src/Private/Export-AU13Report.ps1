function Export-AU13Report {
    <#
    .SYNOPSIS
        Exports AU-13 scan results to CSV.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter()]
        [string]$OutputPath
    )

    if (-not $OutputPath) {
        $projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $outputDir = Join-Path $projectRoot "Output"
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $OutputPath = Join-Path $outputDir "AU13_Scan_$timestamp.csv"
    }

    $parentDir = Split-Path -Parent $OutputPath
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "Report exported to: $OutputPath" -ForegroundColor Green
    return $OutputPath
}
