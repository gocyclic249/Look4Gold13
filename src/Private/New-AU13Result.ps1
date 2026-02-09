function New-AU13Result {
    <#
    .SYNOPSIS
        Creates a standardized AU-13 scan result object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Keyword,
        [Parameter(Mandatory)][string]$Title,
        [Parameter()][string]$Url = '',
        [Parameter()][string]$Snippet = '',
        [Parameter()][string]$DateFound = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        [Parameter()][string]$Severity = 'Review'
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
