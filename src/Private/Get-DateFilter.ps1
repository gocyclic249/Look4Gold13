function Get-DateFilter {
    <#
    .SYNOPSIS
        Returns a date string for filtering results by days back.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$DaysBack,

        [Parameter()]
        [ValidateSet('Google', 'GitHub', 'Unix')]
        [string]$Format = 'Google'
    )

    $targetDate = (Get-Date).AddDays(-$DaysBack)

    switch ($Format) {
        'Google' {
            # Google date restrict format: d[N] for days
            return "d$DaysBack"
        }
        'GitHub' {
            # GitHub uses ISO 8601: YYYY-MM-DD
            return $targetDate.ToString('yyyy-MM-dd')
        }
        'Unix' {
            return [int][double]::Parse(
                (Get-Date $targetDate -UFormat %s)
            )
        }
    }
}
