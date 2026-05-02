# SIC — PowerShell profile helpers
# Paste into your $PROFILE file (run "notepad $PROFILE" to open it),
# or dot-source this file: . "path\to\sic\install\sic-profile.ps1"

function sic-scan {
    <#.SYNOPSIS Run a SIC security scan. Usage: sic-scan [web|recon|network|full]#>
    param([string]$Type = "full")
    npx sic-security@beta scan $Type
}

function sic-health {
    <#.SYNOPSIS Check SIC server health.#>
    $r = Invoke-RestMethod -Uri "http://127.0.0.1:9888/health"
    $r | ConvertTo-Json -Depth 3
}

function sic-incidents {
    <#.SYNOPSIS List open SIC incidents.#>
    $r = Invoke-RestMethod -Uri "http://127.0.0.1:9888/api/incidents"
    $r | ConvertTo-Json -Depth 5
}

function sic-fix {
    <#.SYNOPSIS Apply AI-suggested fix for a finding. Usage: sic-fix <finding-id>#>
    param([Parameter(Mandatory)][string]$Id)
    $r = Invoke-RestMethod -Uri "http://127.0.0.1:9888/api/ai-fix/$Id"
    $r | ConvertTo-Json -Depth 5
}

Write-Host "SIC helpers loaded: sic-scan, sic-health, sic-incidents, sic-fix"
