param (
    [Parameter(Mandatory)]
    [string]$InputFile,

    [Parameter(Mandatory)]
    [string]$OutputFolder
)

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$json = Get-Content $InputFile -Raw | ConvertFrom-Json

foreach ($rule in $json.resources) {

    if ($rule.kind -ne "Scheduled") { continue }

    $p = $rule.properties

    $safeName = ($p.displayName -replace '[^a-zA-Z0-9\- ]','').Replace(' ', '-')
    $fileName = "$safeName.yaml"
    $filePath = Join-Path $OutputFolder $fileName

    $yaml = @"
id: $(New-Guid)
name: "$($p.displayName)"
description: |
  $($p.description)
severity: $($p.severity)
status: $(if ($p.enabled) { "Available" } else { "Disabled" })
requiredDataConnectors: []
queryFrequency: $($p.queryFrequency)
queryPeriod: $($p.queryPeriod)
triggerOperator: $($p.triggerOperator)
triggerThreshold: $($p.triggerThreshold)
tactics:
$(($p.tactics | ForEach-Object { "  - $_" }) -join "`n")
techniques:
$(($p.techniques | ForEach-Object { "  - $_" }) -join "`n")
query: |
$($p.query -replace '^', '  ')
"@

    $yaml | Out-File -Encoding utf8 $filePath
    Write-Host "✅ Generado: $fileName"
}
