param (
    [Parameter(Mandatory = $true)]
    [string]$InputFile,

    [Parameter(Mandatory = $true)]
    [string]$OutputFolder
)

Write-Host "Input file: $InputFile"
Write-Host "Output folder: $OutputFolder"

if (-not (Test-Path $InputFile)) {
    throw "Input file not found: $InputFile"
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

# Load JSON
$json = Get-Content $InputFile -Raw | ConvertFrom-Json

if (-not $json.resources) {
    throw "JSON does not contain 'resources' array"
}

foreach ($rule in $json.resources) {

    if (-not $rule.properties.displayName) {
        Write-Warning "Skipping rule without displayName"
        continue
    }

    # ✅ displayName como filename, SOLO quitando caracteres ilegales
    $safeFileName = $rule.properties.displayName `
        -replace '[\\\/:\*\?"<>\|]', '' `
        .Trim()

    $yamlObject = @{
        id               = $rule.name
        name             = $rule.properties.displayName
        description      = $rule.properties.description
        severity         = $rule.properties.severity
        enabled          = $rule.properties.enabled
        query            = $rule.properties.query
        queryFrequency   = $rule.properties.queryFrequency
        queryPeriod      = $rule.properties.queryPeriod
        triggerOperator  = $rule.properties.triggerOperator
        triggerThreshold = $rule.properties.triggerThreshold
        tactics          = $rule.properties.tactics
        techniques       = $rule.properties.techniques
    }

    $yamlContent = $yamlObject | ConvertTo-Yaml

    $outputFile = Join-Path $OutputFolder "$safeFileName.yaml"

    $yamlContent | Out-File -FilePath $outputFile -Encoding utf8

    Write-Host "Generated YAML: $outputFile"
}

Write-Host "✅ Conversion completed successfully"
