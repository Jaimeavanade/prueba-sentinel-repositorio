param (
    [Parameter(Mandatory = $true)]
    [string]$InputFile
)

Write-Host "Input file: $InputFile"

if (-not (Test-Path $InputFile)) {
    throw "Input file not found: $InputFile"
}

# -------------------------------------------------
# ✅ Determinar entorno (001 / 002) desde el nombre
# -------------------------------------------------
$environment = if ($InputFile -match '001') {
    '001'
}
elseif ($InputFile -match '002') {
    '002'
}
else {
    throw "Cannot determine environment (001/002) from input file name"
}

$OutputFolder = "Detections/Custom/YAML/$environment"

Write-Host "Detected environment: $environment"
Write-Host "Output folder: $OutputFolder"

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

# -------------------------
# Load JSON
# -------------------------
$json = Get-Content $InputFile -Raw | ConvertFrom-Json

if (-not $json.resources) {
    throw "JSON does not contain 'resources' array"
}

foreach ($rule in $json.resources) {

    if (-not $rule.properties.displayName) {
        Write-Warning "Skipping rule without displayName"
        continue
    }

    # -------------------------------------------------
    # ✅ displayName como nombre de archivo
    # - mantiene espacios, acentos y guiones
    # - elimina SOLO caracteres problemáticos
    # -------------------------------------------------
    $safeFileName = (
        $rule.properties.displayName `
            -replace '[\\\/:\*\?"<>\|\[\]]', ''
    ).Trim()

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
