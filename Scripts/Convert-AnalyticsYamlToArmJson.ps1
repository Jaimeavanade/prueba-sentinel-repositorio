param (
    # Carpeta donde están los YAML
    [Parameter(Mandatory = $true)]
    [string]$YamlInputPath,

    # Carpeta donde se dejarán TODOS los ARM JSON
    [Parameter(Mandatory = $true)]
    [string]$ArmOutputPath
)

Write-Host "YAML input path: $YamlInputPath"
Write-Host "ARM output path: $ArmOutputPath"

# -------------------------------------------------
# Requisitos
# -------------------------------------------------
if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
    throw "Required module 'powershell-yaml' is not installed"
}

Import-Module powershell-yaml

if (-not (Test-Path $YamlInputPath)) {
    throw "YAML input path not found: $YamlInputPath"
}

if (-not (Test-Path $ArmOutputPath)) {
    New-Item -ItemType Directory -Path $ArmOutputPath -Force | Out-Null
}

# -------------------------------------------------
# Función: normalizar ISO-8601 a MAYÚSCULAS
# -------------------------------------------------
function Normalize-Iso8601 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    return $Value.ToUpperInvariant()
}

# -------------------------------------------------
# Procesar todos los YAML
# -------------------------------------------------
$yamlFiles = Get-ChildItem -Path $YamlInputPath -Recurse -Filter *.yaml

foreach ($yamlFile in $yamlFiles) {

    Write-Host "Processing YAML: $($yamlFile.FullName)"

    $yaml = Get-Content $yamlFile.FullName -Raw | ConvertFrom-Yaml

    if (-not $yaml.query) {
        Write-Warning "Skipping file without query: $($yamlFile.Name)"
        continue
    }

    # Normalizar ISO-8601 (CRÍTICO PARA SENTINEL)
    $queryFrequency = Normalize-Iso8601 $yaml.queryFrequency
    $queryPeriod    = Normalize-Iso8601 $yaml.queryPeriod

    # -------------------------------------------------
    # ARM Template – Scheduled Analytics Rule
    # -------------------------------------------------
    $armTemplate = @{
        '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        parameters     = @{
            workspaceName = @{
                type = 'string'
            }
        }
        resources      = @(
            @{
                type       = 'Microsoft.SecurityInsights/alertRules'
                apiVersion = '2022-12-01-preview'
                name       = "[concat(parameters('workspaceName'),'/',$yaml.id)]"
                kind       = 'Scheduled'
                properties = @{
                    displayName      = $yaml.name
                    description      = $yaml.description
                    severity         = $yaml.severity
                    enabled          = $yaml.enabled
                    query            = $yaml.query
                    queryFrequency   = $queryFrequency
                    queryPeriod      = $queryPeriod
                    triggerOperator  = $yaml.triggerOperator
                    triggerThreshold = $yaml.triggerThreshold
                    tactics          = $yaml.tactics
                    techniques       = $yaml.techniques
                }
            }
        )
    }

    $outputFile = Join-Path $ArmOutputPath ($yamlFile.BaseName + ".json")

    $armTemplate | ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 $outputFile

    Write-Host "✅ ARM JSON generated: $outputFile"
}

Write-Host "✅ All YAML files converted to ARM templates successfully"
