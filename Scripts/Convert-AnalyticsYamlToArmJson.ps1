param (
    [Parameter(Mandatory = $true)]
    [string]$InputYamlPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputJsonPath
)

Import-Module powershell-yaml -ErrorAction Stop

# Leer YAML
$yamlContent = Get-Content $InputYamlPath -Raw | ConvertFrom-Yaml

# Generar GUIDs estables
$ruleGuid = [guid]::NewGuid().ToString()

# Construir recurso Analytics Rule compatible con Repositories
$armTemplate = @{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    parameters = @{}
    resources = @(
        @{
            type = 'Microsoft.SecurityInsights/alertRules'
            apiVersion = '2023-02-01'
            name = $ruleGuid
            kind = 'Scheduled'
            properties = @{
                displayName = $yamlContent.name
                description = $yamlContent.description
                severity = $yamlContent.severity
                enabled = $true
                query = $yamlContent.query
                queryFrequency = $yamlContent.queryFrequency
                queryPeriod = $yamlContent.queryPeriod
                triggerOperator = $yamlContent.triggerOperator
                triggerThreshold = $yamlContent.triggerThreshold
                tactics = $yamlContent.tactics
                techniques = $yamlContent.techniques

                # 🔑 CLAVE para Repositories
                alertRuleTemplateName = $ruleGuid
            }
        }
    )
}

# Guardar JSON final
$armTemplate |
    ConvertTo-Json -Depth 20 |
    Out-File -FilePath $OutputJsonPath -Encoding utf8

Write-Host "✅ Converted to Repositories-compatible ARM JSON:"
Write-Host "   $OutputJsonPath"
