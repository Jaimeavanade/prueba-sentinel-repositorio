<#
.SYNOPSIS
Activa (crea desde template) o deshabilita una regla de Analíticas en Microsoft Sentinel usando como clave el Display Name.

.DESCRIPTION
- action=enable: localiza el template (Rule template) cuyo displayName coincide y crea la regla desde ese template.
- action=disable: localiza la regla ya creada (Scheduled analytics rule) por displayName y la marca como enabled=false.

.NOTES
Requiere Az.Accounts para obtener token (Get-AzAccessToken). Se ejecuta bien en GitHub Actions con azure/login@v2 + azure/powershell@v2.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $SubscriptionId,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $ResourceGroupName,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $WorkspaceName,

  [Parameter(Mandatory=$true)]
  [ValidateSet("enable","disable")]
  [string] $Action,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $RuleName
)

$ErrorActionPreference = "Stop"

function Invoke-ArmRest {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","PATCH","DELETE")] [string] $Method,
    [Parameter(Mandatory=$true)] [string] $Uri,
    [Parameter(Mandatory=$false)] $Body
  )

  $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
  $headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
  }

  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Depth 80
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
  } else {
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
  }
}

# API versions (puedes ajustar si tu tenant requiere otra)
# OJO: estos endpoints pueden variar según evolución del servicio.
# Si tuvieras ya una ApiVersion definida en tu repo, úsala.
$ApiVersion_Templates = "2023-11-01"
$ApiVersion_Rules     = "2023-11-01"

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

Write-Host "==> Acción: $Action"
Write-Host "==> RuleName (DisplayName): $RuleName"
Write-Host "==> Workspace: $WorkspaceName | RG: $ResourceGroupName | Sub: $SubscriptionId"

if ($Action -eq "enable") {

  # 1) Listar templates instalados (Rule templates)
  # En portal: Sentinel > Analytics > Rule templates (las plantillas) [1](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rule-from-template)
  $templatesUri = "$base/alertRuleTemplates?api-version=$ApiVersion_Templates"
  $templates = Invoke-ArmRest -Method GET -Uri $templatesUri

  $match = $templates.value | Where-Object { $_.properties.displayName -eq $RuleName } | Select-Object -First 1
  if (-not $match) {
    throw "No se encontró ningún Rule template con displayName EXACTO = '$RuleName'. Revisa el nombre en Sentinel > Analytics > Rule templates > Name."
  }

  $templateId = ($match.name)
  Write-Host "Encontrado templateId: $templateId"

  # 2) Crear la regla desde template
  # Crear “una regla desde una plantilla” es el mismo flujo conceptual del portal (Create rule from template). [1](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rule-from-template)
  # Para scheduled rules, se crea un recurso 'alertRules' (Scheduled).
  # Nota: El template no siempre expone directamente un payload listo sin adaptación, pero la mayoría de templates Scheduled
  # incluyen query, severity, tactics, etc.
  $newRuleGuid = (New-Guid).Guid

  $createRuleUri = "$base/alertRules/$newRuleGuid?api-version=$ApiVersion_Rules"

  # Construimos properties a partir del template (Scheduled)
  $p = $match.properties

  # Campos mínimos típicos (si tu template trae más, se pueden mapear)
  $ruleProps = @{
    displayName       = $p.displayName
    description       = $p.description
    severity          = $p.severity
    enabled           = $true
    query             = $p.query
    queryFrequency    = $p.queryFrequency
    queryPeriod       = $p.queryPeriod
    triggerOperator   = $p.triggerOperator
    triggerThreshold  = $p.triggerThreshold
    suppressionDuration = $p.suppressionDuration
    suppressionEnabled  = $p.suppressionEnabled
    tactics           = $p.tactics
    techniques        = $p.techniques
  }

  # Tipo Scheduled
  $body = @{
    kind       = "Scheduled"
    properties = $ruleProps
  }

  Write-Host "Creando regla Scheduled desde template..."
  $created = Invoke-ArmRest -Method PUT -Uri $createRuleUri -Body $body

  Write-Host "✅ Regla creada/activada: $($created.properties.displayName) (id: $newRuleGuid)"
}
else {
  # disable

  # 1) Buscar reglas existentes
  $rulesUri = "$base/alertRules?api-version=$ApiVersion_Rules"
  $rules = Invoke-ArmRest -Method GET -Uri $rulesUri

  $rule = $rules.value | Where-Object { $_.properties.displayName -eq $RuleName } | Select-Object -First 1
  if (-not $rule) {
    throw "No se encontró ninguna regla creada con displayName EXACTO = '$RuleName'."
  }

  $ruleId = $rule.name
  Write-Host "Encontrada reglaId: $ruleId. Marcando enabled=false..."

  $patchUri = "$base/alertRules/$ruleId?api-version=$ApiVersion_Rules"
  $patchBody = @{
    properties = @{
      enabled = $false
    }
  }

  $updated = Invoke-ArmRest -Method PATCH -Uri $patchUri -Body $patchBody
  Write-Host "✅ Regla deshabilitada: $($updated.properties.displayName)"
}
