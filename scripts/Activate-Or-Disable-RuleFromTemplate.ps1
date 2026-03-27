<#
.SYNOPSIS
Activa (crea desde template) o deshabilita una regla de Analíticas en Microsoft Sentinel usando el Display Name.

.DESCRIPTION
- action=enable: localiza el Rule template (Analytics > Rule templates) por displayName y crea la regla (Scheduled) habilitada.
- action=disable: localiza la regla existente (Analytics > Active rules) por displayName y la marca enabled=false.

NOTA IMPORTANTE (GitHub Actions + Az 14+):
- Evitamos Get-AzAccessToken para ARM porque el Token puede venir como SecureString y romper el header.
- Usamos 'az account get-access-token --resource https://management.azure.com/' (patrón ya usado en tu repo).
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

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  # Obtiene token ARM en texto plano (evita SecureString / Az 14+)
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido o vacío. Revisa azure/login (OIDC) y permisos."
  }
  return $t
}

function Invoke-ArmRest {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","PATCH","DELETE")] [string] $Method,
    [Parameter(Mandatory=$true)] [string] $Uri,
    [Parameter(Mandatory=$false)] $Body
  )

  if (-not $script:ArmToken) {
    $script:ArmToken = Get-ArmToken
  }

  $headers = @{
    "Authorization" = "Bearer $script:ArmToken"
    "Content-Type"  = "application/json"
  }

  try {
    if ($null -ne $Body) {
      $json = $Body | ConvertTo-Json -Depth 80
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
    } else {
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
  }
  catch {
    # Intenta extraer body de error para diagnóstico
    $bodyText = $null
    try {
      if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $bodyText = $reader.ReadToEnd()
      }
    } catch {}
    if ($bodyText) {
      throw "Fallo REST ($Method). Uri=$Uri. Body=$bodyText"
    }
    throw
  }
}

# API versions (ajustables si tu tenant exige otra)
$ApiVersion_Templates = "2023-11-01"
$ApiVersion_Rules     = "2023-11-01"

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

Write-Host "==> Acción: $Action"
Write-Host "==> RuleName (DisplayName): $RuleName"
Write-Host "==> Workspace: $WorkspaceName | RG: $ResourceGroupName | Sub: $SubscriptionId"

# Fuerza token ARM al inicio (para fallar pronto si auth está mal)
$script:ArmToken = Get-ArmToken

if ($Action -eq "enable") {

  # 1) Listar templates instalados (Rule templates)
  $templatesUri = "$base/alertRuleTemplates?api-version=$ApiVersion_Templates"
  $templates = Invoke-ArmRest -Method GET -Uri $templatesUri

  $match = $templates.value | Where-Object { $_.properties.displayName -eq $RuleName } | Select-Object -First 1
  if (-not $match) {
    throw "No se encontró ningún Rule template con displayName EXACTO = '$RuleName'. Copia el nombre desde Sentinel > Analytics > Rule templates > Name."
  }

  $templateId = $match.name
  Write-Host "Encontrado templateId: $templateId"

  # 2) Crear regla (Scheduled) usando propiedades del template
  $newRuleGuid = (New-Guid).Guid
  $createRuleUri = "$base/alertRules/$newRuleGuid?api-version=$ApiVersion_Rules"

  $p = $match.properties

  $ruleProps = @{
    displayName        = $p.displayName
    description        = $p.description
    severity           = $p.severity
    enabled            = $true
    query              = $p.query
    queryFrequency     = $p.queryFrequency
    queryPeriod        = $p.queryPeriod
    triggerOperator    = $p.triggerOperator
    triggerThreshold   = $p.triggerThreshold
    suppressionDuration = $p.suppressionDuration
    suppressionEnabled  = $p.suppressionEnabled
    tactics            = $p.tactics
    techniques         = $p.techniques
  }

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

  # 1) Buscar regla existente por displayName
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
