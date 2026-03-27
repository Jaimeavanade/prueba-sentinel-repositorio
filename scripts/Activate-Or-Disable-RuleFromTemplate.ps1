<#
.SYNOPSIS
Activa (crea desde template) o deshabilita una regla de Analíticas en Microsoft Sentinel usando el Display Name.

.DESCRIPTION
- action=enable: localiza el Rule template (Analytics > Rule templates) por displayName y crea la regla (Scheduled) habilitada.
- action=disable: localiza la regla existente (Analytics > Active rules) por displayName y la marca enabled=false.

IMPORTANTE (GitHub Actions + Az 14+):
- Evitamos Get-AzAccessToken para ARM porque el Token puede venir como SecureString y romper el header.
- Usamos 'az account get-access-token --resource https://management.azure.com/' para obtener un token en texto plano.

NOTAS:
- El nombre debe coincidir EXACTO con el "Name" en:
  Azure Portal > Microsoft Sentinel > Analytics > Rule templates > Name

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

# ----------------------------
# Helpers
# ----------------------------
function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido o vacío. Revisa que azure/login (OIDC) se haya ejecutado y que el SP tenga permisos."
  }
  return $t
}

function Get-ErrorBodyFromException {
  param([Parameter(Mandatory=$true)] $Exception)

  try {
    if ($Exception.Response -and $Exception.Response.GetResponseStream) {
      $reader = New-Object System.IO.StreamReader($Exception.Response.GetResponseStream())
      $body = $reader.ReadToEnd()
      if ($body) { return $body }
    }
  } catch { }
  return $null
}

function Invoke-ArmRest {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","PATCH","DELETE")] [string] $Method,
    [Parameter(Mandatory=$true)] [string] $Uri,
    [Parameter(Mandatory=$false)] [object] $Body
  )

  if (-not $script:ArmToken) {
    $script:ArmToken = Get-ArmToken
  }

  $headers = @{
    Authorization = "Bearer $script:ArmToken"
    "Content-Type" = "application/json"
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
    $bodyText = Get-ErrorBodyFromException -Exception $_.Exception
    if ($bodyText) {
      throw "Fallo REST ($Method). Uri=$Uri. Body=$bodyText"
    }
    throw
  }
}

# ----------------------------
# Config
# ----------------------------
# Si te diera problemas de API version, dime tu API version actual y lo ajustamos.
$ApiVersion_Templates = "2023-11-01"
$ApiVersion_Rules     = "2023-11-01"

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

Write-Host "==> Acción: $Action"
Write-Host "==> RuleName (DisplayName): $RuleName"
Write-Host "==> Workspace: $WorkspaceName | RG: $ResourceGroupName | Sub: $SubscriptionId"

# Fuerza token ARM al inicio (fail fast)
$script:ArmToken = Get-ArmToken

# ----------------------------
# Logic
# ----------------------------
if ($Action -eq "enable") {

  # 1) Listar Rule templates instaladas
  $templatesUri = "${base}/alertRuleTemplates?api-version=$ApiVersion_Templates"
  $templates = Invoke-ArmRest -Method GET -Uri $templatesUri

  $match = $templates.value | Where-Object { $_.properties.displayName -eq $RuleName } | Select-Object -First 1
  if (-not $match) {
    throw "No se encontró ningún Rule template con displayName EXACTO = '$RuleName'. Copia el nombre desde Sentinel > Analytics > Rule templates > Name."
  }

  $templateId = $match.name
  Write-Host "Encontrado templateId: $templateId"

  # 2) Crear regla Scheduled desde template
  $newRuleGuid = (New-Guid).Guid

  # IMPORTANTE: usar ${} para evitar el bug $newRuleGuid?api
  $createRuleUri = "${base}/alertRules/${newRuleGuid}?api-version=$ApiVersion_Rules"

  $p = $match.properties

  # Mapeo básico desde template (Scheduled)
  $ruleProps = @{
    displayName         = $p.displayName
    description         = $p.description
    severity            = $p.severity
    enabled             = $true
    query               = $p.query
    queryFrequency      = $p.queryFrequency
    queryPeriod         = $p.queryPeriod
    triggerOperator     = $p.triggerOperator
    triggerThreshold    = $p.triggerThreshold
    suppressionDuration = $p.suppressionDuration
    suppressionEnabled  = $p.suppressionEnabled
    tactics             = $p.tactics
    techniques          = $p.techniques
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

  # 1) Listar reglas existentes
  $rulesUri = "${base}/alertRules?api-version=$ApiVersion_Rules"
  $rules = Invoke-ArmRest -Method GET -Uri $rulesUri

  $rule = $rules.value | Where-Object { $_.properties.displayName -eq $RuleName } | Select-Object -First 1
  if (-not $rule) {
    throw "No se encontró ninguna regla creada con displayName EXACTO = '$RuleName'. (Revisa en Analytics > Active rules)."
  }

  $ruleId = $rule.name
  Write-Host "Encontrada reglaId: $ruleId. Marcando enabled=false..."

  # IMPORTANTE: usar ${} para evitar $ruleId?api
  $patchUri = "${base}/alertRules/${ruleId}?api-version=$ApiVersion_Rules"

  $patchBody = @{
    properties = @{
      enabled = $false
    }
  }

  $updated = Invoke-ArmRest -Method PATCH -Uri $patchUri -Body $patchBody
  Write-Host "✅ Regla deshabilitada: $($updated.properties.displayName)"
}
