<#
.SYNOPSIS
  Crea o habilita una Analytics Rule de Microsoft Sentinel a partir de un template (Content Hub) usando su displayName.

.DESCRIPTION
  - Busca en alertRuleTemplates del workspace el template cuyo properties.displayName coincide con el input.
  - Si ya existe una alertRule con ese mismo displayName y kind:
      * Enable  -> la habilita (enabled=true)
      * Skip    -> no hace nada
      * Replace -> la reemplaza usando el template como base y la habilita
  - Si no existe, crea una nueva alertRule (Scheduled o NRT) copiando propiedades del template y activándola.

  Auth:
    - Requiere haber ejecutado azure/login (OIDC) o login previo con az.
    - El script obtiene token ARM con: az account get-access-token --resource https://management.azure.com/

.PARAMETER SubscriptionId
  Subscription ID donde está el workspace.

.PARAMETER ResourceGroupName
  Resource Group del workspace.

.PARAMETER WorkspaceName
  Log Analytics workspace asociado a Sentinel.

.PARAMETER DisplayName
  Nombre visible del Content Hub item (displayName), por ejemplo:
  "Brute force attack against a Cloud PC"

.PARAMETER IfExists
  Qué hacer si ya existe la regla:
  Enable | Skip | Replace

.PARAMETER ApiVersion
  Versión de API para Microsoft.SecurityInsights. Por defecto 2025-09-01.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $true)]
  [string]$DisplayName,

  [Parameter(Mandatory = $false)]
  [ValidateSet("Enable","Skip","Replace")]
  [string]$IfExists = "Enable",

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegúrate de estar autenticado (azure/login OIDC o az login)."
  }
  return $t
}

function Normalize-NextLink {
  param(
    [Parameter(Mandatory = $false)][string]$NextLink,
    [Parameter(Mandatory = $true)][string]$ApiVersion
  )
  if ([string]::IsNullOrWhiteSpace($NextLink)) { return $null }

  # A veces nextLink puede venir sin api-version; lo garantizamos.
  if ($NextLink -notmatch "api-version=") {
    if ($NextLink -match "\?") { return "$NextLink&api-version=$ApiVersion" }
    return "$NextLink?api-version=$ApiVersion"
  }
  return $NextLink
}

function Invoke-ArmGet {
  param([Parameter(Mandatory = $true)][string]$Uri)

  $headers = @{ Authorization = "Bearer $script:ArmToken" }
  try {
    return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers -ContentType "application/json"
  } catch {
    $msg = $_.Exception.Message
    throw "GET falló: $Uri`n$msg"
  }
}

function Invoke-ArmPut {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [Parameter(Mandatory = $true)][object]$Body
  )

  $headers = @{ Authorization = "Bearer $script:ArmToken" }
  $json = $Body | ConvertTo-Json -Depth 100

  try {
    return Invoke-RestMethod -Method PUT -Uri $Uri -Headers $headers -Body $json -ContentType "application/json"
  } catch {
    $msg = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
      $msg = "$msg`n$($_.ErrorDetails.Message)"
    }
    throw "PUT falló: $Uri`n$msg`nBody:`n$json"
  }
}

function Remove-ReadOnlyProps {
  param([hashtable]$Props)
  foreach ($k in @("lastModifiedUtc","createdTimeUtc","createdBy","lastModifiedBy","systemData","etag")) {
    if ($Props.ContainsKey($k)) { [void]$Props.Remove($k) }
  }
}

function Get-AllPaged {
  <#
    Devuelve todos los items de una respuesta paginada de ARM:
    - Suma r.value
    - Sigue r.nextLink si existe
    Nota: nextLink NO siempre existe; en StrictMode no podemos acceder si falta.
  #>
  param(
    [Parameter(Mandatory=$true)][string]$FirstUri,
    [Parameter(Mandatory=$true)][string]$ApiVersion
  )

  $all = @()
  $uri = $FirstUri

  while (-not [string]::IsNullOrWhiteSpace($uri)) {
    $r = Invoke-ArmGet -Uri $uri
    if ($r -and $r.value) { $all += $r.value }

    # ✅ nextLink puede NO existir: comprobar antes de leer
    $next = $null
    if ($r -and ($r.PSObject.Properties.Name -contains 'nextLink')) {
      $next = $r.nextLink
    }
    $uri = Normalize-NextLink -NextLink $next -ApiVersion $ApiVersion
  }

  return $all
}

Write-Host "== Sentinel | Enable/Create Analytics Rule from Content Hub template =="
Write-Host "SubscriptionId : $SubscriptionId"
Write-Host "ResourceGroup  : $ResourceGroupName"
Write-Host "WorkspaceName  : $WorkspaceName"
Write-Host "DisplayName    : $DisplayName"
Write-Host "IfExists       : $IfExists"
Write-Host "ApiVersion     : $ApiVersion"
Write-Host ""

$script:ArmToken = Get-ArmToken

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# 1) Listar templates instalados (alertRuleTemplates)
Write-Host "-> Listando alertRuleTemplates..."
$templates = Get-AllPaged -FirstUri "$base/alertRuleTemplates?api-version=$ApiVersion" -ApiVersion $ApiVersion
Write-Host ("   Templates encontrados: {0}" -f $templates.Count)

# 2) Buscar template por displayName exacto (case-insensitive)
$matches = @($templates | Where-Object {
  $_.properties.displayName -and ($_.properties.displayName -ieq $DisplayName)
})

if ($matches.Count -eq 0) {
  throw @"
No se encontró ningún alertRuleTemplate con displayName '$DisplayName'.

Causas típicas:
  - La solución del Content Hub que contiene esa regla NO está instalada en este workspace.
  - El displayName no coincide exactamente (espacios/comillas).
"@
}

if ($matches.Count -gt 1) {
  Write-Warning ("Hay {0} templates con el mismo displayName. Se usará el primero: {1}" -f $matches.Count, $matches[0].name)
}

$template = $matches[0]
$kind = $template.kind

Write-Host "-> Template encontrado:"
Write-Host ("   template.name  : {0}" -f $template.name)
Write-Host ("   template.kind  : {0}" -f $kind)
Write-Host ("   displayName    : {0}" -f $template.properties.displayName)

# Solo soportamos Analytics rules típicas aquí
if ($kind -notin @("Scheduled","NRT")) {
  throw "Template kind '$kind' no soportado por este script (solo Scheduled y NRT)."
}

# 3) Listar reglas existentes y buscar coincidencia por displayName+kind
Write-Host ""
Write-Host "-> Comprobando si ya existe alertRule con ese displayName..."
$rules = Get-AllPaged -FirstUri "$base/alertRules?api-version=$ApiVersion" -ApiVersion $ApiVersion

$existing = @($rules | Where-Object {
  $_.properties.displayName -and ($_.properties.displayName -ieq $DisplayName) -and ($_.kind -eq $kind)
})

if ($existing.Count -gt 1) {
  Write-Warning ("Hay {0} alertRules existentes con ese displayName+kind. Se usará la primera: {1}" -f $existing.Count, $existing[0].name)
}

$existingRule = if ($existing.Count -ge 1) { $existing[0] } else { $null }

# Propiedades a copiar desde el template (whitelist segura)
$allowedKeys = @(
  "displayName","description","severity",
  "query","queryFrequency","queryPeriod",
  "triggerOperator","triggerThreshold",
  "suppressionDuration","suppressionEnabled",
  "tactics","techniques",
  "eventGroupingSettings","customDetails","entityMappings",
  "alertDetailsOverride","incidentConfiguration",
  "templateVersion"
)

function Build-PropsFromTemplate {
  param(
    [Parameter(Mandatory=$true)]$Template
  )

  $props = @{}
  foreach ($k in $allowedKeys) {
    if ($Template.properties.PSObject.Properties.Name -contains $k) {
      $props[$k] = $Template.properties.$k
    }
  }

  # obligatorias / recomendadas
  $props["displayName"] = $Template.properties.displayName
  $props["enabled"] = $true
  $props["alertRuleTemplateName"] = $Template.name
  if ($Template.properties.templateVersion) { $props["templateVersion"] = $Template.properties.templateVersion }

  Remove-ReadOnlyProps -Props $props
  return $props
}

if ($existingRule) {
  Write-Host ("   Existe ruleId: {0}" -f $existingRule.name)

  switch ($IfExists) {

    "Skip" {
      Write-Host "==> IfExists=Skip: no se realiza ninguna acción."
      exit 0
    }

    "Enable" {
      # Obtener definición actual y habilitarla
      $ruleId = $existingRule.name
      $getUri = "$base/alertRules/$ruleId?api-version=$ApiVersion"
      $current = Invoke-ArmGet -Uri $getUri

      $props = @{}
      foreach ($p in $current.properties.PSObject.Properties) { $props[$p.Name] = $p.Value }

      $props["enabled"] = $true
      $props["alertRuleTemplateName"] = $template.name
      if ($template.properties.templateVersion) { $props["templateVersion"] = $template.properties.templateVersion }

      Remove-ReadOnlyProps -Props $props

      $body = @{
        kind       = $current.kind
        properties = $props
      }

      $putUri = "$base/alertRules/$ruleId?api-version=$ApiVersion"
      if ($PSCmdlet.ShouldProcess($ruleId, "Habilitar alertRule existente")) {
        $out = Invoke-ArmPut -Uri $putUri -Body $body
        Write-Host ("✅ Regla habilitada: {0}" -f $out.id)
        Write-Host ("::notice title=Sentinel AlertRule Enabled::{0}" -f $out.id)
      }
      exit 0
    }

    "Replace" {
      # Reemplazar regla existente usando el template como base (manteniendo ruleId)
      $ruleId = $existingRule.name
      $props = Build-PropsFromTemplate -Template $template

      $body = @{
        kind       = $kind
        properties = $props
      }

      $putUri = "$base/alertRules/$ruleId?api-version=$ApiVersion"
      if ($PSCmdlet.ShouldProcess($ruleId, "Reemplazar alertRule existente desde template")) {
        $out = Invoke-ArmPut -Uri $putUri -Body $body
        Write-Host ("✅ Regla reemplazada y habilitada: {0}" -f $out.id)
        Write-Host ("::notice title=Sentinel AlertRule Replaced::{0}" -f $out.id)
      }
      exit 0
    }
  }
}

# 4) No existe: crear nueva regla desde template
Write-Host ""
Write-Host "-> No existe alertRule con ese displayName. Creando nueva regla desde template..."
$ruleId = [guid]::NewGuid().ToString()

$props = Build-PropsFromTemplate -Template $template

$body = @{
  kind       = $kind
  properties = $props
}

$putUri = "$base/alertRules/$ruleId?api-version=$ApiVersion"
if ($PSCmdlet.ShouldProcess($ruleId, "Crear alertRule desde template '$DisplayName'")) {
  $out = Invoke-ArmPut -Uri $putUri -Body $body
  Write-Host ("✅ Regla creada y habilitada: {0}" -f $out.id)
  Write-Host ("::notice title=Sentinel AlertRule Created::{0}" -f $out.id)
}

Write-Host ""
Write-Host "FIN."
