<#
.SYNOPSIS
  Microsoft Sentinel - Analytics Rule Templates:
    - list   : Exporta CSV con templateId y displayName
    - create : Crea una regla activa (Scheduled) a partir de un templateId

.DESCRIPTION
  Script pensado para ejecutarse en GitHub Actions (OIDC) tras azure/login@v2.
  Usa Azure Management REST API (Microsoft.SecurityInsights) con api-version configurable.

  Incluye fixes acumulados:
   - StrictMode-safe (no rompe si faltan propiedades en templates)
   - Evita bug PowerShell "$Var?api" usando ${Var} en URLs
   - Normaliza entityMappings[].fieldMappings a ARRAY (Sentinel lo exige)
   - Añade defaults requeridos suppressionEnabled + suppressionDuration si faltan

.PARAMETERS
  -SubscriptionId   : Sub ID
  -ResourceGroup    : RG del workspace
  -WorkspaceName    : Nombre del Log Analytics workspace con Sentinel
  -Action           : list | create
  -TemplateId       : GUID template (para create)
  -TemplateDisplayName : Filtro por displayName (para list, opcional)
  -MatchMode        : contains | equals | startswith (para TemplateDisplayName)
  -NewRuleDisplayName : Nombre de la nueva regla (create, opcional)
  -Enabled          : true/false (create)
  -Location         : Por defecto 'global'
  -ApiVersion       : Por defecto 2025-09-01

.OUTPUT
  - list   : genera sentinel-templates.csv y además escribe el CSV por stdout (útil en logs)
  - create : devuelve JSON con ruleId/displayName
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroup,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $true)]
  [ValidateSet('list','create')]
  [string]$Action,

  [Parameter(Mandatory = $false)]
  [string]$TemplateId,

  [Parameter(Mandatory = $false)]
  [string]$TemplateDisplayName,

  [Parameter(Mandatory = $false)]
  [ValidateSet('contains','equals','startswith')]
  [string]$MatchMode = 'contains',

  [Parameter(Mandatory = $false)]
  [string]$NewRuleDisplayName,

  [Parameter(Mandatory = $false)]
  [bool]$Enabled = $true,

  [Parameter(Mandatory = $false)]
  [string]$Location = 'global',

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = '2025-09-01'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------
# Helpers
# -----------------------------
function Write-DebugLine {
  param([string]$Message)
  Write-Host "DEBUG $Message"
}

function Has-Prop {
  param(
    [Parameter(Mandatory = $true)] $Obj,
    [Parameter(Mandatory = $true)] [string]$Name
  )
  return ($null -ne $Obj -and $null -ne $Obj.PSObject -and $Obj.PSObject.Properties.Match($Name).Count -gt 0)
}

function Get-AzAccessToken {
  # Requiere az cli y login previo (azure/login@v2)
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv 2>$null
  if ([string]::IsNullOrWhiteSpace($t)) {
    throw "No se pudo obtener access token. Asegúrate de ejecutar azure/login@v2 o az login."
  }
  return $t
}

function Invoke-AzRest {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('GET','PUT','POST','DELETE','PATCH')]
    [string]$Method,

    [Parameter(Mandatory = $true)]
    [string]$Uri,

    [Parameter(Mandatory = $false)]
    $Body
  )

  $token = Get-AzAccessToken
  $headers = @{
    Authorization  = "Bearer $token"
    'Content-Type' = 'application/json'
  }

  if ($null -eq $Body) {
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
  } else {
    $json = if ($Body -is [string]) { $Body } else { ($Body | ConvertTo-Json -Depth 100) }
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
  }
}

function New-GuidString {
  return ([guid]::NewGuid().ToString())
}

function ConvertTo-ArrayIfNeeded {
  param([Parameter(ValueFromPipeline = $true)] $Value)

  if ($null -eq $Value) { return @() }

  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string]) -and
      ($Value.GetType().IsArray -or $Value -is [System.Collections.IList])) {
    return @($Value)
  }

  return @($Value)
}

function Normalize-EntityMappings {
  <#
    Sentinel requiere: entityMappings[] y fieldMappings[] (ARRAY).
    Muchos templates traen fieldMappings como objeto si hay 1 elemento.
  #>
  param([Parameter(Mandatory = $false)] $EntityMappings)

  if ($null -eq $EntityMappings) { return $null }

  $normalized = @()

  foreach ($em in (ConvertTo-ArrayIfNeeded $EntityMappings)) {
    if ($null -eq $em) { continue }

    # Clon a PSCustomObject (por si em es Hashtable)
    $emObj = [PSCustomObject]@{}
    if ($em -is [System.Collections.IDictionary]) {
      foreach ($k in $em.Keys) {
        $emObj | Add-Member -NotePropertyName $k -NotePropertyValue $em[$k] -Force
      }
    } else {
      foreach ($p in $em.PSObject.Properties) {
        $emObj | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force
      }
    }

    # fieldMappings -> array SIEMPRE
    $fmArray = @()
    foreach ($m in (ConvertTo-ArrayIfNeeded $emObj.fieldMappings)) {
      if ($null -eq $m) { continue }

      $identifier = $null
      $columnName = $null

      if ($m -is [System.Collections.IDictionary]) {
        if ($m.Contains('identifier')) { $identifier = $m['identifier'] }
        if ($m.Contains('columnName')) { $columnName = $m['columnName'] }
      } else {
        if ((Has-Prop $m 'identifier')) { $identifier = $m.identifier }
        if ((Has-Prop $m 'columnName')) { $columnName = $m.columnName }
      }

      $fmArray += [PSCustomObject]@{
        identifier = $identifier
        columnName = $columnName
      }
    }

    $emObj.fieldMappings = $fmArray
    $normalized += $emObj
  }

  return $normalized
}

function Normalize-TemplatePropertiesForRule {
  <#
    Construye properties de una Scheduled rule a partir de template.properties.
    StrictMode-safe: solo accede a propiedades si existen.
    Añade defaults obligatorios: suppressionEnabled + suppressionDuration.
  #>
  param([Parameter(Mandatory = $true)] $TemplateProps)

  $p = [ordered]@{}

  # Campos comunes
  if ((Has-Prop $TemplateProps 'displayName') -and $TemplateProps.displayName) { $p.displayName = $TemplateProps.displayName }
  if ((Has-Prop $TemplateProps 'description') -and $TemplateProps.description) { $p.description = $TemplateProps.description }
  if ((Has-Prop $TemplateProps 'severity') -and $TemplateProps.severity) { $p.severity = $TemplateProps.severity }
  if ((Has-Prop $TemplateProps 'query') -and $TemplateProps.query) { $p.query = $TemplateProps.query }

  # Scheduling
  if ((Has-Prop $TemplateProps 'queryFrequency') -and $TemplateProps.queryFrequency) { $p.queryFrequency = $TemplateProps.queryFrequency }
  if ((Has-Prop $TemplateProps 'queryPeriod') -and $TemplateProps.queryPeriod) { $p.queryPeriod = $TemplateProps.queryPeriod }
  if ((Has-Prop $TemplateProps 'triggerOperator') -and $TemplateProps.triggerOperator) { $p.triggerOperator = $TemplateProps.triggerOperator }
  if ((Has-Prop $TemplateProps 'triggerThreshold') -and ($TemplateProps.triggerThreshold -ne $null)) { $p.triggerThreshold = $TemplateProps.triggerThreshold }

  # MITRE
  if ((Has-Prop $TemplateProps 'tactics') -and $TemplateProps.tactics) { $p.tactics = $TemplateProps.tactics }
  if ((Has-Prop $TemplateProps 'techniques') -and $TemplateProps.techniques) { $p.techniques = $TemplateProps.techniques }

  # Entity mappings (normalización arrays)
  if ((Has-Prop $TemplateProps 'entityMappings') -and $TemplateProps.entityMappings) {
    $p.entityMappings = Normalize-EntityMappings $TemplateProps.entityMappings
  }

  # Required data connectors (opcional)
  if ((Has-Prop $TemplateProps 'requiredDataConnectors') -and $TemplateProps.requiredDataConnectors) {
    $p.requiredDataConnectors = $TemplateProps.requiredDataConnectors
  }

  # Event grouping (opcional)
  if ((Has-Prop $TemplateProps 'eventGroupingSettings') -and $TemplateProps.eventGroupingSettings) {
    $p.eventGroupingSettings = $TemplateProps.eventGroupingSettings
  }

  # ✅ SUPPRESSION (requerido en tu caso)
  if ((Has-Prop $TemplateProps 'suppressionEnabled') -and ($TemplateProps.suppressionEnabled -ne $null)) {
    $p.suppressionEnabled = [bool]$TemplateProps.suppressionEnabled
  } else {
    $p.suppressionEnabled = $false
  }

  if ((Has-Prop $TemplateProps 'suppressionDuration') -and $TemplateProps.suppressionDuration) {
    $p.suppressionDuration = $TemplateProps.suppressionDuration
  } else {
    $p.suppressionDuration = "PT1H"
  }

  # Opcionales varios
  if ((Has-Prop $TemplateProps 'incidentConfiguration') -and $TemplateProps.incidentConfiguration) { $p.incidentConfiguration = $TemplateProps.incidentConfiguration }
  if ((Has-Prop $TemplateProps 'alertDetailsOverride') -and $TemplateProps.alertDetailsOverride) { $p.alertDetailsOverride = $TemplateProps.alertDetailsOverride }
  if ((Has-Prop $TemplateProps 'customDetails') -and $TemplateProps.customDetails) { $p.customDetails = $TemplateProps.customDetails }
  if ((Has-Prop $TemplateProps 'templateVersion') -and $TemplateProps.templateVersion) { $p.templateVersion = $TemplateProps.templateVersion }

  return $p
}

function Get-BaseSentinelProviderPath {
  param(
    [Parameter(Mandatory = $true)][string]$SubId,
    [Parameter(Mandatory = $true)][string]$Rg,
    [Parameter(Mandatory = $true)][string]$Ws
  )
  return "/subscriptions/$SubId/resourceGroups/$Rg/providers/Microsoft.OperationalInsights/workspaces/$Ws/providers/Microsoft.SecurityInsights"
}

function Get-TemplateUri {
  param([string]$TemplateId)

  $base = Get-BaseSentinelProviderPath -SubId $SubscriptionId -Rg $ResourceGroup -Ws $WorkspaceName

  if ([string]::IsNullOrWhiteSpace($TemplateId)) {
    return "https://management.azure.com$base/alertRuleTemplates?api-version=$ApiVersion"
  }

  # ✅ ${TemplateId} evita el bug "$TemplateId?api"
  return "https://management.azure.com$base/alertRuleTemplates/${TemplateId}?api-version=$ApiVersion"
}

function Get-RuleUri {
  param([string]$RuleId)

  $base = Get-BaseSentinelProviderPath -SubId $SubscriptionId -Rg $ResourceGroup -Ws $WorkspaceName

  # ✅ ${RuleId} evita el bug "$RuleId?api"
  return "https://management.azure.com$base/alertRules/${RuleId}?api-version=$ApiVersion"
}

function Match-ByDisplayName {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][string]$Filter,
    [Parameter(Mandatory = $true)][string]$Mode
  )

  switch ($Mode) {
    'equals'     { return ($Name -eq $Filter) }
    'startswith' { return ($Name -like "$Filter*") }
    default      { return ($Name -like "*$Filter*") } # contains
  }
}

# -----------------------------
# MAIN
# -----------------------------
Write-DebugLine "inputs:"
Write-DebugLine "SubscriptionId = '$SubscriptionId'"
Write-DebugLine "ResourceGroup = '$ResourceGroup'"
Write-DebugLine "WorkspaceName = '$WorkspaceName'"
Write-DebugLine "Action = '$Action'"
Write-DebugLine "TemplateId = '$TemplateId'"
Write-DebugLine "TemplateDisplayName = '$TemplateDisplayName'"
Write-DebugLine "MatchMode = '$MatchMode'"
Write-DebugLine "NewRuleDisplayName = '$NewRuleDisplayName'"
Write-DebugLine "Enabled = '$Enabled'"

# -----------------------------
# LIST -> CSV
# -----------------------------
if ($Action -eq 'list') {
  $uri = Get-TemplateUri -TemplateId $null
  $resp = Invoke-AzRest -Method GET -Uri $uri

  $items = @()
  if ((Has-Prop $resp 'value') -and $resp.value) {
    $items = $resp.value
  } else {
    $items = @($resp)
  }

  if (-not [string]::IsNullOrWhiteSpace($TemplateDisplayName)) {
    $items = $items | Where-Object {
      $_.properties -and
      (Has-Prop $_.properties 'displayName') -and
      $_.properties.displayName -and
      (Match-ByDisplayName -Name $_.properties.displayName -Filter $TemplateDisplayName -Mode $MatchMode)
    }
  }

  $out = $items | ForEach-Object {
    $p = $_.properties
    [PSCustomObject]@{
      templateId  = $_.name
      displayName = if ($p -and (Has-Prop $p 'displayName')) { $p.displayName } else { $null }
    }
  }

  # Guardar CSV
  $csvPath = Join-Path (Get-Location) "sentinel-templates.csv"
  $out | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

  Write-Host "CSV generado: $csvPath"
  # Además lo imprimimos para que se vea en el log si quieres
  $out | ConvertTo-Csv -NoTypeInformation | ForEach-Object { Write-Host $_ }

  exit 0
}

# -----------------------------
# CREATE
# -----------------------------
if ([string]::IsNullOrWhiteSpace($TemplateId)) {
  throw "Para Action=create necesitas -TemplateId (GUID)."
}

# Obtener template completo
$tmplUri = Get-TemplateUri -TemplateId $TemplateId
$template = Invoke-AzRest -Method GET -Uri $tmplUri

if (-not $template -or -not (Has-Prop $template 'properties') -or -not $template.properties) {
  throw "La plantilla '$TemplateId' no tiene properties. No se puede crear regla."
}

$templateName = $template.properties.displayName
Write-Host "Creating Active rule from template:"
Write-Host "Template: $templateName (templateId: $TemplateId)"

# Construir rule payload
$ruleId = New-GuidString
$finalName = if ([string]::IsNullOrWhiteSpace($NewRuleDisplayName)) { $templateName } else { $NewRuleDisplayName }

$props = Normalize-TemplatePropertiesForRule -TemplateProps $template.properties
$props.displayName = $finalName
$props.enabled = [bool]$Enabled

# Guardia final entityMappings
if ((Has-Prop $props 'entityMappings') -and $props.entityMappings) {
  $props.entityMappings = Normalize-EntityMappings $props.entityMappings
}

$kind = if ((Has-Prop $template 'kind') -and $template.kind) { $template.kind } else { "Scheduled" }

$payload = [ordered]@{
  location   = $Location
  kind       = $kind
  properties = $props
}

Write-Host "New rule: $finalName (ruleId: $ruleId)"
$ruleUri = Get-RuleUri -RuleId $ruleId
Write-Host "PUT: $ruleUri"

$result = Invoke-AzRest -Method PUT -Uri $ruleUri -Body $payload

# Salida JSON
[PSCustomObject]@{
  ruleId      = $ruleId
  displayName = $finalName
  enabled     = $Enabled
  kind        = $kind
} | ConvertTo-Json -Depth 10
