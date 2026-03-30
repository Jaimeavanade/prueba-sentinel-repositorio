<#
.SYNOPSIS
  Microsoft Sentinel - Analytics Rule Templates helper:
   - list: Lists templates (optionally filter by displayName)
   - create: Creates an active analytics rule from a template

.FIXES INCLUDED
  - Prevent "$TemplateId?api" parsing: use ${TemplateId}
  - Prevent "$RuleId?api" parsing: use ${RuleId}
  - StrictMode-safe property access (Has-Prop + parentheses with -and)
  - Normalize entityMappings.fieldMappings to ARRAY
  - Ensure required suppression fields exist:
      suppressionEnabled (bool) + suppressionDuration (ISO8601) ALWAYS
      Fixes: "Required property 'suppressionDuration' not found in JSON" [1]()
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
  [ValidateSet('list', 'create')]
  [string]$Action,

  [Parameter(Mandatory = $false)]
  [string]$TemplateId,

  [Parameter(Mandatory = $false)]
  [string]$TemplateDisplayName,

  [Parameter(Mandatory = $false)]
  [ValidateSet('contains', 'equals', 'startswith')]
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
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv 2>$null
  if ([string]::IsNullOrWhiteSpace($t)) {
    throw "No se pudo obtener access token. Asegúrate de haber hecho azure/login@v2 o az login."
  }
  return $t
}

function Invoke-AzRest {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('GET', 'PUT', 'POST', 'DELETE', 'PATCH')]
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

function New-Guid { return ([guid]::NewGuid().ToString()) }

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
  param([Parameter(Mandatory = $false)] $EntityMappings)

  if ($null -eq $EntityMappings) { return $null }

  $normalized = @()

  foreach ($em in (ConvertTo-ArrayIfNeeded $EntityMappings)) {
    if ($null -eq $em) { continue }

    $emObj = [PSCustomObject]@{}
    foreach ($p in $em.PSObject.Properties) {
      $emObj | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force
    }

    $fmArray = @()
    foreach ($m in (ConvertTo-ArrayIfNeeded $emObj.fieldMappings)) {
      if ($null -eq $m) { continue }

      $identifier = $null
      $columnName = $null

      # Soporta PSCustomObject y Hashtable/Dictionary
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
  param([Parameter(Mandatory = $true)] $TemplateProps)

  $p = [ordered]@{}

  # Campos típicos
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

  # Entity mappings (FIX array)
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

  # ✅ SUPPRESSION (OBLIGATORIO en tu API / payload)
  # Si viene de plantilla, lo respetamos. Si NO viene, ponemos defaults seguros.
  if ((Has-Prop $TemplateProps 'suppressionEnabled') -and ($TemplateProps.suppressionEnabled -ne $null)) {
    $p.suppressionEnabled = [bool]$TemplateProps.suppressionEnabled
  } else {
    $p.suppressionEnabled = $false
  }

  if ((Has-Prop $TemplateProps 'suppressionDuration') -and $TemplateProps.suppressionDuration) {
    $p.suppressionDuration = $TemplateProps.suppressionDuration
  } else {
    # Default ISO8601 1h (válido)
    $p.suppressionDuration = "PT1H"
  }

  # Incident config / overrides (opcionales)
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

  return "https://management.azure.com$base/alertRuleTemplates/${TemplateId}?api-version=$ApiVersion"
}

function Get-RuleUri {
  param([string]$RuleId)

  $base = Get-BaseSentinelProviderPath -SubId $SubscriptionId -Rg $ResourceGroup -Ws $WorkspaceName
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
    default      { return ($Name -like "*$Filter*") }
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

if ($Action -eq 'list') {
  $uri = Get-TemplateUri -TemplateId $null
  $resp = Invoke-AzRest -Method GET -Uri $uri

  $items = @()
  if ((Has-Prop $resp 'value') -and $resp.value) { $items = $resp.value } else { $items = @($resp) }

  if (-not [string]::IsNullOrWhiteSpace($TemplateDisplayName)) {
    $items = $items | Where-Object {
      $_.properties -and (Has-Prop $_.properties 'displayName') -and $_.properties.displayName -and
      (Match-ByDisplayName -Name $_.properties.displayName -Filter $TemplateDisplayName -Mode $MatchMode)
    }
  }

  $out = $items | ForEach-Object {
    [PSCustomObject]@{
      templateId  = $_.name
      displayName = $_.properties.displayName
      kind        = $_.kind
      severity    = $_.properties.severity
      tactics     = $_.properties.tactics
      techniques  = $_.properties.techniques
    }
  }

  $out | ConvertTo-Json -Depth 10
  exit 0
}

# CREATE
if ([string]::IsNullOrWhiteSpace($TemplateId)) {
  if ([string]::IsNullOrWhiteSpace($TemplateDisplayName)) {
    throw "Para Action=create necesitas -TemplateId o -TemplateDisplayName."
  }

  $uriList = Get-TemplateUri -TemplateId $null
  $respList = Invoke-AzRest -Method GET -Uri $uriList
  $items = @()
  if ((Has-Prop $respList 'value') -and $respList.value) { $items = $respList.value } else { $items = @($respList) }

  $match = $items | Where-Object {
    $_.properties -and (Has-Prop $_.properties 'displayName') -and $_.properties.displayName -and
    (Match-ByDisplayName -Name $_.properties.displayName -Filter $TemplateDisplayName -Mode $MatchMode)
  } | Select-Object -First 1

  if (-not $match) {
    throw "No se encontró ninguna plantilla con displayName '$TemplateDisplayName' (modo: $MatchMode)."
  }

  $TemplateId = $match.name
}

$tmplUri = Get-TemplateUri -TemplateId $TemplateId
$template = Invoke-AzRest -Method GET -Uri $tmplUri

if (-not $template -or -not (Has-Prop $template 'properties') -or -not $template.properties) {
  throw "La plantilla '$TemplateId' no tiene properties. No se puede crear regla."
}

$templateName = $template.properties.displayName
Write-Host "Creating Active rule from template:"
Write-Host "Template: $templateName (templateId: $TemplateId)"

$ruleId = New-Guid
$finalName = if ([string]::IsNullOrWhiteSpace($NewRuleDisplayName)) { $templateName } else { $NewRuleDisplayName }

$props = Normalize-TemplatePropertiesForRule -TemplateProps $template.properties
$props.displayName = $finalName
$props.enabled = [bool]$Enabled

# Refuerzo final: entityMappings -> array
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

[PSCustomObject]@{
  ruleId      = $ruleId
  displayName = $finalName
  enabled     = $Enabled
  kind        = $kind
} | ConvertTo-Json -Depth 10
