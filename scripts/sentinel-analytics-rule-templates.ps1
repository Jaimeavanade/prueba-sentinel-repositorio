<#
.SYNOPSIS
  Microsoft Sentinel - Analytics Rule Templates helper:
   - List templates
   - Create an Active Scheduled rule from a template

.DESCRIPTION
  This script calls Azure Management API for Microsoft Sentinel:
   - GET templates
   - GET specific template
   - PUT active rule derived from template
  It includes a FIX for entityMappings.fieldMappings to always be an ARRAY, preventing:
   "Cannot deserialize ... List<FieldMapping> ... requires a JSON array ... Path properties.entityMappings[0].fieldMappings.identifier"
  (error seen in GitHub Actions run). 

.PARAMETER SubscriptionId
  Azure subscription ID

.PARAMETER ResourceGroup
  Resource group of the Log Analytics workspace

.PARAMETER WorkspaceName
  Log Analytics workspace name (Sentinel is enabled on it)

.PARAMETER Action
  'list' or 'create'

.PARAMETER TemplateId
  Template GUID to use (required for create)

.PARAMETER TemplateDisplayName
  Alternative filter by displayName (for list / for create selection). Optional.

.PARAMETER MatchMode
  For TemplateDisplayName filter: 'contains' (default) or 'equals' or 'startswith'

.PARAMETER NewRuleDisplayName
  If empty, uses template displayName

.PARAMETER Enabled
  true/false for created rule

.PARAMETER Location
  Optional. If not provided, set to 'global' (works for SecurityInsights resources)

.EXAMPLE
  pwsh ./scripts/sentinel-analytics-rule-templates.ps1 `
    -SubscriptionId "xxxx" -ResourceGroup "rg" -WorkspaceName "law" `
    -Action list

.EXAMPLE
  pwsh ./scripts/sentinel-analytics-rule-templates.ps1 `
    -SubscriptionId "xxxx" -ResourceGroup "rg" -WorkspaceName "law" `
    -Action create -TemplateId "106813db-679e-4382-a51b-1bfc463befc3" -Enabled $true
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory=$true)]
  [string]$ResourceGroup,

  [Parameter(Mandatory=$true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory=$true)]
  [ValidateSet('list','create')]
  [string]$Action,

  [Parameter(Mandatory=$false)]
  [string]$TemplateId,

  [Parameter(Mandatory=$false)]
  [string]$TemplateDisplayName,

  [Parameter(Mandatory=$false)]
  [ValidateSet('contains','equals','startswith')]
  [string]$MatchMode = 'contains',

  [Parameter(Mandatory=$false)]
  [string]$NewRuleDisplayName,

  [Parameter(Mandatory=$false)]
  [bool]$Enabled = $true,

  [Parameter(Mandatory=$false)]
  [string]$Location = 'global',

  [Parameter(Mandatory=$false)]
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

function Get-AzAccessToken {
  # Uses az cli (works great inside GitHub actions after azure/login@v2)
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv 2>$null
  if ([string]::IsNullOrWhiteSpace($t)) {
    throw "No se pudo obtener access token. Asegúrate de haber hecho 'azure/login' o 'az login'."
  }
  return $t
}

function Invoke-AzRest {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('GET','PUT','POST','DELETE','PATCH')]
    [string]$Method,
    [Parameter(Mandatory=$true)]
    [string]$Uri,
    [Parameter(Mandatory=$false)]
    $Body
  )

  $token = Get-AzAccessToken
  $headers = @{
    Authorization = "Bearer $token"
    'Content-Type' = 'application/json'
  }

  if ($null -eq $Body) {
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
  } else {
    $json = if ($Body -is [string]) { $Body } else { ($Body | ConvertTo-Json -Depth 100) }
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
  }
}

function New-Guid {
  return ([guid]::NewGuid().ToString())
}

function ConvertTo-ArrayIfNeeded {
  param([Parameter(ValueFromPipeline=$true)] $Value)

  if ($null -eq $Value) { return @() }

  # If it's already a list/array (but not string), return as array
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string]) -and
      ($Value.GetType().IsArray -or $Value -is [System.Collections.IList])) {
    return @($Value)
  }

  # Wrap single object
  return @($Value)
}

function Normalize-EntityMappings {
  param(
    [Parameter(Mandatory=$false)]
    $EntityMappings
  )

  if ($null -eq $EntityMappings) { return $null }

  $normalized = @()

  foreach ($em in (ConvertTo-ArrayIfNeeded $EntityMappings)) {
    if ($null -eq $em) { continue }

    # Clone to PSCustomObject for safe property writes
    $emObj = [PSCustomObject]@{}
    foreach ($p in $em.PSObject.Properties) {
      $emObj | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force
    }

    # Ensure fieldMappings is ALWAYS an array
    $fmArray = @()
    foreach ($m in (ConvertTo-ArrayIfNeeded $emObj.fieldMappings)) {
      if ($null -eq $m) { continue }

      $identifier = $null
      $columnName = $null

      if ($m.PSObject.Properties.Name -contains 'identifier') { $identifier = $m.identifier }
      if ($m.PSObject.Properties.Name -contains 'columnName') { $columnName = $m.columnName }

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
  param(
    [Parameter(Mandatory=$true)]
    $TemplateProps
  )

  # We build a "Scheduled" rule properties object from template.properties
  # Keep only fields that are relevant/accepted; ignore unknowns safely.
  $p = [ordered]@{}

  # Required/typical fields
  if ($TemplateProps.displayName) { $p.displayName = $TemplateProps.displayName }
  if ($TemplateProps.description) { $p.description = $TemplateProps.description }
  if ($TemplateProps.severity) { $p.severity = $TemplateProps.severity }
  if ($TemplateProps.query) { $p.query = $TemplateProps.query }

  # Scheduling fields (may differ depending on template)
  if ($TemplateProps.queryFrequency) { $p.queryFrequency = $TemplateProps.queryFrequency }
  if ($TemplateProps.queryPeriod) { $p.queryPeriod = $TemplateProps.queryPeriod }
  if ($TemplateProps.triggerOperator) { $p.triggerOperator = $TemplateProps.triggerOperator }
  if ($TemplateProps.triggerThreshold) { $p.triggerThreshold = $TemplateProps.triggerThreshold }

  # Tactics/Techniques
  if ($TemplateProps.tactics) { $p.tactics = $TemplateProps.tactics }
  if ($TemplateProps.techniques) { $p.techniques = $TemplateProps.techniques }

  # Entity mappings (FIX HERE)
  if ($TemplateProps.entityMappings) {
    $p.entityMappings = Normalize-EntityMappings $TemplateProps.entityMappings
  }

  # Required data connectors (optional)
  if ($TemplateProps.requiredDataConnectors) { $p.requiredDataConnectors = $TemplateProps.requiredDataConnectors }

  # Event grouping/suppression (optional)
  if ($TemplateProps.eventGroupingSettings) { $p.eventGroupingSettings = $TemplateProps.eventGroupingSettings }
  if ($TemplateProps.suppressionEnabled -ne $null) { $p.suppressionEnabled = [bool]$TemplateProps.suppressionEnabled }
  if ($TemplateProps.suppressionDuration) { $p.suppressionDuration = $TemplateProps.suppressionDuration }

  # Incident configuration (optional)
  if ($TemplateProps.incidentConfiguration) { $p.incidentConfiguration = $TemplateProps.incidentConfiguration }
  if ($TemplateProps.alertDetailsOverride) { $p.alertDetailsOverride = $TemplateProps.alertDetailsOverride }
  if ($TemplateProps.customDetails) { $p.customDetails = $TemplateProps.customDetails }

  # Other optional fields often present
  if ($TemplateProps.templateVersion) { $p.templateVersion = $TemplateProps.templateVersion }

  return $p
}

function Get-BaseSentinelProviderPath {
  param(
    [Parameter(Mandatory=$true)][string]$SubId,
    [Parameter(Mandatory=$true)][string]$Rg,
    [Parameter(Mandatory=$true)][string]$Ws
  )

  # Microsoft Sentinel resources are nested:
  # /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{ws}/providers/Microsoft.SecurityInsights/...
  return "/subscriptions/$SubId/resourceGroups/$Rg/providers/Microsoft.OperationalInsights/workspaces/$Ws/providers/Microsoft.SecurityInsights"
}

function Get-TemplateUri {
  param([string]$TemplateId)
  $base = Get-BaseSentinelProviderPath -SubId $SubscriptionId -Rg $ResourceGroup -Ws $WorkspaceName
  if ([string]::IsNullOrWhiteSpace($TemplateId)) {
    return "https://management.azure.com$base/alertRuleTemplates?api-version=$ApiVersion"
  }
  return "https://management.azure.com$base/alertRuleTemplates/$TemplateId?api-version=$ApiVersion"
}

function Get-RuleUri {
  param([string]$RuleId)
  $base = Get-BaseSentinelProviderPath -SubId $SubscriptionId -Rg $ResourceGroup -Ws $WorkspaceName
  return "https://management.azure.com$base/alertRules/$RuleId?api-version=$ApiVersion"
}

function Match-ByDisplayName {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$Filter,
    [Parameter(Mandatory=$true)][string]$Mode
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
  if ($resp.value) { $items = $resp.value } else { $items = @($resp) }

  if (-not [string]::IsNullOrWhiteSpace($TemplateDisplayName)) {
    $items = $items | Where-Object {
      $_.properties -and $_.properties.displayName -and (Match-ByDisplayName -Name $_.properties.displayName -Filter $TemplateDisplayName -Mode $MatchMode)
    }
  }

  # Output minimal list as JSON for easy consumption in pipelines
  $out = $items | ForEach-Object {
    [PSCustomObject]@{
      templateId   = $_.name
      displayName  = $_.properties.displayName
      kind         = $_.kind
      severity     = $_.properties.severity
      tactics      = $_.properties.tactics
      techniques   = $_.properties.techniques
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

  # If templateId not provided, try resolve by displayName
  $uriList = Get-TemplateUri -TemplateId $null
  $respList = Invoke-AzRest -Method GET -Uri $uriList
  $items = @()
  if ($respList.value) { $items = $respList.value } else { $items = @($respList) }

  $match = $items | Where-Object {
    $_.properties -and $_.properties.displayName -and (Match-ByDisplayName -Name $_.properties.displayName -Filter $TemplateDisplayName -Mode $MatchMode)
  } | Select-Object -First 1

  if (-not $match) {
    throw "No se encontró ninguna plantilla con displayName '$TemplateDisplayName' (modo: $MatchMode)."
  }

  $TemplateId = $match.name
}

# Get template details
$tmplUri = Get-TemplateUri -TemplateId $TemplateId
$template = Invoke-AzRest -Method GET -Uri $tmplUri
if (-not $template.properties) {
  throw "La plantilla '$TemplateId' no tiene properties. No se puede crear regla."
}

$templateName = $template.properties.displayName
Write-Host "Creating Active rule from template:"
Write-Host "Template: $templateName (templateId: $TemplateId)"

# Build rule payload
$ruleId = New-Guid
$finalName = if ([string]::IsNullOrWhiteSpace($NewRuleDisplayName)) { $templateName } else { $NewRuleDisplayName }

$props = Normalize-TemplatePropertiesForRule -TemplateProps $template.properties
$props.displayName = $finalName
$props.enabled = [bool]$Enabled

# Final FIX guard: ensure entityMappings.fieldMappings array just before sending
if ($props.entityMappings) {
  $props.entityMappings = Normalize-EntityMappings $props.entityMappings
}

# Kind: most templates are Scheduled. If template.kind exists, keep it; otherwise default Scheduled.
$kind = if ($template.kind) { $template.kind } else { "Scheduled" }

$payload = [ordered]@{
  location   = $Location
  kind       = $kind
  properties = $props
}

Write-Host "New rule: $finalName (ruleId: $ruleId)"
$ruleUri = Get-RuleUri -RuleId $ruleId
Write-Host "PUT: $ruleUri"

# OPTIONAL: debug snippet about the problematic path
if ($payload.properties.entityMappings) {
  Write-DebugLine "payload.properties.entityMappings (sanity check):"
  Write-Host ($payload.properties.entityMappings | ConvertTo-Json -Depth 20)
}

# Send
$result = Invoke-AzRest -Method PUT -Uri $ruleUri -Body $payload

# Output created rule id and name
[PSCustomObject]@{
  ruleId      = $ruleId
  displayName = $finalName
  enabled     = $Enabled
  kind        = $kind
} | ConvertTo-Json -Depth 10
