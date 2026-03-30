<#
List & Create Sentinel Analytics Rules from Rule Templates (alertRuleTemplates -> alertRules)
Auth: Azure CLI token (works with azure/login OIDC)
#>

[CmdletBinding()]
param(
  [ValidateSet("list","create")]
  [string]$Action = "list",

  [string]$TemplateId,
  [string]$TemplateDisplayName,

  [ValidateSet("exact","contains")]
  [string]$MatchMode = "contains",

  [string]$NewRuleDisplayName,
  [string]$OutFile,

  [string]$ApiVersion = "2025-09-01",
  [bool]$Enabled = $true,

  [string]$DefaultQueryFrequency = "PT1H",
  [string]$DefaultQueryPeriod    = "PT1H",

  [ValidateSet("GreaterThan","GreaterThanOrEqual","LessThan","LessThanOrEqual","Equal","NotEqual")]
  [string]$DefaultTriggerOperator = "GreaterThan",

  [int]$DefaultTriggerThreshold = 0,

  [string]$DefaultSuppressionDuration = "PT1H",
  [bool]$DefaultSuppressionEnabled = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-EnvOrThrow([string]$name) {
  $v = [Environment]::GetEnvironmentVariable($name)
  if ([string]::IsNullOrWhiteSpace($v)) { throw "Missing required env var: $name" }
  $v
}

function Ensure-AzCli {
  try { $null = & az version | Out-String } catch { throw "Azure CLI (az) not found." }
}

function Get-ArmToken {
  $t = & az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv
  if ([string]::IsNullOrWhiteSpace($t)) { throw "Failed to obtain ARM token via az." }
  $t
}

function Invoke-ArmRest {
  param(
    [ValidateSet("GET","PUT","POST","PATCH","DELETE")]
    [string]$Method,
    [string]$Uri,
    $Body
  )
  $headers = @{
    Authorization  = "Bearer $(Get-ArmToken)"
    "Content-Type" = "application/json"
  }
  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Depth 100
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
  } else {
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
  }
}

function Has-Prop($obj, [string]$name) {
  return ($null -ne $obj -and $null -ne $obj.PSObject.Properties[$name])
}
function Get-PropValue($obj, [string]$name, $default = $null) {
  if (Has-Prop $obj $name) { return $obj.$name }
  $default
}

# ---- Normalizadores robustos ----
function Ensure-ArrayGeneric($value) {
  if ($null -eq $value) { return $null }
  return [object[]]@($value)
}

function Ensure-StringArray($value) {
  if ($null -eq $value) { return $null }

  if ($value -is [string]) {
    return [object[]]@($value)
  }

  if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
    return [object[]]@(@($value) | ForEach-Object { $_.ToString() })
  }

  return [object[]]@($value.ToString())
}

# Normalización FINAL justo antes del PUT (esto evita que algo se “escape” como string)
function Normalize-RuleProperties([hashtable]$props) {
  if ($props.ContainsKey("tactics"))              { $props["tactics"] = Ensure-StringArray  $props["tactics"] }
  if ($props.ContainsKey("techniques"))           { $props["techniques"] = Ensure-StringArray $props["techniques"] }
  if ($props.ContainsKey("entityMappings"))       { $props["entityMappings"] = Ensure-ArrayGeneric $props["entityMappings"] }
  if ($props.ContainsKey("requiredDataConnectors")) { $props["requiredDataConnectors"] = Ensure-ArrayGeneric $props["requiredDataConnectors"] }
  return $props
}

function Remove-NullProperties($obj) {
  if ($null -eq $obj) { return $null }

  if ($obj -is [System.Collections.IDictionary]) {
    foreach ($k in @($obj.Keys)) {
      if ($null -eq $obj[$k]) {
        $obj.Remove($k) | Out-Null
      } else {
        $obj[$k] = Remove-NullProperties $obj[$k]
        if ($null -eq $obj[$k]) { $obj.Remove($k) | Out-Null }
      }
    }
    return $obj
  }

  if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
    $clean = @()
    foreach ($item in @($obj)) {
      $ci = Remove-NullProperties $item
      if ($null -ne $ci) { $clean += $ci }
    }
    return [object[]]$clean
  }

  if ($obj -is [pscustomobject]) {
    $hash = @{}
    foreach ($p in $obj.PSObject.Properties) {
      if ($null -ne $p.Value) { $hash[$p.Name] = Remove-NullProperties $p.Value }
    }
    return $hash
  }

  return $obj
}

# ---- Context ----
Ensure-AzCli
$subId = Get-EnvOrThrow "AZURE_SUBSCRIPTION_ID"
$rg    = Get-EnvOrThrow "SENTINEL_RESOURCE_GROUP"
$ws    = Get-EnvOrThrow "SENTINEL_WORKSPACE_NAME"
$base  = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights"

function Get-RuleTemplates {
  (Invoke-ArmRest -Method GET -Uri "$base/alertRuleTemplates?api-version=$ApiVersion").value
}

function Get-RuleTemplateById([string]$id) {
  # IMPORTANT: $() before '?' to avoid '$id?api' bug
  Invoke-ArmRest -Method GET -Uri "$base/alertRuleTemplates/$($id)?api-version=$ApiVersion"
}

# ---- LIST ----
if ($Action -eq "list") {
  $templates = Get-RuleTemplates
  $view = $templates | ForEach-Object {
    $p = $_.properties
    [pscustomobject]@{
      templateId  = $_.name
      displayName = Get-PropValue $p "displayName"
      severity    = Get-PropValue $p "severity"
      tactics     = ((Get-PropValue $p "tactics") -join ",")
      techniques  = ((Get-PropValue $p "techniques") -join ",")
      version     = Get-PropValue $p "version"
      kind        = $_.kind
      contentId   = Get-PropValue $p "contentId"
    }
  }

  if ($OutFile) {
    $ext = [IO.Path]::GetExtension($OutFile).ToLowerInvariant()
    if ($ext -eq ".csv") { $view | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutFile }
    else { $view | ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 $OutFile }
    Write-Host "Saved templates list to: $OutFile"
  }

  $view | Sort-Object displayName | Format-Table -AutoSize
  exit 0
}

# ---- CREATE ----
if ($Action -eq "create") {
  Write-Host "DEBUG inputs:"
  Write-Host "  TemplateId          = '$TemplateId'"
  Write-Host "  TemplateDisplayName = '$TemplateDisplayName'"
  Write-Host "  MatchMode           = '$MatchMode'"
  Write-Host "  NewRuleDisplayName  = '$NewRuleDisplayName'"
  Write-Host "  Enabled             = '$Enabled'"

  if ([string]::IsNullOrWhiteSpace($TemplateId) -and [string]::IsNullOrWhiteSpace($TemplateDisplayName)) {
    throw "For Action=create you must provide either -TemplateId or -TemplateDisplayName"
  }

  $tpl = $null
  if (-not [string]::IsNullOrWhiteSpace($TemplateId)) {
    $tpl = Get-RuleTemplateById $TemplateId
  } else {
    $all = Get-RuleTemplates
    $matches = if ($MatchMode -eq "exact") {
      @($all | Where-Object { $_.properties.displayName -eq $TemplateDisplayName })
    } else {
      @($all | Where-Object { $_.properties.displayName -like "*$TemplateDisplayName*" })
    }
    if ($matches.Count -ne 1) { throw "TemplateDisplayName matched $($matches.Count) templates. Use TemplateId." }
    $tpl = Get-RuleTemplateById $matches[0].name
  }

  $tp = $tpl.properties
  $newId = (New-Guid).Guid
  $ruleUri = "$base/alertRules/$($newId)?api-version=$ApiVersion"

  # defaults
  $queryFrequency   = Get-PropValue $tp "queryFrequency" $DefaultQueryFrequency
  $queryPeriod      = Get-PropValue $tp "queryPeriod"    $DefaultQueryPeriod
  $triggerOperator  = Get-PropValue $tp "triggerOperator" $DefaultTriggerOperator
  $triggerThreshold = Get-PropValue $tp "triggerThreshold" $DefaultTriggerThreshold

  $suppressionEnabledRaw = Get-PropValue $tp "suppressionEnabled" $DefaultSuppressionEnabled
  $suppressionDuration   = Get-PropValue $tp "suppressionDuration" $DefaultSuppressionDuration

  $properties = [ordered]@{
    displayName           = $(if ([string]::IsNullOrWhiteSpace($NewRuleDisplayName)) { $tp.displayName } else { $NewRuleDisplayName })
    description           = Get-PropValue $tp "description"
    severity              = Get-PropValue $tp "severity"
    enabled               = $Enabled

    query                 = Get-PropValue $tp "query"
    queryFrequency        = $queryFrequency
    queryPeriod           = $queryPeriod
    triggerOperator       = $triggerOperator
    triggerThreshold      = $triggerThreshold

    tactics               = Get-PropValue $tp "tactics"
    techniques            = Get-PropValue $tp "techniques"
    entityMappings        = Get-PropValue $tp "entityMappings"
    requiredDataConnectors= Get-PropValue $tp "requiredDataConnectors"

    suppressionEnabled    = [bool]$suppressionEnabledRaw
    suppressionDuration   = $suppressionDuration

    alertRuleTemplateName = $tpl.name
    templateVersion       = Get-PropValue $tp "version"
  }

  # ✅ blindaje FINAL
  $properties = Normalize-RuleProperties -props $properties
  $body = [ordered]@{
    kind = "Scheduled"
    properties = $properties
  }

  $bodyClean = Remove-NullProperties $body

  Write-Host "Creating Active rule from template:"
  Write-Host "  Template: $($tp.displayName) (templateId: $($tpl.name))"
  Write-Host "  New rule:  $($properties.displayName) (ruleId: $newId)"
  Write-Host "  PUT: $ruleUri"

  Invoke-ArmRest -Method PUT -Uri $ruleUri -Body $bodyClean | Out-Null
  Write-Host "✅ Done."
  exit 0
}

throw "Unknown -Action value: $Action"
