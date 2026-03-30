<#
.SYNOPSIS
  List and create Microsoft Sentinel Analytics Rules from Rule Templates.

.REQUIRED ENV VARS
  AZURE_SUBSCRIPTION_ID
  SENTINEL_RESOURCE_GROUP
  SENTINEL_WORKSPACE_NAME
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

function Ensure-AzCli { $null = & az version | Out-String }

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
  $headers = @{ Authorization="Bearer $(Get-ArmToken)"; "Content-Type"="application/json" }
  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Depth 120
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
  return $default
}

# ---- Normalizadores robustos (clave) ----
function Ensure-ArrayGeneric($value) {
  if ($null -eq $value) { return $null }
  return [object[]]@($value)      # objeto -> [obj], array -> array
}

function Ensure-StringArray($value) {
  if ($null -eq $value) { return $null }

  if ($value -is [string]) {      # "Exfiltration" -> ["Exfiltration"]
    return [object[]]@($value)
  }

  if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
    return [object[]]@(@($value) | ForEach-Object { $_.ToString() })
  }

  return [object[]]@($value.ToString())
}

# Blindaje FINAL justo antes del PUT
function Normalize-RuleProperties([hashtable]$p) {
  if ($p.ContainsKey("tactics"))                { $p["tactics"] = Ensure-StringArray $p["tactics"] }
  if ($p.ContainsKey("techniques"))             { $p["techniques"] = Ensure-StringArray $p["techniques"] }
  if ($p.ContainsKey("entityMappings"))         { $p["entityMappings"] = Ensure-ArrayGeneric $p["entityMappings"] }
  if ($p.ContainsKey("requiredDataConnectors")) { $p["requiredDataConnectors"] = Ensure-ArrayGeneric $p["requiredDataConnectors"] }
  return $p
}

function Remove-NullProperties($obj) {
  if ($null -eq $obj) { return $null }

  if ($obj -is [System.Collections.IDictionary]) {
    foreach ($k in @($obj.Keys)) {
      if ($null -eq $obj[$k]) { $obj.Remove($k) | Out-Null }
      else {
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
    $h = @{}
    foreach ($p in $obj.PSObject.Properties) {
      if ($null -ne $p.Value) { $h[$p.Name] = Remove-NullProperties $p.Value }
    }
    return $h
  }

  return $obj
}

# ---------------- Context ----------------
Ensure-AzCli
$subId = Get-EnvOrThrow "AZURE_SUBSCRIPTION_ID"
$rg    = Get-EnvOrThrow "SENTINEL_RESOURCE_GROUP"
$ws    = Get-EnvOrThrow "SENTINEL_WORKSPACE_NAME"

$base = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights"

function Get-RuleTemplates {
  (Invoke-ArmRest -Method GET -Uri "$base/alertRuleTemplates?api-version=$ApiVersion").value
}
function Get-RuleTemplateById([string]$id) {
  Invoke-ArmRest -Method GET -Uri "$base/alertRuleTemplates/$($id)?api-version=$ApiVersion"
}

# ---------------- LIST ----------------
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

# ---------------- CREATE ----------------
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

  $queryFrequency   = Get-PropValue $tp "queryFrequency" $DefaultQueryFrequency
  $queryPeriod      = Get-PropValue $tp "queryPeriod"    $DefaultQueryPeriod
  $triggerOperator  = Get-PropValue $tp "triggerOperator" $DefaultTriggerOperator
  $triggerThreshold = Get-PropValue $tp "triggerThreshold" $DefaultTriggerThreshold

  $suppEnabled = [bool](Get-PropValue $tp "suppressionEnabled" $DefaultSuppressionEnabled)
  $suppDur     = Get-PropValue $tp "suppressionDuration" $DefaultSuppressionDuration

  $properties = [ordered]@{
    displayName            = $(if ([string]::IsNullOrWhiteSpace($NewRuleDisplayName)) { $tp.displayName } else { $NewRuleDisplayName })
    description            = Get-PropValue $tp "description"
    severity               = Get-PropValue $tp "severity"
    enabled                = $Enabled

    query                  = Get-PropValue $tp "query"
    queryFrequency         = $queryFrequency
    queryPeriod            = $queryPeriod
    triggerOperator        = $triggerOperator
    triggerThreshold       = $triggerThreshold

    tactics                = Get-PropValue $tp "tactics"
    techniques             = Get-PropValue $tp "techniques"
    entityMappings         = Get-PropValue $tp "entityMappings"
    requiredDataConnectors = Get-PropValue $tp "requiredDataConnectors"

    suppressionEnabled     = $suppEnabled
    suppressionDuration    = $suppDur

    alertRuleTemplateName  = $tpl.name
    templateVersion        = Get-PropValue $tp "version"
  }

  # ✅ NORMALIZACIÓN FINAL (esto evita tu error actual de Exfiltration/CredentialAccess)
  $properties = Normalize-RuleProperties -p ([hashtable]$properties)

  $body = [ordered]@{ kind="Scheduled"; properties=$properties }
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
