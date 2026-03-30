<#
.SYNOPSIS
  List and create Microsoft Sentinel Analytics Rules from Rule Templates (alertRuleTemplates -> alertRules)

.REQUIRED ENV VARS
  AZURE_SUBSCRIPTION_ID
  SENTINEL_RESOURCE_GROUP
  SENTINEL_WORKSPACE_NAME

.DESCRIPTION
  -Action list   : lista Rule Templates y opcionalmente exporta a CSV/JSON
  -Action create : crea una regla activa desde un template (equivalente a "Create rule" del portal)

Robust fixes:
  - tactics ALWAYS array
  - techniques ALWAYS array
  - entityMappings ALWAYS array
  - requiredDataConnectors ALWAYS array
  - suppressionDuration ALWAYS present (default PT1H)
  - suppressionEnabled ALWAYS present (default false)
  - StrictMode safe (no props inexistentes)
  - Evita bug PowerShell con '?api-version' usando $() en URLs
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [ValidateSet("list","create")]
  [string]$Action = "list",

  [Parameter(Mandatory = $false)]
  [string]$TemplateId,

  [Parameter(Mandatory = $false)]
  [string]$TemplateDisplayName,

  [Parameter(Mandatory = $false)]
  [ValidateSet("exact","contains")]
  [string]$MatchMode = "contains",

  [Parameter(Mandatory = $false)]
  [string]$NewRuleDisplayName,

  # list: export
  [Parameter(Mandatory = $false)]
  [string]$OutFile,

  # API
  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  # create: enable
  [Parameter(Mandatory = $false)]
  [bool]$Enabled = $true,

  # create: defaults (por si el template no los trae)
  [Parameter(Mandatory = $false)]
  [string]$DefaultQueryFrequency = "PT1H",

  [Parameter(Mandatory = $false)]
  [string]$DefaultQueryPeriod = "PT1H",

  [Parameter(Mandatory = $false)]
  [ValidateSet("GreaterThan","GreaterThanOrEqual","LessThan","LessThanOrEqual","Equal","NotEqual")]
  [string]$DefaultTriggerOperator = "GreaterThan",

  [Parameter(Mandatory = $false)]
  [int]$DefaultTriggerThreshold = 0,

  # suppression defaults
  [Parameter(Mandatory = $false)]
  [string]$DefaultSuppressionDuration = "PT1H",

  [Parameter(Mandatory = $false)]
  [bool]$DefaultSuppressionEnabled = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------------
# Helpers
# -------------------------
function Get-EnvOrThrow([string]$name) {
  $v = [Environment]::GetEnvironmentVariable($name)
  if ([string]::IsNullOrWhiteSpace($v)) { throw "Missing required env var: $name" }
  return $v
}

function Ensure-AzCli {
  try { $null = & az version | Out-String } catch { throw "Azure CLI (az) not found." }
}

function Get-ArmToken {
  $t = & az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv
  if ([string]::IsNullOrWhiteSpace($t)) { throw "Failed to obtain ARM token via az." }
  return $t
}

function Invoke-ArmRest {
  param(
    [Parameter(Mandatory = $true)][ValidateSet("GET","PUT","POST","PATCH","DELETE")]
    [string]$Method,
    [Parameter(Mandatory = $true)]
    [string]$Uri,
    [Parameter(Mandatory = $false)]
    $Body
  )

  $headers = @{
    Authorization  = "Bearer $(Get-ArmToken)"
    "Content-Type" = "application/json"
  }

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

# Normalizadores robustos
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

# Blindaje final antes del PUT
function Normalize-RuleProperties([hashtable]$p) {
  if ($p.ContainsKey("tactics"))                { $p["tactics"] = Ensure-StringArray  $p["tactics"] }
  if ($p.ContainsKey("techniques"))             { $p["techniques"] = Ensure-StringArray $p["techniques"] }
  if ($p.ContainsKey("entityMappings"))         { $p["entityMappings"] = Ensure-ArrayGeneric $p["entityMappings"] }
  if ($p.ContainsKey("requiredDataConnectors")) { $p["requiredDataConnectors"] = Ensure-ArrayGeneric $p["requiredDataConnectors"] }
  return $p
}

# Quita nulos sin romper arrays
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
    $h = @{}
    foreach ($p in $obj.PSObject.Properties) {
      if ($null -ne $p.Value) { $h[$p.Name] = Remove-NullProperties $p.Value }
    }
    return $h
  }

  return $obj
}

# -------------------------
# Context
# -------------------------
Ensure-AzCli

$subId = Get-EnvOrThrow "AZURE_SUBSCRIPTION_ID"
$rg    = Get-EnvOrThrow "SENTINEL_RESOURCE_GROUP"
$ws    = Get-EnvOrThrow "SENTINEL_WORKSPACE_NAME"

$base = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights"

function Get-RuleTemplates {
  (Invoke-ArmRest -Method GET -Uri "$base/alertRuleTemplates?api-version=$ApiVersion").value
}

function Get-RuleTemplateById([string]$id) {
  # IMPORTANT: $() antes de '?'
  Invoke-ArmRest -Method GET -Uri "$base/alertRuleTemplates/$($id)?api-version=$ApiVersion"
}

# -------------------------
# LIST
# -------------------------
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
    if ($ext -eq ".csv") {
      $view | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutFile
    } else {
      $view | ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 $OutFile
    }
    Write-Host "Saved templates list to: $OutFile"
  }

  $view | Sort-Object displayName | Format-Table -AutoSize
  exit 0
}

# -------------------------
# CREATE
# -------------------------
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

  # Resolver template
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
    if ($matches.Count -ne 1) {
      throw "TemplateDisplayName matched $($matches.Count) templates. Use TemplateId."
    }
    $tpl = Get-RuleTemplateById $matches[0].name
  }

  $tp = $tpl.properties
  $newId = (New-Guid).Guid
  $ruleUri = "$base/alertRules/$($newId)?api-version=$ApiVersion"

  # defaults si faltan
  $queryFrequency   = Get-PropValue $tp "queryFrequency"   $DefaultQueryFrequency
  $queryPeriod      = Get-PropValue $tp "queryPeriod"      $DefaultQueryPeriod
  $triggerOperator  = Get-PropValue $tp "triggerOperator"  $DefaultTriggerOperator
  $triggerThreshold = Get-PropValue $tp "triggerThreshold" $DefaultTriggerThreshold

  # suppression (siempre presentes)
  $suppEnabled = Get-PropValue $tp "suppressionEnabled"  $DefaultSuppressionEnabled
  $suppDur     = Get-PropValue $tp "suppressionDuration" $DefaultSuppressionDuration

  $displayName = if ([string]::IsNullOrWhiteSpace($NewRuleDisplayName)) { $tp.displayName } else { $NewRuleDisplayName }

  # Construir propiedades
  $properties = [ordered]@{
    displayName            = $displayName
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

    suppressionEnabled     = [bool]$suppEnabled
    suppressionDuration    = $suppDur

    alertRuleTemplateName  = $tpl.name
    templateVersion        = Get-PropValue $tp "version"
  }

  # ✅ Normalización final
  $properties = Normalize-RuleProperties -p ([hashtable]$properties)

  # Kind: por defecto Scheduled
  $ruleKind = "Scheduled"

  $body = [ordered]@{
    kind       = $ruleKind
    properties = $properties
  }

  $bodyClean = Remove-NullProperties $body

  # Debug de tipos antes del PUT (para que el log sea autoexplicativo)
  Write-Host "DEBUG payload types:"
  Write-Host ("  tactics type: " + ($(if($bodyClean.properties.tactics){$bodyClean.properties.tactics.GetType().FullName}else{"<null>"})))
  Write-Host ("  techniques type: " + ($(if($bodyClean.properties.techniques){$bodyClean.properties.techniques.GetType().FullName}else{"<null>"})))
  Write-Host ("  entityMappings type: " + ($(if($bodyClean.properties.entityMappings){$bodyClean.properties.entityMappings.GetType().FullName}else{"<null>"})))
  Write-Host ("  suppressionEnabled: " + $bodyClean.properties.suppressionEnabled)
  Write-Host ("  suppressionDuration: " + $bodyClean.properties.suppressionDuration)

  Write-Host "Creating Active rule from template:"
  Write-Host "  Template: $($tp.displayName) (templateId: $($tpl.name))"
  Write-Host "  New rule:  $displayName (ruleId: $newId)"
  Write-Host "  PUT: $ruleUri"

  Invoke-ArmRest -Method PUT -Uri $ruleUri -Body $bodyClean | Out-Null
  Write-Host "✅ Done."
  exit 0
}

throw "Unknown -Action value: $Action"
