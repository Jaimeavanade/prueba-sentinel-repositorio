<#
.SYNOPSIS
  List and create Microsoft Sentinel Analytics Rules from Rule Templates.

.DESCRIPTION
  -Action list   : lists alertRuleTemplates and optionally exports to CSV/JSON
  -Action create : creates an alertRule from a selected alertRuleTemplate (portal "Create rule")

.REQUIRED ENV VARS
  AZURE_SUBSCRIPTION_ID
  SENTINEL_RESOURCE_GROUP
  SENTINEL_WORKSPACE_NAME

AUTH
  Uses Azure CLI token (azure/login OIDC in GitHub Actions).

NOTES
  - Fixes PowerShell "$ruleId?api" interpolation by using "$($ruleId)?api-version=..." (required)
  - ConvertTo-Json max depth is 100 in PowerShell -> enforce Depth<=100
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

    [Parameter(Mandatory = $false)]
    [string]$OutFile,

    [Parameter(Mandatory = $false)]
    [string]$ApiVersion = "2025-09-01",

    [Parameter(Mandatory = $false)]
    [bool]$Enabled = $true,

    # Defaults if missing on template (some templates omit fields)
    [Parameter(Mandatory = $false)]
    [string]$DefaultQueryFrequency = "PT1H",

    [Parameter(Mandatory = $false)]
    [string]$DefaultQueryPeriod = "PT1H",

    [Parameter(Mandatory = $false)]
    [ValidateSet("GreaterThan","GreaterThanOrEqual","LessThan","LessThanOrEqual","Equal","NotEqual")]
    [string]$DefaultTriggerOperator = "GreaterThan",

    [Parameter(Mandatory = $false)]
    [int]$DefaultTriggerThreshold = 0,

    # Suppression defaults (API may require suppressionDuration)
    [Parameter(Mandatory = $false)]
    [bool]$DefaultSuppressionEnabled = $false,

    [Parameter(Mandatory = $false)]
    [string]$DefaultSuppressionDuration = "PT1H",

    # ConvertTo-Json depth (PowerShell max 100)
    [Parameter(Mandatory = $false)]
    [ValidateRange(1,100)]
    [int]$JsonDepth = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------------
# Helpers
# -------------------------
function Get-EnvOrThrow([string]$name) {
    $v = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($v)) {
        throw "Missing required environment variable: $name"
    }
    return $v
}

function Ensure-AzCli {
    try { $null = & az version | Out-String }
    catch { throw "Azure CLI (az) not found in PATH." }
}

function Get-ArmToken {
    $t = & az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv
    if ([string]::IsNullOrWhiteSpace($t)) { throw "Failed to obtain ARM token (az account get-access-token)" }
    return $t
}

function Invoke-ArmRest {
    param(
        [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","PATCH","DELETE")]
        [string]$Method,

        [Parameter(Mandatory=$true)]
        [string]$Uri,

        [Parameter(Mandatory=$false)]
        $Body
    )

    $headers = @{
        Authorization  = "Bearer $(Get-ArmToken)"
        "Content-Type" = "application/json"
    }

    if ($null -ne $Body) {
        # IMPORTANT: PowerShell ConvertTo-Json depth max is 100
        $json = $Body | ConvertTo-Json -Depth $JsonDepth
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
    }
    else {
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

# Normalizers: always send correct JSON types
function Ensure-ArrayGeneric($value) {
    if ($null -eq $value) { return $null }
    return [object[]]@($value)   # object -> [obj], list/array -> array
}

function Ensure-StringArray($value) {
    if ($null -eq $value) { return $null }

    if ($value -is [string]) {
        return [object[]]@($value) # "T1059" -> ["T1059"]
    }

    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        return [object[]]@(@($value) | ForEach-Object { $_.ToString() })
    }

    return [object[]]@($value.ToString())
}

function Normalize-RuleProperties([hashtable]$p) {
    if ($p.ContainsKey("tactics"))                { $p["tactics"] = Ensure-StringArray  $p["tactics"] }
    if ($p.ContainsKey("techniques"))             { $p["techniques"] = Ensure-StringArray $p["techniques"] }
    if ($p.ContainsKey("entityMappings"))         { $p["entityMappings"] = Ensure-ArrayGeneric $p["entityMappings"] }
    if ($p.ContainsKey("requiredDataConnectors")) { $p["requiredDataConnectors"] = Ensure-ArrayGeneric $p["requiredDataConnectors"] }
    return $p
}

# Remove nulls without breaking arrays
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
# Context (workspace)
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
    Invoke-ArmRest -Method GET -Uri "$base/alertRuleTemplates/$($id)?api-version=$ApiVersion"
}

# -------------------------
# ACTION: LIST
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
            $view | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 -FilePath $OutFile
        }
        Write-Host "Saved templates to: $OutFile"
    }

    $view | Sort-Object displayName | Format-Table -AutoSize
    exit 0
}

# -------------------------
# ACTION: CREATE
# -------------------------
if ($Action -eq "create") {

    Write-Host "DEBUG inputs:"
    Write-Host "  TemplateId          = '$TemplateId'"
    Write-Host "  TemplateDisplayName = '$TemplateDisplayName'"
    Write-Host "  MatchMode           = '$MatchMode'"
    Write-Host "  NewRuleDisplayName  = '$NewRuleDisplayName'"
    Write-Host "  Enabled             = '$Enabled'"

    if ([string]::IsNullOrWhiteSpace($TemplateId) -and [string]::IsNullOrWhiteSpace($TemplateDisplayName)) {
        throw "For Action=create provide -TemplateId or -TemplateDisplayName"
    }

    # Resolve template
    $tpl = $null
    if (-not [string]::IsNullOrWhiteSpace($TemplateId)) {
        $tpl = Get-RuleTemplateById -id $TemplateId
    }
    else {
        $all = Get-RuleTemplates

        $matches = if ($MatchMode -eq "exact") {
            @($all | Where-Object { (Get-PropValue $_.properties "displayName") -eq $TemplateDisplayName })
        } else {
            @($all | Where-Object { (Get-PropValue $_.properties "displayName") -like "*$TemplateDisplayName*" })
        }

        if ($matches.Count -eq 0) { throw "No template matched displayName ($MatchMode): $TemplateDisplayName" }
        if ($matches.Count -gt 1) {
            Write-Host "Multiple templates matched. Use TemplateId. Candidates:"
            $matches | ForEach-Object { Write-Host ("- {0} | {1}" -f $_.name, (Get-PropValue $_.properties "displayName")) }
            throw "Ambiguous TemplateDisplayName."
        }

        $tpl = Get-RuleTemplateById -id $matches[0].name
    }

    $p = $tpl.properties
    $ruleId = (New-Guid).Guid

    # Build properties with defaults
    $displayName = if ([string]::IsNullOrWhiteSpace($NewRuleDisplayName)) { $p.displayName } else { $NewRuleDisplayName }

    $props = [ordered]@{
        displayName            = $displayName
        description            = Get-PropValue $p "description"
        severity               = Get-PropValue $p "severity"
        enabled                = $Enabled

        query                  = Get-PropValue $p "query"
        queryFrequency         = Get-PropValue $p "queryFrequency" $DefaultQueryFrequency
        queryPeriod            = Get-PropValue $p "queryPeriod"    $DefaultQueryPeriod
        triggerOperator        = Get-PropValue $p "triggerOperator" $DefaultTriggerOperator
        triggerThreshold       = Get-PropValue $p "triggerThreshold" $DefaultTriggerThreshold

        tactics                = Get-PropValue $p "tactics"
        techniques             = Get-PropValue $p "techniques"
        entityMappings         = Get-PropValue $p "entityMappings"
        requiredDataConnectors = Get-PropValue $p "requiredDataConnectors"

        # always present
        suppressionEnabled     = [bool](Get-PropValue $p "suppressionEnabled" $DefaultSuppressionEnabled)
        suppressionDuration    = Get-PropValue $p "suppressionDuration" $DefaultSuppressionDuration

        # link to template
        alertRuleTemplateName  = $tpl.name
        templateVersion        = Get-PropValue $p "version"
    }

    # Normalize and remove nulls
    $props = Normalize-RuleProperties -p ([hashtable]$props)
    $body = [ordered]@{
        kind       = "Scheduled"
        properties = $props
    }
    $bodyClean = Remove-NullProperties $body

    # Debug types before PUT
    Write-Host "DEBUG payload types:"
    Write-Host ("  tactics type: " + ($(if($bodyClean.properties.tactics){$bodyClean.properties.tactics.GetType().FullName}else{"<null>"})))
    Write-Host ("  techniques type: " + ($(if($bodyClean.properties.techniques){$bodyClean.properties.techniques.GetType().FullName}else{"<null>"})))
    Write-Host ("  entityMappings type: " + ($(if($bodyClean.properties.entityMappings){$bodyClean.properties.entityMappings.GetType().FullName}else{"<null>"})))
    Write-Host ("  requiredDataConnectors type: " + ($(if($bodyClean.properties.requiredDataConnectors){$bodyClean.properties.requiredDataConnectors.GetType().FullName}else{"<null>"})))
    Write-Host ("  suppressionEnabled: " + $bodyClean.properties.suppressionEnabled)
    Write-Host ("  suppressionDuration: " + $bodyClean.properties.suppressionDuration)

    # IMPORTANT: fix PowerShell interpolation bug by using $() before '?'
    $ruleUri = "$base/alertRules/$($ruleId)?api-version=$ApiVersion"

    Write-Host "Creating Active rule from template:"
    Write-Host "  Template: $($p.displayName) (templateId: $($tpl.name))"
    Write-Host "  New rule:  $displayName (ruleId: $ruleId)"
    Write-Host "  PUT: $ruleUri"

    Invoke-ArmRest -Method PUT -Uri $ruleUri -Body $bodyClean | Out-Null
    Write-Host "✅ Rule created OK"
    exit 0
}

throw "Unknown Action: $Action"
