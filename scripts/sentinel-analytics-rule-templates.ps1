<#
.SYNOPSIS
  List and create Microsoft Sentinel Analytics Rules from Rule Templates.

.DESCRIPTION
  - Action=list: Lists alertRuleTemplates and optionally exports to CSV/JSON.
  - Action=create: Creates an Active Analytics Rule (alertRules) from a selected template.
  Authentication uses Azure CLI token (works with azure/login OIDC on GitHub Actions).

.REQUIRED ENV VARS
  AZURE_SUBSCRIPTION_ID
  SENTINEL_RESOURCE_GROUP
  SENTINEL_WORKSPACE_NAME

FIXES
  - entityMappings must be JSON array (some templates return object)
  - tactics/techniques must be JSON arrays (some templates return a single string)
  - suppressionDuration is REQUIRED for some templates/rules -> always provide a default (PT1H) [1]()
  - avoids PowerShell parsing bug with '?' by using $() in URLs
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

    # ✅ defaults for suppression (some APIs require suppressionDuration always)
    [string]$DefaultSuppressionDuration = "PT1H",
    [bool]$DefaultSuppressionEnabled = $false
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
    catch { throw "Azure CLI (az) not found. Ensure Azure CLI is available." }
}

function Get-ArmToken {
    $t = & az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv
    if ([string]::IsNullOrWhiteSpace($t)) {
        throw "Failed to obtain ARM token via az account get-access-token"
    }
    return $t
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
        $json = $Body | ConvertTo-Json -Depth 80
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

# ✅ Force array of objects
function Ensure-ArrayGeneric($value) {
    if ($null -eq $value) { return $null }
    return [object[]]@($value)
}

# ✅ Force array of strings
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

# ✅ Remove nulls without breaking arrays
function Remove-NullProperties {
    param([Parameter(Mandatory = $true)]$obj)

    if ($null -eq $obj) { return $null }

    if ($obj -is [System.Collections.IDictionary]) {
        foreach ($k in @($obj.Keys)) {
            if ($null -eq $obj[$k]) {
                $obj.Remove($k) | Out-Null
            } else {
                $obj[$k] = Remove-NullProperties -obj $obj[$k]
                if ($null -eq $obj[$k]) { $obj.Remove($k) | Out-Null }
            }
        }
        return $obj
    }

    if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
        $clean = @()
        foreach ($item in @($obj)) {
            $ci = Remove-NullProperties -obj $item
            if ($null -ne $ci) { $clean += $ci }
        }
        return [object[]]$clean
    }

    if ($obj -is [pscustomobject]) {
        $hash = @{}
        foreach ($p in $obj.PSObject.Properties) {
            if ($null -ne $p.Value) {
                $hash[$p.Name] = Remove-NullProperties -obj $p.Value
            }
        }
        return $hash
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
    $uri = "$base/alertRuleTemplates?api-version=$ApiVersion"
    (Invoke-ArmRest -Method GET -Uri $uri).value
}

function Get-RuleTemplateById([string]$id) {
    $uri = "$base/alertRuleTemplates/$($id)?api-version=$ApiVersion"
    Invoke-ArmRest -Method GET -Uri $uri
}

function Create-RuleFromTemplate($template, [string]$displayNameOverride) {
    $newId   = (New-Guid).Guid
    $ruleUri = "$base/alertRules/$($newId)?api-version=$ApiVersion"

    $tp = $template.properties
    $ruleKind = "Scheduled"

    $displayName = if ([string]::IsNullOrWhiteSpace($displayNameOverride)) { $tp.displayName } else { $displayNameOverride }

    $queryFrequency   = if (Has-Prop $tp "queryFrequency" -and $tp.queryFrequency) { $tp.queryFrequency } else { $DefaultQueryFrequency }
    $queryPeriod      = if (Has-Prop $tp "queryPeriod" -and $tp.queryPeriod) { $tp.queryPeriod } else { $DefaultQueryPeriod }
    $triggerOperator  = if (Has-Prop $tp "triggerOperator" -and $tp.triggerOperator) { $tp.triggerOperator } else { $DefaultTriggerOperator }
    $triggerThreshold = if (Has-Prop $tp "triggerThreshold" -and $tp.triggerThreshold -ne $null) { [int]$tp.triggerThreshold } else { $DefaultTriggerThreshold }

    # ✅ Normalize arrays
    $entityMappings = Ensure-ArrayGeneric (Get-PropValue $tp "entityMappings")
    $tactics        = Ensure-StringArray  (Get-PropValue $tp "tactics")
    $techniques     = Ensure-StringArray  (Get-PropValue $tp "techniques")
    $reqConnectors  = Ensure-ArrayGeneric (Get-PropValue $tp "requiredDataConnectors")

    # ✅ Suppression REQUIRED for some templates: always send values
    $suppressionEnabled  = if (Has-Prop $tp "suppressionEnabled" -and $tp.suppressionEnabled -ne $null) { [bool]$tp.suppressionEnabled } else { $DefaultSuppressionEnabled }
    $suppressionDuration = if (Has-Prop $tp "suppressionDuration" -and $tp.suppressionDuration) { $tp.suppressionDuration } else { $DefaultSuppressionDuration }

    $properties = [ordered]@{
        displayName              = $displayName
        description              = Get-PropValue $tp "description"
        severity                 = Get-PropValue $tp "severity"
        enabled                  = $Enabled

        query                    = Get-PropValue $tp "query"
        queryFrequency           = $queryFrequency
        queryPeriod              = $queryPeriod
        triggerOperator          = $triggerOperator
        triggerThreshold         = $triggerThreshold

        tactics                  = $tactics
        techniques               = $techniques
        entityMappings           = $entityMappings

        eventGroupingSettings    = Get-PropValue $tp "eventGroupingSettings"
        incidentConfiguration    = Get-PropValue $tp "incidentConfiguration"
        alertDetailsOverride     = Get-PropValue $tp "alertDetailsOverride"
        customDetails            = Get-PropValue $tp "customDetails"

        # ✅ always present to satisfy API requirement [1]()
        suppressionEnabled       = $suppressionEnabled
        suppressionDuration      = $suppressionDuration

        alertRuleTemplateName    = $template.name
        templateVersion          = Get-PropValue $tp "version"
        requiredDataConnectors   = $reqConnectors
    }

    $body = [ordered]@{
        kind       = $ruleKind
        properties = $properties
    }

    $bodyClean = Remove-NullProperties -obj $body

    Write-Host "Creating Active rule from template:"
    Write-Host "  Template: $($tp.displayName) (templateId: $($template.name))"
    Write-Host "  New rule:  $displayName (ruleId: $newId)"
    Write-Host "  PUT: $ruleUri"

    Invoke-ArmRest -Method PUT -Uri $ruleUri -Body $bodyClean
}

# -------------------------
# LIST
# -------------------------
if ($Action -eq "list") {
    $templates = Get-RuleTemplates

    $view = $templates | ForEach-Object {
        $p = $_.properties
        [pscustomobject]@{
            templateId   = $_.name
            displayName  = Get-PropValue $p "displayName"
            severity     = Get-PropValue $p "severity"
            tactics      = (Get-PropValue $p "tactics") -join ","
            techniques   = (Get-PropValue $p "techniques") -join ","
            version      = Get-PropValue $p "version"
            createdBy    = Get-PropValue $p "createdBy"
            status       = Get-PropValue $p "status"
            kind         = $_.kind
            contentId    = Get-PropValue $p "contentId"
        }
    }

    if ($OutFile) {
        $ext = [IO.Path]::GetExtension($OutFile).ToLowerInvariant()
        if ($ext -eq ".csv") {
            $view | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutFile
        } else {
            $view | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 $OutFile
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

    if (-not [string]::IsNullOrWhiteSpace($TemplateId)) {
        $tpl = Get-RuleTemplateById -id $TemplateId
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
        $tpl = Get-RuleTemplateById -id $matches[0].name
    }

    $null = Create-RuleFromTemplate -template $tpl -displayNameOverride $NewRuleDisplayName
    Write-Host "Done."
    exit 0
}

throw "Unknown -Action value: $Action"
