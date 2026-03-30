# scripts/sentinel-analytics-rule-templates.ps1
# Requires: Azure CLI (az) logged-in (azure/login en GitHub Actions o az login local)
#
# Purpose:
#   - List Sentinel Analytics Rule Templates (alertRuleTemplates)
#   - Create an Active Analytics Rule from a selected template (alertRules)
#
# Environment variables required:
#   AZURE_SUBSCRIPTION_ID
#   SENTINEL_RESOURCE_GROUP
#   SENTINEL_WORKSPACE_NAME
#
# Fixes implemented:
# - Some templates do NOT include properties.tactics -> safe access to avoid crash [1]()
# - Some templates do NOT include properties.createdBy -> safe access (previous failure)
#
# Notes:
# - Uses Azure CLI token for ARM (https://management.azure.com/)
# - Uses SecurityInsights API version 2025-09-01 by default

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("list", "create")]
    [string]$Action = "list",

    # Selection (either TemplateId OR DisplayName)
    [Parameter(Mandatory = $false)]
    [string]$TemplateId,

    [Parameter(Mandatory = $false)]
    [string]$TemplateDisplayName,

    # Match mode when using TemplateDisplayName
    [Parameter(Mandatory = $false)]
    [ValidateSet("exact", "contains")]
    [string]$MatchMode = "contains",

    # Optional: override new rule display name
    [Parameter(Mandatory = $false)]
    [string]$NewRuleDisplayName,

    # Optional: export list to file (json/csv)
    [Parameter(Mandatory = $false)]
    [string]$OutFile,

    # API version for SecurityInsights
    [Parameter(Mandatory = $false)]
    [string]$ApiVersion = "2025-09-01",

    # When creating rule
    [Parameter(Mandatory = $false)]
    [bool]$Enabled = $true,

    [Parameter(Mandatory = $false)]
    [string]$DefaultQueryFrequency = "PT1H",

    [Parameter(Mandatory = $false)]
    [string]$DefaultQueryPeriod = "PT1H",

    [Parameter(Mandatory = $false)]
    [ValidateSet("GreaterThan", "GreaterThanOrEqual", "LessThan", "LessThanOrEqual", "Equal", "NotEqual")]
    [string]$DefaultTriggerOperator = "GreaterThan",

    [Parameter(Mandatory = $false)]
    [int]$DefaultTriggerThreshold = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-EnvOrThrow([string]$name) {
    $v = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($v)) {
        throw "Missing required environment variable: $name"
    }
    return $v
}

function Ensure-AzCli {
    try {
        $null = & az version | Out-String
    } catch {
        throw "Azure CLI (az) not found. Install Azure CLI or use GitHub Actions ubuntu-latest."
    }
}

function Get-ArmToken {
    $t = & az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv
    if ([string]::IsNullOrWhiteSpace($t)) { throw "Failed to obtain ARM token via az account get-access-token" }
    return $t
}

function Invoke-ArmRest {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("GET", "PUT", "POST", "PATCH", "DELETE")]
        [string]$Method,
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $false)]
        $Body
    )

    $token = Get-ArmToken
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }

    if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Depth 50
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
    } else {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
}

function Remove-NullProperties {
    param([Parameter(Mandatory = $true)]$obj)

    if ($null -eq $obj) { return $null }

    if ($obj -is [System.Collections.IDictionary]) {
        $keys = @($obj.Keys)
        foreach ($k in $keys) {
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
        $list = New-Object System.Collections.ArrayList
        foreach ($item in $obj) {
            $clean = Remove-NullProperties -obj $item
            if ($null -ne $clean) { [void]$list.Add($clean) }
        }
        return ,$list
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

function Has-Prop($obj, [string]$name) {
    return ($null -ne $obj -and $null -ne $obj.PSObject.Properties[$name])
}

function Get-PropValue($obj, [string]$name, $default = $null) {
    if (Has-Prop $obj $name) { return $obj.$name }
    return $default
}

function Join-IfArray($value) {
    if ($null -eq $value) { return $null }
    if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        return (@($value) -join ",")
    }
    return [string]$value
}

# -------------------------
# MAIN
# -------------------------
Ensure-AzCli

$subId = Get-EnvOrThrow "AZURE_SUBSCRIPTION_ID"
$rg    = Get-EnvOrThrow "SENTINEL_RESOURCE_GROUP"
$ws    = Get-EnvOrThrow "SENTINEL_WORKSPACE_NAME"

$base = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights"

function Get-RuleTemplates {
    $uri = "$base/alertRuleTemplates?api-version=$ApiVersion"
    $res = Invoke-ArmRest -Method "GET" -Uri $uri
    return @($res.value)
}

function Get-RuleTemplateById([string]$id) {
    $uri = "$base/alertRuleTemplates/$id?api-version=$ApiVersion"
    return Invoke-ArmRest -Method "GET" -Uri $uri
}

function Create-RuleFromTemplate($template, [string]$displayNameOverride) {
    $newId = ([guid]::NewGuid()).Guid
    $ruleUri = "$base/alertRules/$newId?api-version=$ApiVersion"

    $tp = $template.properties

    $ruleKind = "Scheduled"

    $displayName = if ([string]::IsNullOrWhiteSpace($displayNameOverride)) { $tp.displayName } else { $displayNameOverride }

    $queryFrequency   = if (Has-Prop $tp "queryFrequency" -and $tp.queryFrequency) { $tp.queryFrequency } else { $DefaultQueryFrequency }
    $queryPeriod      = if (Has-Prop $tp "queryPeriod" -and $tp.queryPeriod) { $tp.queryPeriod } else { $DefaultQueryPeriod }
    $triggerOperator  = if (Has-Prop $tp "triggerOperator" -and $tp.triggerOperator) { $tp.triggerOperator } else { $DefaultTriggerOperator }
    $triggerThreshold = if (Has-Prop $tp "triggerThreshold" -and $tp.triggerThreshold -ne $null) { [int]$tp.triggerThreshold } else { $DefaultTriggerThreshold }

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

        tactics                  = Get-PropValue $tp "tactics"
        techniques               = Get-PropValue $tp "techniques"
        entityMappings           = Get-PropValue $tp "entityMappings"
        eventGroupingSettings    = Get-PropValue $tp "eventGroupingSettings"
        incidentConfiguration    = Get-PropValue $tp "incidentConfiguration"
        alertDetailsOverride     = Get-PropValue $tp "alertDetailsOverride"
        customDetails            = Get-PropValue $tp "customDetails"
        suppressionDuration      = Get-PropValue $tp "suppressionDuration"
        suppressionEnabled       = Get-PropValue $tp "suppressionEnabled"

        # link back to template (when supported)
        alertRuleTemplateName    = $template.name
        templateVersion          = Get-PropValue $tp "version"
        requiredDataConnectors   = Get-PropValue $tp "requiredDataConnectors"
    }

    $body = [ordered]@{
        kind       = $ruleKind
        properties = $properties
    }

    $bodyClean = Remove-NullProperties -obj $body

    Write-Host "Creating Active rule from template:"
    Write-Host "  Template: $($tp.displayName)  (id: $($template.name))"
    Write-Host "  New rule: $displayName (id: $newId)"
    Write-Host "  PUT: $ruleUri"

    $created = Invoke-ArmRest -Method "PUT" -Uri $ruleUri -Body $bodyClean
    return $created
}

if ($Action -eq "list") {
    $templates = Get-RuleTemplates

    # IMPORTANT: Some templates don't have tactics/createdBy/etc. -> safe access
    $view = $templates | ForEach-Object {
        $p = $_.properties

        [pscustomobject]@{
            templateId   = $_.name
            displayName  = Get-PropValue $p "displayName"
            severity     = Get-PropValue $p "severity"
            tactics      = Join-IfArray (Get-PropValue $p "tactics")          # FIX for missing tactics [1]()
            techniques   = Join-IfArray (Get-PropValue $p "techniques")
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

if ($Action -eq "create") {
    if ([string]::IsNullOrWhiteSpace($TemplateId) -and [string]::IsNullOrWhiteSpace($TemplateDisplayName)) {
        throw "For Action=create you must provide either -TemplateId or -TemplateDisplayName"
    }

    $selected = $null

    if (-not [string]::IsNullOrWhiteSpace($TemplateId)) {
        $selected = Get-RuleTemplateById -id $TemplateId
    } else {
        $all = Get-RuleTemplates

        if ($MatchMode -eq "exact") {
            $matches = @($all | Where-Object { (Get-PropValue $_.properties "displayName") -eq $TemplateDisplayName })
        } else {
            $matches = @($all | Where-Object { (Get-PropValue $_.properties "displayName") -like "*$TemplateDisplayName*" })
        }

        if ($matches.Count -eq 0) {
            throw "No templates matched displayName ($MatchMode): $TemplateDisplayName"
        }
        if ($matches.Count -gt 1) {
            Write-Host "Multiple templates matched. Showing candidates:"
            $matches | ForEach-Object {
                Write-Host ("- {0}  |  {1}" -f $_.name, (Get-PropValue $_.properties "displayName"))
            }
            throw "Multiple templates matched. Use -TemplateId to disambiguate."
        }
        $selected = Get-RuleTemplateById -id $matches[0].name
    }

    $created = Create-RuleFromTemplate -template $selected -displayNameOverride $NewRuleDisplayName

    Write-Host "Created rule resourceId: $($created.id)"
    Write-Host "Done."
}
