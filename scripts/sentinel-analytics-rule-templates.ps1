# scripts/sentinel-analytics-rule-templates.ps1
# FINAL FIX: evita errores tipo '$id?api' usando subexpresiones $()

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
    [bool]$Enabled = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------- helpers ----------
function Get-Env($n) {
    $v = [Environment]::GetEnvironmentVariable($n)
    if ([string]::IsNullOrWhiteSpace($v)) {
        throw "Missing env var: $n"
    }
    $v
}

function ArmToken {
    az account get-access-token `
        --resource https://management.azure.com/ `
        --query accessToken -o tsv
}

function ArmCall($method,$uri,$body=$null) {
    $h = @{ Authorization="Bearer $(ArmToken)"; "Content-Type"="application/json" }
    if ($body) {
        Invoke-RestMethod -Method $method -Uri $uri -Headers $h `
            -Body ($body | ConvertTo-Json -Depth 50)
    } else {
        Invoke-RestMethod -Method $method -Uri $uri -Headers $h
    }
}

function P($o,$n){ if($o.PSObject.Properties[$n]){$o.$n}else{$null} }

# ---------- context ----------
$sub = Get-Env AZURE_SUBSCRIPTION_ID
$rg  = Get-Env SENTINEL_RESOURCE_GROUP
$ws  = Get-Env SENTINEL_WORKSPACE_NAME

$base = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights"

# ---------- list ----------
if ($Action -eq "list") {

    $uri = "$base/alertRuleTemplates?api-version=$ApiVersion"
    $res = ArmCall GET $uri

    $rows = $res.value | ForEach-Object {
        $p = $_.properties
        [pscustomobject]@{
            templateId  = $_.name
            displayName = P $p displayName
            severity    = P $p severity
            tactics     = (P $p tactics) -join ","
            version     = P $p version
            contentId   = P $p contentId
        }
    }

    if ($OutFile) {
        $rows | Export-Csv -NoTypeInformation -Encoding UTF8 $OutFile
    }

    $rows | Format-Table -AutoSize
    return
}

# ---------- create ----------
if (-not $TemplateId -and -not $TemplateDisplayName) {
    throw "Provide TemplateId or TemplateDisplayName"
}

# Resolve template
if ($TemplateId) {
    $tplUri = "$base/alertRuleTemplates/$($TemplateId)?api-version=$ApiVersion"
    $tpl = ArmCall GET $tplUri
} else {
    $all = (ArmCall GET "$base/alertRuleTemplates?api-version=$ApiVersion").value
    $match = if ($MatchMode -eq "exact") {
        $all | Where-Object { $_.properties.displayName -eq $TemplateDisplayName }
    } else {
        $all | Where-Object { $_.properties.displayName -like "*$TemplateDisplayName*" }
    }
    if ($match.Count -ne 1) { throw "Ambiguous template name" }
    $tpl = ArmCall GET "$base/alertRuleTemplates/$($match[0].name)?api-version=$ApiVersion"
}

$p = $tpl.properties
$newId = (New-Guid).Guid

$body = @{
    kind = "Scheduled"
    properties = @{
        displayName           = $(if($NewRuleDisplayName){$NewRuleDisplayName}else{$p.displayName})
        enabled               = $Enabled
        severity              = $p.severity
        query                 = $p.query
        queryFrequency        = $p.queryFrequency
        queryPeriod           = $p.queryPeriod
        triggerOperator       = $p.triggerOperator
        triggerThreshold      = $p.triggerThreshold
        tactics               = $p.tactics
        alertRuleTemplateName = $tpl.name
        templateVersion       = $p.version
    }
}

$ruleUri = "$base/alertRules/$($newId)?api-version=$ApiVersion"
ArmCall PUT $ruleUri $body

Write-Host "✅ Rule created: $($body.properties.displayName)"
