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

# ---------------- Helpers ----------------
function Get-EnvOrThrow($name) {
    $v = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($v)) {
        throw "Missing env var: $name"
    }
    $v
}

function Get-ArmToken {
    az account get-access-token `
        --resource "https://management.azure.com/" `
        --query accessToken -o tsv
}

function Invoke-ArmRest {
    param($Method, $Uri, $Body)

    $headers = @{
        Authorization  = "Bearer $(Get-ArmToken)"
        "Content-Type" = "application/json"
    }

    if ($Body) {
        $json = $Body | ConvertTo-Json -Depth 100
        Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
    } else {
        Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
}

function HasProp($o,$n){$null -ne $o -and $null -ne $o.PSObject.Properties[$n]}
function GetProp($o,$n,$d=$null){ if(HasProp $o $n){$o.$n}else{$d} }

function EnsureArray($v){
    if($null -eq $v){return $null}
    [object[]]@($v)
}

function EnsureStringArray($v){
    if($null -eq $v){return $null}
    if($v -is [string]){return @($v)}
    @($v | ForEach-Object { $_.ToString() })
}

function NormalizeProps($p){
    if($p.tactics){$p.tactics = EnsureStringArray $p.tactics}
    if($p.techniques){$p.techniques = EnsureStringArray $p.techniques}
    if($p.entityMappings){$p.entityMappings = EnsureArray $p.entityMappings}
    if($p.requiredDataConnectors){$p.requiredDataConnectors = EnsureArray $p.requiredDataConnectors}
    $p
}

# ---------------- Context ----------------
$subId = Get-EnvOrThrow "AZURE_SUBSCRIPTION_ID"
$rg    = Get-EnvOrThrow "SENTINEL_RESOURCE_GROUP"
$ws    = Get-EnvOrThrow "SENTINEL_WORKSPACE_NAME"

$base = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights"

# ---------------- LIST ----------------
if ($Action -eq "list") {
    $res = Invoke-ArmRest GET "$base/alertRuleTemplates?api-version=$ApiVersion"
    $view = $res.value | ForEach-Object {
        [pscustomobject]@{
            templateId  = $_.name
            displayName = $_.properties.displayName
            severity    = $_.properties.severity
            tactics     = ($_.properties.tactics -join ",")
            techniques  = ($_.properties.techniques -join ",")
            version     = $_.properties.version
        }
    }

    if ($OutFile) {
        $view | Export-Csv -NoTypeInformation -Encoding UTF8 $OutFile
    }

    $view | Format-Table -AutoSize
    exit 0
}

# ---------------- CREATE ----------------
if ($Action -eq "create") {

    if ([string]::IsNullOrWhiteSpace($TemplateId) -and
        [string]::IsNullOrWhiteSpace($TemplateDisplayName)) {
        throw "TemplateId o TemplateDisplayName obligatorio"
    }

    if ($TemplateId) {
        $tpl = Invoke-ArmRest GET "$base/alertRuleTemplates/$($TemplateId)?api-version=$ApiVersion"
    } else {
        $all = Invoke-ArmRest GET "$base/alertRuleTemplates?api-version=$ApiVersion"
        $tpl = ($all.value | Where-Object {
            $_.properties.displayName -like "*$TemplateDisplayName*"
        }) | Select-Object -First 1
        $tpl = Invoke-ArmRest GET "$base/alertRuleTemplates/$($tpl.name)?api-version=$ApiVersion"
    }

    $p = $tpl.properties
    $ruleId = (New-Guid).Guid

    $props = [ordered]@{
        displayName           = $(if($NewRuleDisplayName){$NewRuleDisplayName}else{$p.displayName})
        description           = $p.description
        severity              = $p.severity
        enabled               = $Enabled
        query                 = $p.query
        queryFrequency         = GetProp $p queryFrequency $DefaultQueryFrequency
        queryPeriod            = GetProp $p queryPeriod    $DefaultQueryPeriod
        triggerOperator        = GetProp $p triggerOperator $DefaultTriggerOperator
        triggerThreshold       = GetProp $p triggerThreshold $DefaultTriggerThreshold
        tactics                = $p.tactics
        techniques             = $p.techniques
        entityMappings         = $p.entityMappings
        requiredDataConnectors = $p.requiredDataConnectors
        suppressionEnabled     = GetProp $p suppressionEnabled $DefaultSuppressionEnabled
        suppressionDuration    = GetProp $p suppressionDuration $DefaultSuppressionDuration
        alertRuleTemplateName  = $tpl.name
        templateVersion        = $p.version
    }

    $props = NormalizeProps $props

    Write-Host "DEBUG tactics type:" $props.tactics.GetType().Name
    Write-Host "DEBUG techniques type:" $props.techniques.GetType().Name

    $body = @{
        kind = "Scheduled"
        properties = $props
    }

    Invoke-ArmRest PUT "$base/alertRules/$ruleId?api-version=$ApiVersion" $body
    Write-Host "✅ Rule created successfully"
}
