[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SubscriptionId,
    [Parameter(Mandatory=$true)][string]$ResourceGroup,
    [Parameter(Mandatory=$true)][string]$WorkspaceName,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Analytics rules","Hunting queries","Parsers","Workbooks","Playbooks")]
    [string]$ContentType,

    [Parameter(Mandatory=$true)][string]$SolutionName,
    [Parameter(Mandatory=$true)][string]$ItemName,

    [string]$ApiVersion = "2025-09-01",
    [string]$OutputRoot = ".",
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Has-Prop($obj, $name) { return ($null -ne $obj) -and ($obj.PSObject.Properties.Name -contains $name) }
function Get-Prop($obj, $name, $default = $null) { if (Has-Prop $obj $name) { return $obj.$name } return $default }

function New-DeterministicGuid([string]$seed) {
    # GUID estable a partir de MD5(seed)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($seed)
    $hash = $md5.ComputeHash($bytes)
    return New-Object Guid (,$hash)
}

# ---------- VALIDACIONES ----------
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { throw "ResourceGroup vacío. Revisa vars.RESOURCE_GROUP." }
if ([string]::IsNullOrWhiteSpace($WorkspaceName)) { throw "WorkspaceName vacío. Revisa vars.WORKSPACE_NAME." }

Write-Host "ResourceGroup : $ResourceGroup"
Write-Host "WorkspaceName: $WorkspaceName"
Write-Host "ContentType  : $ContentType"
Write-Host "SolutionName : $SolutionName"
Write-Host "ItemName     : $ItemName"
Write-Host "ApiVersion   : $ApiVersion"

# ---------- AUTH ----------
$token = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
if (-not $token -or $token.Length -lt 100) { throw "No se pudo obtener token ARM." }

$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# ---------- 1) LISTAR PAQUETES (SIN ODATA) ----------
$listUri = "$base/contentProductPackages?api-version=$ApiVersion"
Write-Host "GET $listUri"
$packages = Invoke-RestMethod -Method GET -Uri $listUri -Headers $headers

$solution = $packages.value | Where-Object {
    $_.properties.contentKind -eq "Solution" -and $_.properties.displayName -eq $SolutionName
} | Select-Object -First 1

if (-not $solution) {
    $names = ($packages.value | Where-Object { $_.properties.contentKind -eq "Solution" } | ForEach-Object { $_.properties.displayName }) -join " | "
    throw "No se encontró la solución '$SolutionName'. Disponibles: $names"
}

$packageId = $solution.name
Write-Host "Solución encontrada → packageId=$packageId"

# ---------- 2) GET DEL PAQUETE ----------
$getPkgUri = "$base/contentProductPackages/${packageId}?api-version=$ApiVersion"
Write-Host "GET $getPkgUri"
$pkg = Invoke-RestMethod -Method GET -Uri $getPkgUri -Headers $headers

$pc = $pkg.properties.packagedContent
if (-not $pc) { throw "packagedContent vacío para '$SolutionName'" }

# ---------- 3) packagedContent suele venir como ARM template con resources ----------
if (-not (Has-Prop $pc "resources")) {
    throw "packagedContent no viene como ARM template (sin resources)."
}

Write-Host "packagedContent detectado como ARM template (tiene resources)."

$resources = @($pc.resources)
if (-not $resources -or $resources.Count -eq 0) { throw "packagedContent ARM sin resources." }

# Buscar el recurso cuyo properties.displayName coincide con ItemName
$wanted = $resources | Where-Object {
    (Has-Prop $_ "properties") -and (Has-Prop $_.properties "displayName") -and ($_.properties.displayName -eq $ItemName)
} | Select-Object -First 1

if (-not $wanted) {
    $wanted = $resources | Where-Object {
        (Has-Prop $_ "properties") -and (Has-Prop $_.properties "displayName") -and ($_.properties.displayName -like "*$ItemName*")
    } | Select-Object -First 1
}

if (-not $wanted) {
    $sample = ($resources | Where-Object { Has-Prop $_ "properties" -and (Has-Prop $_.properties "displayName") } |
        Select-Object -First 30 | ForEach-Object { $_.properties.displayName }) -join " | "
    throw "No se encontró item '$ItemName' dentro del ARM. Ejemplos: $sample"
}

Write-Host "✅ Item encontrado en packagedContent: $($wanted.properties.displayName)"

# ---------- 4) CONSTRUIR ARM “ScheduledRule.json style” PARA ANALYTICS RULES ----------
# Basado en la estructura de ScheduledRule.json (schema/params/resources/type/name/apiVersion/kind) [2](https://github.com/Azure/Azure-Sentinel/blob/master/Tools/ARM-Templates/AnalyticsRules/ScheduledRule/ScheduledRule.json)
if ($ContentType -ne "Analytics rules") {
    throw "Este script (versión ScheduledRule-style) está preparado para Analytics rules. Para otros contentTypes, crea otra plantilla equivalente."
}

# Extraer propiedades del template (si existen)
$tplProps = $wanted.properties

$ruleDescription     = Get-Prop $tplProps "description" ""
$query               = Get-Prop $tplProps "query" ""
$queryFrequency      = Get-Prop $tplProps "queryFrequency" "PT1H"
$queryPeriod         = Get-Prop $tplProps "queryPeriod" "PT1H"
$severity            = Get-Prop $tplProps "severity" "Medium"
$suppressionDuration = Get-Prop $tplProps "suppressionDuration" "PT0H"
$suppressionEnabled  = [bool](Get-Prop $tplProps "suppressionEnabled" $false)
$tactics             = @(Get-Prop $tplProps "tactics" @())
$triggerOperator     = Get-Prop $tplProps "triggerOperator" "GreaterThan"
$triggerThreshold    = [int](Get-Prop $tplProps "triggerThreshold" 0)

# ruleId estable (evita crear duplicados en despliegues repetidos)
$stableGuid = (New-DeterministicGuid "$SolutionName|$ItemName|$WorkspaceName").ToString()

$template = [pscustomobject]@{
    '$schema'       = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    contentVersion  = "1.0.0.0"
    parameters      = @{
        location = @{
            type = "string"
            minLength = 1
            defaultValue = "[resourceGroup().location]"
            metadata = @{ description = "Resource group to deploy solution resources" }
        }
        workspaceName = @{
            type = "string"
            defaultValue = $WorkspaceName
            metadata = @{ description = "Workspace name for Log Analytics where Sentinel is setup" }
        }
        ruleDescription = @{
            type = "string"
            defaultValue = $ruleDescription
            metadata = @{ description = "The description of the alert rule." }
        }
        query = @{
            type = "string"
            defaultValue = $query
            metadata = @{ description = "The query in KQL that creates alerts for this rule." }
        }
        queryFrequency = @{
            type = "string"
            defaultValue = $queryFrequency
            metadata = @{ description = "The frequency (ISO 8601) for this alert rule to run. Example: PT1H" }
        }
        queryPeriod = @{
            type = "string"
            defaultValue = $queryPeriod
            metadata = @{ description = "The lookback period (ISO 8601). Example: P2DT1H30M" }
        }
        severity = @{
            type = "string"
            defaultValue = $severity
            allowedValues = @("High","Medium","Low","Informational")
            metadata = @{ description = "The severity for alerts created by this alert rule." }
        }
        suppressionDuration = @{
            type = "string"
            defaultValue = $suppressionDuration
            metadata = @{ description = "Suppression duration (ISO 8601). Example: PT1H" }
        }
        suppressionEnabled = @{
            type = "bool"
            defaultValue = $suppressionEnabled
            metadata = @{ description = "Enable/disable suppression." }
        }
        tactics = @{
            type = "array"
            defaultValue = $tactics
            metadata = @{ description = "The tactics of the alert rule" }
        }
        triggerOperator = @{
            type = "string"
            defaultValue = $triggerOperator
            allowedValues = @("Equal","GreaterThan","LessThan","NotEqual")
            metadata = @{ description = "Trigger operator." }
        }
        triggerThreshold = @{
            type = "int"
            defaultValue = $triggerThreshold
            metadata = @{ description = "Trigger threshold." }
        }
        ruleDisplayName = @{
            type = "string"
            defaultValue = $ItemName
            metadata = @{ description = "Friendly name for the scheduled alert rule" }
        }
        ruleId = @{
            type = "string"
            defaultValue = $stableGuid
            metadata = @{ description = "Stable GUID for this scheduled alert rule" }
        }
    }
    functions        = @()
    variables        = @{}
    resources        = @(
        @{
            # 🔥 CLAVE: el type “deployable” que Sentinel espera para analytics rule en ARM (como ScheduledRule.json) [2](https://github.com/Azure/Azure-Sentinel/blob/master/Tools/ARM-Templates/AnalyticsRules/ScheduledRule/ScheduledRule.json)
            type       = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
            name       = "[concat(parameters('workspaceName'),'/Microsoft.SecurityInsights/',parameters('ruleId'))]"
            apiVersion = "2020-01-01"
            kind       = "Scheduled"
            location   = "[parameters('location')]"
            dependsOn  = @()
            properties = @{
                description          = "[parameters('ruleDescription')]"
                displayName          = "[parameters('ruleDisplayName')]"
                enabled              = $true
                query                = "[parameters('query')]"
                queryFrequency       = "[parameters('queryFrequency')]"
                queryPeriod          = "[parameters('queryPeriod')]"
                severity             = "[parameters('severity')]"
                suppressionDuration  = "[parameters('suppressionDuration')]"
                suppressionEnabled   = "[parameters('suppressionEnabled')]"
                tactics              = "[parameters('tactics')]"
                triggerOperator      = "[parameters('triggerOperator')]"
                triggerThreshold     = "[parameters('triggerThreshold')]"
            }
        }
    )
    outputs = @{
        ruleId = @{
            type  = "string"
            value = "[parameters('ruleId')]"
        }
    }
}

# ---------- 5) GUARDAR ----------
$outDir  = Join-Path $OutputRoot (Join-Path $ContentType $SolutionName)
$outFile = Join-Path $outDir ($ItemName + ".json")

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
if ((Test-Path $outFile) -and -not $Force) { throw "El archivo ya existe: $outFile (usa Force=true)." }

$template | ConvertTo-Json -Depth 100 | Out-File -FilePath $outFile -Encoding utf8 -Force
Write-Host "✅ Export OK (ScheduledRule style) → $outFile"
