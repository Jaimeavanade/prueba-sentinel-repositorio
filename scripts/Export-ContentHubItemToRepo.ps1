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

# ---------- VALIDACIONES ----------
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) {
    throw "ResourceGroup vacío. Revisa vars.RESOURCE_GROUP."
}
if ([string]::IsNullOrWhiteSpace($WorkspaceName)) {
    throw "WorkspaceName vacío. Revisa vars.WORKSPACE_NAME."
}

Write-Host "ResourceGroup : $ResourceGroup"
Write-Host "WorkspaceName: $WorkspaceName"
Write-Host "ContentType  : $ContentType"
Write-Host "SolutionName : $SolutionName"
Write-Host "ItemName     : $ItemName"
Write-Host "ApiVersion   : $ApiVersion"

# ---------- AUTH ----------
$token = az account get-access-token `
    --resource https://management.azure.com/ `
    --query accessToken -o tsv

if (-not $token -or $token.Length -lt 100) {
    throw "No se pudo obtener token ARM."
}

$headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
}

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# ---------- MAPEOS ----------
$typeMap = @{
    "analytics rules" = "Microsoft.SecurityInsights/alertRules"
    "hunting queries" = "Microsoft.SecurityInsights/huntingQueries"
    "parsers"         = "Microsoft.SecurityInsights/parsers"
    "workbooks"       = "Microsoft.Insights/workbooks"
    "playbooks"       = "Microsoft.Logic/workflows"
}

$targetType = $typeMap[$ContentType.ToLowerInvariant()]
if (-not $targetType) { throw "No hay mapeo para ContentType='$ContentType'." }

# ---------- 1) LISTAR PAQUETES ----------
$listUri = "$base/contentProductPackages?api-version=$ApiVersion"
Write-Host "GET $listUri"

$packages = Invoke-RestMethod -Method GET -Uri $listUri -Headers $headers

$solution = $packages.value |
    Where-Object {
        $_.properties.contentKind -eq "Solution" -and
        $_.properties.displayName -eq $SolutionName
    } |
    Select-Object -First 1

if (-not $solution) {
    $names = ($packages.value | Where-Object { $_.properties.contentKind -eq "Solution" } |
        ForEach-Object { $_.properties.displayName }) -join " | "
    throw "No se encontró la solución '$SolutionName'. Disponibles: $names"
}

$packageId = $solution.name
Write-Host "Solución encontrada → packageId=$packageId"

# ---------- 2) GET DEL PAQUETE ----------
$getPkgUri = "$base/contentProductPackages/${packageId}?api-version=$ApiVersion"
Write-Host "GET $getPkgUri"

$pkg = Invoke-RestMethod -Method GET -Uri $getPkgUri -Headers $headers

$pc = $pkg.properties.packagedContent
if (-not $pc) {
    throw "packagedContent vacío para '$SolutionName'"
}

# ---------- 3) packagedContent COMO ARM TEMPLATE ----------
if ($pc.PSObject.Properties.Name -contains "resources") {
    Write-Host "packagedContent detectado como ARM template."

    $resources = @($pc.resources)
    if (-not $resources -or $resources.Count -eq 0) {
        throw "El ARM packagedContent no trae resources."
    }

    $wanted = $resources | Where-Object {
        $_.PSObject.Properties.Name -contains "properties" -and
        $_.properties.PSObject.Properties.Name -contains "displayName" -and
        $_.properties.displayName -eq $ItemName
    } | Select-Object -First 1

    if (-not $wanted) {
        $wanted = $resources | Where-Object {
            $_.PSObject.Properties.Name -contains "properties" -and
            $_.properties.PSObject.Properties.Name -contains "displayName" -and
            $_.properties.displayName -like "*$ItemName*"
        } | Select-Object -First 1
    }

    if (-not $wanted) {
        $sample = ($resources |
            Where-Object { $_.PSObject.Properties.Name -contains "properties" -and $_.properties.PSObject.Properties.Name -contains "displayName" } |
            Select-Object -First 30 |
            ForEach-Object { $_.properties.displayName }) -join " | "
        throw "No se encontró item '$ItemName' dentro del ARM. Ejemplos: $sample"
    }

    # Mantener metadata si existe
    $metadata = $resources | Where-Object { $_.type -like "*providers/metadata*" }

    # Clonar template base (DEPTH 100 ✅)
    $exportTemplateObj = $pc | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
    $exportTemplateObj.resources = @()

    if ($metadata) { $exportTemplateObj.resources += @($metadata) }
    $exportTemplateObj.resources += $wanted

    $mainRes = $exportTemplateObj.resources |
        Where-Object { $_.type -notlike "*providers/metadata*" } |
        Select-Object -First 1

    $oldType = $mainRes.type
    $mainRes.type = $targetType
    Write-Host "Type reescrito: '$oldType' -> '$targetType'"
}
else {
    throw "packagedContent no es ARM template (caso no soportado en este tenant)."
}

# ---------- 4) GUARDAR ----------
$outDir  = Join-Path $OutputRoot (Join-Path $ContentType $SolutionName)
$outFile = Join-Path $outDir ($ItemName + ".json")

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$exportTemplateObj |
    ConvertTo-Json -Depth 100 |
    Out-File -FilePath $outFile -Encoding utf8 -Force

Write-Host "✅ Export OK → $outFile"
