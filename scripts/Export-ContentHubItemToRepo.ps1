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

# ---------- 1. LISTAR PAQUETES (SIN ODATA) ----------
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
    $names = ($packages.value | Where-Object { $_.properties.contentKind -eq "Solution" } | ForEach-Object { $_.properties.displayName }) -join " | "
    throw "No se encontró la solución '$SolutionName'. Disponibles: $names"
}

$packageId = $solution.name
Write-Host "Solución encontrada → packageId=$packageId"

# ---------- 2. GET DEL PAQUETE ----------
# ✅ FIX CRÍTICO: ${packageId} antes de ?api-version para evitar '$packageId?api' [1]()
$getPkgUri = "$base/contentProductPackages/${packageId}?api-version=$ApiVersion"
Write-Host "GET $getPkgUri"

$pkg = Invoke-RestMethod -Method GET -Uri $getPkgUri -Headers $headers

$items = $pkg.properties.packagedContent
if (-not $items) {
    throw "packagedContent vacío para '$SolutionName'"
}

# ---------- 3. ITEM ----------
$item = $items |
    Where-Object { $_.properties.displayName -eq $ItemName } |
    Select-Object -First 1

if (-not $item) {
    $available = ($items | ForEach-Object { $_.properties.displayName }) -join " | "
    throw "Item '$ItemName' no encontrado. Disponibles: $available"
}

$main = $item.properties.mainTemplate
if (-not $main) {
    throw "El item '$ItemName' no tiene mainTemplate."
}

# ---------- 4. REWRITE TYPE ----------
$arm = $main | ConvertTo-Json -Depth 200 | ConvertFrom-Json -Depth 200

$typeMap = @{
    "analytics rules" = "Microsoft.SecurityInsights/alertRules"
    "hunting queries" = "Microsoft.SecurityInsights/huntingQueries"
    "parsers"         = "Microsoft.SecurityInsights/parsers"
    "workbooks"       = "Microsoft.Insights/workbooks"
    "playbooks"       = "Microsoft.Logic/workflows"
}

$targetType = $typeMap[$ContentType.ToLowerInvariant()]

$res = $arm.resources |
    Where-Object { $_.type -and $_.type -notlike "*metadata*" -and $_.type -notlike "Microsoft.Resources/deployments" } |
    Select-Object -First 1

if (-not $res) {
    throw "No se encontró recurso principal en resources para cambiar el type."
}

$oldType = $res.type
$res.type = $targetType
Write-Host "Type reescrito: '$oldType' -> '$targetType'"

# ---------- 5. GUARDAR ----------
$outDir = Join-Path $OutputRoot (Join-Path $ContentType $SolutionName)
$outFile = Join-Path $outDir ($ItemName + ".json")

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$arm | ConvertTo-Json -Depth 200 |
    Out-File -FilePath $outFile -Encoding utf8 -Force

Write-Host "✅ Export OK → $outFile"
