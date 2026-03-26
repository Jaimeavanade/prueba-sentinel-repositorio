<#
.SYNOPSIS
Exporta un item del Content Hub (Microsoft Sentinel) a un ARM JSON "repo-ready"
usando contentProductPackages SIN $expand (evita 502).

.DESCRIPTION
Flujo robusto:
1) GET contentProductPackages (SIN $expand)
2) Seleccionar la solución por displayName
3) GET contentProductPackages/{packageId} (aquí sí viene packagedContent)
4) Extraer el item (Analytics rule / workbook / etc.)
5) Reescribir resource.type a formato Repositories
6) Guardar en <ContentType>/<SolutionName>/<ItemName>.json
#>

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

    [Parameter(Mandatory=$false)][string]$ApiVersion = "2025-09-01",
    [Parameter(Mandatory=$false)][string]$OutputRoot = ".",
    [Parameter(Mandatory=$false)][switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------- Helpers ----------------

function Get-ArmToken {
    $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
    if (-not $t -or $t.Length -lt 100) {
        throw "Token ARM inválido. Revisa azure/login (OIDC)."
    }
    return $t
}

function Invoke-ArmGet {
    param([string]$Uri)

    $headers = @{
        Authorization = "Bearer $script:ArmToken"
        "Content-Type" = "application/json"
    }

    try {
        return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
    } catch {
        throw "Fallo GET. Uri=$Uri. Error=$($_.Exception.Message)"
    }
}

function Get-RepoResourceType {
    switch ($ContentType.ToLowerInvariant()) {
        'analytics rules' { 'Microsoft.SecurityInsights/alertRules' }
        'hunting queries' { 'Microsoft.SecurityInsights/huntingQueries' }
        'parsers'         { 'Microsoft.SecurityInsights/parsers' }
        'workbooks'       { 'Microsoft.Insights/workbooks' }
        'playbooks'       { 'Microsoft.Logic/workflows' }
    }
}

function Sanitize-Name($s) {
    [IO.Path]::GetInvalidFileNameChars() | ForEach-Object { $s = $s.Replace($_,' ') }
    $s.Trim()
}

# ---------------- MAIN ----------------

$script:ArmToken = Get-ArmToken

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# 1️⃣ Listar paquetes SIN expand (evita 502)
$listUri = "$base/contentProductPackages?api-version=$ApiVersion"
Write-Host "GET packages list: $listUri"

$packages = Invoke-ArmGet -Uri $listUri

$package = $packages.value |
    Where-Object { $_.properties.displayName -eq $SolutionName } |
    Select-Object -First 1

if (-not $package) {
    throw "No se encontró la solución '$SolutionName' en Content Hub."
}

$packageId = $package.name
Write-Host "PackageId seleccionado: $packageId"

# 2️⃣ GET del paquete concreto (aquí sí viene packagedContent)
$getPkgUri = "$base/contentProductPackages/$packageId?api-version=$ApiVersion"
Write-Host "GET package detail: $getPkgUri"

$packageDetail = Invoke-ArmGet -Uri $getPkgUri

$items = $packageDetail.properties.packagedContent
if (-not $items) {
    throw "La solución '$SolutionName' no contiene packagedContent."
}

# 3️⃣ Buscar el item concreto
$item = $items |
    Where-Object { $_.properties.displayName -eq $ItemName } |
    Select-Object -First 1

if (-not $item) {
    $names = ($items | ForEach-Object { $_.properties.displayName }) -join ", "
    throw "No se encontró el item '$ItemName'. Items disponibles: $names"
}

$main = $item.properties.mainTemplate
if (-not $main) {
    throw "El item '$ItemName' no contiene mainTemplate."
}

# 4️⃣ Reescribir resource type
$arm = $main | ConvertTo-Json -Depth 200 | ConvertFrom-Json -Depth 200
$targetType = Get-RepoResourceType

$resource = $arm.resources |
    Where-Object {
        $_.type -and
        $_.type -notlike '*providers/metadata*' -and
        $_.type -notlike 'Microsoft.Resources/deployments'
    } |
    Select-Object -First 1

if (-not $resource) {
    throw "No se encontró recurso principal en el ARM template."
}

$resource.type = $targetType
$json = $arm | ConvertTo-Json -Depth 200

# 5️⃣ Guardar
$outDir  = Join-Path $OutputRoot (Join-Path $ContentType (Sanitize-Name $SolutionName))
$outFile = Join-Path $outDir ((Sanitize-Name $ItemName) + ".json")

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

if ((Test-Path $outFile) -and -not $Force) {
    throw "El archivo ya existe: $outFile"
}

[IO.File]::WriteAllText($outFile, $json, (New-Object Text.UTF8Encoding($false)))

Write-Host "✅ Export generado correctamente: $outFile"
