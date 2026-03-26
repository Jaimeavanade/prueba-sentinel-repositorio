<#
.SYNOPSIS
Exporta un item del Content Hub desde contentProductPackages (catálogo de soluciones)
a un ARM JSON "repo-ready" para Microsoft Sentinel Repositories.

.DESCRIPTION
- Autenticación: token ARM vía Azure CLI (az account get-access-token)
- Fuente: contentProductPackages con $expand=properties/packagedContent
- Busca la solución (p.e. "Azure Key Vault")
- Dentro de packagedContent localiza el item (p.e. Analytics rule)
- Extrae el ARM template real
- Reescribe el resource type para Repositories
- Guarda en <ContentType>/<SolutionName>/<ItemName>.json
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

function Get-RepoResourceTypeFromContentType {
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

# 1) Obtener solución desde catálogo
$packagesUri = "$base/contentProductPackages?api-version=$ApiVersion&`$expand=properties/packagedContent"
Write-Host "GET contentProductPackages: $packagesUri"

$packages = Invoke-ArmGet -Uri $packagesUri

$solution = $packages.value |
    Where-Object { $_.properties.displayName -eq $SolutionName } |
    Select-Object -First 1

if (-not $solution) {
    throw "No se encontró la solución '$SolutionName' en Content Hub."
}

# 2) Buscar el item dentro de packagedContent
$items = $solution.properties.packagedContent

if (-not $items) {
    throw "La solución '$SolutionName' no contiene packagedContent."
}

$item = $items |
    Where-Object {
        $_.properties.displayName -eq $ItemName
    } |
    Select-Object -First 1

if (-not $item) {
    $names = ($items | ForEach-Object { $_.properties.displayName }) -join ", "
    throw "No se encontró el item '$ItemName'. Items disponibles: $names"
}

# 3) Extraer ARM template real
$main = $item.properties.mainTemplate
if (-not $main) {
    throw "El item '$ItemName' no contiene mainTemplate."
}

# 4) Reescribir type para Repositories
$arm = $main | ConvertTo-Json -Depth 200 | ConvertFrom-Json -Depth 200
$targetType = Get-RepoResourceTypeFromContentType

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

# 5) Guardar en repo
$outDir = Join-Path $OutputRoot (Join-Path $ContentType (Sanitize-Name $SolutionName))
$outFile = Join-Path $outDir ((Sanitize-Name $ItemName) + ".json")

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

if ((Test-Path $outFile) -and -not $Force) {
    throw "El archivo ya existe: $outFile"
}

[IO.File]::WriteAllText($outFile, $json, (New-Object Text.UTF8Encoding($false)))

Write-Host "✅ Export generado: $outFile"
