<#
.SYNOPSIS
  Exporta inventario de soluciones instaladas (Content Hub) y sus content items instalados en Microsoft Sentinel
  y lo guarda como TXT dentro de la carpeta Solutions.

.DESCRIPTION
  - Lee soluciones instaladas desde:
      Microsoft.SecurityInsights/contentPackages (API 2025-09-01)
  - Lee content items instalados desde:
      Microsoft.SecurityInsights/contentTemplates (API 2025-09-01)
  - Relaciona items con soluciones usando properties.packageId del template.

.OUTPUT
  - Solutions/contenthub-installed-report.txt
  Columnas:
    solution_name<TAB>content_name<TAB>content_type

.REQUIREMENTS
  - azure/login (OIDC) ya autenticado
  - Azure CLI disponible
  - Variables de entorno:
      AZURE_SUBSCRIPTION_ID
      RESOURCE_GROUP
      WORKSPACE_NAME
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# Config desde ENV
# =========================
$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
$ResourceGroup  = $env:RESOURCE_GROUP
$WorkspaceName  = $env:WORKSPACE_NAME

# API Version Sentinel (SecurityInsights)
$ApiVersion = "2025-09-01"

if (-not $SubscriptionId) { throw "Falta env: AZURE_SUBSCRIPTION_ID" }
if (-not $ResourceGroup)  { throw "Falta env: RESOURCE_GROUP" }
if (-not $WorkspaceName)  { throw "Falta env: WORKSPACE_NAME" }

# =========================
# Output en carpeta Solutions/
# =========================
$repoRoot = Get-Location
$solutionsDir = Join-Path $repoRoot "Solutions"
if (-not (Test-Path $solutionsDir)) {
  New-Item -ItemType Directory -Path $solutionsDir | Out-Null
}
$OutputPath = Join-Path $solutionsDir "contenthub-installed-report.txt"

# =========================
# Helpers
# =========================
function Get-ArmToken {
  try {
    $t = az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv 2>$null
    if (-not $t) { throw "Token vacío" }
    return $t
  } catch {
    throw "No se pudo obtener token ARM via Azure CLI. Asegúrate de haber ejecutado azure/login. Error: $($_.Exception.Message)"
  }
}

function Normalize-NextLink {
  param(
    [Parameter(Mandatory=$true)][string]$NextLink,
    [Parameter(Mandatory=$true)][string]$ApiVersion
  )
  $fixed = $NextLink

  # Normalizar casing del skiptoken si viene como $SkipToken
  $fixed = $fixed -replace '\$SkipToken', '`$skipToken'

  # Si no tiene api-version, añadirlo
  if ($fixed -notmatch 'api-version=') {
    if ($fixed -match '\?') { $fixed = "$fixed&api-version=$ApiVersion" }
    else { $fixed = "$fixed?api-version=$ApiVersion" }
  }
  return $fixed
}

function Invoke-ArmGetAll {
  param(
    [Parameter(Mandatory=$true)][string] $InitialUri
  )

  $token = Get-ArmToken
  $headers = @{
    Authorization  = "Bearer $token"
    "Content-Type" = "application/json"
  }

  $all = New-Object System.Collections.Generic.List[object]
  $uri = $InitialUri

  while ($uri) {
    try {
      $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
    } catch {
      $body = $null
      try {
        if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
          $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
          $body = $reader.ReadToEnd()
        }
      } catch {}
      if ($body) { throw "Fallo GET. Uri=$uri. Body=$body" }
      throw "Fallo GET. Uri=$uri. Error=$($_.Exception.Message)"
    }

    if ($resp.value) {
      foreach ($v in $resp.value) { [void]$all.Add($v) }
    }

    $uri = $null
    if ($resp.nextLink) {
      $uri = Normalize-NextLink -NextLink ([string]$resp.nextLink) -ApiVersion $ApiVersion
    }
  }

  return $all
}

# =========================
# 1) Soluciones instaladas (Content Hub) -> contentPackages
# =========================
$packagesUri =
  "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
  "Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
  "contentPackages?api-version=$ApiVersion"

$installedPackages = Invoke-ArmGetAll -InitialUri $packagesUri

# Mapa: packageId(resource name) -> displayName
$packageMap = @{}
foreach ($p in $installedPackages) {
  $pid = [string]$p.name
  $pname = $pid
  if ($p.properties -and $p.properties.displayName) {
    $pname = [string]$p.properties.displayName
  }
  $packageMap[$pid] = $pname
}

# =========================
# 2) Content items instalados -> contentTemplates
# =========================
$templatesUri =
  "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
  "Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
  "contentTemplates?api-version=$ApiVersion&`$top=500"

$installedTemplates = Invoke-ArmGetAll -InitialUri $templatesUri

# =========================
# 3) Generar filas (SolutionName | ContentName | ContentType)
# =========================
$rows = New-Object System.Collections.Generic.List[string]
$rows.Add("solution_name`tcontent_name`tcontent_type")

foreach ($t in $installedTemplates) {
  $tp = $t.properties
  if (-not $tp) { continue }

  $contentName =
    if ($tp.displayName) { [string]$tp.displayName }
    elseif ($tp.contentId) { [string]$tp.contentId }
    else { [string]$t.name }

  $contentType =
    if ($tp.contentKind) { [string]$tp.contentKind }
    else { "Unknown" }

  $pkgId = $null
  if ($tp.packageId) { $pkgId = [string]$tp.packageId }

  $solutionName = "Standalone/UnknownSolution"
  if ($pkgId) {
    if ($packageMap.ContainsKey($pkgId)) { $solutionName = $packageMap[$pkgId] }
    else { $solutionName = $pkgId }
  }

  $rows.Add("$solutionName`t$contentName`t$contentType")
}

# Ordenar dejando header arriba
$sorted = $rows | Select-Object -First 1
$sorted += ($rows | Select-Object -Skip 1 | Sort-Object)

# Guardar UTF-8 sin BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($OutputPath, $sorted, $utf8NoBom)

Write-Host "OK -> generado: $OutputPath"
Write-Host "Soluciones instaladas encontradas: $($installedPackages.Count)"
Write-Host "Content items instalados encontrados: $($installedTemplates.Count)"
