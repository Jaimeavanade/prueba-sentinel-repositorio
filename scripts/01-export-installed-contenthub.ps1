Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# Config desde ENV
# =========================
$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
$ResourceGroup  = $env:RESOURCE_GROUP
$WorkspaceName  = $env:WORKSPACE_NAME
$ApiVersion     = "2025-09-01"

if (-not $SubscriptionId) { throw "Falta env: AZURE_SUBSCRIPTION_ID" }
if (-not $ResourceGroup)  { throw "Falta env: RESOURCE_GROUP" }
if (-not $WorkspaceName)  { throw "Falta env: WORKSPACE_NAME" }

# =========================
# Output en carpeta Solutions/
# =========================
$solutionsDir = Join-Path (Get-Location) "Solutions"
if (-not (Test-Path $solutionsDir)) {
  New-Item -ItemType Directory -Path $solutionsDir | Out-Null
}
$OutputPath = Join-Path $solutionsDir "contenthub-installed-report.txt"

# =========================
# Helpers ARM
# =========================
function Get-ArmToken {
  $t = az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv 2>$null
  if (-not $t) { throw "No se pudo obtener token ARM (azure/login + az account get-access-token)." }
  return $t
}

function Normalize-NextLink {
  param([string]$NextLink)

  $fixed = $NextLink -replace '\$SkipToken', '`$skipToken'
  if ($fixed -notmatch 'api-version=') {
    if ($fixed -match '\?') { $fixed = "$fixed&api-version=$ApiVersion" }
    else { $fixed = "$fixed?api-version=$ApiVersion" }
  }
  return $fixed
}

function Invoke-ArmGetAll {
  param([Parameter(Mandatory=$true)][string]$InitialUri)

  $headers = @{
    Authorization  = "Bearer $(Get-ArmToken)"
    "Content-Type" = "application/json"
  }

  $all = @()
  $uri = $InitialUri

  while ($uri) {
    $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
    if ($resp.value) { $all += $resp.value }
    $uri = $null
    if ($resp.nextLink) {
      $uri = Normalize-NextLink $resp.nextLink
    }
  }
  return $all
}

# =========================
# 1) Soluciones instaladas (contentPackages)
# =========================
$installedPackagesUri =
"https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
"Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
"contentPackages?api-version=$ApiVersion"

$installedPackages = Invoke-ArmGetAll -InitialUri $installedPackagesUri
Write-Host "Soluciones instaladas (contentPackages): $($installedPackages.Count)"

# =========================
# 2) Para cada solución instalada -> catálogo contentProductPackages con packagedContent
#    Patrón de filtro/expand como tu script 03-reinstall-contenthub-solutions.ps1 [2](https://docs.azure.cn/en-us/sentinel/sentinel-solutions-deploy)[3](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01)
# =========================
$rows = New-Object System.Collections.Generic.List[string]
$rows.Add("solution_name`tcontent_name`tcontent_type")

foreach ($pkg in $installedPackages) {

  $solName = if ($pkg.properties.displayName) { [string]$pkg.properties.displayName } else { [string]$pkg.name }
  $contentId = [string]$pkg.properties.contentId
  $contentKind = [string]$pkg.properties.contentKind  # normalmente "Solution"

  if (-not $contentId -or -not $contentKind) {
    Write-Warning "Solución sin contentId/contentKind: $solName"
    continue
  }

  $filter = "properties/contentId eq '$contentId' and properties/contentKind eq '$contentKind'"
  $encodedFilter = [System.Uri]::EscapeDataString($filter)

  $catalogUri =
    "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
    "Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
    "contentProductPackages?api-version=$ApiVersion&`$filter=$encodedFilter&`$expand=properties/packagedContent"

  $catalog = Invoke-ArmGetAll -InitialUri $catalogUri

  if (-not $catalog -or $catalog.Count -eq 0) {
    Write-Warning "No encontrado en catálogo (contentProductPackages) para: $solName"
    continue
  }

  # Normalmente llega 1 “product package” por solución
  foreach ($c in $catalog) {
    $pc = $c.properties.packagedContent
    if (-not $pc) {
      Write-Warning "Catálogo sin packagedContent para: $solName"
      continue
    }

    foreach ($item in $pc) {
      # item suele traer displayName + contentKind/contentType (depende del schema)
      $itemName =
        if ($item.displayName) { [string]$item.displayName }
        elseif ($item.properties -and $item.properties.displayName) { [string]$item.properties.displayName }
        else { "UnknownName" }

      $itemType =
        if ($item.contentKind) { [string]$item.contentKind }
        elseif ($item.kind) { [string]$item.kind }
        elseif ($item.properties -and $item.properties.contentKind) { [string]$item.properties.contentKind }
        else { "UnknownType" }

      $rows.Add("$solName`t$itemName`t$itemType")
    }
  }
}

# =========================
# Guardado + validación para evitar artifact vacío
# =========================
$sorted = $rows | Select-Object -First 1
$sorted += ($rows | Select-Object -Skip 1 | Sort-Object)

# Guardar UTF-8 sin BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($OutputPath, $sorted, $utf8NoBom)

# Validación: si solo hay header -> error
if ($sorted.Count -le 1) {
  throw "El reporte quedó vacío (solo header). Revisa permisos o que haya soluciones instaladas."
}

Write-Host "✅ OK -> generado: $OutputPath"
Write-Host "Filas (incluye header): $($sorted.Count)"
Write-Host "Preview (primeras 30 líneas):"
$sorted | Select-Object -First 30 | ForEach-Object { Write-Host $_ }
