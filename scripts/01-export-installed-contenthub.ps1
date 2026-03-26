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
  if (-not $t) { throw "No se pudo obtener token ARM" }
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
# Utilidades seguras para propiedades
# =========================
function Get-SafeProp {
  param(
    [Parameter(Mandatory=$true)][object]$Obj,
    [Parameter(Mandatory=$true)][string]$Name
  )
  if ($null -eq $Obj) { return $null }
  if ($Obj.PSObject.Properties.Name -contains $Name) {
    return $Obj.$Name
  }
  return $null
}

# =========================
# 1) Soluciones instaladas
# =========================
$installedPackagesUri =
"https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
"Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
"contentPackages?api-version=$ApiVersion"

$installedPackages = Invoke-ArmGetAll -InitialUri $installedPackagesUri
Write-Host "Soluciones instaladas (contentPackages): $($installedPackages.Count)"

# =========================
# 2) Por cada solución -> catálogo + packagedContent
# =========================
$rows = New-Object System.Collections.Generic.List[string]
$rows.Add("solution_name`tcontent_name`tcontent_type")

foreach ($pkg in $installedPackages) {

  $solutionName = Get-SafeProp $pkg.properties "displayName"
  if (-not $solutionName) { $solutionName = $pkg.name }

  $contentId   = Get-SafeProp $pkg.properties "contentId"
  $contentKind = Get-SafeProp $pkg.properties "contentKind"

  if (-not $contentId -or -not $contentKind) {
    Write-Warning "Solución sin contentId/contentKind: $solutionName"
    continue
  }

  $filter = "properties/contentId eq '$contentId' and properties/contentKind eq '$contentKind'"
  $encodedFilter = [System.Uri]::EscapeDataString($filter)

  $catalogUri =
    "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
    "Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
    "contentProductPackages?api-version=$ApiVersion&`$filter=$encodedFilter&`$expand=properties/packagedContent"

  $catalog = Invoke-ArmGetAll -InitialUri $catalogUri

  foreach ($c in $catalog) {
    $packagedContent = Get-SafeProp $c.properties "packagedContent"
    if (-not $packagedContent) { continue }

    foreach ($item in $packagedContent) {

      # content name (robusto)
      $name =
        (Get-SafeProp $item "displayName") ??
        (Get-SafeProp (Get-SafeProp $item "properties") "displayName") ??
        (Get-SafeProp $item "name") ??
        "UnknownName"

      # content type (robusto)
      $type =
        (Get-SafeProp $item "contentKind") ??
        (Get-SafeProp $item "kind") ??
        (Get-SafeProp (Get-SafeProp $item "properties") "contentKind") ??
        "UnknownType"

      $rows.Add("$solutionName`t$name`t$type")
    }
  }
}

# =========================
# Guardado + validación
# =========================
$sorted = $rows | Select-Object -First 1
$sorted += ($rows | Select-Object -Skip 1 | Sort-Object)

if ($sorted.Count -le 1) {
  throw "Reporte vacío: no se encontraron content items."
}

[System.IO.File]::WriteAllLines(
  $OutputPath,
  $sorted,
  (New-Object System.Text.UTF8Encoding($false))
)

Write-Host "✅ OK -> generado: $OutputPath"
Write-Host "Filas totales (incluye header): $($sorted.Count)"
Write-Host "Preview:"
$sorted | Select-Object -First 20 | ForEach-Object { Write-Host $_ }
