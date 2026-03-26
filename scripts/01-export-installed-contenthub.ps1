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
  if (-not $t) { throw "No se pudo obtener token ARM (azure/login + az)." }
  return $t
}

function Normalize-NextLink {
  param([AllowNull()][string]$NextLink)

  if (-not $NextLink) { return $null }

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
    $uri = Normalize-NextLink $resp.nextLink
  }

  return $all
}

# =========================
# Helper robusto: leer propiedades (soporta null y paths anidados "properties.displayName")
# =========================
function Get-Prop {
  param(
    [AllowNull()][object]$Obj,
    [Parameter(Mandatory=$true)][string]$Path
  )

  if ($null -eq $Obj) { return $null }
  $cur = $Obj
  foreach ($p in $Path.Split('.')) {
    if ($null -eq $cur) { return $null }
    $names = $cur.PSObject.Properties.Name
    if ($names -notcontains $p) { return $null }
    $cur = $cur.$p
  }
  return $cur
}

function First-NonEmpty {
  param([object[]]$Values)

  foreach ($v in $Values) {
    if ($null -ne $v) {
      $s = [string]$v
      if (-not [string]::IsNullOrWhiteSpace($s)) { return $s }
    }
  }
  return $null
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
# 2) Por cada solución -> catálogo (contentProductPackages) + packagedContent
# =========================
$rows = New-Object System.Collections.Generic.List[string]
$rows.Add("solution_name`tcontent_name`tcontent_type")

foreach ($pkg in $installedPackages) {

  $solutionName = First-NonEmpty @(
    (Get-Prop $pkg "properties.displayName"),
    (Get-Prop $pkg "name")
  )

  $contentId   = Get-Prop $pkg "properties.contentId"
  $contentKind = Get-Prop $pkg "properties.contentKind"

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

  if (-not $catalog -or $catalog.Count -eq 0) {
    Write-Warning "No encontrado en catálogo para: $solutionName"
    continue
  }

  foreach ($c in $catalog) {
    $packagedContent = Get-Prop $c "properties.packagedContent"
    if (-not $packagedContent) { continue }

    foreach ($item in $packagedContent) {

      # Nombre del content item (varía por schema)
      $contentName = First-NonEmpty @(
        (Get-Prop $item "displayName"),
        (Get-Prop $item "properties.displayName"),
        (Get-Prop $item "name"),
        (Get-Prop $item "properties.name"),
        (Get-Prop $item "contentId"),
        (Get-Prop $item "properties.contentId"),
        (Get-Prop $item "id")
      )
      if (-not $contentName) { $contentName = "UnknownName" }

      # Tipo del content item (varía por schema)
      $contentType = First-NonEmpty @(
        (Get-Prop $item "contentKind"),
        (Get-Prop $item "kind"),
        (Get-Prop $item "properties.contentKind"),
        (Get-Prop $item "properties.kind"),
        (Get-Prop $item "properties.contentType")
      )
      if (-not $contentType) { $contentType = "UnknownType" }

      $rows.Add("$solutionName`t$contentName`t$contentType")
    }
  }
}

# =========================
# Guardado + validación (evitar artifact vacío)
# =========================
# Ordenar dejando header arriba
$sorted = $rows | Select-Object -First 1
$sorted += ($rows | Select-Object -Skip 1 | Sort-Object)

# Si solo hay header, aborta
if ($sorted.Count -le 1) {
  throw "Reporte vacío: no se han obtenido content items. (Soluciones instaladas: $($installedPackages.Count))"
}

# Guardar UTF-8 sin BOM
[System.IO.File]::WriteAllLines(
  $OutputPath,
  $sorted,
  (New-Object System.Text.UTF8Encoding($false))
)

Write-Host "✅ OK -> generado: $OutputPath"
Write-Host "Filas totales (incluye header): $($sorted.Count)"
Write-Host "Preview (primeras 25 líneas):"
$sorted | Select-Object -First 25 | ForEach-Object { Write-Host $_ }
