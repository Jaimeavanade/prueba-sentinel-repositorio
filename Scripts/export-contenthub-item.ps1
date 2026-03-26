#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Exporta un Content Item instalado en Microsoft Sentinel a un JSON deployable compatible con Microsoft Sentinel Repositories
  y lo coloca en la carpeta correcta en el repo según Content type y Solution (packageName).

.DESCRIPTION
  - Lista soluciones instaladas (contentPackages) o templates instaladas (contentTemplates) bajo demanda
  - Exporta recurso REAL deployable:
      Analytics rules -> Microsoft.SecurityInsights/alertRules
      Hunting queries -> Microsoft.SecurityInsights/huntingQueries
      Parsers         -> Microsoft.SecurityInsights/parsers
      Workbooks       -> Microsoft.Insights/workbooks
  - Detecta solución a partir del contentTemplate instalado (packageName)
  - Guarda en:
      Analytics rules/<Solution>/<ContentName>.json
      Hunting/<Solution>/<ContentName>.json
      Parsers/<Solution>/<ContentName>.json
      Workbooks/<Solution>/<ContentName>.json

.PARAMETER ContentName
  Display name exacto del portal (para export).

.PARAMETER ContentType
  Content type como aparece en el portal ("Analytics rule", "Hunting query", "Parser", "Workbook"). Opcional.

.PARAMETER ListInstalledSolutions
  Lista contentPackages instalados.

.PARAMETER ListInstalledTemplates
  Lista contentTemplates instalados (muestra displayName, contentKind, packageName).

.NOTES
  Requiere Azure CLI autenticado (azure/login OIDC en workflow).
  Usa AZURE_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string] $ContentName = "",

  [Parameter(Mandatory=$false)]
  [ValidateSet("", "Analytics rule", "Hunting query", "Parser", "Workbook")]
  [string] $ContentType = "",

  [Parameter(Mandatory=$false)]
  [switch] $ListInstalledSolutions,

  [Parameter(Mandatory=$false)]
  [switch] $ListInstalledTemplates,

  [Parameter(Mandatory=$false)]
  [string] $Search = "",

  [Parameter(Mandatory=$false)]
  [int] $Top = 200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Env([string]$Name) {
  $v = (Get-Item -Path "Env:$Name" -ErrorAction SilentlyContinue).Value
  if (-not $v -or [string]::IsNullOrWhiteSpace($v)) {
    throw "Falta la variable/secret '$Name'."
  }
  return $v
}

function Invoke-AzRestGet([string]$Url) {
  $raw = az rest --method get --url $Url --only-show-errors
  if (-not $raw) { throw "Respuesta vacía desde az rest: $Url" }
  return ($raw | ConvertFrom-Json -Depth 200)
}

function Normalize-FileName([string]$Name) {
  $invalid = [System.IO.Path]::GetInvalidFileNameChars()
  $safe = ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } }) -join ''
  return $safe.Trim().TrimEnd('.')
}

function Remove-NonDeployableFields([object]$Obj) {
  # Elimina campos típicos no deployables en repo
  $clone = $Obj | ConvertTo-Json -Depth 200 | ConvertFrom-Json -Depth 200

  foreach ($p in @("id","etag","systemData","managedBy","identity","sku","zones","tags")) {
    if ($clone.PSObject.Properties.Name -contains $p) {
      $clone.PSObject.Properties.Remove($p)
    }
  }

  # Asegura que quede location si aplica (workbooks suelen necesitarla)
  return $clone
}

# Required env
$sub = Require-Env "AZURE_SUBSCRIPTION_ID"
$rg  = Require-Env "SENTINEL_RESOURCE_GROUP"
$ws  = Require-Env "SENTINEL_WORKSPACE_NAME"

# API versions
$apiSI = "2025-09-01"  # contentTemplates/contentPackages/alertRules etc. [2](https://outlook.office365.com/owa/?ItemID=AAMkAGE4ODZlODM3LTA4MzQtNDY4YS05OTEyLTdiMTY3ZTA0MTUzMABGAAAAAAD%2bKeucZIeERL0hHC2t8EkPBwD27tzHVq1%2fToeJmMvQ6b9pAAAAAAEMAAD27tzHVq1%2fToeJmMvQ6b9pAAXELQKAAAA%3d&exvsurl=1&viewmodel=ReadMessageItem)[1](https://avanade.sharepoint.com/sites/AvanadeGlobalSecurityPractices/_layouts/15/Doc.aspx?sourcedoc=%7BEF8EE1A2-00DE-4416-8D50-80AA70BBC011%7D&file=Data-Lake-Candidacy-Review-Process.docx&action=default&mobileredirect=true&DefaultItemOpen=1)
$apiWB = "2023-04-01"  # Workbooks

# Helper URIs
$wsBase = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights"
$rgBase = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers"

# -------------------------
# LIST INSTALLED SOLUTIONS
# -------------------------
if ($ListInstalledSolutions) {
  $url = "$wsBase/contentPackages?api-version=$apiSI"
  if ($Search -and $Search.Trim().Length -gt 0) {
    $enc = [uri]::EscapeDataString($Search)
    $url = "$url&`$search=$enc"
  }
  if ($Top -gt 0) {
    $url = "$url&`$top=$Top"
  }

  $res = Invoke-AzRestGet $url
  Write-Host "=== Soluciones instaladas (contentPackages) ==="
  ($res.value | Sort-Object { $_.properties.packageName } | Select-Object `
      @{n="packageName";e={$_.properties.packageName}},
      @{n="packageVersion";e={$_.properties.packageVersion}},
      @{n="packageId";e={$_.name}}) | Format-Table -AutoSize
  exit 0
}

# -------------------------
# LIST INSTALLED TEMPLATES
# -------------------------
if ($ListInstalledTemplates) {
  $url = "$wsBase/contentTemplates?api-version=$apiSI"
  if ($Search -and $Search.Trim().Length -gt 0) {
    $enc = [uri]::EscapeDataString($Search)
    $url = "$url&`$search=$enc"
  }
  if ($Top -gt 0) {
    $url = "$url&`$top=$Top"
  }

  $res = Invoke-AzRestGet $url
  Write-Host "=== Templates instaladas (contentTemplates) ==="
  ($res.value | Sort-Object { $_.properties.displayName } | Select-Object `
      @{n="displayName";e={$_.properties.displayName}},
      @{n="contentKind";e={$_.properties.contentKind}},
      @{n="packageName";e={$_.properties.packageName}},
      @{n="templateId";e={$_.name}}) | Format-Table -AutoSize
  exit 0
}

# -------------------------
# EXPORT ITEM
# -------------------------
if (-not $ContentName -or $ContentName.Trim().Length -eq 0) {
  throw "Debes indicar -ContentName para exportar."
}

# 1) Encontrar contentTemplate para deducir solución y kind
$encodedName = [uri]::EscapeDataString($ContentName)
$tplUrl = "$wsBase/contentTemplates?api-version=$apiSI&`$search=$encodedName&`$top=50"
$tplRes = Invoke-AzRestGet $tplUrl

$exact = @($tplRes.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() })

if ($exact.Count -eq 0) {
  Write-Host "No encontré contentTemplate instalado con displayName exacto: '$ContentName'."
  $suggest = @($tplRes.value | Select-Object -First 15 | ForEach-Object { $_.properties.displayName })
  if ($suggest.Count -gt 0) {
    Write-Host "Sugerencias:"
    $suggest | ForEach-Object { Write-Host " - $_" }
  }
  throw "No hay coincidencia exacta."
}

# Si hay varios exactos y no informas tipo, obliga a desambiguar
if ($exact.Count -gt 1 -and [string]::IsNullOrWhiteSpace($ContentType)) {
  Write-Host "Ambigüedad: hay varias coincidencias exactas para '$ContentName'. Indica -ContentType."
  $exact | ForEach-Object {
    Write-Host (" - packageName: {0} | contentKind: {1} | templateId: {2}" -f $_.properties.packageName, $_.properties.contentKind, $_.name)
  }
  throw "Ambigüedad sin ContentType."
}

$template = $exact[0]

# Filtra por tipo si procede
if ($exact.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($ContentType)) {
  $wantedKind =
    switch ($ContentType) {
      "Analytics rule" { "AnalyticsRule" }
      "Hunting query"  { "HuntingQuery" }
      "Parser"         { "Parser" }
      "Workbook"       { "Workbook" }
      default { "" }
    }

  $filtered = @($exact | Where-Object { $_.properties.contentKind -eq $wantedKind })
  if ($filtered.Count -eq 1) { $template = $filtered[0] }
}

$solutionName = $template.properties.packageName
if ([string]::IsNullOrWhiteSpace($solutionName)) { $solutionName = "Standalone" }

$kind = $template.properties.contentKind
$normalizedType =
  switch ($kind) {
    "AnalyticsRule" { "Analytics rule" }
    "HuntingQuery"  { "Hunting query" }
    "Parser"        { "Parser" }
    "Workbook"      { "Workbook" }
    default         { $ContentType }
  }

if ([string]::IsNullOrWhiteSpace($normalizedType)) {
  throw "No pude determinar el Content type. Indica -ContentType (Analytics rule / Hunting query / Parser / Workbook)."
}

# 2) Exportar recurso REAL deployable según tipo
$exported = $null

switch ($normalizedType) {
  "Analytics rule" {
    $url = "$wsBase/alertRules?api-version=$apiSI"
    $list = Invoke-AzRestGet $url
    $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
    if (-not $exported) { throw "No encontré la Analytics rule instalada (alertRules) con displayName '$ContentName'." }
    $exported.type = "Microsoft.SecurityInsights/alertRules"
  }
  "Hunting query" {
    $url = "$wsBase/huntingQueries?api-version=$apiSI"
    $list = Invoke-AzRestGet $url
    $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
    if (-not $exported) { throw "No encontré la Hunting query instalada (huntingQueries) con displayName '$ContentName'." }
    $exported.type = "Microsoft.SecurityInsights/huntingQueries"
  }
  "Parser" {
    $url = "$wsBase/parsers?api-version=$apiSI"
    $list = Invoke-AzRestGet $url
    $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
    if (-not $exported) { throw "No encontré el Parser instalado (parsers) con displayName '$ContentName'." }
    $exported.type = "Microsoft.SecurityInsights/parsers"
  }
  "Workbook" {
    $url = "$rgBase/Microsoft.Insights/workbooks?api-version=$apiWB"
    $list = Invoke-AzRestGet $url
    $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
    if (-not $exported) { throw "No encontré el Workbook instalado (workbooks) con displayName '$ContentName' en el RG '$rg'." }
    $exported.type = "Microsoft.Insights/workbooks"
  }
  default { throw "Tipo no soportado: $normalizedType" }
}

# 3) Limpieza para Repositories
$finalObj = Remove-NonDeployableFields $exported

# 4) Carpeta destino
$rootFolder =
  switch ($normalizedType) {
    "Analytics rule" { "Analytics rules" }
    "Hunting query"  { "Hunting" }
    "Parser"         { "Parsers" }
    "Workbook"       { "Workbooks" }
  }

$repoRoot = $env:GITHUB_WORKSPACE
if ([string]::IsNullOrWhiteSpace($repoRoot)) { $repoRoot = (Get-Location).Path }

$destDir = Join-Path $repoRoot $rootFolder
$destDir = Join-Path $destDir $solutionName
New-Item -ItemType Directory -Path $destDir -Force | Out-Null

$fileName = (Normalize-FileName $ContentName) + ".json"
$destPath = Join-Path $destDir $fileName

($finalObj | ConvertTo-Json -Depth 200) | Out-File -FilePath $destPath -Encoding utf8

Write-Host "Export OK:"
Write-Host " - ContentName : $ContentName"
Write-Host " - ContentType : $normalizedType"
Write-Host " - Solution    : $solutionName"
Write-Host " - Path        : $destPath"
