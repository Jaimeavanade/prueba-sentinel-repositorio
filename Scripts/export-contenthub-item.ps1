#!/usr/bin/env pwsh
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
  if (-not $v -or [string]::IsNullOrWhiteSpace($v)) { throw "Falta la variable/secret '$Name'." }
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
  $clone = $Obj | ConvertTo-Json -Depth 200 | ConvertFrom-Json -Depth 200
  foreach ($p in @("id","etag","systemData","managedBy","identity","sku","zones","tags")) {
    if ($clone.PSObject.Properties.Name -contains $p) { $clone.PSObject.Properties.Remove($p) }
  }
  return $clone
}

$sub = Require-Env "AZURE_SUBSCRIPTION_ID"
$rg  = Require-Env "SENTINEL_RESOURCE_GROUP"
$ws  = Require-Env "SENTINEL_WORKSPACE_NAME"

$apiSI = "2025-09-01"
$apiWB = "2023-04-01"

$wsBase = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights"
$rgBase = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers"

if ($ListInstalledSolutions) {
  $url = "$wsBase/contentPackages?api-version=$apiSI"
  if ($Search -and $Search.Trim().Length -gt 0) { $url += "&`$search=$([uri]::EscapeDataString($Search))" }
  if ($Top -gt 0) { $url += "&`$top=$Top" }

  $res = Invoke-AzRestGet $url
  Write-Host "=== Soluciones instaladas (contentPackages) ==="
  ($res.value | Sort-Object { $_.properties.packageName } | Select-Object `
    @{n="packageName";e={$_.properties.packageName}},
    @{n="packageVersion";e={$_.properties.packageVersion}},
    @{n="packageId";e={$_.name}}) | Format-Table -AutoSize
  exit 0
}

if ($ListInstalledTemplates) {
  $url = "$wsBase/contentTemplates?api-version=$apiSI"
  if ($Search -and $Search.Trim().Length -gt 0) { $url += "&`$search=$([uri]::EscapeDataString($Search))" }
  if ($Top -gt 0) { $url += "&`$top=$Top" }

  $res = Invoke-AzRestGet $url
  Write-Host "=== Templates instaladas (contentTemplates) ==="
  ($res.value | Sort-Object { $_.properties.displayName } | Select-Object `
    @{n="displayName";e={$_.properties.displayName}},
    @{n="contentKind";e={$_.properties.contentKind}},
    @{n="packageName";e={$_.properties.packageName}},
    @{n="templateId";e={$_.name}}) | Format-Table -AutoSize
  exit 0
}

if (-not $ContentName -or $ContentName.Trim().Length -eq 0) { throw "Debes indicar -ContentName para exportar." }

# 1) Encontrar el contentTemplate instalado para deducir packageName + contentKind
$tplUrl = "$wsBase/contentTemplates?api-version=$apiSI&`$search=$([uri]::EscapeDataString($ContentName))&`$top=50"
$tplRes = Invoke-AzRestGet $tplUrl

$exact = @($tplRes.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() })
if ($exact.Count -eq 0) { throw "No encontré contentTemplate instalado con displayName exacto: '$ContentName'." }

if ($exact.Count -gt 1 -and [string]::IsNullOrWhiteSpace($ContentType)) {
  Write-Host "Ambigüedad: hay varias coincidencias exactas para '$ContentName'. Indica -ContentType."
  $exact | ForEach-Object { Write-Host (" - packageName: {0} | contentKind: {1} | templateId: {2}" -f $_.properties.packageName, $_.properties.contentKind, $_.name) }
  throw "Ambigüedad sin ContentType."
}

$template = $exact[0]
if ($exact.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($ContentType)) {
  $wantedKind = switch ($ContentType) {
    "Analytics rule" { "AnalyticsRule" }
    "Hunting query"  { "HuntingQuery" }
    "Parser"         { "Parser" }
    "Workbook"       { "Workbook" }
    default          { "" }
  }
  $filtered = @($exact | Where-Object { $_.properties.contentKind -eq $wantedKind })
  if ($filtered.Count -eq 1) { $template = $filtered[0] }
}

$solutionName = $template.properties.packageName
if ([string]::IsNullOrWhiteSpace($solutionName)) { $solutionName = "Standalone" }

$kind = $template.properties.contentKind
$normalizedType = switch ($kind) {
  "AnalyticsRule" { "Analytics rule" }
  "HuntingQuery"  { "Hunting query" }
  "Parser"        { "Parser" }
  "Workbook"      { "Workbook" }
  default         { $ContentType }
}
if ([string]::IsNullOrWhiteSpace($normalizedType)) { throw "No pude determinar el Content type. Indica -ContentType." }

# 2) Exportar el recurso REAL instalado (deployable)
$exported = $null
switch ($normalizedType) {
  "Analytics rule" {
    $list = Invoke-AzRestGet "$wsBase/alertRules?api-version=$apiSI"
    $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
    if (-not $exported) { throw "No encontré la Analytics rule instalada (alertRules) con displayName '$ContentName'." }
    $exported.type = "Microsoft.SecurityInsights/alertRules"
  }
  "Hunting query" {
    $list = Invoke-AzRestGet "$wsBase/huntingQueries?api-version=$apiSI"
    $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
    if (-not $exported) { throw "No encontré la Hunting query instalada (huntingQueries) con displayName '$ContentName'." }
    $exported.type = "Microsoft.SecurityInsights/huntingQueries"
  }
  "Parser" {
    $list = Invoke-AzRestGet "$wsBase/parsers?api-version=$apiSI"
    $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
    if (-not $exported) { throw "No encontré el Parser instalado (parsers) con displayName '$ContentName'." }
    $exported.type = "Microsoft.SecurityInsights/parsers"
  }
  "Workbook" {
    $list = Invoke-AzRestGet "$rgBase/Microsoft.Insights/workbooks?api-version=$apiWB"
    $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
    if (-not $exported) { throw "No encontré el Workbook instalado (workbooks) con displayName '$ContentName'." }
    $exported.type = "Microsoft.Insights/workbooks"
  }
  default { throw "Tipo no soportado: $normalizedType" }
}

$finalObj = Remove-NonDeployableFields $exported

$rootFolder = switch ($normalizedType) {
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

$destPath = Join-Path $destDir ((Normalize-FileName $ContentName) + ".json")
($finalObj | ConvertTo-Json -Depth 200) | Out-File -FilePath $destPath -Encoding utf8

Write-Host "Export OK:"
Write-Host " - ContentName : $ContentName"
Write-Host " - ContentType : $normalizedType"
Write-Host " - Solution    : $solutionName"
Write-Host " - Path        : $destPath"
