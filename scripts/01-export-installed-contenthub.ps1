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
# Helpers
# =========================
function Get-ArmToken {
  $t = az account get-access-token `
        --resource "https://management.azure.com/" `
        --query accessToken -o tsv 2>$null
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
  param([string]$InitialUri)

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
$packagesUri =
"https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
"Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
"contentPackages?api-version=$ApiVersion"

$installedPackages = Invoke-ArmGetAll $packagesUri

$packageMap = @{}
foreach ($p in $installedPackages) {
  $packageId = $p.name
  $displayName = if ($p.properties.displayName) {
    $p.properties.displayName
  } else {
    $packageId
  }
  $packageMap[$packageId] = $displayName
}

# =========================
# 2) Content items instalados (contentTemplates)
# =========================
$templatesUri =
"https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
"Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
"contentTemplates?api-version=$ApiVersion"

$installedTemplates = Invoke-ArmGetAll $templatesUri

# =========================
# 3) Generar TXT
# =========================
$rows = @()
$rows += "solution_name`tcontent_name`tcontent_type"

foreach ($t in $installedTemplates) {
  $tp = $t.properties
  if (-not $tp) { continue }

  $contentName =
    if ($tp.displayName) { $tp.displayName }
    elseif ($tp.contentId) { $tp.contentId }
    else { $t.name }

  $contentType = if ($tp.contentKind) { $tp.contentKind } else { "Unknown" }

  $solutionName = "Standalone/UnknownSolution"
  if ($tp.packageId -and $packageMap.ContainsKey($tp.packageId)) {
    $solutionName = $packageMap[$tp.packageId]
  }

  $rows += "$solutionName`t$contentName`t$contentType"
}

$rows = $rows | Select-Object -First 1
$rows += ($rows | Select-Object -Skip 1 | Sort-Object)

[System.IO.File]::WriteAllLines(
  $OutputPath,
  $rows,
  (New-Object System.Text.UTF8Encoding($false))
)

Write-Host "✅ OK -> generado: $OutputPath"
Write-Host "Soluciones: $($installedPackages.Count)"
Write-Host "Items: $($installedTemplates.Count)"
