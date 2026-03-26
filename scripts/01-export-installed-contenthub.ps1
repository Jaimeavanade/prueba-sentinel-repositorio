Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# Config desde ENV
# =========================
$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
$ResourceGroup  = $env:RESOURCE_GROUP
$WorkspaceName  = $env:WORKSPACE_NAME
$ApiVersion     = "2025-09-01"

if (-not $SubscriptionId) { throw "Falta AZURE_SUBSCRIPTION_ID" }
if (-not $ResourceGroup)  { throw "Falta RESOURCE_GROUP" }
if (-not $WorkspaceName)  { throw "Falta WORKSPACE_NAME" }

# =========================
# Output
# =========================
$solutionsDir = Join-Path (Get-Location) "Solutions"
if (-not (Test-Path $solutionsDir)) {
  New-Item -ItemType Directory -Path $solutionsDir | Out-Null
}
$OutputPath = Join-Path $solutionsDir "contenthub-installed-report.txt"

# =========================
# ARM helpers
# =========================
function Get-ArmToken {
  az account get-access-token `
    --resource "https://management.azure.com/" `
    --query accessToken -o tsv
}

function Invoke-ArmGetAll {
  param([string]$Uri)

  $headers = @{
    Authorization  = "Bearer $(Get-ArmToken)"
    "Content-Type" = "application/json"
  }

  $items = @()
  while ($Uri) {
    $resp = Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
    if ($resp.value) { $items += $resp.value }
    $Uri = $resp.nextLink
  }
  return $items
}

# =========================
# 1) Soluciones instaladas
# =========================
$packagesUri =
"https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
"Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
"contentPackages?api-version=$ApiVersion"

$packages = Invoke-ArmGetAll $packagesUri

# Mapa packageId -> solution displayName
$packageMap = @{}
foreach ($p in $packages) {
  $packageMap[$p.name] = $p.properties.displayName
}

# =========================
# 2) Content items INSTALADOS
# =========================
$templatesUri =
"https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
"Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/" +
"contentTemplates?api-version=$ApiVersion"

$templates = Invoke-ArmGetAll $templatesUri

# =========================
# 3) Generar TXT
# =========================
$rows = @()
$rows += "solution_name`tcontent_name`tcontent_type"

foreach ($t in $templates) {

  $pkgId = $t.properties.packageId
  if (-not $pkgId) { continue }

  $solutionName = $packageMap[$pkgId]
  if (-not $solutionName) { $solutionName = $pkgId }

  $contentName = $t.properties.displayName
  $contentType = $t.properties.contentKind

  $rows += "$solutionName`t$contentName`t$contentType"
}

if ($rows.Count -le 1) {
  throw "No se han encontrado content items instalados."
}

# Guardar
[System.IO.File]::WriteAllLines(
  $OutputPath,
  $rows,
  (New-Object System.Text.UTF8Encoding($false))
)

Write-Host "✅ OK -> $OutputPath"
Write-Host "Items instalados: $($rows.Count - 1)"
Write-Host "Preview:"
$rows | Select-Object -First 20 | ForEach-Object { Write-Host $_ }
