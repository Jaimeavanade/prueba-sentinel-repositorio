Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# INPUTS
# =========================
$RuleDisplayName = $env:CONTENT_NAME
if (-not $RuleDisplayName) {
  throw "Falta CONTENT_NAME (displayName de la Analytics Rule)"
}

$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
$ResourceGroup  = $env:RESOURCE_GROUP
$WorkspaceName  = $env:WORKSPACE_NAME
$ApiVersion     = "2025-09-01"

# =========================
# Helpers ARM
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
# 1) Leer inventario generado previamente
# =========================
$inventoryPath = "Solutions/contenthub-installed-report.txt"
if (-not (Test-Path $inventoryPath)) {
  throw "No existe $inventoryPath"
}

$inventory = Import-Csv $inventoryPath -Delimiter "`t"

$entry = $inventory | Where-Object {
  $_.content_name -eq $RuleDisplayName -and
  $_.content_type -eq "Analytics rule"
}

if (-not $entry) {
  throw "La regla '$RuleDisplayName' no existe o no es Analytics rule"
}

$SolutionName = $entry.solution_name

Write-Host "✅ Regla encontrada en solución: $SolutionName"

# =========================
# 2) Exportar Analytics Rule INSTALADA
# =========================
$rulesUri =
"https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
"Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/" +
"Microsoft.SecurityInsights/alertRules?api-version=$ApiVersion"

$rules = Invoke-ArmGetAll $rulesUri

$rule = $rules | Where-Object {
  $_.properties.displayName -eq $RuleDisplayName
}

if (-not $rule) {
  throw "No se ha encontrado la Analytics Rule instalada en Sentinel"
}

# =========================
# 3) Convertir a JSON válido para repositorios
# =========================
$export = @{
  type       = "Microsoft.SecurityInsights/alertRules"
  apiVersion = $ApiVersion
  name       = $rule.name
  kind       = $rule.kind
  properties = $rule.properties
}

# =========================
# 4) Guardar en carpeta correcta
# =========================
$targetDir = Join-Path "Analytics rules" $SolutionName
if (-not (Test-Path $targetDir)) {
  New-Item -ItemType Directory -Path $targetDir | Out-Null
}

# Limpieza básica del nombre de fichero
$safeName = $RuleDisplayName -replace '[\\/:*?"<>|]', ''
$outputPath = Join-Path $targetDir "$safeName.json"

$export | ConvertTo-Json -Depth 50 | Out-File $outputPath -Encoding utf8

Write-Host "✅ Exportado:"
Write-Host $outputPath
