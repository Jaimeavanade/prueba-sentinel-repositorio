Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# INPUTS (desde workflow)
# =========================
$RuleDisplayNameInput = $env:CONTENT_NAME
if (-not $RuleDisplayNameInput) { throw "Falta CONTENT_NAME (displayName de la Analytics Rule)" }

$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID
$ResourceGroup  = $env:RESOURCE_GROUP
$WorkspaceName  = $env:WORKSPACE_NAME
$ApiVersion     = "2025-09-01"

if (-not $SubscriptionId) { throw "Falta AZURE_SUBSCRIPTION_ID" }
if (-not $ResourceGroup)  { throw "Falta RESOURCE_GROUP" }
if (-not $WorkspaceName)  { throw "Falta WORKSPACE_NAME" }

# =========================
# Normalización (evita fallos por espacios/case/comillas raras)
# =========================
function Normalize-Text {
  param([AllowNull()][string]$s)
  if ($null -eq $s) { return "" }
  $x = $s.Trim()

  # normalizar comillas/apóstrofes “raros”
  $x = $x -replace "[‘’´`]", "'"
  $x = $x -replace "[“”]", '"'

  # espacios múltiples -> 1
  $x = ($x -replace "\s+", " ").Trim()

  return $x.ToLowerInvariant()
}

$RuleDisplayNameNorm = Normalize-Text $RuleDisplayNameInput

# =========================
# ARM helpers (paginación + nextLink roto)
# =========================
function Get-ArmToken {
  az account get-access-token `
    --resource "https://management.azure.com/" `
    --query accessToken -o tsv
}

function Normalize-NextLink {
  param([AllowNull()][string]$NextLink)

  if (-not $NextLink) { return $null }

  # Normaliza $SkipToken -> $skipToken
  $fixed = $NextLink -replace '\$SkipToken', '`$skipToken'

  # A veces nextLink viene sin api-version
  if ($fixed -notmatch 'api-version=') {
    if ($fixed -match '\?') { $fixed = "$fixed&api-version=$ApiVersion" }
    else { $fixed = "$fixed?api-version=$ApiVersion" }
  }
  return $fixed
}

function Invoke-ArmGetAll {
  param([Parameter(Mandatory=$true)][string]$Uri)

  $headers = @{
    Authorization  = "Bearer $(Get-ArmToken)"
    "Content-Type" = "application/json"
  }

  $items = @()
  while ($Uri) {
    $resp = Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
    if ($resp.value) { $items += $resp.value }
    $Uri = Normalize-NextLink $resp.nextLink
  }
  return $items
}

# =========================
# 1) Leer inventario: Solutions/contenthub-installed-report.txt
# =========================
$inventoryPath = "Solutions/contenthub-installed-report.txt"
if (-not (Test-Path $inventoryPath)) { throw "No existe $inventoryPath" }

$inventory = Import-Csv $inventoryPath -Delimiter "`t"

# content_type puede variar: "Analytics rule", "Analytics Rule", "AnalyticsRule", etc.
function Is-AnalyticsRuleType {
  param([string]$t)
  $n = Normalize-Text $t
  return ($n -eq "analytics rule" -or $n -eq "analyticsrule" -or $n -like "analytics*rule*")
}

$match = $inventory | Where-Object {
  (Normalize-Text $_.content_name) -eq $RuleDisplayNameNorm -and (Is-AnalyticsRuleType $_.content_type)
} | Select-Object -First 1

if (-not $match) {
  # Ayuda rápida: sugerencias (mismo substring) para que lo veas en log
  $candidates = $inventory | Where-Object { Is-AnalyticsRuleType $_.content_type } |
    Where-Object { (Normalize-Text $_.content_name) -like "*$RuleDisplayNameNorm*" } |
    Select-Object -First 10

  Write-Host "❌ No encontré coincidencia exacta en contenthub-installed-report.txt para:"
  Write-Host "   INPUT: $RuleDisplayNameInput"
  Write-Host ""
  Write-Host "Sugerencias (hasta 10) que sí existen como Analytics rule:"
  foreach ($c in $candidates) {
    Write-Host " - [$($c.solution_name)] $($c.content_name)"
  }

  throw "La regla '$RuleDisplayNameInput' no existe o no es Analytics rule (según el TXT)."
}

$SolutionName = $match.solution_name
Write-Host "✅ Regla encontrada en solución: $SolutionName"

# =========================
# 2) Buscar la regla INSTALADA en Sentinel (Microsoft.SecurityInsights/alertRules)
# =========================
$rulesUri =
"https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/" +
"Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=$ApiVersion"

$rules = Invoke-ArmGetAll $rulesUri

# Match robusto por displayName
$rule = $rules | Where-Object {
  (Normalize-Text $_.properties.displayName) -eq $RuleDisplayNameNorm
} | Select-Object -First 1

if (-not $rule) {
  # debug: muestra 10 que contengan texto
  $near = $rules | Where-Object { (Normalize-Text $_.properties.displayName) -like "*$RuleDisplayNameNorm*" } | Select-Object -First 10
  Write-Host "❌ No encontré la regla instalada en alertRules por displayName."
  Write-Host "Sugerencias (hasta 10) desde alertRules:"
  foreach ($n in $near) { Write-Host " - $($n.properties.displayName) (kind=$($n.kind))" }

  throw "No se ha encontrado la Analytics Rule instalada en Sentinel con displayName '$RuleDisplayNameInput'."
}

# =========================
# 3) Preparar ARM template estilo ScheduledRule.json (pero NO plantilla)
#    - type = Microsoft.SecurityInsights/alertRules  ✅ (lo que pediste)
#    - scope al workspace
# =========================

# Copia propiedades y limpia campos típicamente read-only (para evitar errores en despliegue)
$props = $rule.properties.PSObject.Copy()
$readonlyProps = @(
  "lastModifiedUtc","createdUtc","createdBy","lastModifiedBy","etag","systemData"
)
foreach ($rp in $readonlyProps) {
  if ($props.PSObject.Properties.Name -contains $rp) { $props.PSObject.Properties.Remove($rp) }
}

# ARM Template (repositorios)
$template = @{
  '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
  contentVersion = "1.0.0.0"
  parameters     = @{
    workspace = @{ type = "string" }
    ruleId    = @{ type = "string"; defaultValue = $rule.name }
  }
  resources      = @(
    @{
      type       = "Microsoft.SecurityInsights/alertRules"
      apiVersion = $ApiVersion
      name       = "[parameters('ruleId')]"
      kind       = $rule.kind
      scope      = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]"
      properties = $props
    }
  )
}

# =========================
# 4) Guardar en carpeta: Analytics rules/<SolutionName>/<RuleDisplayName>.json
# =========================
$targetDir = Join-Path "Analytics rules" $SolutionName
if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir | Out-Null }

# Limpieza de nombre de fichero (windows+linux safe)
$safeName = $RuleDisplayNameInput -replace '[\\/:*?"<>|]', ''  # deja espacios como quieres
$outputPath = Join-Path $targetDir "$safeName.json"

$template | ConvertTo-Json -Depth 80 | Out-File $outputPath -Encoding utf8

Write-Host "✅ Exportado ARM JSON (repositorios) en:"
Write-Host "   $outputPath"
Write-Host "   type(resource) = Microsoft.SecurityInsights/alertRules"
