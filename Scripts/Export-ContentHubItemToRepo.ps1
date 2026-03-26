<#
.SYNOPSIS
Exporta un Content Item instalado (regla activa / hunting query / parser / workbook)
a un repo GitHub en formato ARM (single-resource) compatible con Microsoft Sentinel Repositories.

.REQUIERE (variables de entorno)
  AZURE_SUBSCRIPTION_ID          (Secret en GitHub)
  SENTINEL_RESOURCE_GROUP        (Variable en GitHub)
  SENTINEL_WORKSPACE_NAME        (Variable en GitHub)

.PARAMETER ContentName
DisplayName exacto (o parcial) del item. Ej: "Aqua Blizzard AV hits - Feb 2022"

.PARAMETER RepoRoot
Raíz del repositorio (por defecto: carpeta padre del script)

.NOTES
- Analytics rules:
    - Busca primero en alertRuleTemplates por displayName
    - Luego busca la regla activa en alertRules por properties.alertRuleTemplateName
- Hunting queries/parsers: busca directamente en recursos activos
- Workbooks: busca en RG en Microsoft.Insights/workbooks
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$ContentName,

  [Parameter(Mandatory = $false)]
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

  [Parameter(Mandatory = $false)]
  [ValidateSet("2025-09-01","2023-02-01","2023-02-01-preview")]
  [string]$SecurityInsightsApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string]$WorkbooksApiVersion = "2022-04-01"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-EnvVar([string]$Name) {
  $val = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($val)) {
    throw "Falta variable de entorno obligatoria: $Name"
  }
  return $val
}

# --- Required ENV ---
$AZURE_SUBSCRIPTION_ID   = Assert-EnvVar "AZURE_SUBSCRIPTION_ID"
$SENTINEL_RESOURCE_GROUP = Assert-EnvVar "SENTINEL_RESOURCE_GROUP"
$SENTINEL_WORKSPACE_NAME = Assert-EnvVar "SENTINEL_WORKSPACE_NAME"

# --- Token (no interactive) ---
if (-not (Get-Module Az.Accounts -ListAvailable)) {
  throw "No se encuentra el módulo Az.Accounts. Instálalo en el workflow antes de ejecutar este script."
}

# azure/login@v2 prepara la sesión Az en el runner (si enable-AzPSSession true o al usar Az módulos)
# Aun así, Get-AzAccessToken funcionará en ese contexto.
$tokenPlain = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop).Token
$headers = @{ Authorization = "Bearer $tokenPlain" }

function Invoke-ArmGetAll {
  param([Parameter(Mandatory=$true)][string]$Uri)

  $all = @()
  $next = $Uri
  while ($next) {
    $resp = Invoke-RestMethod -Method GET -Uri $next -Headers $headers -ContentType "application/json"
    if ($resp.value) { $all += $resp.value }
    $next = $resp.nextLink
  }
  return $all
}

function Sanitize-FileName([string]$name) {
  $invalid = [IO.Path]::GetInvalidFileNameChars() + [char[]]"/\"
  foreach ($c in $invalid | Select-Object -Unique) {
    $name = $name.Replace($c, " ")
  }
  $name = ($name -replace "\s+", " ").Trim()
  return $name
}

function Sanitize-PathSegment([string]$name) {
  $name = Sanitize-FileName $name
  $name = $name.Trim(".")
  if ([string]::IsNullOrWhiteSpace($name)) { return "UnknownSolution" }
  return $name
}

function Get-SolutionNameFromObject($obj) {
  # 1) properties.source.name (muy habitual en contenido de Sentinel)
  try {
    if ($obj.properties -and $obj.properties.source -and $obj.properties.source.name) {
      return (Sanitize-PathSegment [string]$obj.properties.source.name)
    }
    if ($obj.properties -and $obj.properties.source -and $obj.properties.source.solutionName) {
      return (Sanitize-PathSegment [string]$obj.properties.source.solutionName)
    }
  } catch {}

  # 2) tags comunes
  try {
    if ($obj.tags) {
      foreach ($k in @("Solution","solution","ContentHubSolution","contentHubSolution","SolutionName","solutionName")) {
        if ($obj.tags.$k) { return (Sanitize-PathSegment [string]$obj.tags.$k) }
      }
    }
  } catch {}

  return "UnknownSolution"
}

# --- Base URIs ---
$subscriptionId = $AZURE_SUBSCRIPTION_ID

$wsBase = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$SENTINEL_RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$SENTINEL_WORKSPACE_NAME/providers/Microsoft.SecurityInsights"

$alertRulesUri         = "$wsBase/alertRules?api-version=$SecurityInsightsApiVersion"
$alertRuleTemplatesUri = "$wsBase/alertRuleTemplates?api-version=$SecurityInsightsApiVersion"
$huntingQueriesUri     = "$wsBase/huntingQueries?api-version=$SecurityInsightsApiVersion"
$parsersUri            = "$wsBase/parsers?api-version=$SecurityInsightsApiVersion"

$workbooksUri          = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$SENTINEL_RESOURCE_GROUP/providers/Microsoft.Insights/workbooks?api-version=$WorkbooksApiVersion"

# --- Input box (local) ---
if ([string]::IsNullOrWhiteSpace($ContentName)) {
  $ContentName = Read-Host "Escribe el Content Name (displayName) a exportar"
}

$needle = $ContentName.Trim()

function Match-DisplayName($obj) {
  $dn = $obj.properties.displayName
  if (-not $dn) { return $false }
  return ($dn -eq $needle) -or ($dn -like "*$needle*")
}

Write-Host "Buscando '$ContentName' en el workspace '$SENTINEL_WORKSPACE_NAME'..." -ForegroundColor Cyan

$selectedResource = $null
$contentType = $null
$solutionName = $null

# ---------------------------------------------------------
# 1) Analytics rule: template -> active rule
# ---------------------------------------------------------
$template = $null
try {
  $templates = Invoke-ArmGetAll $alertRuleTemplatesUri
  $template = $templates |
    Where-Object { $_.properties.displayName } |
    Where-Object { ($_.properties.displayName -eq $needle) -or ($_.properties.displayName -like "*$needle*") } |
    Select-Object -First 1
} catch {}

if ($template) {
  $solutionName = Get-SolutionNameFromObject $template
  $templateId = $template.name

  $rules = Invoke-ArmGetAll $alertRulesUri

  # Preferido: match por alertRuleTemplateName
  $rule = $rules | Where-Object { $_.properties.alertRuleTemplateName -eq $templateId } | Select-Object -First 1

  # Fallback: match por displayName directo
  if (-not $rule) {
    $rule = $rules | Where-Object { Match-DisplayName $_ } | Select-Object -First 1
  }

  if ($rule) {
    $selectedResource = $rule
    $contentType = "Analytics rule"
  }
}

# ---------------------------------------------------------
# 2) Hunting query
# ---------------------------------------------------------
if (-not $selectedResource) {
  try {
    $hq = Invoke-ArmGetAll $huntingQueriesUri
    $hit = $hq | Where-Object { Match-DisplayName $_ } | Select-Object -First 1
    if ($hit) {
      $selectedResource = $hit
      $contentType = "Hunting query"
      $solutionName = Get-SolutionNameFromObject $hit
    }
  } catch {}
}

# ---------------------------------------------------------
# 3) Parser
# ---------------------------------------------------------
if (-not $selectedResource) {
  try {
    $par = Invoke-ArmGetAll $parsersUri
    $hit = $par | Where-Object { Match-DisplayName $_ } | Select-Object -First 1
    if ($hit) {
      $selectedResource = $hit
      $contentType = "Parser"
      $solutionName = Get-SolutionNameFromObject $hit
    }
  } catch {}
}

# ---------------------------------------------------------
# 4) Workbook
# ---------------------------------------------------------
if (-not $selectedResource) {
  try {
    $wbs = Invoke-ArmGetAll $workbooksUri
    $hit = $wbs | Where-Object { $_.properties.displayName -and (($_.properties.displayName -eq $needle) -or ($_.properties.displayName -like "*$needle*")) } | Select-Object -First 1
    if ($hit) {
      $selectedResource = $hit
      $contentType = "Workbook"
      $solutionName = Get-SolutionNameFromObject $hit
    }
  } catch {}
}

if (-not $selectedResource) {
  throw "No se encontró ningún contenido instalado que coincida con '$ContentName'."
}

if (-not $solutionName) { $solutionName = Get-SolutionNameFromObject $selectedResource }

# --- Folder and ResourceType mapping (lo que pediste) ---
$folderMap = @{
  "Analytics rule" = "Analytics rules"
  "Hunting query"  = "Hunting"
  "Parser"         = "Parsers"
  "Workbook"       = "Workbooks"
}

$typeMap = @{
  "Analytics rule" = "Microsoft.SecurityInsights/alertRules"
  "Hunting query"  = "Microsoft.SecurityInsights/huntingQueries"
  "Parser"         = "Microsoft.SecurityInsights/parsers"
  "Workbook"       = "Microsoft.Insights/workbooks"
}

$apiMap = @{
  "Analytics rule" = $SecurityInsightsApiVersion
  "Hunting query"  = $SecurityInsightsApiVersion
  "Parser"         = $SecurityInsightsApiVersion
  "Workbook"       = $WorkbooksApiVersion
}

$repoFolder = $folderMap[$contentType]
$resourceTypeValid = $typeMap[$contentType]
$apiVersion = $apiMap[$contentType]

$solSeg = Sanitize-PathSegment $solutionName
$fileName = (Sanitize-FileName $needle) + ".json"
$outPath = Join-Path $RepoRoot (Join-Path $repoFolder (Join-Path $solSeg $fileName))

# --- Build ARM single-resource template (portable) ---
$resourceName = [string]$selectedResource.name
$kind = $selectedResource.kind

$resourceObj = [ordered]@{
  type       = $resourceTypeValid
  apiVersion = $apiVersion
  name       = $resourceName
}

if ($kind) { $resourceObj.kind = $kind }
if ($selectedResource.location) { $resourceObj.location = $selectedResource.location }

# Quitamos campos read-only típicos a nivel recurso (id/etag/systemData) -> no forman parte del recurso ARM
# properties las dejamos tal cual (si hay read-only dentro, normalmente ARM lo ignora o no rompe)
$resourceObj.properties = $selectedResource.properties

# Workspace-scoped resources: añadimos scope para que el recurso sea extension bajo el workspace
if ($contentType -in @("Analytics rule","Hunting query","Parser")) {
  $resourceObj.scope = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"
}

$template = [ordered]@{
  '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
  contentVersion = '1.0.0.0'
  parameters     = [ordered]@{}
  resources      = @($resourceObj)
}

if ($contentType -in @("Analytics rule","Hunting query","Parser")) {
  $template.parameters.workspaceName = [ordered]@{ type = "string" }
}

$json = $template | ConvertTo-Json -Depth 200

$dir = Split-Path $outPath -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outPath, $json, $utf8NoBom)

Write-Host "OK ✅ Exportado" -ForegroundColor Green
Write-Host " - Content type : $contentType"
Write-Host " - Solución     : $solutionName"
Write-Host " - Ruta repo    : $outPath"
