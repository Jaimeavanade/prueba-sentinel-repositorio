<#
.SYNOPSIS
Exporta un Content Item instalado (regla activa / query activa / parser / workbook) a un repo GitHub
en formato ARM (single-resource) compatible con Microsoft Sentinel Repositories.

.ENVIRONMENT VARIABLES (requeridas)
  SENTINEL_RESOURCE_GROUP
  SENTINEL_WORKSPACE_NAME

.PARAMETER ContentName
DisplayName exacto (o casi exacto) del content item. Ej: "Brute force attack against a Cloud PC"

.PARAMETER RepoRoot
Raíz del repositorio (por defecto: carpeta padre del script)

.NOTES
- Para Analytics rules: busca primero template por displayName y luego la regla activa por alertRuleTemplateName.
- Para Hunting/Parsers: busca por displayName directamente en recursos activos (fallback a template si existiera).
- Para Workbooks: busca en el RG por displayName.

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

$SENTINEL_RESOURCE_GROUP = Assert-EnvVar "SENTINEL_RESOURCE_GROUP"
$SENTINEL_WORKSPACE_NAME = Assert-EnvVar "SENTINEL_WORKSPACE_NAME"

# --- Auth / Context ---
if (-not (Get-Module Az.Accounts -ListAvailable)) {
  throw "No se encuentra el módulo Az.Accounts. Instálalo (Install-Module Az.Accounts) o añade paso en workflow."
}

$ctx = Get-AzContext
if (-not $ctx) {
  # En GH Actions, azure/login deja el contexto listo. En local, esto te pedirá login.
  Connect-AzAccount | Out-Null
  $ctx = Get-AzContext
}
if (-not $ctx.Subscription -or -not $ctx.Subscription.Id) {
  throw "No se pudo determinar la subscription actual (Get-AzContext)."
}

$subscriptionId = $ctx.Subscription.Id
$token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
$headers = @{ Authorization = "Bearer $token" }

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
  # GitHub/Windows safe-ish folder segment
  $name = Sanitize-FileName $name
  $name = $name.Trim(".")
  if ([string]::IsNullOrWhiteSpace($name)) { return "UnknownSolution" }
  return $name
}

function Get-SolutionNameFromObject($obj) {
  # 1) properties.source.name (muy habitual en templates/artefactos de Sentinel)
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

function Build-ArmSingleResourceTemplate {
  param(
    [Parameter(Mandatory=$true)][hashtable]$ResourceObject,
    [Parameter(Mandatory=$true)][string]$OutFile
  )

  $template = [ordered]@{
    '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    parameters     = [ordered]@{}
    resources      = @($ResourceObject)
  }

  $json = $template | ConvertTo-Json -Depth 100
  $dir = Split-Path $OutFile -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

  # UTF8 sin BOM para evitar problemas
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($OutFile, $json, $utf8NoBom)
}

# --- Endpoints base (workspace-scoped SecurityInsights) ---
$wsBase = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$SENTINEL_RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/$SENTINEL_WORKSPACE_NAME/providers/Microsoft.SecurityInsights"

$alertRulesUri        = "$wsBase/alertRules?api-version=$SecurityInsightsApiVersion"
$alertRuleTemplatesUri= "$wsBase/alertRuleTemplates?api-version=$SecurityInsightsApiVersion"

# Best-effort para otros tipos (mismo patrón de workspace + provider)
$huntingQueriesUri    = "$wsBase/huntingQueries?api-version=$SecurityInsightsApiVersion"
$parsersUri           = "$wsBase/parsers?api-version=$SecurityInsightsApiVersion"

# Workbooks viven en el RG (habitualmente el mismo RG del workspace, como en tu repo)
$workbooksUri         = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$SENTINEL_RESOURCE_GROUP/providers/Microsoft.Insights/workbooks?api-version=$WorkbooksApiVersion"

if ([string]::IsNullOrWhiteSpace($ContentName)) {
  Write-Host "No se indicó ContentName. Te muestro un resumen y te pido el nombre..." -ForegroundColor Yellow

  $rules = Invoke-ArmGetAll $alertRulesUri
  $hq    = @()
  $par   = @()
  $wbs   = @()

  try { $hq  = Invoke-ArmGetAll $huntingQueriesUri } catch {}
  try { $par = Invoke-ArmGetAll $parsersUri } catch {}
  try { $wbs = Invoke-ArmGetAll $workbooksUri } catch {}

  $list = @()
  $list += $rules | Where-Object { $_.properties.displayName } | ForEach-Object {
    [pscustomobject]@{ Type="Analytics rule"; DisplayName=$_.properties.displayName }
  }
  $list += $hq | Where-Object { $_.properties.displayName } | ForEach-Object {
    [pscustomobject]@{ Type="Hunting query"; DisplayName=$_.properties.displayName }
  }
  $list += $par | Where-Object { $_.properties.displayName } | ForEach-Object {
    [pscustomobject]@{ Type="Parser"; DisplayName=$_.properties.displayName }
  }
  $list += $wbs | Where-Object { $_.properties.displayName } | ForEach-Object {
    [pscustomobject]@{ Type="Workbook"; DisplayName=$_.properties.displayName }
  }

  $list | Sort-Object Type, DisplayName | Format-Table -AutoSize
  $ContentName = Read-Host "Escribe EXACTAMENTE el DisplayName del contenido a exportar"
}

# Normalizamos para comparaciones flexibles
$needle = $ContentName.Trim()
function Match-DisplayName($obj) {
  $dn = $obj.properties.displayName
  if (-not $dn) { return $false }
  return ($dn -eq $needle) -or ($dn -like "*$needle*")
}

# --- 1) Intento: Analytics rule (template -> active rule) ---
$selectedResource = $null
$contentType      = $null
$solutionName     = $null

Write-Host "Buscando '$ContentName'..." -ForegroundColor Cyan

# 1A) Buscar template (por displayName)
$template = $null
try {
  $templates = Invoke-ArmGetAll $alertRuleTemplatesUri
  $template = $templates | Where-Object { $_.properties.displayName } | Where-Object { ($_.properties.displayName -eq $needle) -or ($_.properties.displayName -like "*$needle*") } | Select-Object -First 1
} catch {}

if ($template) {
  $solutionName = Get-SolutionNameFromObject $template
  $templateId = $template.name

  # 1B) Buscar regla activa creada desde ese template
  $rules = Invoke-ArmGetAll $alertRulesUri
  $rule = $rules | Where-Object { $_.properties.alertRuleTemplateName -eq $templateId } | Select-Object -First 1

  # Fallback: si no aparece por templateName, intenta por displayName directo
  if (-not $rule) {
    $rule = $rules | Where-Object { Match-DisplayName $_ } | Select-Object -First 1
  }

  if ($rule) {
    $selectedResource = $rule
    $contentType = "Analytics rule"
  }
}

# --- 2) Si no es Analytics rule, buscar Hunting query activa ---
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

# --- 3) Si no, buscar Parser activo ---
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

# --- 4) Si no, buscar Workbook ---
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

# --- Mapas solicitados repo-folder + resource type correcto ---
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

# Construir recurso ARM “single-resource” quitando campos read-only y añadiendo scope cuando aplique
$resourceName = [string]$selectedResource.name
$kind = $selectedResource.kind

$resourceObj = [ordered]@{
  type       = $resourceTypeValid
  apiVersion = $apiVersion
  name       = $resourceName
}

if ($kind) { $resourceObj.kind = $kind }

# location: Workbooks sí; SecurityInsights normalmente no lleva location (aun así, si viene, lo respetamos)
if ($selectedResource.location) { $resourceObj.location = $selectedResource.location }

# Propiedades (limpiamos lastModifiedUtc / etc no suele romper, pero quitamos id/etag/systemData)
$resourceObj.properties = $selectedResource.properties

# Scope para recursos workspace-scoped (SecurityInsights)
if ($contentType -in @("Analytics rule","Hunting query","Parser")) {
  # ARM scope: despliegue como extension resource bajo el workspace
  $resourceObj.scope = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"
}

# Plantilla con parámetros
# - Para workspace-scoped incluimos workspaceName para que el despliegue sea portable.
if ($contentType -in @("Analytics rule","Hunting query","Parser")) {
  # El wrapper lo creamos en Build-ArmSingleResourceTemplate; aquí solo dejamos claro que existe el param
  # (se añade al template final)
  $null = $resourceObj # placeholder
}

# Output path
$solSeg = Sanitize-PathSegment $solutionName
$fileName = (Sanitize-FileName $needle) + ".json"
$outPath = Join-Path $RepoRoot (Join-Path $repoFolder (Join-Path $solSeg $fileName))

# Crear template final con parámetros correctos
$templateResource = $resourceObj

# Construimos el ARM template wrapper aquí para poder añadir parameters.workspaceName cuando toca
$wrapper = [ordered]@{
  '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
  contentVersion = '1.0.0.0'
  parameters     = [ordered]@{}
  resources      = @($templateResource)
}

if ($contentType -in @("Analytics rule","Hunting query","Parser")) {
  $wrapper.parameters.workspaceName = [ordered]@{ type = "string" }
}

$json = $wrapper | ConvertTo-Json -Depth 100
$dir = Split-Path $outPath -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($outPath, $json, $utf8NoBom)

Write-Host "OK ✅ Exportado:" -ForegroundColor Green
Write-Host " - Content type : $contentType"
Write-Host " - Solución     : $solutionName"
Write-Host " - Ruta repo    : $outPath"
