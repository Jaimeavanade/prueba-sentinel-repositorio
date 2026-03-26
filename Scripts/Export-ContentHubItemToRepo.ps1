<#
.SYNOPSIS
  Exporta un Content Item instalado desde Microsoft Sentinel Content Hub (Content Templates)
  y lo guarda en la estructura del repo (Analytics rules / Hunting / Parsers / Playbooks / Workbooks).

.DESCRIPTION
  - Lista soluciones instaladas (contentPackages)
  - Busca un content template instalado por displayName (contentTemplates)
  - Descarga el mainTemplate (ARM JSON) y lo coloca en la carpeta correcta
  - Intenta resolver el nombre de la solución (Content Hub) a partir de propiedades del template o del package.

REQUIREMENTS
  - Autenticación previa contra Azure (ideal: azure/login en GitHub Actions)
  - Azure CLI disponible (para obtener access token)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $false)]
  [string]$ContentName,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

  [switch]$ListOnly
)

function Get-AzRestToken {
  param([string]$SubscriptionId)
  az account set --subscription $SubscriptionId | Out-Null
  $token = az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv
  if (-not $token) { throw "No se pudo obtener access token. Revisa autenticación (azure/login / az login)." }
  return $token
}

function Invoke-AzRest {
  param(
    [Parameter(Mandatory=$true)][string]$Method,
    [Parameter(Mandatory=$true)][string]$Uri,
    [Parameter(Mandatory=$true)][string]$Token
  )
  $headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type"  = "application/json"
  }
  return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
}

function Sanitize-Name {
  param([string]$Name)
  if (-not $Name) { return "Unknown" }
  # Windows invalid filename chars + control chars
  $invalid = [Regex]::Escape(([IO.Path]::GetInvalidFileNameChars() -join ""))
  $safe = [Regex]::Replace($Name, "[$invalid]", "_")
  $safe = $safe.Trim()
  if ($safe.Length -gt 180) { $safe = $safe.Substring(0,180).Trim() }
  return $safe
}

function Detect-ContentFolder {
  param(
    [object]$TemplateObj
  )

  # 1) Preferir contentKind si existe
  $kind = $null
  try { $kind = $TemplateObj.properties.contentKind } catch {}
  if (-not $kind) {
    try { $kind = $TemplateObj.properties.kind } catch {}
  }

  # 2) Inferir por tipos de recursos dentro del mainTemplate si no hay kind
  if (-not $kind -and $TemplateObj.properties.mainTemplate) {
    $resTypes = @()
    try { $resTypes = $TemplateObj.properties.mainTemplate.resources.type } catch {}
    if ($resTypes -contains "Microsoft.SecurityInsights/alertRules") { $kind = "AnalyticsRule" }
    elseif ($resTypes -contains "Microsoft.SecurityInsights/huntingQueries") { $kind = "HuntingQuery" }
    elseif ($resTypes -contains "Microsoft.SecurityInsights/parsers") { $kind = "Parser" }
    elseif ($resTypes -contains "Microsoft.Logic/workflows") { $kind = "Playbook" }
    elseif ($resTypes -contains "Microsoft.Insights/workbooks") { $kind = "Workbook" }
  }

  switch -Regex ($kind) {
    "AnalyticsRule"   { return "Analytics rules" }
    "HuntingQuery"    { return "Hunting" }
    "Parser"          { return "Parsers" }
    "Playbook"        { return "Playbooks" }
    "Workbook"        { return "Workbooks" }
    default           { return "Unknown" }
  }
}

function Resolve-SolutionName {
  param(
    [object]$TemplateObj,
    [object[]]$InstalledPackages
  )

  # Intentos en orden (porque las propiedades pueden variar por versión / tipo)
  $candidate = $null

  # A) source.name
  try { $candidate = $TemplateObj.properties.source.name } catch {}

  # B) package id en el template, y cruzar con contentPackages instalados
  $packageKey = $null
  if (-not $candidate) {
    foreach ($p in @("packageId","contentPackageId","packageName","contentProductId","contentId")) {
      try {
        $v = $TemplateObj.properties.$p
        if ($v) { $packageKey = $v; break }
      } catch {}
    }
  }

  if (-not $candidate -and $packageKey -and $InstalledPackages) {
    $match = $InstalledPackages | Where-Object {
      $_.name -eq $packageKey -or
      $_.properties.contentId -eq $packageKey -or
      $_.properties.contentProductId -eq $packageKey -or
      $_.properties.displayName -eq $packageKey
    } | Select-Object -First 1

    if ($match) { $candidate = $match.properties.displayName }
  }

  # C) fallback
  if (-not $candidate) { $candidate = "UnknownSolution" }
  return $candidate
}

# ---------------- MAIN ----------------

$token = Get-AzRestToken -SubscriptionId $SubscriptionId

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# 1) Listar soluciones instaladas (contentPackages) [3](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)
$packagesUri = "$base/contentPackages?api-version=$ApiVersion"
$packages = Invoke-AzRest -Method "GET" -Uri $packagesUri -Token $token
$installedPackages = @()
if ($packages.value) { $installedPackages = $packages.value }

Write-Host "== Soluciones instaladas (contentPackages) =="
if ($installedPackages.Count -gt 0) {
  $installedPackages |
    Select-Object @{n="displayName";e={$_.properties.displayName}}, @{n="version";e={$_.properties.version}}, @{n="name";e={$_.name}} |
    Format-Table -AutoSize | Out-String | Write-Host
} else {
  Write-Host "No se encontraron contentPackages instalados."
}

# 2) Listar templates instalados (contentTemplates) [4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-templates/list?view=rest-securityinsights-2025-09-01)
#    Si vamos a exportar uno, usamos $search y expandimos mainTemplate
$expand = [Uri]::EscapeDataString("properties/mainTemplate")
$templatesUri = "$base/contentTemplates?api-version=$ApiVersion&`$expand=$expand"

if ($ListOnly -or -not $ContentName) {
  $templates = Invoke-AzRest -Method "GET" -Uri $templatesUri -Token $token
  Write-Host "== Content items instalados (contentTemplates) =="
  if ($templates.value) {
    $templates.value |
      Select-Object @{n="displayName";e={$_.properties.displayName}},
                    @{n="contentKind";e={$_.properties.contentKind}},
                    @{n="name";e={$_.name}} |
      Sort-Object displayName |
      Format-Table -AutoSize | Out-String | Write-Host
  } else {
    Write-Host "No se encontraron contentTemplates instalados."
  }
  if ($ListOnly -or -not $ContentName) { exit 0 }
}

# 3) Buscar por ContentName (displayName)
$search = [Uri]::EscapeDataString($ContentName)
$templatesSearchUri = "$base/contentTemplates?api-version=$ApiVersion&`$expand=$expand&`$search=$search"
$templatesFound = Invoke-AzRest -Method "GET" -Uri $templatesSearchUri -Token $token

if (-not $templatesFound.value -or $templatesFound.value.Count -eq 0) {
  throw "No se encontró ningún contentTemplate instalado que coincida con: '$ContentName'"
}

# Preferir match exacto por displayName (case-insensitive); si no, el primero
$template = $templatesFound.value |
  Where-Object { $_.properties.displayName -and $_.properties.displayName.Trim().ToLower() -eq $ContentName.Trim().ToLower() } |
  Select-Object -First 1

if (-not $template) { $template = $templatesFound.value | Select-Object -First 1 }

$displayName = $template.properties.displayName
Write-Host "Seleccionado: '$displayName' (resource name: $($template.name))"

# 4) Determinar carpeta por tipo
$targetFolder = Detect-ContentFolder -TemplateObj $template
if ($targetFolder -eq "Unknown") {
  throw "No se pudo determinar el Content type/carpeta para '$displayName'. Revisa propiedades.contentKind o mainTemplate."
}

# 5) Determinar nombre de solución
$solutionName = Resolve-SolutionName -TemplateObj $template -InstalledPackages $installedPackages

# 6) Preparar paths
$solutionSafe = Sanitize-Name $solutionName
$fileSafe     = Sanitize-Name $displayName

$destDir  = Join-Path $RepoRoot (Join-Path $targetFolder $solutionSafe)
$destFile = Join-Path $destDir ("$fileSafe.json")

New-Item -ItemType Directory -Path $destDir -Force | Out-Null

# 7) Extraer mainTemplate y escribir JSON
$mainTemplate = $template.properties.mainTemplate
if (-not $mainTemplate) {
  throw "El contentTemplate no incluye properties.mainTemplate (¿falta $expand?)."
}

# Guardar como JSON ARM compatible (profundidad alta)
$mainTemplate | ConvertTo-Json -Depth 100 | Out-File -FilePath $destFile -Encoding UTF8

Write-Host "Export OK -> $destFile"
Write-Host "Tipo/carpeta: $targetFolder"
Write-Host "Solución: $solutionName"

# 8) Outputs para GitHub Actions
if ($env:GITHUB_OUTPUT) {
  "exported_path=$destFile"     | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
  "exported_folder=$targetFolder" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
  "exported_solution=$solutionName" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
