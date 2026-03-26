<#
.SYNOPSIS
  Exporta un Content Item instalado desde Microsoft Sentinel Content Hub (contentTemplates)
  y lo guarda en la estructura del repo (Analytics rules / Hunting / Parsers / Playbooks / Workbooks).

.DESCRIPTION
  - Lista soluciones instaladas (contentPackages)
  - Busca un content template instalado por displayName con match EXACTO
    * Primero con $filter (properties/displayName eq '...')
    * Si $filter falla, usa $search solo para traer candidatos y filtrar localmente
    * Si NO hay match exacto, ABORTA y muestra sugerencias (no exporta “otra cosa”)
  - Descarga el mainTemplate (ARM JSON) via $expand=properties/mainTemplate
  - Detecta carpeta por contentKind o por tipos en mainTemplate
  - Detecta la solución por packageName (si existe) o cruza con contentPackages

.NOTES
  El endpoint contentTemplates soporta $filter/$search/$expand, y properties/mainTemplate es expandible. 
  El schema de contentTemplates incluye packageName/packageId/contentKind/mainTemplate. 

.REQUIREMENTS
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

  [Parameter(Mandatory = $false)]
  [ValidateSet("AnalyticsRule","HuntingQuery","Parser","Playbook","Workbook")]
  [string]$ExpectedType,

  [switch]$ListOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------------
# Helpers: Auth + REST
# -----------------------------
function Get-AzRestToken {
  param([string]$SubscriptionId)
  az account set --subscription $SubscriptionId | Out-Null
  $token = az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv
  if (-not $token -or $token.Trim().Length -lt 100) { throw "No se pudo obtener access token. Revisa autenticación (azure/login / az login)." }
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

# -----------------------------
# Helpers: String / OData
# -----------------------------
function Escape-ODataString {
  param([string]$s)
  if ($null -eq $s) { return "" }
  # OData literal: escapar comillas simples duplicándolas: ' => ''
  return $s -replace "'", "''"
}

function Normalize-DisplayName {
  param([string]$s)
  if (-not $s) { return "" }
  $t = $s.Trim()
  # Normaliza guiones raros a "-"
  $t = $t -replace "[\u2013\u2014\u2212]", "-"
  # Colapsa espacios múltiples
  $t = [regex]::Replace($t, "\s+", " ")
  return $t.ToLowerInvariant()
}

function Sanitize-Name {
  param([string]$Name)
  if (-not $Name) { return "Unknown" }
  $invalid = [Regex]::Escape(([IO.Path]::GetInvalidFileNameChars() -join ""))
  $safe = [Regex]::Replace($Name, "[$invalid]", "_")
  $safe = $safe.Trim()
  if ($safe.Length -gt 180) { $safe = $safe.Substring(0,180).Trim() }
  return $safe
}

# -----------------------------
# Helpers: ContentTemplates paging + query building
# -----------------------------
function Get-ContentTemplatesPage {
  param(
    [Parameter(Mandatory=$true)][string]$Base,
    [Parameter(Mandatory=$true)][string]$ApiVersion,
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$false)][string]$Filter,
    [Parameter(Mandatory=$false)][string]$Search,
    [Parameter(Mandatory=$false)][switch]$ExpandMainTemplate,
    [Parameter(Mandatory=$false)][int]$Top = 200,
    [Parameter(Mandatory=$false)][string]$SkipToken
  )

  $uri = "$Base/contentTemplates?api-version=$ApiVersion"

  if ($ExpandMainTemplate) {
    # Expandable: properties/mainTemplate 
    $expand = [Uri]::EscapeDataString("properties/mainTemplate")
    $uri += "&`$expand=$expand"
  }

  if ($Top -gt 0) { $uri += "&`$top=$Top" }
  if ($Filter)    { $uri += "&`$filter=$([Uri]::EscapeDataString($Filter))" }
  if ($Search)    { $uri += "&`$search=$([Uri]::EscapeDataString($Search))" }
  if ($SkipToken) { $uri += "&`$skipToken=$([Uri]::EscapeDataString($SkipToken))" }

  return Invoke-AzRest -Method "GET" -Uri $uri -Token $Token
}

function Get-ContentTemplatesAll {
  param(
    [Parameter(Mandatory=$true)][string]$Base,
    [Parameter(Mandatory=$true)][string]$ApiVersion,
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$false)][string]$Filter,
    [Parameter(Mandatory=$false)][string]$Search,
    [Parameter(Mandatory=$false)][switch]$ExpandMainTemplate,
    [Parameter(Mandatory=$false)][int]$MaxPages = 5,
    [Parameter(Mandatory=$false)][int]$Top = 200
  )

  $all = New-Object System.Collections.Generic.List[object]
  $skipToken = $null
  for ($i=1; $i -le $MaxPages; $i++) {
    $resp = Get-ContentTemplatesPage -Base $Base -ApiVersion $ApiVersion -Token $Token -Filter $Filter -Search $Search -ExpandMainTemplate:$ExpandMainTemplate -Top $Top -SkipToken $skipToken
    if ($resp.value) { $resp.value | ForEach-Object { [void]$all.Add($_) } }

    # nextLink puede venir como "nextLink" (ARM style). Si no hay, terminamos.
    $next = $null
    try { $next = $resp.nextLink } catch {}
    if (-not $next) { break }

    # Extraer skiptoken del nextLink si existe
    if ($next -match "[$]skipToken=([^&]+)") {
      $skipToken = [Uri]::UnescapeDataString($matches[1])
    } else {
      break
    }
  }
  return ,$all.ToArray()
}

# -----------------------------
# Helpers: Detect folder + solution name
# -----------------------------
function Detect-ContentFolder {
  param([object]$TemplateObj)

  # 1) Preferir contentKind (schema oficial) 
  $kind = $null
  try { $kind = $TemplateObj.properties.contentKind } catch {}
  if (-not $kind) { try { $kind = $TemplateObj.properties.kind } catch {} }

  # 2) Inferir por tipos de recursos en mainTemplate si no hay kind
  if (-not $kind -and $TemplateObj.properties.mainTemplate) {
    $types = @()
    try { $types = @($TemplateObj.properties.mainTemplate.resources.type) } catch {}
    if ($types -contains "Microsoft.SecurityInsights/alertRules" -or $types -contains "Microsoft.SecurityInsights/AlertRuleTemplates") { $kind = "AnalyticsRule" }
    elseif ($types -contains "Microsoft.SecurityInsights/huntingQueries") { $kind = "HuntingQuery" }
    elseif ($types -contains "Microsoft.SecurityInsights/parsers") { $kind = "Parser" }
    elseif ($types -contains "Microsoft.Logic/workflows") { $kind = "Playbook" }
    elseif ($types -contains "Microsoft.Insights/workbooks") { $kind = "Workbook" }
  }

  switch -Regex ($kind) {
    "AnalyticsRule"        { return "Analytics rules" }
    "HuntingQuery"         { return "Hunting" }
    "Parser"               { return "Parsers" }
    "Playbook"             { return "Playbooks" }   # incluye Playbook / PlaybookTemplate
    "Workbook"             { return "Workbooks" }   # incluye Workbook / WorkbookTemplate
    default                { return "Unknown" }
  }
}

function Resolve-SolutionName {
  param(
    [object]$TemplateObj,
    [object[]]$InstalledPackages
  )

  # 1) packageName es lo más fiable si viene (schema lo incluye) 
  try { if ($TemplateObj.properties.packageName) { return $TemplateObj.properties.packageName } } catch {}

  # 2) source.name como fallback
  try { if ($TemplateObj.properties.source.name) { return $TemplateObj.properties.source.name } } catch {}

  # 3) Cruce con contentPackages por packageId/contentProductId/contentId
  $packageKey = $null
  foreach ($p in @("packageId","contentProductId","contentId")) {
    try {
      $v = $TemplateObj.properties.$p
      if ($v) { $packageKey = $v; break }
    } catch {}
  }

  if ($packageKey -and $InstalledPackages) {
    $match = $InstalledPackages | Where-Object {
      $_.name -eq $packageKey -or
      $_.properties.contentId -eq $packageKey -or
      $_.properties.contentProductId -eq $packageKey -or
      $_.properties.displayName -eq $packageKey
    } | Select-Object -First 1

    if ($match) { return $match.properties.displayName }
  }

  return "UnknownSolution"
}

# -----------------------------
# MAIN
# -----------------------------
$token = Get-AzRestToken -SubscriptionId $SubscriptionId

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# 1) Listar soluciones instaladas (contentPackages) [1](https://learn.microsoft.com/en-us/azure/sentinel/quickstart-onboard)
$packagesUri = "$base/contentPackages?api-version=$ApiVersion"
$packages = Invoke-AzRest -Method "GET" -Uri $packagesUri -Token $token
$installedPackages = @()
if ($packages.value) { $installedPackages = @($packages.value) }

Write-Host "== Soluciones instaladas (contentPackages) =="
if ($installedPackages.Count -gt 0) {
  $installedPackages |
    Select-Object @{n="displayName";e={$_.properties.displayName}}, @{n="version";e={$_.properties.version}}, @{n="name";e={$_.name}} |
    Format-Table -AutoSize | Out-String | Write-Host
} else {
  Write-Host "No se encontraron contentPackages instalados."
}

# 2) Listar templates instalados si ListOnly o no hay ContentName 
if ($ListOnly -or -not $ContentName) {
  $templates = Get-ContentTemplatesAll -Base $base -ApiVersion $ApiVersion -Token $token -ExpandMainTemplate:$false -MaxPages 3 -Top 200
  Write-Host "== Content items instalados (contentTemplates) =="
  if ($templates.Count -gt 0) {
    $templates |
      Select-Object @{n="displayName";e={$_.properties.displayName}},
                    @{n="contentKind";e={$_.properties.contentKind}},
                    @{n="packageName";e={$_.properties.packageName}},
                    @{n="name";e={$_.name}} |
      Sort-Object displayName |
      Format-Table -AutoSize | Out-String | Write-Host
  } else {
    Write-Host "No se encontraron contentTemplates instalados."
  }
  exit 0
}

# 3) Selección estricta del template por displayName EXACTO
$requestedNorm = Normalize-DisplayName $ContentName
$filterLiteral = Escape-ODataString $ContentName

$candidates = @()

# Intento A: $filter exacto (si el servicio lo admite) 
try {
  $filter = "properties/displayName eq '$filterLiteral'"
  $filtered = Get-ContentTemplatesAll -Base $base -ApiVersion $ApiVersion -Token $token -Filter $filter -ExpandMainTemplate -MaxPages 2 -Top 50
  if ($filtered.Count -gt 0) { $candidates = @($filtered) }
} catch {
  Write-Host "WARN: Falló el $filter exacto. Se usará $search solo para candidatos."
}

# Intento B: $search como fallback para candidatos (pero match exacto local obligatorio) 
if ($candidates.Count -eq 0) {
  $searched = Get-ContentTemplatesAll -Base $base -ApiVersion $ApiVersion -Token $token -Search $ContentName -ExpandMainTemplate -MaxPages 5 -Top 200
  if ($searched.Count -gt 0) { $candidates = @($searched) }
}

if ($candidates.Count -eq 0) {
  throw "No se encontró ningún contentTemplate instalado que coincida con: '$ContentName'"
}

# Match EXACTO local (normalizado). Si no hay, abortamos con sugerencias.
$exact = @(
  $candidates | Where-Object {
    $_.properties.displayName -and (Normalize-DisplayName $_.properties.displayName) -eq $requestedNorm
  }
)

if ($exact.Count -eq 1) {
  $template = $exact[0]
}
elseif ($exact.Count -gt 1) {
  $names = ($exact | ForEach-Object { $_.properties.displayName }) -join "; "
  throw "Ambigüedad: hay $($exact.Count) templates con displayName EXACTO '$ContentName'. Candidatos: $names"
}
else {
  $suggest = $candidates |
    Where-Object { $_.properties.displayName } |
    Select-Object -First 10 |
    ForEach-Object {
      [pscustomobject]@{
        displayName  = $_.properties.displayName
        contentKind  = $_.properties.contentKind
        packageName  = $_.properties.packageName
        packageId    = $_.properties.packageId
      }
    }

  Write-Host "No hay coincidencia EXACTA para: '$ContentName'."
  Write-Host "Sugerencias (top 10) desde el resultado de búsqueda:"
  $suggest | Format-Table -AutoSize | Out-String | Write-Host

  throw "Abortado para evitar exportar un item incorrecto. Usa el displayName exacto de las sugerencias."
}

$displayName = $template.properties.displayName
Write-Host "Seleccionado: '$displayName' (resource name: $($template.name))"

# 4) (Opcional) Guardarraíl por tipo esperado
if ($ExpectedType) {
  $kind = $null
  try { $kind = $template.properties.contentKind } catch {}
  if (-not $kind) { try { $kind = $template.properties.kind } catch {} }

  if ($kind -and ($kind -notmatch $ExpectedType)) {
    throw "El item encontrado es tipo '$kind' pero esperabas '$ExpectedType'. Abortado."
  }
}

# 5) Determinar carpeta por tipo
$targetFolder = Detect-ContentFolder -TemplateObj $template
if ($targetFolder -eq "Unknown") {
  throw "No se pudo determinar el Content type/carpeta para '$displayName'. Revisa properties.contentKind o el mainTemplate."
}

# 6) Determinar nombre de solución
$solutionName = Resolve-SolutionName -TemplateObj $template -InstalledPackages $installedPackages

# 7) Preparar paths
$solutionSafe = Sanitize-Name $solutionName
$fileSafe     = Sanitize-Name $displayName

$destDir  = Join-Path $RepoRoot (Join-Path $targetFolder $solutionSafe)
$destFile = Join-Path $destDir ("$fileSafe.json")

New-Item -ItemType Directory -Path $destDir -Force | Out-Null

# 8) Extraer mainTemplate y escribir JSON
$mainTemplate = $template.properties.mainTemplate
if (-not $mainTemplate) {
  throw "El contentTemplate no incluye properties.mainTemplate (¿falta $expand=properties/mainTemplate?)."
}

$mainTemplate | ConvertTo-Json -Depth 120 | Out-File -FilePath $destFile -Encoding UTF8

Write-Host "Export OK -> $destFile"
Write-Host "Tipo/carpeta: $targetFolder"
Write-Host "Solución: $solutionName"

# 9) Outputs para GitHub Actions
if ($env:GITHUB_OUTPUT) {
  "exported_path=$destFile" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
  "exported_folder=$targetFolder" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
  "exported_solution=$solutionName" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
