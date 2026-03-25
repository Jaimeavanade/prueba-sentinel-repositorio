<#
.SYNOPSIS
  Exporta (copia) al repo las soluciones instaladas en Microsoft Sentinel Content Hub,
  trayendo su contenido desde el repo oficial Azure/Azure-Sentinel (/Solutions).

.DESCRIPTION
  1) Lista soluciones instaladas en el workspace via REST:
     GET .../providers/Microsoft.SecurityInsights/contentPackages?api-version=2025-09-01
     (La operación "List" indica "Gets all installed packages").  (ref: Microsoft Learn) 
  2) Obtiene el listado de carpetas /Solutions del repo oficial (GitHub API).
  3) Mapea DisplayName de Content Hub -> nombre de carpeta en /Solutions (best-effort).
  4) Hace sparse-checkout de SOLO esas soluciones y copia únicamente:
     - Analytic Rules
     - Automation Rules
     - Hunting Queries
     - Parsers
     - Playbooks
     - Workbooks
  5) Escribe un resumen en stdout y continúa si faltan carpetas.

.REQUIREMENTS
  - Autenticación a Azure ya realizada (ideal: azure/login OIDC en GitHub Actions).
  - git instalado (en GitHub Actions ubuntu-latest ya está).
  - Acceso a la API de ARM para leer contentPackages.

.PARAMETER SubscriptionId
.PARAMETER ResourceGroupName
.PARAMETER WorkspaceName
.PARAMETER DestinationRoot
  Por defecto: Detections/Solutions
.PARAMETER AzureSentinelRepo
  Por defecto: https://github.com/Azure/Azure-Sentinel.git
.PARAMETER AzureSentinelBranch
  Por defecto: master

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string] $SubscriptionId,
  [Parameter(Mandatory = $true)] [string] $ResourceGroupName,
  [Parameter(Mandatory = $true)] [string] $WorkspaceName,

  [Parameter(Mandatory = $false)] [string] $DestinationRoot = "Detections/Solutions",

  [Parameter(Mandatory = $false)] [string] $AzureSentinelRepo = "https://github.com/Azure/Azure-Sentinel.git",
  [Parameter(Mandatory = $false)] [string] $AzureSentinelBranch = "master"
)

$ErrorActionPreference = "Stop"

function Write-Info($msg)  { Write-Host "[INFO ] $msg" -ForegroundColor Cyan }
function Write-Warn($msg)  { Write-Host "[WARN ] $msg" -ForegroundColor Yellow }
function Write-Ok($msg)    { Write-Host "[ OK  ] $msg" -ForegroundColor Green }

function Get-ArmAccessToken {
  # Prefer Azure CLI token (muy robusto con OIDC en GitHub Actions)
  $az = Get-Command az -ErrorAction SilentlyContinue
  if ($az) {
    $token = & az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv 2>$null
    if ($LASTEXITCODE -eq 0 -and $token) { return $token }
  }

  # Fallback: Az.Accounts si existe
  $getAzToken = Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue
  if ($getAzToken) {
    return (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
  }

  throw "No se pudo obtener token ARM. Asegura login previo (azure/login) o instala Az.Accounts."
}

function Normalize-Name([string]$s) {
  if (-not $s) { return "" }
  $t = $s.ToLowerInvariant()
  # elimina todo lo no alfanumérico
  $t = [regex]::Replace($t, "[^a-z0-9]", "")
  return $t
}

function Get-InstalledContentHubSolutions {
  param([string]$subId,[string]$rg,[string]$ws,[string]$token)

  $uri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/contentPackages?api-version=2025-09-01"
  Write-Info "Listando installed packages (contentPackages) de workspace '$ws'..."
  $headers = @{ Authorization = "Bearer $token" }
  $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers

  $items = @()
  if ($resp.value) { $items = $resp.value }
  elseif ($resp)   { $items = @($resp) }

  # Filtra por contentKind=Solution si existe la propiedad (best-effort)
  $solutions = $items | Where-Object {
    $_.properties -and (
      $_.properties.contentKind -eq "Solution" -or
      $_.properties.contentKind -eq "solution" -or
      $_.kind -eq "Solution"
    )
  }

  # Si no devolvió nada filtrado, asume que todo lo devuelto son packages y aplica heurística
  if (-not $solutions -or $solutions.Count -eq 0) {
    Write-Warn "No se pudo filtrar por contentKind=Solution. Se intentará tratar todos los items como candidatos."
    $solutions = $items
  }

  $solutions | ForEach-Object {
    [pscustomobject]@{
      displayName = $_.properties.displayName
      contentId   = $_.properties.contentId
      packageId   = $_.name
    }
  } | Where-Object { $_.displayName } | Sort-Object displayName -Unique
}

function Get-OfficialSolutionsFolders {
  param([string]$branch)

  # GitHub contents API para /Solutions
  $uri = "https://api.github.com/repos/Azure/Azure-Sentinel/contents/Solutions?ref=$branch"
  Write-Info "Leyendo listado de carpetas oficiales /Solutions (GitHub API)..."
  $headers = @{
    "User-Agent" = "Jaime-Sentinel-Sync"
    "Accept"     = "application/vnd.github+json"
  }
  $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
  ($resp | Where-Object { $_.type -eq "dir" } | Select-Object -ExpandProperty name)
}

function Map-SolutionToFolder {
  param(
    [string]$displayName,
    [string]$contentId,
    [string[]]$officialFolders
  )

  # 1) Exact match por nombre de carpeta
  $exact = $officialFolders | Where-Object { $_ -eq $displayName }
  if ($exact) { return $exact[0] }

  # 2) Normalizado (quita espacios/símbolos)
  $n = Normalize-Name $displayName
  $normMatch = $officialFolders | Where-Object { (Normalize-Name $_) -eq $n }
  if ($normMatch) { return $normMatch[0] }

  # 3) Heurística: si contentId contiene tokens útiles, intenta match por substring normalizado
  if ($contentId) {
    $cid = Normalize-Name $contentId
    # intenta encontrar carpeta cuyo nombre normalizado esté contenida en contentId o viceversa
    $byCid = $officialFolders | Where-Object {
      $fn = Normalize-Name $_
      ($cid -like "*$fn*") -or ($fn -like "*$cid*")
    }
    if ($byCid) { return $byCid[0] }
  }

  return $null
}

function Ensure-Dir([string]$path) {
  if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path | Out-Null }
}

# ---------------- MAIN ----------------

$token = Get-ArmAccessToken

$installed = Get-InstalledContentHubSolutions -subId $SubscriptionId -rg $ResourceGroupName -ws $WorkspaceName -token $token
Write-Ok ("Soluciones detectadas (candidatas) en Content Hub: {0}" -f $installed.Count)

$officialFolders = Get-OfficialSolutionsFolders -branch $AzureSentinelBranch

# Mapea soluciones instaladas -> carpetas oficiales
$map = @()
foreach ($s in $installed) {
  $folder = Map-SolutionToFolder -displayName $s.displayName -contentId $s.contentId -officialFolders $officialFolders
  $map += [pscustomobject]@{
    displayName = $s.displayName
    contentId   = $s.contentId
    folder      = $folder
  }
}

$found    = $map | Where-Object { $_.folder }
$notFound = $map | Where-Object { -not $_.folder }

Write-Ok ("Mapeadas a repo oficial: {0}" -f $found.Count)
if ($notFound.Count -gt 0) {
  Write-Warn "No mapeadas (se omiten):"
  $notFound | ForEach-Object { Write-Warn (" - {0} (contentId: {1})" -f $_.displayName, $_.contentId) }
}

if ($found.Count -eq 0) {
  Write-Warn "No hay soluciones mapeadas. Fin."
  exit 0
}

# Sparse checkout del repo oficial solo para las soluciones detectadas
$tmpBase = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$tmpRepo = Join-Path $tmpBase ("azure-sentinel-" + [guid]::NewGuid().ToString("N"))

Write-Info "Clonando repo oficial (sparse-checkout) en: $tmpRepo"
& git clone --filter=blob:none --no-checkout --depth 1 --branch $AzureSentinelBranch $AzureSentinelRepo $tmpRepo | Out-Null
Push-Location $tmpRepo

& git sparse-checkout init --cone | Out-Null

$dirs = $found | Select-Object -ExpandProperty folder -Unique | ForEach-Object { "Solutions/$_" }

# En Windows/Pwsh a veces conviene splatting en array
& git sparse-checkout set --cone @($dirs) | Out-Null
& git checkout $AzureSentinelBranch | Out-Null

Pop-Location

# Copia de contenido a tu repo
$wantedSubfolders = @(
  "Analytic Rules",
  "Automation Rules",
  "Hunting Queries",
  "Parsers",
  "Playbooks",
  "Workbooks"
)

Ensure-Dir $DestinationRoot

$copiedAny = 0
foreach ($x in $found) {
  $srcSolutionPath = Join-Path $tmpRepo ("Solutions/{0}" -f $x.folder)
  if (-not (Test-Path $srcSolutionPath)) {
    Write-Warn "No existe en clone: $srcSolutionPath (se omite)"
    continue
  }

  $dstSolutionPath = Join-Path $DestinationRoot $x.folder
  Ensure-Dir $dstSolutionPath

  Write-Info "==> Copiando solución: $($x.displayName)  ->  $dstSolutionPath"

  foreach ($sub in $wantedSubfolders) {
    $src = Join-Path $srcSolutionPath $sub
    if (Test-Path $src) {
      $dst = Join-Path $dstSolutionPath $sub
      Ensure-Dir $dst
      Copy-Item -Path (Join-Path $src "*") -Destination $dst -Recurse -Force -ErrorAction Stop
      Write-Ok "  Copiado: $sub"
      $copiedAny++
    }
    else {
      Write-Warn "  No existe: $sub (continúo)"
    }
  }
}

Write-Ok "Finalizado. Carpetas copiadas (conteo aproximado por tipo): $copiedAny"
Write-Info "Destino: $DestinationRoot"
