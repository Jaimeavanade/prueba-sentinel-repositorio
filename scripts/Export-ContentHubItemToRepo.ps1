<#
.SYNOPSIS
Exporta un item de Content Hub (catálogo) a un ARM JSON "repo-ready" para Microsoft Sentinel Repositories.

.DESCRIPTION
Patrón robusto (evita 502 por expand masivo):
1) Buscar SOLUCIÓN con contentProductPackages usando $search (sin expand)
2) Resolver contentId exacto (mejor match por displayName + preferir no-preview + version más alta)
3) Traer SOLO ese paquete con $filter por contentId + $expand=properties/packagedContent (payload pequeño)
4) Encontrar el item dentro de packagedContent por displayName (case-insensitive; fallback contains)
5) Extraer mainTemplate (o packagedContent si aplica)
6) Reescribir el resource.type principal a formato Repositories
7) Guardar <ContentType>/<SolutionName>/<ItemName>.json (UTF-8 sin BOM)

Incluye retry/backoff para 429/5xx + logging explícito para que SIEMPRE veas el fallo en Actions.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SubscriptionId,
  [Parameter(Mandatory=$true)][string]$ResourceGroup,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,

  [Parameter(Mandatory=$true)]
  [ValidateSet("Analytics rules","Hunting queries","Parsers","Workbooks","Playbooks")]
  [string]$ContentType,

  [Parameter(Mandatory=$true)][string]$SolutionName,
  [Parameter(Mandatory=$true)][string]$ItemName,

  [Parameter(Mandatory=$false)][string]$ApiVersion = "2025-09-01",
  [Parameter(Mandatory=$false)][string]$OutputRoot = ".",
  [Parameter(Mandatory=$false)][switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------ Auth ------------------------
function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegura azure/login (OIDC) antes de ejecutar."
  }
  return $t
}

# ------------------------ REST with retry ------------------------
function Invoke-ArmGetWithRetry {
  param(
    [Parameter(Mandatory=$true)][string]$Uri,
    [int]$MaxRetries = 6,
    [int]$BaseDelaySeconds = 2
  )

  $headers = @{
    Authorization = "Bearer $script:ArmToken"
    "Content-Type" = "application/json"
  }

  for ($attempt=1; $attempt -le $MaxRetries; $attempt++) {
    try {
      Write-Host "GET [$attempt/$MaxRetries] $Uri"
      return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
    } catch {
      $status = $null
      $body = $null

      try {
        if ($_.Exception.Response) {
          $status = [int]$_.Exception.Response.StatusCode
          if ($_.Exception.Response.GetResponseStream) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $body = $reader.ReadToEnd()
          }
        }
      } catch {}

      # Reintentos para 429 y 5xx (incluye 502 Bad Gateway observado) [2](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={7bc34aef-96df-4345-8bfd-69f04009d2cf}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})
      $retryable = $false
      if ($status -eq 429) { $retryable = $true }
      if ($status -ge 500 -and $status -lt 600) { $retryable = $true }

      if (-not $retryable -or $attempt -eq $MaxRetries) {
        if ($body) {
          throw "Fallo GET (Status=$status). Uri=$Uri. Body=$body"
        }
        throw "Fallo GET. Uri=$Uri. Error=$($_.Exception.Message)"
      }

      $sleep = [Math]::Min(60, $BaseDelaySeconds * [Math]::Pow(2, ($attempt-1)))
      Write-Warning "Fallo transitorio (Status=$status). Reintentando en $sleep s..."
      Start-Sleep -Seconds $sleep
    }
  }
}

function Normalize-NextLink {
  param([Parameter(Mandatory=$true)][string]$NextLink, [Parameter(Mandatory=$true)][string]$ApiVersion)
  $fixed = $NextLink
  $fixed = $fixed -replace '\$SkipToken', '`$skipToken'
  if ($fixed -notmatch 'api-version=') {
    if ($fixed -match '\?') { $fixed = "$fixed&api-version=$ApiVersion" }
    else { $fixed = "$fixed?api-version=$ApiVersion" }
  }
  return $fixed
}

# ------------------------ Mapping ------------------------
function Get-RepoResourceTypeFromContentType {
  switch ($ContentType.ToLowerInvariant()) {
    'analytics rules' { 'Microsoft.SecurityInsights/alertRules' }
    'hunting queries' { 'Microsoft.SecurityInsights/huntingQueries' }
    'parsers'         { 'Microsoft.SecurityInsights/parsers' }
    'workbooks'       { 'Microsoft.Insights/workbooks' }
    'playbooks'       { 'Microsoft.Logic/workflows' }
    default { throw "ContentType '$ContentType' no soportado." }
  }
}

function Sanitize-Name([string]$s) {
  [IO.Path]::GetInvalidFileNameChars() | ForEach-Object { $s = $s.Replace($_,' ') }
  $s.Trim()
}

function Try-ParseVersion([string]$v) {
  try { return [version]$v } catch { return [version]"0.0.0" }
}

# ------------------------ Catalog helpers ------------------------
function Get-CatalogPackagesBySearch {
  param(
    [Parameter(Mandatory=$true)][string]$Base,
    [Parameter(Mandatory=$true)][string]$SearchText,
    [Parameter(Mandatory=$true)][string]$ApiVersion
  )

  $searchEncoded = [System.Uri]::EscapeDataString($SearchText)
  $uri = "$Base/contentProductPackages?api-version=$ApiVersion&`$search=$searchEncoded&`$top=100"
  $resp = Invoke-ArmGetWithRetry -Uri $uri
  return @($resp.value)
}

function Select-BestSolutionPackage {
  param(
    [Parameter(Mandatory=$true)][object[]]$Packages,
    [Parameter(Mandatory=$true)][string]$SolutionDisplayName
  )

  $matches = $Packages | Where-Object {
    $_.properties -and $_.properties.contentKind -eq 'Solution' -and $_.properties.displayName -and ($_.properties.displayName -ieq $SolutionDisplayName)
  }

  if (-not $matches -or $matches.Count -eq 0) { return $null }

  # Preferir no-preview y mayor versión
  $best = $matches |
    Sort-Object `
      @{ Expression = { [bool]$_.properties.isPreview }; Ascending = $true }, `
      @{ Expression = { Try-ParseVersion $_.properties.version }; Descending = $true } |
    Select-Object -First 1

  return $best
}

function Get-PackageWithPackagedContent {
  param(
    [Parameter(Mandatory=$true)][string]$Base,
    [Parameter(Mandatory=$true)][string]$ContentId,
    [Parameter(Mandatory=$true)][string]$ApiVersion
  )

  # $filter por contentId + contentKind=Solution y expand SOLO para 1 paquete (payload pequeño => evita 502)
  $contentIdEsc = $ContentId.Replace("'", "''")
  $filter = "properties/contentKind eq 'Solution' and properties/contentId eq '$contentIdEsc'"
  $filterEncoded = [System.Uri]::EscapeDataString($filter)

  $uri = "$Base/contentProductPackages?api-version=$ApiVersion&`$filter=$filterEncoded&`$expand=properties/packagedContent&`$top=5"
  $resp = Invoke-ArmGetWithRetry -Uri $uri
  if (-not $resp.value -or $resp.value.Count -eq 0) { return $null }
  return ($resp.value | Select-Object -First 1)
}

function Find-ItemInPackagedContent {
  param(
    [Parameter(Mandatory=$true)][object[]]$PackagedContent,
    [Parameter(Mandatory=$true)][string]$ItemDisplayName
  )

  $exact = $PackagedContent | Where-Object { $_.properties -and $_.properties.displayName -and ($_.properties.displayName -ieq $ItemDisplayName) } | Select-Object -First 1
  if ($exact) { return $exact }

  $contains = $PackagedContent | Where-Object { $_.properties -and $_.properties.displayName -and ($_.properties.displayName -ilike "*$ItemDisplayName*") } | Select-Object -First 1
  if ($contains) { return $contains }

  return $null
}

function Update-ArmTypeRepoReady {
  param(
    [Parameter(Mandatory=$true)]$MainTemplateObj,
    [Parameter(Mandatory=$true)][string]$TargetType
  )

  $arm = $MainTemplateObj | ConvertTo-Json -Depth 200 | ConvertFrom-Json -Depth 200

  if (-not $arm.resources -or $arm.resources.Count -eq 0) {
    throw "ARM template sin 'resources'."
  }

  $res = $arm.resources |
    Where-Object {
      $_.type -and
      $_.type -notlike '*providers/metadata*' -and
      $_.type -notlike 'Microsoft.Resources/deployments'
    } |
    Select-Object -First 1

  if (-not $res) { throw "No se encontró recurso principal para cambiar type." }

  $old = $res.type
  $res.type = $TargetType
  Write-Host "✅ Type cambiado: '$old' -> '$TargetType'"

  return ($arm | ConvertTo-Json -Depth 200)
}

# ------------------------ MAIN ------------------------
Write-Host "=== Export Content Hub Item To Repo (Repo-ready) ==="
Write-Host "SolutionName: $SolutionName"
Write-Host "ItemName:     $ItemName"
Write-Host "ContentType:  $ContentType"
Write-Host "ApiVersion:   $ApiVersion"

$script:ArmToken = Get-ArmToken

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# 1) Buscar solución en catálogo (sin expand)
$pkgs = Get-CatalogPackagesBySearch -Base $base -SearchText $SolutionName -ApiVersion $ApiVersion
if (-not $pkgs -or $pkgs.Count -eq 0) {
  throw "No se devolvieron paquetes en catálogo para search='$SolutionName'."
}

$best = Select-BestSolutionPackage -Packages $pkgs -SolutionDisplayName $SolutionName
if (-not $best) {
  $names = ($pkgs | Where-Object { $_.properties -and $_.properties.contentKind -eq 'Solution' } | ForEach-Object { $_.properties.displayName } | Select-Object -Unique) -join ", "
  throw "No encontré match exacto de solución '$SolutionName'. Soluciones candidatas: $names"
}

$contentId = $best.properties.contentId
Write-Host "✅ Solución resuelta -> contentId: $contentId (version: $($best.properties.version), isPreview: $($best.properties.isPreview))"

# 2) Traer SOLO ese paquete con packagedContent (expand pequeño)
$pkgFull = Get-PackageWithPackagedContent -Base $base -ContentId $contentId -ApiVersion $ApiVersion
if (-not $pkgFull) { throw "No se pudo obtener packagedContent para contentId='$contentId'." }

$packaged = @($pkgFull.properties.packagedContent)
if (-not $packaged -or $packaged.Count -eq 0) {
  throw "packagedContent vacío para solución '$SolutionName' (contentId=$contentId)."
}
Write-Host "✅ packagedContent items: $($packaged.Count)"

# 3) Encontrar el item
$item = Find-ItemInPackagedContent -PackagedContent $packaged -ItemDisplayName $ItemName
if (-not $item) {
  $top = ($packaged | Select-Object -First 30 | ForEach-Object { $_.properties.displayName }) -join " | "
  throw "No encontré item '$ItemName' en packagedContent. Ejemplos (top 30): $top"
}

Write-Host "✅ Item encontrado -> displayName: $($item.properties.displayName)"

# 4) Extraer mainTemplate
$main = $null
if ($item.properties.PSObject.Properties.Name -contains 'mainTemplate' -and $item.properties.mainTemplate) {
  $main = $item.properties.mainTemplate
} elseif ($item.properties.PSObject.Properties.Name -contains 'packagedContent' -and $item.properties.packagedContent) {
  $main = $item.properties.packagedContent
}
if (-not $main) {
  throw "El item no trae mainTemplate ni packagedContent (displayName=$($item.properties.displayName))."
}

# 5) Reescribir type
$targetType = Get-RepoResourceTypeFromContentType -ContentType $ContentType
$json = Update-ArmTypeRepoReady -MainTemplateObj $main -TargetType $targetType

# 6) Guardar
$outDir  = Join-Path $OutputRoot (Join-Path $ContentType (Sanitize-Name $SolutionName))
$outFile = Join-Path $outDir ((Sanitize-Name $ItemName) + ".json")

if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
if ((Test-Path $outFile) -and -not $Force) { throw "El archivo ya existe: $outFile (usa Force=true)." }

[IO.File]::WriteAllText($outFile, $json, (New-Object Text.UTF8Encoding($false)))
Write-Host "✅ Export generado correctamente: $outFile"
