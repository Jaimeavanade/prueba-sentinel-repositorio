<#
.SYNOPSIS
  Exporta un inventario de soluciones instaladas (Content Hub) y sus content items instalados en Microsoft Sentinel
  y lo guarda como TXT.

.DESCRIPTION
  - Lee soluciones instaladas desde:
      Microsoft.SecurityInsights/contentPackages  (API 2025-09-01)
    (Gets all installed packages)  [1](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)

  - Lee content items instalados desde:
      Microsoft.SecurityInsights/contentTemplates (API 2025-09-01)
    (Gets all installed templates) [2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-templates/list?view=rest-securityinsights-2025-09-01)

  - Relaciona items con soluciones usando properties.packageId del template.

.OUTPUT
  - contenthub-installed-report.txt (por defecto en la raíz del repo)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string] $SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string] $ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string] $WorkspaceName,

  [Parameter(Mandatory = $false)]
  [string] $ApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string] $OutputPath = "$(Join-Path (Get-Location) 'contenthub-installed-report.txt')"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  # En GitHub Actions con azure/login (OIDC), ARM token suele venir en AZURE_FEDERATED_TOKEN_FILE para login,
  # pero para llamadas ARM lo más estable aquí es pedir token vía Azure CLI.
  # Requisito: azure/login ya autenticó y az está disponible.
  try {
    $t = az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv 2>$null
    if (-not $t) { throw "Token vacío" }
    return $t
  } catch {
    throw "No se pudo obtener token ARM. Asegúrate de ejecutar azure/login antes. Error: $($_.Exception.Message)"
  }
}

function Invoke-ArmGetAll {
  param(
    [Parameter(Mandatory=$true)][string] $InitialUri
  )

  $token = Get-ArmToken
  $headers = @{
    Authorization  = "Bearer $token"
    "Content-Type" = "application/json"
  }

  $all = New-Object System.Collections.Generic.List[object]
  $uri = $InitialUri

  while ($uri) {
    $resp = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
    if ($resp.value) {
      foreach ($v in $resp.value) { [void]$all.Add($v) }
    }
    $uri = $null
    if ($resp.nextLink) {
      # nextLink a veces viene sin api-version, lo añadimos si hace falta (patrón que ya tienes en tus scripts) [4](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={de506d0d-e4ee-4270-8873-e1ea6b67e29b}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})
      $nl = [string]$resp.nextLink
      if ($nl -notmatch "api-version=") {
        if ($nl -match "\?") { $nl = "$nl&api-version=$ApiVersion" } else { $nl = "$nl?api-version=$ApiVersion" }
      }
      # Normaliza casing raro si viniera como $SkipToken -> $skipToken
      $nl = $nl -replace '\$SkipToken', '`$skipToken'
      $uri = $nl
    }
  }

  return $all
}

# 1) Soluciones instaladas (Content Hub installed packages) [1](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)
$packagesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
$installedPackages = Invoke-ArmGetAll -InitialUri $packagesUri

# Mapa: packageId(resource name) -> displayName
$packageMap = @{}
foreach ($p in $installedPackages) {
  $pid = $p.name
  $pname = $null
  if ($p.properties -and $p.properties.displayName) { $pname = [string]$p.properties.displayName }
  if (-not $pname) { $pname = $pid }
  $packageMap[$pid] = $pname
}

# 2) Content items instalados (installed templates) [2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-templates/list?view=rest-securityinsights-2025-09-01)
$templatesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersion&`$top=500"
$installedTemplates = Invoke-ArmGetAll -InitialUri $templatesUri

# 3) Construir filas (SolutionName | ContentName | ContentType)
$rows = New-Object System.Collections.Generic.List[string]

# Header
$rows.Add("solution_name`tcontent_name`tcontent_type")

foreach ($t in $installedTemplates) {
  $tp = $t.properties
  if (-not $tp) { continue }

  $contentName = $null
  if ($tp.displayName) { $contentName = [string]$tp.displayName }
  elseif ($tp.contentId) { $contentName = [string]$tp.contentId }
  else { $contentName = [string]$t.name }

  $contentType = $null
  if ($tp.contentKind) { $contentType = [string]$tp.contentKind }
  else { $contentType = "Unknown" }

  # Relación con paquete
  $pkgId = $null
  if ($tp.packageId) { $pkgId = [string]$tp.packageId }

  $solutionName = "Standalone/UnknownSolution"
  if ($pkgId) {
    if ($packageMap.ContainsKey($pkgId)) {
      $solutionName = $packageMap[$pkgId]
    } else {
      # Si el template dice packageId pero no está en contentPackages, mantenemos el id como fallback.
      $solutionName = $pkgId
    }
  }

  $rows.Add("$solutionName`t$contentName`t$contentType")
}

# 4) Ordenar y guardar
$sorted = $rows | Select-Object -First 1
$sorted += ($rows | Select-Object -Skip 1 | Sort-Object)

# Guardar TXT (UTF8 sin BOM para evitar problemas en pipelines)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($OutputPath, $sorted, $utf8NoBom)

Write-Host "OK -> generado: $OutputPath"
Write-Host "Soluciones instaladas encontradas: $($installedPackages.Count)"
Write-Host "Content items instalados encontrados: $($installedTemplates.Count)"
