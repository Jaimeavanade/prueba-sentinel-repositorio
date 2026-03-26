<#
Exporta inventario de:
- Soluciones instaladas (Content Hub) -> contentPackages (installed packages) [3](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)
- Content items instalados -> contentTemplates (installed templates) [4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-templates/list?view=rest-securityinsights-2025-09-01)

Salida:
- contenthub-installed-report.txt
Columnas:
- solution name
- content name
- content type
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ====== Config desde ENV ======
$SubscriptionId   = $env:AZURE_SUBSCRIPTION_ID
$ResourceGroup    = $env:RESOURCE_GROUP
$WorkspaceName    = $env:WORKSPACE_NAME
$ApiVersion       = "2025-09-01"
$OutputPath       = Join-Path (Get-Location) "contenthub-installed-report.txt"

if (-not $SubscriptionId) { throw "Falta env: AZURE_SUBSCRIPTION_ID" }
if (-not $ResourceGroup)  { throw "Falta env: RESOURCE_GROUP" }
if (-not $WorkspaceName)  { throw "Falta env: WORKSPACE_NAME" }

function Get-ArmToken {
  try {
    $t = az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv 2>$null
    if (-not $t) { throw "Token vacío" }
    return $t
  } catch {
    throw "No se pudo obtener token ARM via Azure CLI. Asegúrate de haber hecho azure/login. Error: $($_.Exception.Message)"
  }
}

function Invoke-ArmGetAll {
  param([Parameter(Mandatory=$true)][string] $InitialUri)

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
      $nl = [string]$resp.nextLink

      # nextLink a veces viene sin api-version; lo añadimos (patrón que ya usas en tus scripts) [5](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={de506d0d-e4ee-4270-8873-e1ea6b67e29b}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})
      if ($nl -notmatch "api-version=") {
        if ($nl -match "\?") { $nl = "$nl&api-version=$ApiVersion" } else { $nl = "$nl?api-version=$ApiVersion" }
      }

      # Normaliza casing si viniera como $SkipToken
      $nl = $nl -replace '\$SkipToken', '`$skipToken'

      $uri = $nl
    }
  }

  return $all
}

# 1) Soluciones instaladas (contentPackages) [3](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)
$packagesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
$installedPackages = Invoke-ArmGetAll -InitialUri $packagesUri

# Mapa: packageId(name) -> displayName
$packageMap = @{}
foreach ($p in $installedPackages) {
  $pid = $p.name
  $pname = if ($p.properties -and $p.properties.displayName) { [string]$p.properties.displayName } else { $pid }
  $packageMap[$pid] = $pname
}

# 2) Content items instalados (contentTemplates) [4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-templates/list?view=rest-securityinsights-2025-09-01)
$templatesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersion&`$top=500"
$installedTemplates = Invoke-ArmGetAll -InitialUri $templatesUri

# 3) Construcción del TXT
$rows = New-Object System.Collections.Generic.List[string]
$rows.Add("solution_name`tcontent_name`tcontent_type")

foreach ($t in $installedTemplates) {
  $tp = $t.properties
  if (-not $tp) { continue }

  $contentName =
    if ($tp.displayName) { [string]$tp.displayName }
    elseif ($tp.contentId) { [string]$tp.contentId }
    else { [string]$t.name }

  $contentType = if ($tp.contentKind) { [string]$tp.contentKind } else { "Unknown" }

  $pkgId = if ($tp.packageId) { [string]$tp.packageId } else { $null }

  $solutionName = "Standalone/UnknownSolution"
  if ($pkgId) {
    if ($packageMap.ContainsKey($pkgId)) { $solutionName = $packageMap[$pkgId] }
    else { $solutionName = $pkgId }
  }

  $rows.Add("$solutionName`t$contentName`t$contentType")
}

# Ordenar (dejando header arriba)
$sorted = $rows | Select-Object -First 1
$sorted += ($rows | Select-Object -Skip 1 | Sort-Object)

# Guardar UTF-8 sin BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($OutputPath, $sorted, $utf8NoBom)

Write-Host "OK -> generado: $OutputPath"
Write-Host "Soluciones instaladas encontradas: $($installedPackages.Count)"
Write-Host "Content items instalados encontrados: $($installedTemplates.Count)"
