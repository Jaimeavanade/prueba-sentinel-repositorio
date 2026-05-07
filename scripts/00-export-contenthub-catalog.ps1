# scripts/00-export-contenthub-catalog.ps1
<#
.SYNOPSIS
Exporta el catálogo completo de soluciones (Content Hub) a CSV con installedVersion real.

.DESCRIPTION
- Catálogo: GET contentProductPackages (filtrando contentKind=Solution).
- Instaladas: GET contentPackages (contentKind=Solution) para mapear installedVersion por contentId.
- Paginación: usa nextLink y normaliza api-version + $skipToken.
- Exporta: displayName,contentId,contentProductId,version,isPreview,installedVersion

API:
- Product Packages (catálogo): /contentProductPackages  (api-version 2025-09-01)  [5](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01)
- Content Packages (instaladas): /contentPackages        (api-version 2025-09-01)  [3](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$SubscriptionId,
  [Parameter(Mandatory=$true)][string]$ResourceGroupName,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,

  [Parameter(Mandatory=$false)][string]$ApiVersion = "2025-09-01",
  [Parameter(Mandatory=$false)][string]$OutCsv     = "contenthub-solutions-catalog.csv",
  [Parameter(Mandatory=$false)][switch]$IncludePreview,
  [Parameter(Mandatory=$false)][string]$Search = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegura azure/login (OIDC) antes."
  }
  return $t
}

function Invoke-ArmGet {
  param([Parameter(Mandatory=$true)][string]$Uri)

  $headers = @{
    Authorization  = "Bearer $script:ArmToken"
    "Content-Type" = "application/json"
  }

  try {
    return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
  } catch {
    $body = $null
    try {
      if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $body = $reader.ReadToEnd()
      }
    } catch {}
    if ($body) { throw "Fallo GET. Uri=$Uri. Body=$body" }
    throw "Fallo GET. Uri=$Uri. Error=$($_.Exception.Message)"
  }
}

function Normalize-NextLink {
  param(
    [Parameter(Mandatory=$true)][string]$NextLink,
    [Parameter(Mandatory=$true)][string]$ApiVersion
  )
  $fixed = $NextLink
  $fixed = $fixed -replace '\$SkipToken', '`$skipToken'
  if ($fixed -notmatch 'api-version=') {
    if ($fixed -match '\?') { $fixed = "$fixed&api-version=$ApiVersion" }
    else { $fixed = "$fixed?api-version=$ApiVersion" }
  }
  return $fixed
}

$script:ArmToken = Get-ArmToken

# 1) Mapear installedVersion desde contentPackages (instaladas)
$installedMap = @{}  # contentId -> version
$installedUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
$installed = Invoke-ArmGet -Uri $installedUri

if ($installed.value) {
  foreach ($pkg in $installed.value) {
    if (-not $pkg.properties) { continue }
    if ($pkg.properties.contentKind -ne "Solution") { continue }
    $cid = $pkg.properties.contentId
    $ver = $pkg.properties.version
    if ($cid) { $installedMap[$cid] = $ver }
  }
}

# 2) Catálogo contentProductPackages (Solutions)
$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion"
if ($Search -and $Search.Trim().Length -gt 0) {
  $q = [System.Uri]::EscapeDataString($Search.Trim())
  $base = "$base&`$search=$q"
}
$base = "$base&`$top=50"

Write-Host "Export catálogo Content Hub (Solutions)"
Write-Host "Workspace: $WorkspaceName"
Write-Host "ApiVersion: $ApiVersion"
Write-Host "IncludePreview: $IncludePreview"
if ($Search -and $Search.Trim()) { Write-Host "Search: $Search" }
Write-Host "OutCsv: $OutCsv"
Write-Host ""

$items = New-Object System.Collections.Generic.List[object]
$next = $base
$page = 0

while ($next) {
  $page++
  Write-Host "Descargando página $page ..."
  $resp = Invoke-ArmGet -Uri $next

  if ($resp.value) {
    foreach ($p in $resp.value) {
      if (-not $p.properties) { continue }
      if ($p.properties.contentKind -ne "Solution") { continue }

      $isPreview = $false
      if ($p.properties.PSObject.Properties.Name -contains "isPreview") {
        try { $isPreview = [bool]$p.properties.isPreview } catch { $isPreview = $false }
      }
      if (-not $IncludePreview -and $isPreview) { continue }

      $contentId = $p.properties.contentId
      $installedVersion = $null
      if ($contentId -and $installedMap.ContainsKey($contentId)) {
        $installedVersion = $installedMap[$contentId]
      }

      $items.Add([pscustomobject]@{
        displayName      = $p.properties.displayName
        contentId        = $contentId
        contentProductId = $p.properties.contentProductId
        version          = $p.properties.version
        isPreview        = $isPreview
        installedVersion = $installedVersion
      })
    }
  }

  if ($resp.nextLink) { $next = Normalize-NextLink -NextLink $resp.nextLink -ApiVersion $ApiVersion }
  else { $next = $null }
}

Write-Host ""
Write-Host "Total Solutions exportadas: $($items.Count)"

($items | Sort-Object displayName) | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host "CSV generado: $OutCsv"
