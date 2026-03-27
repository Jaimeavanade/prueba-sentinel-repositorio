[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$SubscriptionId,
  [Parameter(Mandatory = $true)][string]$ResourceGroupName,
  [Parameter(Mandatory = $true)][string]$WorkspaceName,
  [string]$ApiVersion = "2025-09-01",
  [string]$OutReportJson = "Solutions/contenthub-installed-items-report.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------- Helpers ----------

function Get-ArmToken {
  az account get-access-token `
    --resource https://management.azure.com/ `
    --query accessToken -o tsv
}

function Invoke-ArmGet {
  param([string]$Uri)
  Invoke-RestMethod -Method GET -Uri $Uri -Headers @{
    Authorization = "Bearer $script:ArmToken"
  }
}

function Get-AllPages {
  param([string]$Uri)
  $all = @()
  while ($Uri) {
    $r = Invoke-ArmGet $Uri
    if ($r.value) { $all += $r.value }
    $Uri = $r.nextLink
  }
  return $all
}

function Map-Kind {
  param([string]$Type)
  switch -Wildcard ($Type.ToLower()) {
    "*/alertrules"      { "AnalyticsRule" }
    "*/workbooks"       { "Workbook" }
    "*/huntqueries"     { "HuntingQuery" }
    "*/automationrules" { "AutomationRule" }
    "*/parsers"         { "Parser" }
    default             { "Other" }
  }
}

# ---------- START ----------

$script:ArmToken = Get-ArmToken
$report = @()

Write-Host "==> Listando soluciones de Content Hub INSTALADAS..."

$packagesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/${WorkspaceName}/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersion"
$packages = Get-AllPages $packagesUri

foreach ($pkg in $packages) {

  $solutionName    = $pkg.name
  $solutionDisplay = $pkg.properties.displayName
  $contentId       = $pkg.properties.contentId

  Write-Host "----"
  Write-Host "Solución: $solutionDisplay"

  # ==========================
  # 1️⃣ CONTENT ITEMS INSTALADOS
  # ==========================

  $installedUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/${WorkspaceName}/providers/Microsoft.SecurityInsights/contentPackages/${solutionName}/contentTemplates?api-version=$ApiVersion"

  try {
    $installedItems = Get-AllPages $installedUri
  } catch {
    $installedItems = @()
  }

  foreach ($item in $installedItems) {
    $report += [pscustomobject]@{
      solutionDisplayName = $solutionDisplay
      solutionName        = $solutionName
      itemDisplayName     = $item.properties.displayName
      itemKind            = Map-Kind $item.type
      itemType            = $item.type
      source              = "installed"
    }
  }

  # ==========================
  # 2️⃣ CONTENT ITEMS DEL CATÁLOGO
  # ==========================

  if (-not $contentId) { continue }

  $catalogUri = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.SecurityInsights/contentProductPackages/${contentId}?api-version=$ApiVersion&`$expand=properties/packagedContent"

  try {
    $catalog = Invoke-ArmGet $catalogUri
    $template = $catalog.properties.packagedContent.template
  } catch {
    continue
  }

  foreach ($res in $template.resources) {
    if (-not $res.properties.displayName) { continue }

    $report += [pscustomobject]@{
      solutionDisplayName = $solutionDisplay
      solutionName        = $solutionName
      itemDisplayName     = $res.properties.displayName
      itemKind            = Map-Kind $res.type
      itemType            = $res.type
      source              = "catalog"
    }
  }
}

# ---------- OUTPUT ----------

$report |
  Sort-Object solutionDisplayName, itemKind, itemDisplayName |
  ConvertTo-Json -Depth 20 |
  Out-File $OutReportJson -Encoding utf8

Write-Host "✅ Report generado correctamente:"
Write-Host "   $OutReportJson"
