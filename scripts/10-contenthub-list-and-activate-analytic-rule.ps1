<#
.SYNOPSIS
  - Lista soluciones de Content Hub instaladas en un workspace de Sentinel.
  - Lista content items INSTALADOS por solución (contentTemplates).
  - Lista content items del CATÁLOGO por solución (packagedContent).
  - Opcional: activa/crea UNA Analytics Rule por displayName (deployment incremental con template mínimo).

.REQUIREMENTS
  - Ejecutar tras azure/login (OIDC) en GitHub Actions.
  - Requiere Azure CLI (az) para obtener token ARM.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory = $true)][string]$SubscriptionId,
  [Parameter(Mandatory = $true)][string]$ResourceGroupName,
  [Parameter(Mandatory = $true)][string]$WorkspaceName,

  [Parameter(Mandatory = $false)][ValidateSet("list-only","activate")]
  [string]$Mode = "list-only",

  [Parameter(Mandatory = $false)]
  [string]$DisplayName = "",

  [Parameter(Mandatory = $false)][ValidateSet("exact","contains")]
  [string]$MatchMode = "exact",

  [Parameter(Mandatory = $false)]
  [string]$ApiVersionSecurityInsights = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string]$ApiVersionOperationalInsights = "2025-07-01",

  [Parameter(Mandatory = $false)]
  [string]$ApiVersionDeployments = "2022-09-01",

  [Parameter(Mandatory = $false)]
  [string]$OutReportJson = "Solutions/contenthub-installed-items-report.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------- Helpers ----------------

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegura azure/login (OIDC) antes."
  }
  return $t
}

function Invoke-ArmGet {
  param([Parameter(Mandatory=$true)][string]$Uri)
  $headers = @{ Authorization = "Bearer $script:ArmToken" }
  return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
}

function Invoke-ArmPut {
  param(
    [Parameter(Mandatory=$true)][string]$Uri,
    [Parameter(Mandatory=$true)][object]$Body
  )
  $headers = @{ Authorization = "Bearer $script:ArmToken" }
  $json = ($Body | ConvertTo-Json -Depth 80)
  return Invoke-RestMethod -Method PUT -Uri $Uri -Headers $headers -ContentType "application/json" -Body $json
}

function Get-AllPages {
  param([Parameter(Mandatory=$true)][string]$FirstUri)

  $all = @()
  $uri = $FirstUri
  $page = 0

  while ($uri) {
    $page++
    $resp = Invoke-ArmGet -Uri $uri
    if ($resp.value) { $all += $resp.value }
    $uri = $null
    if ($resp.nextLink) { $uri = $resp.nextLink }
  }
  return $all
}

function Map-KindFromResourceType {
  param([Parameter(Mandatory=$true)][string]$Type)

  $t = $Type.ToLowerInvariant()
  if ($t -like "*/alertrules")      { return "AnalyticsRule" }
  if ($t -like "*/workbooks")       { return "Workbook" }
  if ($t -like "*/huntqueries")     { return "HuntingQuery" }
  if ($t -like "*/automationrules") { return "AutomationRule" }
  if ($t -like "*/watchlists")      { return "Watchlist" }
  if ($t -like "*/parsers")         { return "Parser" }
  if ($t -like "*/savedsearches")   { return "SavedSearch" }
  return "Other"
}

function Get-WorkspaceInfo {
  # FIX: ${WorkspaceName} porque va pegado a '?api-version'
  $wsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/${WorkspaceName}?api-version=$ApiVersionOperationalInsights"
  return Invoke-ArmGet -Uri $wsUri
}

function Try-Get-CatalogPackageById {
  param([Parameter(Mandatory=$true)][string]$CatalogId)

  # FIX: ${CatalogId} porque va pegado a '?api-version'
  $u = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.SecurityInsights/contentProductPackages/${CatalogId}?api-version=$ApiVersionSecurityInsights&`$expand=properties/packagedContent"
  try { return Invoke-ArmGet -Uri $u } catch { return $null }
}

function Try-Get-CatalogPackageByContentProductId {
  param([Parameter(Mandatory=$true)][string]$ContentProductId)

  $u = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersionSecurityInsights&`$filter=properties/contentProductId eq '$ContentProductId'&`$expand=properties/packagedContent&`$top=1"
  try {
    $r = Invoke-ArmGet -Uri $u
    if ($r.value -and $r.value.Count -ge 1) { return $r.value[0] }
    return $null
  } catch { return $null }
}

function Normalize-PackagedContentTemplate {
  param([Parameter(Mandatory=$true)][object]$CatalogObj)

  $pc = $CatalogObj.properties.packagedContent
  if (-not $pc) { return $null }

  if ($pc -is [string]) {
    try { $pc = $pc | ConvertFrom-Json -Depth 80 } catch { }
  }

  if ($pc.template)     { return $pc.template }
  if ($pc.mainTemplate) { return $pc.mainTemplate }
  if ($pc.resources -or $pc.parameters) { return $pc }

  return $null
}

function Build-DeploymentParameters {
  param(
    [Parameter(Mandatory=$true)][hashtable]$TemplateParameters,
    [Parameter(Mandatory=$true)][string]$WorkspaceResourceId,
    [Parameter(Mandatory=$true)][string]$WorkspaceLocation
  )

  $p = @{}

  foreach ($k in $TemplateParameters.Keys) {
    $kLower = $k.ToLowerInvariant()

    $hasDefault = $false
    try { if ($TemplateParameters[$k].defaultValue) { $hasDefault = $true } } catch { }

    if ($kLower -in @("workspace","workspaceid","workspace_resource_id")) {
      $p[$k] = @{ value = $WorkspaceResourceId }
      continue
    }
    if ($kLower -in @("workspacename","workspace_name")) {
      $p[$k] = @{ value = $WorkspaceName }
      continue
    }
    if ($kLower -in @("location","workspacelocation","workspace_location")) {
      $p[$k] = @{ value = $WorkspaceLocation }
      continue
    }
    if ($kLower -in @("subscriptionid")) {
      $p[$k] = @{ value = $SubscriptionId }
      continue
    }
    if ($kLower -in @("resourcegroup","resourcegroupname")) {
      $p[$k] = @{ value = $ResourceGroupName }
      continue
    }

    if (-not $hasDefault) {
      $p[$k] = $null
    }
  }

  return $p
}

function Matches-DisplayName {
  param(
    [Parameter(Mandatory=$true)][string]$Candidate,
    [Parameter(Mandatory=$true)][string]$Wanted,
    [Parameter(Mandatory=$true)][string]$Mode
  )

  if ([string]::IsNullOrWhiteSpace($Candidate)) { return $false }

  if ($Mode -eq "contains") {
    return $Candidate.IndexOf($Wanted, [System.StringComparison]::InvariantCultureIgnoreCase) -ge 0
  }

  return $Candidate.Equals($Wanted, [System.StringComparison]::InvariantCultureIgnoreCase)
}

# ---------------- MAIN ----------------

Write-Host "==> Token ARM..."
$script:ArmToken = Get-ArmToken

Write-Host "==> Workspace info..."
$wsInfo = Get-WorkspaceInfo
$workspaceLocation   = $wsInfo.location
$workspaceResourceId = $wsInfo.id

Write-Host "Workspace: $WorkspaceName | Location: $workspaceLocation"
Write-Host "Workspace ResourceId: $workspaceResourceId"
Write-Host "Mode: $Mode | MatchMode: $MatchMode | DisplayName: '$DisplayName'"

# 1) List installed solutions (contentPackages)
Write-Host "==> Listando soluciones instaladas (contentPackages)..."
$installedPackagesUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/${WorkspaceName}/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersionSecurityInsights"
$packages = Get-AllPages -FirstUri $installedPackagesUri

# Filtrar solo solutions si vienen otros kinds
$solutions = $packages | Where-Object {
  $_.properties -and $_.properties.contentKind -and $_.properties.contentKind -eq "Solution"
}

Write-Host ("Soluciones instaladas (Solutions) encontradas: {0}" -f ($solutions.Count))

$report = New-Object System.Collections.Generic.List[object]

# Para activar, necesitamos identificar el recurso de catálogo exacto
$activationTarget = $null
$activationCatalogTemplate = $null
$activationSolutionDisplay = $null

foreach ($pkg in $solutions) {
  $solutionName     = $pkg.name
  $solutionDisplay  = $pkg.properties.displayName
  $contentId        = $pkg.properties.contentId
  $contentProductId = $pkg.properties.contentProductId

  Write-Host "----"
  Write-Host "Solution installed: $solutionDisplay"

  # 2) INSTALLED content items por solución (contentTemplates)
  $installedItemsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/${WorkspaceName}/providers/Microsoft.SecurityInsights/contentPackages/${solutionName}/contentTemplates?api-version=$ApiVersionSecurityInsights"
  $installedItems = @()
  try { $installedItems = Get-AllPages -FirstUri $installedItemsUri } catch { $installedItems = @() }

  foreach ($it in $installedItems) {
    $dn = ""
    try { $dn = [string]$it.properties.displayName } catch { $dn = "" }

    $report.Add([pscustomobject]@{
      solutionDisplayName = $solutionDisplay
      solutionName        = $solutionName
      contentProductId    = $contentProductId
      contentId           = $contentId
      itemKind            = Map-KindFromResourceType -Type ([string]$it.type)
      itemType            = [string]$it.type
      itemName            = [string]$it.name
      itemDisplayName     = $dn
      source              = "installed"
    })
  }

  # 3) CATÁLOGO content items por solución (packagedContent)
  $catalog = $null
  if ($contentId) { $catalog = Try-Get-CatalogPackageById -CatalogId $contentId }
  if (-not $catalog -and $contentProductId) { $catalog = Try-Get-CatalogPackageByContentProductId -ContentProductId $contentProductId }

  if (-not $catalog) {
    Write-Warning "No se pudo obtener catálogo (packagedContent) para: $solutionDisplay"
    continue
  }

  $tmpl = Normalize-PackagedContentTemplate -CatalogObj $catalog
  if (-not $tmpl -or -not $tmpl.resources) {
    Write-Warning "packagedContent sin template/resources para: $solutionDisplay"
    continue
  }

  foreach ($res in $tmpl.resources) {
    $rtype = [string]$res.type
    $rname = [string]$res.name
    $kind  = Map-KindFromResourceType -Type $rtype

    $itemDisplay = ""
    try { if ($res.properties.displayName) { $itemDisplay = [string]$res.properties.displayName } } catch { $itemDisplay = "" }

    $report.Add([pscustomobject]@{
      solutionDisplayName = $solutionDisplay
      solutionName        = $solutionName
      contentProductId    = $contentProductId
      contentId           = $contentId
      itemKind            = $kind
      itemType            = $rtype
      itemName            = $rname
      itemDisplayName     = $itemDisplay
      source              = "catalog"
    })

    # Si se quiere activar, buscar aquí el recurso (solo AnalyticsRule)
    if ($Mode -eq "activate" -and -not [string]::IsNullOrWhiteSpace($DisplayName)) {
      if ($kind -eq "AnalyticsRule" -and (Matches-DisplayName -Candidate $itemDisplay -Wanted $DisplayName -Mode $MatchMode)) {
        $activationTarget = $res
        $activationCatalogTemplate = $tmpl
        $activationSolutionDisplay = $solutionDisplay
      }
    }
  }
}

# Guardar inventario
$reportDir = Split-Path -Parent $OutReportJson
if ($reportDir -and -not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }

($report | Sort-Object solutionDisplayName, source, itemKind, itemDisplayName | ConvertTo-Json -Depth 25) |
  Out-File -FilePath $OutReportJson -Encoding utf8

Write-Host "==> Inventario guardado en: $OutReportJson"
Write-Host "==> Total filas (installed+catalog): $($report.Count)"

# Si no toca activar, terminar
if ($Mode -ne "activate") {
  Write-Host "==> Mode=list-only. Fin."
  exit 0
}

if ([string]::IsNullOrWhiteSpace($DisplayName)) {
  throw "Mode=activate pero DisplayName está vacío. Indica un displayName."
}

if (-not $activationTarget) {
  throw "No se encontró ninguna AnalyticsRule en el CATÁLOGO con displayName '$DisplayName' (MatchMode=$MatchMode)."
}

Write-Host "==> Activando regla (AnalyticsRule) encontrada en solución: $activationSolutionDisplay"
Write-Host "    displayName: $DisplayName"

# Construir template mínimo con solo esa regla
$newTemplate = @{
  '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
  contentVersion = "1.0.0.0"
  parameters     = $activationCatalogTemplate.parameters
  variables      = $activationCatalogTemplate.variables
  resources      = @($activationTarget)
  outputs        = @{}
}

# Parámetros del deployment
$templateParams = @{}
if ($activationCatalogTemplate.parameters) {
  $templateParams = Build-DeploymentParameters -TemplateParameters $activationCatalogTemplate.parameters -WorkspaceResourceId $workspaceResourceId -WorkspaceLocation $workspaceLocation
}

# Validar parámetros requeridos no resueltos
$missing = @()
foreach ($k in $templateParams.Keys) {
  if ($null -eq $templateParams[$k]) { $missing += $k }
}
if ($missing.Count -gt 0) {
  throw "No puedo rellenar automáticamente estos parámetros requeridos del template: $($missing -join ', ')."
}

$deploymentName = ("deploy-analyticrule-{0}" -f (Get-Date -Format "yyyyMMddHHmmss"))
$deployUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$deploymentName?api-version=$ApiVersionDeployments"

$payload = @{
  properties = @{
    mode       = "Incremental"
    template   = $newTemplate
    parameters = $templateParams
  }
}

if ($PSCmdlet.ShouldProcess("RG $ResourceGroupName", "Deploy AnalyticsRule '$DisplayName' (deployment: $deploymentName)")) {
  Write-Host "==> Ejecutando deployment incremental..."
  $resp = Invoke-ArmPut -Uri $deployUri -Body $payload
  Write-Host "==> Deployment enviado: $deploymentName"
  Write-Host ("ProvisioningState: {0}" -f $resp.properties.provisioningState)
  Write-Host "==> Hecho."
}
