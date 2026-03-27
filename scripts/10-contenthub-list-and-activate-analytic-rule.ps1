<#
.SYNOPSIS
  Lista soluciones instaladas de Content Hub y sus content items (desde packagedContent).
  Opcionalmente, activa (despliega) una Analytics Rule por displayName.

.DESCRIPTION
  - Lee soluciones instaladas: Microsoft.SecurityInsights/contentPackages
  - Para cada solución instalada, obtiene el paquete del catálogo: Microsoft.SecurityInsights/contentProductPackages?$expand=properties/packagedContent
  - Enumera items dentro del ARM template "packagedContent"
  - Si -DisplayName coincide con un recurso tipo alertRules, hace un deployment RG incremental SOLO con esa regla.

.REQUIREMENTS
  - Ejecutar tras azure/login (OIDC) en GitHub Actions.
  - Requiere Azure CLI disponible (az) para obtener token ARM (robusto con OIDC).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $false)]
  [string]$DisplayName = "",

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

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegura que 'azure/login' (OIDC) se ejecutó antes."
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
  $json = ($Body | ConvertTo-Json -Depth 50)
  return Invoke-RestMethod -Method PUT -Uri $Uri -Headers $headers -ContentType "application/json" -Body $json
}

function Get-AllPages {
  param([Parameter(Mandatory=$true)][string]$FirstUri)
  $all = @()
  $uri = $FirstUri
  while ($uri) {
    $resp = Invoke-ArmGet -Uri $uri
    if ($resp.value) { $all += $resp.value }
    $uri = $null
    if ($resp.nextLink) { $uri = $resp.nextLink }
  }
  return $all
}

function Get-WorkspaceInfo {
  $wsUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName?api-version=$ApiVersionOperationalInsights"
  return Invoke-ArmGet -Uri $wsUri
}

function Try-Get-CatalogPackageById {
  param([Parameter(Mandatory=$true)][string]$CatalogId)
  # Intento directo por resource name
  $u = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.SecurityInsights/contentProductPackages/$CatalogId?api-version=$ApiVersionSecurityInsights&`$expand=properties/packagedContent"
  try {
    return Invoke-ArmGet -Uri $u
  } catch {
    return $null
  }
}

function Try-Get-CatalogPackageByContentProductId {
  param([Parameter(Mandatory=$true)][string]$ContentProductId)
  # Búsqueda por filtro en catálogo
  $u = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersionSecurityInsights&`$filter=properties/contentProductId eq '$ContentProductId'&`$expand=properties/packagedContent&`$top=1"
  try {
    $r = Invoke-ArmGet -Uri $u
    if ($r.value -and $r.value.Count -ge 1) { return $r.value[0] }
    return $null
  } catch {
    return $null
  }
}

function Normalize-PackagedContentTemplate {
  param([Parameter(Mandatory=$true)][object]$CatalogObj)

  $pc = $CatalogObj.properties.packagedContent
  if (-not $pc) { return $null }

  # packagedContent puede venir como string JSON o como objeto
  if ($pc -is [string]) {
    try { $pc = $pc | ConvertFrom-Json -Depth 50 } catch { }
  }

  # Diferentes formas de representar el template
  if ($pc.template) { return $pc.template }
  if ($pc.mainTemplate) { return $pc.mainTemplate }
  if ($pc.resources -or $pc.parameters) { return $pc }

  return $null
}

function Map-KindFromResourceType {
  param([Parameter(Mandatory=$true)][string]$Type)

  $t = $Type.ToLowerInvariant()
  if ($t -like "*/alertrules") { return "AnalyticsRule" }
  if ($t -like "*/workbooks") { return "Workbook" }
  if ($t -like "*/savedsearches") { return "SavedSearch" }
  if ($t -like "*/automationrules") { return "AutomationRule" }
  if ($t -like "*/watchlists") { return "Watchlist" }
  if ($t -like "*/parsers") { return "Parser" }
  if ($t -like "*/huntqueries") { return "HuntingQuery" }
  return "Other"
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

    # Si el parámetro tiene defaultValue, no es obligatorio pasarlo
    $hasDefault = $false
    try { if ($TemplateParameters[$k].defaultValue) { $hasDefault = $true } } catch { }

    if ($kLower -in @("workspace", "workspaceid", "workspace_resource_id")) {
      $p[$k] = @{ value = $WorkspaceResourceId }
      continue
    }
    if ($kLower -in @("workspacename", "workspace_name")) {
      $p[$k] = @{ value = $WorkspaceName }
      continue
    }
    if ($kLower -in @("location", "workspacelocation", "workspace_location")) {
      $p[$k] = @{ value = $WorkspaceLocation }
      continue
    }
    if ($kLower -in @("subscriptionid", "workspaceSubscriptionId".ToLowerInvariant())) {
      $p[$k] = @{ value = $SubscriptionId }
      continue
    }
    if ($kLower -in @("resourcegroup", "resourcegroupname", "workspaceResourceGroup".ToLowerInvariant())) {
      $p[$k] = @{ value = $ResourceGroupName }
      continue
    }

    if (-not $hasDefault) {
      # No sabemos rellenarlo automáticamente: lo dejamos sin valor para que el script lo detecte
      # (se validará antes del deployment)
      $p[$k] = $null
    }
  }

  return $p
}

# ---------------- MAIN ----------------

Write-Host "==> Obteniendo token ARM..."
$script:ArmToken = Get-ArmToken

Write-Host "==> Obteniendo info del workspace..."
$ws = Get-WorkspaceInfo
$workspaceLocation = $ws.location
$workspaceResourceId = $ws.id

Write-Host "Workspace: $WorkspaceName | Location: $workspaceLocation"
Write-Host "Workspace ResourceId: $workspaceResourceId"

Write-Host "==> Listando soluciones instaladas (contentPackages)..."
$installedUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages?api-version=$ApiVersionSecurityInsights"
$installed = Get-AllPages -FirstUri $installedUri

Write-Host ("Soluciones instaladas encontradas: {0}" -f ($installed.Count))

# Para cada solución instalada: buscar packagedContent en catálogo y enumerar recursos
$report = [System.Collections.Generic.List[object]]::new()

foreach ($pkg in $installed) {
  $solutionName = $pkg.name
  $solutionDisplay = $pkg.properties.displayName
  $contentProductId = $pkg.properties.contentProductId
  $contentId = $pkg.properties.contentId

  Write-Host "----"
  Write-Host "Solution installed: $solutionDisplay"
  Write-Host " contentProductId: $contentProductId"
  Write-Host " contentId:        $contentId"

  $catalog = $null
  if ($contentId) { $catalog = Try-Get-CatalogPackageById -CatalogId $contentId }
  if (-not $catalog -and $contentProductId) { $catalog = Try-Get-CatalogPackageByContentProductId -ContentProductId $contentProductId }

  if (-not $catalog) {
    Write-Warning "No se pudo resolver packagedContent desde catálogo para: $solutionDisplay"
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

    # Intento de displayName en distintas posiciones comunes
    $itemDisplay = $null
    try { if ($res.properties.displayName) { $itemDisplay = [string]$res.properties.displayName } } catch { }
    if (-not $itemDisplay) {
      try { if ($res.properties.DisplayName) { $itemDisplay = [string]$res.properties.DisplayName } } catch { }
    }
    if (-not $itemDisplay) { $itemDisplay = "" }

    $report.Add([pscustomobject]@{
      solutionDisplayName = $solutionDisplay
      solutionName        = $solutionName
      contentProductId    = $contentProductId
      contentId           = $contentId
      itemKind            = $kind
      itemType            = $rtype
      itemName            = $rname
      itemDisplayName     = $itemDisplay
    })
  }
}

# Guardar report
$reportDir = Split-Path -Parent $OutReportJson
if ($reportDir -and -not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }

($report | Sort-Object solutionDisplayName, itemKind, itemDisplayName | ConvertTo-Json -Depth 20) | Out-File -FilePath $OutReportJson -Encoding utf8
Write-Host "==> Report guardado en: $OutReportJson"
Write-Host "==> Total content items enumerados: $($report.Count)"

if ([string]::IsNullOrWhiteSpace($DisplayName)) {
  Write-Host "==> No se indicó -DisplayName. Finalizando (solo listado)."
  exit 0
}

Write-Host "==> Buscando item con displayName EXACTO: '$DisplayName' (case-insensitive)..."
$match = $report | Where-Object { $_.itemDisplayName -and $_.itemDisplayName.Equals($DisplayName, [System.StringComparison]::InvariantCultureIgnoreCase) }

if (-not $match -or $match.Count -eq 0) {
  Write-Error "No se encontró ningún content item con displayName='$DisplayName' en las soluciones instaladas."
}

# Si hay varios matches, preferimos AnalyticsRule
$chosen = $match | Where-Object { $_.itemKind -eq "AnalyticsRule" } | Select-Object -First 1
if (-not $chosen) { $chosen = $match | Select-Object -First 1 }

Write-Host "==> Match elegido:"
$chosen | Format-List | Out-String | Write-Host

if ($chosen.itemKind -ne "AnalyticsRule") {
  Write-Error "El item encontrado NO es una AnalyticsRule (es '$($chosen.itemKind)'). Este script solo crea reglas analíticas."
}

# Re-resolver el catálogo para esa solución para extraer el recurso exacto desde el template original
$catalog2 = $null
if ($chosen.contentId) { $catalog2 = Try-Get-CatalogPackageById -CatalogId $chosen.contentId }
if (-not $catalog2 -and $chosen.contentProductId) { $catalog2 = Try-Get-CatalogPackageByContentProductId -ContentProductId $chosen.contentProductId }
if (-not $catalog2) { throw "No se pudo re-resolver el paquete del catálogo para desplegar." }

$tmpl2 = Normalize-PackagedContentTemplate -CatalogObj $catalog2
if (-not $tmpl2 -or -not $tmpl2.resources) { throw "Template inválido en packagedContent (sin resources)." }

# Encontrar recurso exacto dentro del template por displayName
$resourceToDeploy = $null
foreach ($r in $tmpl2.resources) {
  $rtype = [string]$r.type
  if (-not $rtype.ToLowerInvariant().EndsWith("/alertrules")) { continue }
  $d = $null
  try { if ($r.properties.displayName) { $d = [string]$r.properties.displayName } } catch { }
  if (-not $d) { continue }
  if ($d.Equals($DisplayName, [System.StringComparison]::InvariantCultureIgnoreCase)) {
    $resourceToDeploy = $r
    break
  }
}

if (-not $resourceToDeploy) {
  throw "No se encontró el recurso alertRules con displayName '$DisplayName' dentro del packagedContent."
}

# Construir template mínimo con solo esa regla
$newTemplate = @{
  '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
  contentVersion = "1.0.0.0"
  parameters     = $tmpl2.parameters
  variables      = $tmpl2.variables
  resources      = @($resourceToDeploy)
  outputs        = @{}
}

# Construir parámetros
$templateParams = @{}
if ($tmpl2.parameters) {
  $templateParams = Build-DeploymentParameters -TemplateParameters $tmpl2.parameters -WorkspaceResourceId $workspaceResourceId -WorkspaceLocation $workspaceLocation
}

# Validar parámetros requeridos sin valor
$missing = @()
foreach ($k in $templateParams.Keys) {
  if ($null -eq $templateParams[$k]) { $missing += $k }
}
if ($missing.Count -gt 0) {
  throw "No puedo rellenar automáticamente estos parámetros requeridos del template: $($missing -join ', '). Ajusta el script para mapearlos o usa un template con defaultValue."
}

# Payload ARM deployment
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
  Write-Host "==> Desplegando AnalyticsRule via deployment incremental..."
  $resp = Invoke-ArmPut -Uri $deployUri -Body $payload
  Write-Host "==> Deployment enviado OK: $deploymentName"
  Write-Host ("ProvisioningState: {0}" -f $resp.properties.provisioningState)
  Write-Host "==> Hecho."
}
