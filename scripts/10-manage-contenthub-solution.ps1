[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet("install","update","uninstall")]
  [string]$Action,

  [Parameter(Mandatory)][string]$SubscriptionId,
  [Parameter(Mandatory)][string]$ResourceGroupName,
  [Parameter(Mandatory)][string]$WorkspaceName,
  [Parameter(Mandatory)][string]$ContentId,

  [string]$ApiVersion = "2025-09-01",
  [string]$DeploymentApiVersion = "2021-04-01",
  [int]$DeploymentWaitSeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------- Helpers ----------------
function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t) { throw "No se pudo obtener token ARM" }
  return $t
}

function Invoke-Arm {
  param(
    [ValidateSet("GET","PUT","POST","DELETE")]$Method,
    [string]$Uri,
    $Body = $null
  )

  $headers = @{
    Authorization  = "Bearer $script:ArmToken"
    "Content-Type" = "application/json"
  }

  if ($Body) {
    $json = $Body | ConvertTo-Json -Depth 100
    Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
  } else {
    Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
  }
}

# ---------------- Sentinel enabled ----------------
$script:ArmToken = Get-ArmToken

$onboardingUri =
  "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=$ApiVersion"

Invoke-Arm GET $onboardingUri | Out-Null
Write-Host "✅ Sentinel habilitado"

# ---------------- Catálogo ----------------
$filter = [System.Uri]::EscapeDataString(
  "properties/contentId eq '$ContentId' and properties/contentKind eq 'Solution'"
)

$catalogUri =
  "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages" +
  "?api-version=$ApiVersion&`$filter=$filter&`$expand=properties/packagedContent"

$catalog = (Invoke-Arm GET $catalogUri).value | Select-Object -First 1
if (-not $catalog) {
  throw "No se encontró la solución $ContentId en el catálogo"
}

$p = $catalog.properties

Write-Host "📦 Solución: $($p.displayName)"
Write-Host "📄 Versión catálogo: $($p.version)"

# ---------------- Uninstall ----------------
if ($Action -eq "uninstall") {
  $uri =
    "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${ContentId}?api-version=$ApiVersion"

  Invoke-Arm DELETE $uri
  Write-Host "✅ Desinstalada"
  exit 0
}

# ---------------- Install / Update ----------------
$pkgUri =
  "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/$($p.contentId)?api-version=$ApiVersion"

$body = @{
  properties = @{
    contentId            = $p.contentId
    contentKind          = "Solution"
    contentProductId     = $p.contentProductId
    displayName          = $p.displayName
    version              = $p.version
    contentSchemaVersion = "2.0"
  }
}

Invoke-Arm PUT $pkgUri $body
Write-Host "✅ Solución instalada en Content Hub"

# ---------------- Deploy packagedContent ----------------
if (-not $p.packagedContent) {
  throw "packagedContent vacío; no se pueden desplegar items"
}

$deploymentName = "contenthub-$($p.contentId)-$Action"

$deployUri =
  "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$deploymentName?api-version=$DeploymentApiVersion"

$deployBody = @{
  properties = @{
    mode     = "Incremental"
    template = $p.packagedContent
    parameters = @{
      workspace            = @{ value = $WorkspaceName }
      "workspace-location" = @{ value = "" }
    }
  }
}

Invoke-Arm PUT $deployUri $deployBody
Write-Host "✅ packagedContent desplegado"
