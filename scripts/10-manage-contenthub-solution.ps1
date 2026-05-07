# scripts/10-manage-contenthub-solution.ps1
<#
.SYNOPSIS
Instala / Actualiza / Desinstala una solución de Content Hub por contentId.
Incluye despliegue de packagedContent para materializar los content items.

.PARAMETER Action
install | update | uninstall

.NOTES
- Catálogo: contentProductPackages (expand packagedContent)  [5](https://learn.microsoft.com/en-us/rest/api/securityinsights/product-packages/list?view=rest-securityinsights-2025-09-01)
- Instalar: contentPackages/{packageId} PUT               [4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-package/install?view=rest-securityinsights-2025-09-01)
- Desinstalar: contentPackages/{packageId} DELETE        [10](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-package?view=rest-securityinsights-2025-09-01)[3](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)
- Requisitos RBAC: Microsoft Sentinel Contributor a nivel RG para instalar/actualizar/borrar en Content hub. [13](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-deploy)
- Borrado: borrar solución elimina templates; items activos/clonados/guardados/custom pueden permanecer. [12](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-delete)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory=$true)][ValidateSet("install","update","uninstall")][string]$Action,
  [Parameter(Mandatory=$true)][string]$SubscriptionId,
  [Parameter(Mandatory=$true)][string]$ResourceGroupName,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,
  [Parameter(Mandatory=$true)][string]$ContentId,

  [Parameter(Mandatory=$false)][string]$ApiVersion = "2025-09-01",
  [Parameter(Mandatory=$false)][string]$DeploymentApiVersion = "2021-04-01",
  [Parameter(Mandatory=$false)][int]$DeploymentWaitSeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) { throw "Token ARM inválido. Revisa azure/login y permisos." }
  return $t
}

function Invoke-Arm {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","DELETE")]$Method,
    [Parameter(Mandatory=$true)][string]$Uri,
    [Parameter(Mandatory=$false)]$Body
  )
  $headers = @{ Authorization="Bearer $script:ArmToken"; "Content-Type"="application/json" }
  if ($null -ne $Body) {
    $json = $Body | ConvertTo-Json -Depth 80
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
  } else {
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
  }
}

function Get-CatalogSolutionLatest {
  param([Parameter(Mandatory=$true)][string]$ContentId)

  $filter = "properties/contentId eq '$ContentId' and properties/contentKind eq 'Solution'"
  $encoded = [System.Uri]::EscapeDataString($filter)

  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion&`$filter=$encoded&`$expand=properties/packagedContent&`$top=50"
  $resp = Invoke-Arm -Method GET -Uri $uri

  if (-not $resp.value -or $resp.value.Count -eq 0) {
    throw "No se encontró en catálogo el contentId='$ContentId' (Solution)."
  }

  # Elegir latest por semver (siempre que sea posible)
  $latest = $resp.value | Sort-Object -Property @{
    Expression = { try { [version]$_.properties.version } catch { [version]"0.0.0" } }
  } -Descending | Select-Object -First 1

  return $latest
}

function Get-InstalledPackage {
  param([Parameter(Mandatory=$true)][string]$ContentId)

  $pkgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/$ContentId?api-version=$ApiVersion"
  try {
    return Invoke-Arm -Method GET -Uri $pkgUri
  } catch {
    return $null
  }
}

function Install-Or-Update {
  param([Parameter(Mandatory=$true)]$CatalogItem)

  $p = $CatalogItem.properties
  $pkgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/$($p.contentId)?api-version=$ApiVersion"

  $schema = $p.contentSchemaVersion
  if (-not $schema) { $schema = "2.0" } # fallback defensivo

  $body = @{
    properties = @{
      contentId          = $p.contentId
      contentKind        = $p.contentKind
      contentProductId   = $p.contentProductId
      displayName        = $p.displayName
      version            = $p.version
      contentSchemaVersion = $schema
    }
  }

  if ($PSCmdlet.ShouldProcess($p.displayName, "PUT contentPackages (install/update)")) {
    Invoke-Arm -Method PUT -Uri $pkgUri -Body $body | Out-Null
  }

  # Desplegar packagedContent para materializar items
  $template = $p.packagedContent
  if (-not $template) { throw "El catálogo no devolvió packagedContent para '$($p.displayName)'." }

  $safe = ($p.displayName -replace '[^a-zA-Z0-9\-]', '-')
  $deployName = "ContentHub-$($Action)-$safe"
  if ($deployName.Length -gt 62) { $deployName = $deployName.Substring(0,62) }

  $deployUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$deployName?api-version=$DeploymentApiVersion"
  $deployBody = @{
    properties = @{
      mode = "Incremental"
      template = $template
      parameters = @{
        workspace = @{ value = $WorkspaceName }
        "workspace-location" = @{ value = "" }
      }
    }
  }

  if ($PSCmdlet.ShouldProcess($p.displayName, "Deploy packagedContent (Incremental)")) {
    Invoke-Arm -Method PUT -Uri $deployUri -Body $deployBody | Out-Null
  }

  # Espera provisioningState
  $deadline = (Get-Date).AddSeconds($DeploymentWaitSeconds)
  while ((Get-Date) -lt $deadline) {
    $get = Invoke-Arm -Method GET -Uri $deployUri
    $state = $get.properties.provisioningState
    Write-Host "Deployment state: $state"
    if ($state -eq "Succeeded") { return }
    if ($state -in @("Failed","Canceled")) {
      $err = $get.properties.error | ConvertTo-Json -Depth 30
      throw "Deployment $deployName terminó en $state. Error: $err"
    }
    Start-Sleep -Seconds 10
  }

  Write-Warning "Timeout esperando el deployment $deployName. Puede seguir ejecutándose."
}

function Uninstall-Package {
  param([Parameter(Mandatory=$true)][string]$ContentId)

  $pkgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/$ContentId?api-version=$ApiVersion"

  if ($PSCmdlet.ShouldProcess($ContentId, "DELETE contentPackages (uninstall)")) {
    Invoke-Arm -Method DELETE -Uri $pkgUri | Out-Null
  }

  Write-Host "Uninstall solicitado. Nota: borrar solución elimina templates; items activos/clonados/guardados/custom pueden permanecer." -ForegroundColor Yellow
}

# ---------------- MAIN ----------------
$script:ArmToken = Get-ArmToken

Write-Host "== Content Hub Solution Manager ==" -ForegroundColor Cyan
Write-Host "Action   : $Action"
Write-Host "Sub      : $SubscriptionId"
Write-Host "RG       : $ResourceGroupName"
Write-Host "Workspace: $WorkspaceName"
Write-Host "contentId: $ContentId"
Write-Host ""

if ($Action -eq "uninstall") {
  Uninstall-Package -ContentId $ContentId
  exit 0
}

# install / update
$catalog = Get-CatalogSolutionLatest -ContentId $ContentId
$installed = Get-InstalledPackage -ContentId $ContentId

if ($Action -eq "update" -and $installed -and $installed.properties -and $installed.properties.version) {
  $installedVer = $installed.properties.version
  $latestVer = $catalog.properties.version
  Write-Host "InstalledVersion: $installedVer"
  Write-Host "LatestVersion   : $latestVer"

  if ($installedVer -eq $latestVer) {
    Write-Host "Ya está en la última versión. Aun así, puedes forzar el deploy packagedContent volviendo a ejecutar 'install'." -ForegroundColor Green
    exit 0
  }
}

Install-Or-Update -CatalogItem $catalog
Write-Host "OK: Acción '$Action' completada para $($catalog.properties.displayName)" -ForegroundColor Green
