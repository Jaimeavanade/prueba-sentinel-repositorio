# scripts/10-manage-contenthub-solution.ps1
<#
.SYNOPSIS
Gestiona una solución de Microsoft Sentinel Content Hub por contentId:
- install  : instala/actualiza el paquete y despliega packagedContent (content items)
- update   : actualiza si hay versión nueva (o fuerza deploy con -ForceDeploy)
- uninstall: desinstala el paquete

APIs (2025-09-01):
- Catálogo: contentProductPackages (List, con $filter / $search / $expand)  [2](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&sourcedoc=%7bdcde3f4e-f42d-4456-93b2-470a520e4bb2%7d&wdsectionfileid=%7bcfe6086a-3179-430a-9536-53117009c186%7d&wdpartId=%7B375c720e-0447-42ca-b2b1-81bb5da241ae%7D%7B1%7D)
- Install:  contentPackages/{packageId} PUT                               [3](https://charbelnemnom.com/automate-microsoft-sentinel-content-hub-updates/)
- List installed: contentPackages GET                                     [4](https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/sentinel/sentinel-solutions-deploy.md)
- Uninstall: contentPackages/{packageId} DELETE                           [5](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-package/install?view=rest-securityinsights-2025-09-01)[4](https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/sentinel/sentinel-solutions-deploy.md)

NOTA:
Borrar la solución elimina templates, pero no garantiza borrar items activos/clonados/guardados/custom. [6](https://stackoverflow.com/questions/68297643/how-to-use-nextlink-property-in-azure-pagination-in-providers-microsoft-compute)
Para instalar/actualizar/borrar en Content Hub necesitas Microsoft Sentinel Contributor a nivel RG. [7](https://learn.microsoft.com/en-us/azure/sentinel/sentinel-solutions-delete)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("install","update","uninstall")]
  [string]$Action,

  [Parameter(Mandatory=$true)][string]$SubscriptionId,
  [Parameter(Mandatory=$true)][string]$ResourceGroupName,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,
  [Parameter(Mandatory=$true)][string]$ContentId,

  [Parameter(Mandatory=$false)][string]$ApiVersion = "2025-09-01",
  [Parameter(Mandatory=$false)][string]$DeploymentApiVersion = "2021-04-01",

  # Guardrail: comprobar Sentinel habilitado antes de instalar/actualizar
  [Parameter(Mandatory=$false)][switch]$ValidateSentinelOnboarding = $true,

  # update: si ya está en la última versión, por defecto NO despliega. Puedes forzar.
  [Parameter(Mandatory=$false)][switch]$ForceDeploy,

  # Esperas
  [Parameter(Mandatory=$false)][int]$DeploymentWaitSeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido o vacío. Revisa azure/login y permisos."
  }
  return $t
}

function Get-ErrorBodyFromException {
  param([Parameter(Mandatory=$true)] $Exception)
  try {
    if ($Exception.Response -and $Exception.Response.GetResponseStream) {
      $reader = New-Object System.IO.StreamReader($Exception.Response.GetResponseStream())
      $body = $reader.ReadToEnd()
      if ($body) { return $body }
    }
  } catch {}
  return $null
}

function Invoke-Arm {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","DELETE")] [string]$Method,
    [Parameter(Mandatory=$true)][string]$Uri,
    [Parameter(Mandatory=$false)] $Body
  )

  $headers = @{
    Authorization  = "Bearer $script:ArmToken"
    "Content-Type" = "application/json"
  }

  try {
    Write-Verbose "$Method $Uri"
    if ($null -ne $Body) {
      $json = $Body | ConvertTo-Json -Depth 80
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
    } else {
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
  } catch {
    $statusCode = $null
    try {
      if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $statusCode = [int]$_.Exception.Response.StatusCode
      }
    } catch {}

    $body = Get-ErrorBodyFromException -Exception $_.Exception
    if ($body) {
      throw "Fallo HTTP($statusCode) en $Method $Uri. Body=$body"
    }
    throw "Fallo HTTP($statusCode) en $Method $Uri. Error=$($_.Exception.Message)"
  }
}

function Test-SentinelOnboarding {
  # onboardingStates/default debe responder 200 si Sentinel está habilitado
  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=$ApiVersion"
  Invoke-Arm -Method GET -Uri $uri | Out-Null
  Write-Host "OK: Sentinel parece habilitado (onboardingStates/default accesible)." -ForegroundColor Green
}

function Get-CatalogSolutionLatest {
  # Buscar EXACTO por contentId en catálogo, expandiendo packagedContent
  $contentIdEscaped = $ContentId.Replace("'", "''")
  $filter = "properties/contentId eq '$contentIdEscaped' and properties/contentKind eq 'Solution'"
  $encoded = [System.Uri]::EscapeDataString($filter)

  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion&`$filter=$encoded&`$expand=properties/packagedContent&`$top=50"
  $resp = Invoke-Arm -Method GET -Uri $uri

  if (-not $resp.value -or $resp.value.Count -eq 0) {
    throw "Catálogo: no se encontró contentId='$ContentId' como Solution. Revisa el contentId."
  }

  # Elegir latest por semver (si parsea); si no, cae a 0.0.0
  $latest = $resp.value | Sort-Object -Property @{
    Expression = { try { [version]$_.properties.version } catch { [version]"0.0.0" } }
  } -Descending | Select-Object -First 1

  return $latest
}

function Get-InstalledPackage {
  # ✅ FIX: ${ContentId} antes de ?api-version
  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${ContentId}?api-version=$ApiVersion"
  try {
    return Invoke-Arm -Method GET -Uri $uri
  } catch {
    return $null
  }
}

function Put-InstallOrUpdatePackage {
  param([Parameter(Mandatory=$true)] $CatalogItem)

  $p = $CatalogItem.properties

  $schema = $p.contentSchemaVersion
  if (-not $schema) { $schema = "2.0" } # fallback defensivo

  # ✅ FIX: ${($p.contentId)} antes de ?api-version
  $pkgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${($p.contentId)}?api-version=$ApiVersion"

  $body = @{
    properties = @{
      contentId            = $p.contentId
      contentKind          = $p.contentKind
      contentProductId     = $p.contentProductId
      displayName          = $p.displayName
      version              = $p.version
      contentSchemaVersion = $schema
    }
  }

  Write-Host "==> PUT contentPackages (install/update): $($p.displayName)" -ForegroundColor Cyan
  Write-Host " contentId: $($p.contentId)"
  Write-Host " version  : $($p.version)"
  Write-Host " productId: $($p.contentProductId)"
  Write-Host " schema   : $schema"

  if ($PSCmdlet.ShouldProcess($p.displayName, "PUT contentPackages/$($p.contentId)")) {
    Invoke-Arm -Method PUT -Uri $pkgUri -Body $body | Out-Null
  }
}

function Deploy-PackagedContent {
  param([Parameter(Mandatory=$true)] $CatalogItem)

  $p = $CatalogItem.properties
  $template = $p.packagedContent

  if (-not $template) {
    throw "Catálogo: packagedContent vacío para '$($p.displayName)'. No puedo desplegar content items."
  }

  $safe = ($p.displayName -replace '[^a-zA-Z0-9\-]', '-')
  $deploymentName = "ContentHub-$Action-$safe"
  if ($deploymentName.Length -gt 62) { $deploymentName = $deploymentName.Substring(0,62) }

  # ✅ FIX: ${deploymentName} antes de ?api-version
  $deployUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/${deploymentName}?api-version=$DeploymentApiVersion"

  $deployBody = @{
    properties = @{
      mode       = "Incremental"
      template   = $template
      parameters = @{
        workspace            = @{ value = $WorkspaceName }
        "workspace-location" = @{ value = "" }
      }
    }
  }

  Write-Host "==> Deploy packagedContent (Incremental): $deploymentName" -ForegroundColor Cyan

  if ($PSCmdlet.ShouldProcess($p.displayName, "PUT deployments/$deploymentName (packagedContent)")) {
    Invoke-Arm -Method PUT -Uri $deployUri -Body $deployBody | Out-Null
  }

  # Espera a Succeeded/Failed
  $deadline = (Get-Date).AddSeconds($DeploymentWaitSeconds)
  while ((Get-Date) -lt $deadline) {
    $get = Invoke-Arm -Method GET -Uri $deployUri
    $state = $get.properties.provisioningState
    Write-Host "Deployment state: $state"
    if ($state -eq "Succeeded") {
      Write-Host "OK: packagedContent desplegado (content items materializados)." -ForegroundColor Green
      return
    }
    if ($state -in @("Failed","Canceled")) {
      $err = $get.properties.error | ConvertTo-Json -Depth 30
      throw "Deployment $deploymentName terminó en $state. Error=$err"
    }
    Start-Sleep -Seconds 10
  }

  Write-Warning "Timeout esperando deployment $deploymentName. Puede seguir ejecutándose."
}

function Delete-Package {
  # ✅ FIX: ${ContentId} antes de ?api-version
  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/${ContentId}?api-version=$ApiVersion"

  Write-Host "==> DELETE contentPackages (uninstall): $ContentId" -ForegroundColor Yellow
  if ($PSCmdlet.ShouldProcess($ContentId, "DELETE contentPackages/$ContentId")) {
    Invoke-Arm -Method DELETE -Uri $uri | Out-Null
  }

  Write-Host "Uninstall solicitado. Nota: puede no borrar items activos/clonados/guardados/custom." -ForegroundColor Yellow
}

# ---------------- MAIN ----------------
Write-Host "== Content Hub Solution Manager ==" -ForegroundColor Cyan
Write-Host "Action    : $Action"
Write-Host "Sub       : $SubscriptionId"
Write-Host "RG        : $ResourceGroupName"
Write-Host "Workspace : $WorkspaceName"
Write-Host "contentId : $ContentId"
Write-Host ""

$script:ArmToken = Get-ArmToken

if ($ValidateSentinelOnboarding -and $Action -in @("install","update")) {
  Test-SentinelOnboarding
}

if ($Action -eq "uninstall") {
  Delete-Package
  exit 0
}

$catalog = Get-CatalogSolutionLatest
$installed = Get-InstalledPackage

if ($installed -and $installed.properties -and $installed.properties.version) {
  Write-Host "InstalledVersion: $($installed.properties.version)" -ForegroundColor DarkGray
} else {
  Write-Host "InstalledVersion: (no instalada)" -ForegroundColor DarkGray
}
Write-Host "CatalogLatest   : $($catalog.properties.version)" -ForegroundColor DarkGray

if ($Action -eq "update" -and $installed -and $installed.properties -and $installed.properties.version) {
  if ($installed.properties.version -eq $catalog.properties.version -and -not $ForceDeploy) {
    Write-Host "Ya está en la última versión. (update no hace nada). Usa -ForceDeploy para redeploy packagedContent." -ForegroundColor Green
    exit 0
  }
}

# install/update => PUT + Deploy packagedContent
Put-InstallOrUpdatePackage -CatalogItem $catalog
Deploy-PackagedContent      -CatalogItem $catalog

Write-Host ""
Write-Host "OK: Acción '$Action' completada para $($catalog.properties.displayName)" -ForegroundColor Green
