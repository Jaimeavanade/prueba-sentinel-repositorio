# scripts/10-manage-contenthub-solution.ps1
<#
.SYNOPSIS
Gestiona una solución de Microsoft Sentinel Content Hub por contentId:
- install  : instala/actualiza el paquete y despliega packagedContent (content items)
- update   : si hay versión nueva, actualiza; si no, no falla (y puedes forzar con -ForceDeploy)
- uninstall: desinstala el paquete (nota: puede no borrar items "custom/active" según comportamiento del producto)

APIs (2025-09-01):
- Catálogo: contentProductPackages (List, con $filter / $search / $expand)  [2](https://github.com/Jaimeavanade/prueba-sentinel-repositorio/actions)
- Install:  contentPackages/{packageId} PUT                               [3](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-packages/list?view=rest-securityinsights-2025-09-01)
- Uninstall:contentPackages/{packageId} DELETE                            [4](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-template/install?view=rest-securityinsights-2025-09-01)[5](https://charbelnemnom.com/automate-microsoft-sentinel-content-hub-updates/)

NOTA sobre borrado:
Microsoft documenta que borrar una solución elimina templates, pero no necesariamente items activos/clonados/guardados/custom. [8](https://www.youtube.com/watch?v=HLn3OSRdqo4)
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
  try {
    $resp = Invoke-Arm -Method GET -Uri $uri
    # si no lanza excepción, consideramos OK
    Write-Host "OK: Sentinel parece habilitado (onboardingStates/default accesible)." -ForegroundColor Green
    return $true
  } catch {
    Write-Host "ERROR: Sentinel no parece habilitado o no hay permisos para onboardingStates/default." -ForegroundColor Red
    throw
  }
}

function Get-CatalogSolutionLatest {
  # Buscar EXACTO por contentId en catálogo, expandiendo packagedContent
  $filter = "properties/contentId eq '$ContentId' and properties/contentKind eq 'Solution'"
  $encoded = [System.Uri]::EscapeDataString($filter)

  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=$ApiVersion&`$filter=$encoded&`$expand=properties/packagedContent&`$top=50"
  $resp = Invoke-Arm -Method GET -Uri $uri

  if (-not $resp.value -or $resp.value.Count -eq 0) {
    throw "Catálogo: no se encontró contentId='$ContentId' como Solution. Revisa el contentId."
  }

  # Elegir latest por versión semver (si parsea); si no, cae a 0.0.0
  $latest = $resp.value | Sort-Object -Property @{
    Expression = { try { [version]$_.properties.version } catch { [version]"0.0.0" } }
  } -Descending | Select-Object -First 1

  return $latest
}

function Get-InstalledPackage {
  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/$ContentId?api-version=$ApiVersion"
  try {
    return Invoke-Arm -Method GET -Uri $uri
  } catch {
    return $null
  }
}

function Put-InstallOrUpdatePackage {
  param([Parameter(Mandatory=$true)] $CatalogItem)

  $p = $CatalogItem.properties

  if (-not $p.contentSchemaVersion) {
    # En install el schema puede ser requerido; hacemos fallback defensivo
    $p | Add-Member -NotePropertyName contentSchemaVersion -NotePropertyValue "2.0" -Force
  }

  $pkgUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/$($p.contentId)?api-version=$ApiVersion"

  $body = @{
    properties = @{
      contentId            = $p.contentId
      contentKind          = $p.contentKind
      contentProductId     = $p.contentProductId
      displayName          = $p.displayName
      version              = $p.version
      contentSchemaVersion = $p.contentSchemaVersion
    }
  }

  Write-Host "==> PUT contentPackages (install/update): $($p.displayName)" -ForegroundColor Cyan
  Write-Host " contentId: $($p.contentId)"
  Write-Host " version  : $($p.version)"
  Write-Host " productId: $($p.contentProductId)"
  Write-Host " schema   : $($p.contentSchemaVersion)"

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

  $deployUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$deploymentName?api-version=$DeploymentApiVersion"

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
  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentPackages/$ContentId?api-version=$ApiVersion"
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

# install / update
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
    Write-Host "Ya está en la última versión. (update no hace nada). Usa -ForceDeploy si quieres redeploy packagedContent." -ForegroundColor Green
    exit 0
  }
}

# ✅ install siempre hace PUT + deploy packagedContent (para que “aparezcan” los items)
Put-InstallOrUpdatePackage -CatalogItem $catalog
Deploy-PackagedContent      -CatalogItem $catalog

Write-Host ""
Write-Host "OK: Acción '$Action' completada para $($catalog.properties.displayName)" -ForegroundColor Green
