# scripts/sentinel-workbook-templates.ps1
<#
.SYNOPSIS
  Microsoft Sentinel - Workbooks Templates (List/Create)
.DESCRIPTION
  - list: Lista templates instalados (contentTemplates) cuyo contentKind sea Workbook/WorkbookTemplate.
  - create: Despliega (deployment ARM) el properties.mainTemplate del templateId indicado,
            creando el Workbook en el Resource Group del workspace.

  Requisitos:
   - Autenticación ARM disponible (recomendado: GitHub Actions con azure/login OIDC + Azure CLI).
   - El template debe estar INSTALADO en el workspace (Workbooks > Templates proviene de Content Hub).
.NOTES
  Basado en Content Templates REST API (List) y despliegue ARM por Microsoft.Resources/deployments.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet('list','create')]
  [string]$Action,

  [Parameter(Mandatory=$true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory=$true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory=$true)]
  [string]$WorkspaceName,

  # create: obligatorio
  [Parameter(Mandatory=$false)]
  [string]$TemplateId,

  # list: opcional
  [Parameter(Mandatory=$false)]
  [string]$DisplayNameFilter,

  [Parameter(Mandatory=$false)]
  [ValidateSet('contains','equals','startswith')]
  [string]$DisplayNameFilterMode = 'contains',

  # create: opcional (si la plantilla soporta workbookDisplayName / displayName param)
  [Parameter(Mandatory=$false)]
  [string]$WorkbookDisplayName,

  # create: opcional
  [Parameter(Mandatory=$false)]
  [string]$Location,

  # API version Sentinel contentTemplates
  [Parameter(Mandatory=$false)]
  [string]$ApiVersionSecurityInsights = '2025-09-01',

  # API version deployments
  [Parameter(Mandatory=$false)]
  [string]$ApiVersionDeployments = '2021-04-01',

  # Si quieres ver más debug
  [Parameter(Mandatory=$false)]
  [switch]$VerboseOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------
# Helpers
# ----------------------------
function Write-Info([string]$m) { Write-Host "ℹ️  $m" }
function Write-Warn([string]$m) { Write-Warning $m }

function Get-ArmToken {
  # Preferimos Azure CLI porque en GitHub Actions con azure/login OIDC queda listo.
  try {
    $t = & az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv 2>$null
    if ($t -and $t.Trim().Length -gt 100) { return $t.Trim() }
  } catch {}
  throw "No se pudo obtener token ARM. Asegura 'azure/login' (OIDC) o 'az login' antes de ejecutar."
}

function Invoke-ArmRest {
  param(
    [Parameter(Mandatory=$true)][ValidateSet('GET','PUT','POST','DELETE')][string]$Method,
    [Parameter(Mandatory=$true)][string]$Uri,
    [Parameter(Mandatory=$false)][object]$Body,
    [int]$MaxRetries = 6
  )

  $token = Get-ArmToken
  $headers = @{
    Authorization = "Bearer $token"
    'Content-Type' = 'application/json'
  }

  $payload = $null
  if ($null -ne $Body) {
    $payload = ($Body | ConvertTo-Json -Depth 100)
  }

  $attempt = 0
  while ($true) {
    $attempt++
    try {
      if ($VerboseOutput) { Write-Info "$Method $Uri" }
      if ($null -eq $payload) {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
      } else {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $payload
      }
    } catch {
      $msg = $_.Exception.Message
      if ($attempt -ge $MaxRetries) { throw $_ }
      # Backoff simple
      $sleep = [Math]::Min(30, (2 * $attempt))
      Write-Warn "Fallo REST (intento $attempt/$MaxRetries): $msg. Reintentando en $sleep s..."
      Start-Sleep -Seconds $sleep
    }
  }
}

function Get-WorkspaceResourceId {
  return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
}

function Get-ContentTemplatesList {
  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersionSecurityInsights"
  return Invoke-ArmRest -Method GET -Uri $uri
}

function Get-ContentTemplateById {
  param([Parameter(Mandatory=$true)][string]$Id)

  # Expand para traer mainTemplate (no viene siempre por defecto)
  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$Id?api-version=$ApiVersionSecurityInsights&`$expand=properties/mainTemplate"
  return Invoke-ArmRest -Method GET -Uri $uri
}

function Is-WorkbookTemplateKind {
  param($contentKind)
  if ($null -eq $contentKind) { return $false }
  $k = $contentKind.ToString()
  return ($k -eq 'Workbook' -or $k -eq 'WorkbookTemplate')
}

function Match-DisplayName {
  param(
    [string]$Name,
    [string]$Filter,
    [string]$Mode
  )
  if ([string]::IsNullOrWhiteSpace($Filter)) { return $true }
  if ($null -eq $Name) { return $false }

  switch ($Mode) {
    'equals'     { return ($Name -eq $Filter) }
    'startswith' { return ($Name.StartsWith($Filter, [System.StringComparison]::OrdinalIgnoreCase)) }
    default      { return ($Name.IndexOf($Filter, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) }
  }
}

function Build-DeploymentParametersFromTemplate {
  param(
    [Parameter(Mandatory=$true)]$TemplateObj,
    [Parameter(Mandatory=$true)][string]$WorkspaceResourceId,
    [Parameter(Mandatory=$false)][string]$WorkbookNameOverride,
    [Parameter(Mandatory=$false)][string]$LocationOverride
  )

  # ARM template shape: { parameters: { p1: {type, defaultValue?}, ... } }
  $params = @{}
  $tmplParams = $TemplateObj.parameters

  if ($null -eq $tmplParams) {
    return $params
  }

  # Helper interno para setear valor si existe el parámetro
  function Set-IfExists([string]$paramName, [object]$value) {
    if ($tmplParams.PSObject.Properties.Name -contains $paramName) {
      $params[$paramName] = @{ value = $value }
    }
  }

  # Valores que solemos poder inferir
  $workbookGuid = ([Guid]::NewGuid()).ToString()
  $rgId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"

  # Parámetros comunes vistos en ARM Workbooks (varían por plantilla)
  Set-IfExists -paramName 'workbookId' -value $workbookGuid
  Set-IfExists -paramName 'workbookName' -value $workbookGuid
  Set-IfExists -paramName 'resourceName' -value $workbookGuid

  Set-IfExists -paramName 'workspace' -value $WorkspaceName
  Set-IfExists -paramName 'workspaceName' -value $WorkspaceName
  Set-IfExists -paramName 'workspaceResourceId' -value $WorkspaceResourceId
  Set-IfExists -paramName 'workspaceId' -value $WorkspaceResourceId

  # sourceId puede ser workspaceResourceId o el RG (según diseño de la plantilla)
  Set-IfExists -paramName 'workbookSourceId' -value $WorkspaceResourceId
  Set-IfExists -paramName 'sourceId' -value $WorkspaceResourceId
  Set-IfExists -paramName 'resourceGroupId' -value $rgId

  if (-not [string]::IsNullOrWhiteSpace($WorkbookNameOverride)) {
    Set-IfExists -paramName 'workbookDisplayName' -value $WorkbookNameOverride
    Set-IfExists -paramName 'displayName' -value $WorkbookNameOverride
  }

  if (-not [string]::IsNullOrWhiteSpace($LocationOverride)) {
    Set-IfExists -paramName 'location' -value $LocationOverride
  }

  return $params
}

function Get-MissingRequiredParams {
  param(
    [Parameter(Mandatory=$true)]$TemplateObj,
    [Parameter(Mandatory=$true)]$ProvidedParams
  )

  $missing = @()
  $tmplParams = $TemplateObj.parameters
  if ($null -eq $tmplParams) { return $missing }

  foreach ($p in $tmplParams.PSObject.Properties) {
    $name = $p.Name
    $def  = $p.Value

    $hasDefault = $false
    if ($def -and ($def.PSObject.Properties.Name -contains 'defaultValue')) {
      $hasDefault = ($null -ne $def.defaultValue -and $def.defaultValue.ToString().Length -gt 0)
    }

    $provided = $ProvidedParams.ContainsKey($name)
    if (-not $provided -and -not $hasDefault) {
      # Puede ser opcional según plantilla; aquí lo tratamos como potencialmente requerido
      $missing += $name
    }
  }

  return $missing
}

function Start-ArmDeployment {
  param(
    [Parameter(Mandatory=$true)][string]$DeploymentName,
    [Parameter(Mandatory=$true)]$TemplateObj,
    [Parameter(Mandatory=$true)]$ParametersObj,
    [Parameter(Mandatory=$false)][string]$LocationOverride
  )

  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$DeploymentName?api-version=$ApiVersionDeployments"

  $body = @{
    properties = @{
      mode = 'Incremental'
      template = $TemplateObj
      parameters = $ParametersObj
    }
  }

  # Algunos despliegues requieren location dentro del template (lo maneja el template); aquí no forzamos.
  Invoke-ArmRest -Method PUT -Uri $uri -Body $body | Out-Null
}

function Wait-ArmDeployment {
  param(
    [Parameter(Mandatory=$true)][string]$DeploymentName,
    [int]$MaxWaitSeconds = 600
  )

  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$DeploymentName?api-version=$ApiVersionDeployments"
  $deadline = (Get-Date).AddSeconds($MaxWaitSeconds)

  while ((Get-Date) -lt $deadline) {
    $d = Invoke-ArmRest -Method GET -Uri $uri
    $state = $d.properties.provisioningState
    if ($state -in @('Succeeded','Failed','Canceled')) {
      return $d
    }
    Start-Sleep -Seconds 5
  }

  throw "Timeout esperando el deployment '$DeploymentName'. Puede seguir ejecutándose en Azure."
}

# ----------------------------
# MAIN
# ----------------------------
Write-Info "Acción: $Action"
Write-Info "Workspace: $WorkspaceName (RG: $ResourceGroupName, Sub: $SubscriptionId)"
$wsId = Get-WorkspaceResourceId
if ($VerboseOutput) { Write-Info "WorkspaceResourceId: $wsId" }

if ($Action -eq 'list') {
  $all = Get-ContentTemplatesList
  $items = @($all.value)

  $filtered = foreach ($it in $items) {
    $p = $it.properties
    if ($null -eq $p) { continue }
    if (-not (Is-WorkbookTemplateKind -contentKind $p.contentKind)) { continue }
    if (-not (Match-DisplayName -Name $p.displayName -Filter $DisplayNameFilter -Mode $DisplayNameFilterMode)) { continue }

    [pscustomobject]@{
      templateId    = $it.name
      displayName   = $p.displayName
      contentKind   = $p.contentKind
      packageName   = $p.packageName
      packageVersion= $p.packageVersion
      version       = $p.version
      sourceKind    = $p.source.kind
      sourceName    = $p.source.name
    }
  }

  $filtered | Sort-Object displayName | Format-Table -AutoSize
  Write-Host ""
  Write-Info "Total templates (Workbook/WorkbookTemplate) encontrados: $($filtered.Count)"
  exit 0
}

if ($Action -eq 'create') {
  if ([string]::IsNullOrWhiteSpace($TemplateId)) {
    throw "TemplateId es obligatorio para Action=create"
  }

  Write-Info "Cargando templateId: $TemplateId"
  $tpl = Get-ContentTemplateById -Id $TemplateId

  if ($null -eq $tpl.properties) { throw "El template no trae 'properties'. No se puede continuar." }

  $kind = $tpl.properties.contentKind
  if (-not (Is-WorkbookTemplateKind -contentKind $kind)) {
    throw "El TemplateId indicado no parece de Workbook. contentKind='$kind'"
  }

  # mainTemplate (ARM) es lo que desplegamos
  $mainTemplate = $tpl.properties.mainTemplate
  if ($null -eq $mainTemplate) {
    throw "El template no contiene properties.mainTemplate. Ejecuta list con expand o revisa si está instalado correctamente."
  }

  $targetName = if ($WorkbookDisplayName) { $WorkbookDisplayName } else { $tpl.properties.displayName }
  Write-Info "WorkbookDisplayName objetivo: $targetName"

  $params = Build-DeploymentParametersFromTemplate -TemplateObj $mainTemplate -WorkspaceResourceId $wsId -WorkbookNameOverride $targetName -LocationOverride $Location
  $missing = Get-MissingRequiredParams -TemplateObj $mainTemplate -ProvidedParams $params

  if ($missing.Count -gt 0) {
    Write-Warn "La plantilla declara parámetros sin default y no hemos podido autocompletarlos:"
    $missing | ForEach-Object { Write-Warn " - $_" }
    throw "Faltan parámetros requeridos. Añade soporte de mapeo o expón inputs nuevos en el workflow."
  }

  $deploymentName = ("sentinel-wbtemplate-" + $TemplateId.Replace('/','-') + "-" + (Get-Date -Format "yyyyMMddHHmmss"))
  Write-Info "Lanzando deployment: $deploymentName"

  Start-ArmDeployment -DeploymentName $deploymentName -TemplateObj $mainTemplate -ParametersObj $params -LocationOverride $Location
  $res = Wait-ArmDeployment -DeploymentName $deploymentName -MaxWaitSeconds 900

  $state = $res.properties.provisioningState
  if ($state -ne 'Succeeded') {
    $err = $res.properties.error
    if ($err) {
      throw "Deployment falló: $($err.code) - $($err.message)"
    }
    throw "Deployment terminó en estado: $state"
  }

  Write-Host ""
  Write-Info "✅ Workbook desplegado desde templateId=$TemplateId (deployment=$deploymentName)"
  Write-Info "Nota: el workbook aparecerá en el RG del workspace; Sentinel lo mostrará en 'My workbooks' si el template lo asocia correctamente."
  exit 0
}

throw "Acción no soportada: $Action"
