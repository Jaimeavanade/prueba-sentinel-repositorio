<#
.SYNOPSIS
  Microsoft Sentinel - Workbooks Templates (List/Create)
.DESCRIPTION
  - list:
      Lista templates instalados (Microsoft.SecurityInsights/contentTemplates) filtrando por contentKind
      Workbook o WorkbookTemplate y opcionalmente por displayName.
      Además exporta CSV (para artifact) si se indica -CsvOutputPath o si estamos en GitHub Actions.
  - create:
      A partir de un TemplateId (contentTemplate), obtiene properties.mainTemplate (ARM template)
      y ejecuta un deployment ARM en el Resource Group del workspace para materializar el workbook.

  Requisitos:
   - Autenticación ARM disponible (recomendado: GitHub Actions con azure/login OIDC + Azure CLI).
   - El template debe estar INSTALADO en el workspace (Workbooks > Templates proviene de Content Hub).

.NOTES
  - Acceso defensivo a propiedades opcionales (p.ej. packageName).
  - FIX create: evitar bug PowerShell con "$Id?api-version" usando concatenación segura. [1]()
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

  # create: opcional
  [Parameter(Mandatory=$false)]
  [string]$WorkbookDisplayName,

  # create: opcional
  [Parameter(Mandatory=$false)]
  [string]$Location,

  # list: opcional -> ruta donde exportar CSV
  [Parameter(Mandatory=$false)]
  [string]$CsvOutputPath,

  # API version Sentinel contentTemplates
  [Parameter(Mandatory=$false)]
  [string]$ApiVersionSecurityInsights = '2025-09-01',

  # API version deployments
  [Parameter(Mandatory=$false)]
  [string]$ApiVersionDeployments = '2021-04-01',

  # Debug
  [Parameter(Mandatory=$false)]
  [switch]$VerboseOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------
# Helpers (logging)
# ----------------------------
function Write-Info([string]$m) { Write-Host "ℹ️  $m" }
function Write-Warn([string]$m) { Write-Warning $m }

# ----------------------------
# Helpers (safe property access)
# ----------------------------
function Has-Prop([object]$Obj, [string]$Name) {
  return ($null -ne $Obj -and $Obj.PSObject.Properties.Name -contains $Name)
}
function Get-Prop([object]$Obj, [string]$Name, $Default=$null) {
  if (Has-Prop $Obj $Name) { return $Obj.$Name }
  return $Default
}

# ----------------------------
# Auth / REST
# ----------------------------
function Get-ArmToken {
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
    Authorization  = "Bearer $token"
    'Content-Type' = 'application/json'
  }

  $payload = $null
  if ($null -ne $Body) {
    $payload = ($Body | ConvertTo-Json -Depth 200)
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
      $sleep = [Math]::Min(30, (2 * $attempt))
      Write-Warn "Fallo REST (intento $attempt/$MaxRetries): $msg. Reintentando en $sleep s..."
      Start-Sleep -Seconds $sleep
    }
  }
}

# ----------------------------
# Sentinel ContentTemplates helpers
# ----------------------------
function Get-WorkspaceResourceId {
  return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
}

function Get-ContentTemplatesList {
  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersionSecurityInsights"
  return Invoke-ArmRest -Method GET -Uri $uri
}

function Get-ContentTemplateById {
  param([Parameter(Mandatory=$true)][string]$Id)

  # ✅ FIX: evitar "$Id?api-version" que PowerShell interpreta como variable "$Id?api" (no existe) [1]()
  $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$($Id)"
  $query   = "?api-version=$ApiVersionSecurityInsights&`$expand=properties/mainTemplate"
  $uri     = $baseUri + $query

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

# ----------------------------
# CSV helper
# ----------------------------
function Resolve-DefaultCsvPath {
  param([string]$Provided)

  if (-not [string]::IsNullOrWhiteSpace($Provided)) {
    return $Provided
  }

  if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_WORKSPACE)) {
    return (Join-Path $env:GITHUB_WORKSPACE "artifacts/workbook-templates.csv")
  }

  return (Join-Path (Get-Location).Path "workbook-templates.csv")
}

function Ensure-Directory([string]$Path) {
  $dir = Split-Path -Parent $Path
  if (-not [string]::IsNullOrWhiteSpace($dir)) {
    [System.IO.Directory]::CreateDirectory($dir) | Out-Null
  }
}

function Export-CsvUtf8NoBom {
  param(
    [Parameter(Mandatory=$true)][object[]]$Data,
    [Parameter(Mandatory=$true)][string]$Path
  )

  Ensure-Directory -Path $Path
  $csv = $Data | ConvertTo-Csv -NoTypeInformation
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllLines($Path, $csv, $utf8NoBom)
}

# ----------------------------
# Deployment helpers
# ----------------------------
function Build-DeploymentParametersFromTemplate {
  param(
    [Parameter(Mandatory=$true)]$TemplateObj,
    [Parameter(Mandatory=$true)][string]$WorkspaceResourceId,
    [Parameter(Mandatory=$false)][string]$WorkbookNameOverride,
    [Parameter(Mandatory=$false)][string]$LocationOverride
  )

  $params = @{}
  $tmplParams = Get-Prop $TemplateObj 'parameters' $null
  if ($null -eq $tmplParams) { return $params }

  function Set-IfExists([string]$paramName, [object]$value) {
    if ($tmplParams.PSObject.Properties.Name -contains $paramName) {
      $params[$paramName] = @{ value = $value }
    }
  }

  $workbookGuid = ([Guid]::NewGuid()).Guid
  $rgId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"

  # ids/names comunes
  Set-IfExists -paramName 'workbookId' -value $workbookGuid
  Set-IfExists -paramName 'workbookName' -value $workbookGuid
  Set-IfExists -paramName 'resourceName' -value $workbookGuid

  # workspace
  Set-IfExists -paramName 'workspace' -value $WorkspaceName
  Set-IfExists -paramName 'workspaceName' -value $WorkspaceName
  Set-IfExists -paramName 'workspaceResourceId' -value $WorkspaceResourceId
  Set-IfExists -paramName 'workspaceId' -value $WorkspaceResourceId

  # sourceId típico
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
  $tmplParams = Get-Prop $TemplateObj 'parameters' $null
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
      $missing += $name
    }
  }

  return $missing
}

function Start-ArmDeployment {
  param(
    [Parameter(Mandatory=$true)][string]$DeploymentName,
    [Parameter(Mandatory=$true)]$TemplateObj,
    [Parameter(Mandatory=$true)]$ParametersObj
  )

  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$DeploymentName?api-version=$ApiVersionDeployments"

  $body = @{
    properties = @{
      mode       = 'Incremental'
      template   = $TemplateObj
      parameters = $ParametersObj
    }
  }

  Invoke-ArmRest -Method PUT -Uri $uri -Body $body | Out-Null
}

function Wait-ArmDeployment {
  param(
    [Parameter(Mandatory=$true)][string]$DeploymentName,
    [int]$MaxWaitSeconds = 900
  )

  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$DeploymentName?api-version=$ApiVersionDeployments"
  $deadline = (Get-Date).AddSeconds($MaxWaitSeconds)

  while ((Get-Date) -lt $deadline) {
    $d = Invoke-ArmRest -Method GET -Uri $uri
    $state = Get-Prop (Get-Prop $d 'properties' $null) 'provisioningState' $null

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
    $p = Get-Prop $it 'properties' $null
    if ($null -eq $p) { continue }

    $ck = Get-Prop $p 'contentKind' $null
    if (-not (Is-WorkbookTemplateKind -contentKind $ck)) { continue }

    $dn = Get-Prop $p 'displayName' ''
    if (-not (Match-DisplayName -Name $dn -Filter $DisplayNameFilter -Mode $DisplayNameFilterMode)) { continue }

    $src = Get-Prop $p 'source' $null

    [pscustomobject]@{
      templateId       = Get-Prop $it 'name' ''
      displayName      = $dn
      contentKind      = $ck
      contentId        = Get-Prop $p 'contentId' ''
      contentProductId = Get-Prop $p 'contentProductId' ''
      packageId        = Get-Prop $p 'packageId' ''
      packageVersion   = Get-Prop $p 'packageVersion' ''
      packageName      = Get-Prop $p 'packageName' ''  # opcional
      version          = Get-Prop $p 'version' ''
      sourceKind       = Get-Prop $src 'kind' ''
      sourceName       = Get-Prop $src 'name' ''
    }
  }

  $filtered = @($filtered | Sort-Object displayName)

  $filtered | Format-Table -AutoSize
  Write-Host ""
  Write-Info "Total templates (Workbook/WorkbookTemplate) encontrados: $($filtered.Count)"

  $csvPath = Resolve-DefaultCsvPath -Provided $CsvOutputPath
  Export-CsvUtf8NoBom -Data $filtered -Path $csvPath
  Write-Host ""
  Write-Info "✅ CSV generado: $csvPath"
  exit 0
}

if ($Action -eq 'create') {
  if ([string]::IsNullOrWhiteSpace($TemplateId)) {
    throw "TemplateId es obligatorio para Action=create"
  }

  Write-Info "Cargando templateId: $TemplateId"
  $tpl = Get-ContentTemplateById -Id $TemplateId

  if (-not $tpl -or -not (Get-Prop $tpl 'properties' $null)) {
    throw "No se pudo obtener el Content Template '$TemplateId'. Revisa que esté instalado en el workspace."
  }

  $props = Get-Prop $tpl 'properties' $null
  $kind = Get-Prop $props 'contentKind' ''
  if (-not (Is-WorkbookTemplateKind -contentKind $kind)) {
    throw "El TemplateId indicado no parece de Workbook. contentKind='$kind'"
  }

  $mainTemplate = Get-Prop $props 'mainTemplate' $null
  if ($null -eq $mainTemplate) {
    throw "El template no contiene properties.mainTemplate (expand). Revisa instalación o permisos."
  }

  $defaultName = Get-Prop $props 'displayName' ''
  $targetName = if (-not [string]::IsNullOrWhiteSpace($WorkbookDisplayName)) { $WorkbookDisplayName } else { $defaultName }
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

  Start-ArmDeployment -DeploymentName $deploymentName -TemplateObj $mainTemplate -ParametersObj $params
  $res = Wait-ArmDeployment -DeploymentName $deploymentName -MaxWaitSeconds 900

  $pRes = Get-Prop $res 'properties' $null
  $state = Get-Prop $pRes 'provisioningState' ''
  if ($state -ne 'Succeeded') {
    $err = Get-Prop $pRes 'error' $null
    if ($err) {
      $code = Get-Prop $err 'code' ''
      $msg  = Get-Prop $err 'message' ''
      throw "Deployment falló: $code - $msg"
    }
    throw "Deployment terminó en estado: $state"
  }

  Write-Host ""
  Write-Info "✅ Workbook desplegado desde templateId=$TemplateId (deployment=$deploymentName)"
  exit 0
}

throw "Acción no soportada: $Action"
