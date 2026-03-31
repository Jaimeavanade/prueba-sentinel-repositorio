<#
.SYNOPSIS
  Microsoft Sentinel - Workbooks Templates (List/Create)

.DESCRIPTION
  - list:
      Lista templates instalados (Microsoft.SecurityInsights/contentTemplates) filtrando por contentKind
      Workbook o WorkbookTemplate y opcionalmente por displayName.
      Exporta CSV (para artifact) si se indica -CsvOutputPath o si estamos en GitHub Actions.
  - create:
      A partir de un TemplateId (contentTemplate), obtiene properties.mainTemplate (ARM template)
      y ejecuta un deployment ARM en el Resource Group del workspace para materializar el workbook.

.FIXES
  - FIX URL TemplateId: evita bug "$Id?api-version" (PowerShell interpreta $Id?api).
  - FIX URL DeploymentName: evita bug "$DeploymentName?api-version" (PowerShell interpreta $DeploymentName?api). [1]()
  - FIX params: normaliza mainTemplate.parameters a Hashtable (Dictionary/PSCustomObject).
  - FIX Count: garantiza que $missing sea SIEMPRE array antes de usar .Count.
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

  [Parameter(Mandatory=$false)]
  [string]$TemplateId,

  [Parameter(Mandatory=$false)]
  [string]$DisplayNameFilter,

  [Parameter(Mandatory=$false)]
  [ValidateSet('contains','equals','startswith')]
  [string]$DisplayNameFilterMode = 'contains',

  [Parameter(Mandatory=$false)]
  [string]$WorkbookDisplayName,

  [Parameter(Mandatory=$false)]
  [string]$Location,

  [Parameter(Mandatory=$false)]
  [string]$CsvOutputPath,

  [Parameter(Mandatory=$false)]
  [string]$ApiVersionSecurityInsights = '2025-09-01',

  [Parameter(Mandatory=$false)]
  [string]$ApiVersionDeployments = '2021-04-01',

  [Parameter(Mandatory=$false)]
  [switch]$VerboseOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info([string]$m) { Write-Host "ℹ️  $m" }
function Write-Warn([string]$m) { Write-Warning $m }

function Has-Prop([object]$Obj, [string]$Name) {
  return ($null -ne $Obj -and $Obj.PSObject.Properties.Name -contains $Name)
}
function Get-Prop([object]$Obj, [string]$Name, $Default=$null) {
  if (Has-Prop $Obj $Name) { return $Obj.$Name }
  return $Default
}

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
  if ($null -ne $Body) { $payload = ($Body | ConvertTo-Json -Depth 200) }

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

function Get-WorkspaceResourceId {
  return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
}

function Get-ContentTemplatesList {
  $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersionSecurityInsights"
  return Invoke-ArmRest -Method GET -Uri $uri
}

function Get-ContentTemplateById {
  param([Parameter(Mandatory=$true)][string]$Id)

  # ✅ FIX: evitar "$Id?api-version" => PowerShell intenta leer $Id?api
  $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$($Id)"
  $uri = $baseUri + "?api-version=$ApiVersionSecurityInsights&`$expand=properties/mainTemplate"
  return Invoke-ArmRest -Method GET -Uri $uri
}

function Is-WorkbookTemplateKind {
  param($contentKind)
  if ($null -eq $contentKind) { return $false }
  $k = $contentKind.ToString()
  return ($k -eq 'Workbook' -or $k -eq 'WorkbookTemplate')
}

function Match-DisplayName {
  param([string]$Name, [string]$Filter, [string]$Mode)
  if ([string]::IsNullOrWhiteSpace($Filter)) { return $true }
  if ($null -eq $Name) { return $false }
  switch ($Mode) {
    'equals'     { return ($Name -eq $Filter) }
    'startswith' { return ($Name.StartsWith($Filter, [System.StringComparison]::OrdinalIgnoreCase)) }
    default      { return ($Name.IndexOf($Filter, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) }
  }
}

function Resolve-DefaultCsvPath {
  param([string]$Provided)
  if (-not [string]::IsNullOrWhiteSpace($Provided)) { return $Provided }
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
  param([Parameter(Mandatory=$true)][object[]]$Data, [Parameter(Mandatory=$true)][string]$Path)
  Ensure-Directory -Path $Path
  $csv = $Data | ConvertTo-Csv -NoTypeInformation
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllLines($Path, $csv, $utf8NoBom)
}

function Get-TemplateParametersHashtable {
  param([Parameter(Mandatory=$true)]$TemplateObj)
  $raw = Get-Prop $TemplateObj 'parameters' $null
  if ($null -eq $raw) { return $null }
  if ($raw -is [System.Collections.IDictionary]) { return $raw }
  $ht = @{}
  foreach ($prop in $raw.PSObject.Properties) { $ht[$prop.Name] = $prop.Value }
  return $ht
}

function Param-HasDefaultValue {
  param([object]$Definition)
  if ($null -eq $Definition) { return $false }
  if ($Definition -is [System.Collections.IDictionary]) {
    if (-not $Definition.Contains('defaultValue')) { return $false }
    $dv = $Definition['defaultValue']
    return ($null -ne $dv -and $dv.ToString().Length -gt 0)
  } else {
    if (-not (Has-Prop $Definition 'defaultValue')) { return $false }
    $dv = $Definition.defaultValue
    return ($null -ne $dv -and $dv.ToString().Length -gt 0)
  }
}

function Build-DeploymentParametersFromTemplate {
  param(
    [Parameter(Mandatory=$true)]$TemplateObj,
    [Parameter(Mandatory=$true)][string]$WorkspaceResourceId,
    [Parameter(Mandatory=$false)][string]$WorkbookNameOverride,
    [Parameter(Mandatory=$false)][string]$LocationOverride
  )

  $params = @{}
  $tmplParams = Get-TemplateParametersHashtable -TemplateObj $TemplateObj
  if ($null -eq $tmplParams) { return $params }

  function Set-IfExists([string]$paramName, [object]$value) {
    if ($tmplParams.Contains($paramName)) { $params[$paramName] = @{ value = $value } }
  }

  $workbookGuid = (New-Guid).Guid
  $rgId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName"

  Set-IfExists 'workbookId' $workbookGuid
  Set-IfExists 'workbookName' $workbookGuid
  Set-IfExists 'resourceName' $workbookGuid

  Set-IfExists 'workspace' $WorkspaceName
  Set-IfExists 'workspaceName' $WorkspaceName
  Set-IfExists 'workspaceResourceId' $WorkspaceResourceId
  Set-IfExists 'workspaceId' $WorkspaceResourceId

  Set-IfExists 'workbookSourceId' $WorkspaceResourceId
  Set-IfExists 'sourceId' $WorkspaceResourceId
  Set-IfExists 'resourceGroupId' $rgId

  if (-not [string]::IsNullOrWhiteSpace($WorkbookNameOverride)) {
    Set-IfExists 'workbookDisplayName' $WorkbookNameOverride
    Set-IfExists 'displayName' $WorkbookNameOverride
  }

  if (-not [string]::IsNullOrWhiteSpace($LocationOverride)) {
    Set-IfExists 'location' $LocationOverride
  }

  return $params
}

function Get-MissingRequiredParams {
  param([Parameter(Mandatory=$true)]$TemplateObj, [Parameter(Mandatory=$true)]$ProvidedParams)

  $missing = @()
  $tmplParams = Get-TemplateParametersHashtable -TemplateObj $TemplateObj
  if ($null -eq $tmplParams) { return @() }

  foreach ($key in $tmplParams.Keys) {
    $def = $tmplParams[$key]
    $hasDefault = Param-HasDefaultValue -Definition $def
    $provided = $ProvidedParams.ContainsKey($key)
    if (-not $provided -and -not $hasDefault) { $missing += $key }
  }

  return ,$missing
}

function Start-ArmDeployment {
  param(
    [Parameter(Mandatory=$true)][string]$DeploymentName,
    [Parameter(Mandatory=$true)]$TemplateObj,
    [Parameter(Mandatory=$true)]$ParametersObj
  )

  # ✅ FIX: evitar "$DeploymentName?api-version" => PS intenta $DeploymentName?api [1]()
  $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$($DeploymentName)"
  $uri = $baseUri + "?api-version=$ApiVersionDeployments"

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
  param([Parameter(Mandatory=$true)][string]$DeploymentName, [int]$MaxWaitSeconds = 900)

  $baseUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Resources/deployments/$($DeploymentName)"
  $uri = $baseUri + "?api-version=$ApiVersionDeployments"

  $deadline = (Get-Date).AddSeconds($MaxWaitSeconds)
  while ((Get-Date) -lt $deadline) {
    $d = Invoke-ArmRest -Method GET -Uri $uri
    $state = Get-Prop (Get-Prop $d 'properties' $null) 'provisioningState' $null
    if ($state -in @('Succeeded','Failed','Canceled')) { return $d }
    Start-Sleep -Seconds 5
  }
  throw "Timeout esperando el deployment '$DeploymentName'."
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
      packageName      = Get-Prop $p 'packageName' ''
      version          = Get-Prop $p 'version' ''
      sourceKind       = Get-Prop $src 'kind' ''
      sourceName       = Get-Prop $src 'name' ''
    }
  }

  $filtered = @($filtered | Sort-Object displayName)
  $filtered | Format-Table -AutoSize
  Write-Host ""
  Write-Info "Total templates encontrados: $($filtered.Count)"

  $csvPath = Resolve-DefaultCsvPath -Provided $CsvOutputPath
  Export-CsvUtf8NoBom -Data $filtered -Path $csvPath
  Write-Host ""
  Write-Info "✅ CSV generado: $csvPath"
  exit 0
}

if ($Action -eq 'create') {
  if ([string]::IsNullOrWhiteSpace($TemplateId)) { throw "TemplateId es obligatorio para Action=create" }

  Write-Info "Cargando templateId: $TemplateId"
  $tpl = Get-ContentTemplateById -Id $TemplateId
  $props = Get-Prop $tpl 'properties' $null
  if ($null -eq $props) { throw "No se pudo obtener el Content Template '$TemplateId'." }

  $kind = Get-Prop $props 'contentKind' ''
  if (-not (Is-WorkbookTemplateKind -contentKind $kind)) {
    throw "El TemplateId indicado no parece de Workbook. contentKind='$kind'"
  }

  $mainTemplate = Get-Prop $props 'mainTemplate' $null
  if ($null -eq $mainTemplate) { throw "El template no contiene properties.mainTemplate." }

  $defaultName = Get-Prop $props 'displayName' ''
  $targetName = if (-not [string]::IsNullOrWhiteSpace($WorkbookDisplayName)) { $WorkbookDisplayName } else { $defaultName }
  Write-Info "WorkbookDisplayName objetivo: $targetName"

  $params = Build-DeploymentParametersFromTemplate -TemplateObj $mainTemplate -WorkspaceResourceId $wsId -WorkbookNameOverride $targetName -LocationOverride $Location

  $missing = Get-MissingRequiredParams -TemplateObj $mainTemplate -ProvidedParams $params
  $missingList = @($missing)
  if ($missingList.Count -gt 0) {
    Write-Warn "La plantilla declara parámetros sin default que no pudimos autocompletar:"
    $missingList | ForEach-Object { Write-Warn " - $_" }
    throw "Faltan parámetros requeridos."
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

  Write-Info "✅ Workbook desplegado desde templateId=$TemplateId (deployment=$deploymentName)"
  exit 0
}

throw "Acción no soportada: $Action"
