#!/usr/bin/env pwsh
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet("list","create")]
  [string]$Action,

  [Parameter(Mandatory)]
  [string]$SubscriptionId,

  [Parameter(Mandatory)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory)]
  [string]$WorkspaceName,

  [ValidateSet("contains","equals")]
  [string]$DisplayNameFilterMode = "contains",

  [string]$DisplayNameFilter = "",

  [string]$TemplateId = "",

  [string]$WorkbookDisplayName = "",

  [string]$Location = "",

  [string]$CsvOutputPath = "artifacts/workbook-templates.csv",

  [switch]$Force,

  [switch]$UpdateIfExists,

  [switch]$VerboseOutput
)

$ErrorActionPreference = "Stop"

function Write-Info([string]$msg) { Write-Host "ℹ️ $msg" }
function Write-Warn([string]$msg) { Write-Host "⚠️ $msg" }
function Write-Ok([string]$msg)   { Write-Host "✅ $msg" }
function Write-Step([string]$msg) { Write-Host "➡️ $msg" }

function Assert-AzCli {
  try { & az --version *> $null } catch { throw "Azure CLI (az) no está disponible en el runner." }
}

# Ejecuta az con argumentos tokenizados (array), NO con string
function Az-Json {
  param(
    [Parameter(Mandatory)]
    [string[]]$Args
  )

  if ($VerboseOutput) {
    $pretty = ($Args | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    Write-Host "🔎 az $pretty"
  }

  $raw = & az @Args --only-show-errors -o json 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Fallo ejecutando: az $($Args -join ' ')`n$raw"
  }
  if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
  return ($raw | ConvertFrom-Json -Depth 80)
}

function Az-Rest {
  param(
    [Parameter(Mandatory)][ValidateSet("get","put","post","delete","patch")]
    [string]$Method,
    [Parameter(Mandatory)][string]$Url
  )
  return Az-Json -Args @("rest","--method",$Method,"--url",$Url)
}

function Get-WorkspaceResourceId {
  return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
}

# Construye URL segura con UriBuilder y querystring controlada
function Build-SentinelUrl {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][hashtable]$Query
  )

  $ub = [System.UriBuilder]::new("https://management.azure.com")
  $ub.Path = $Path.TrimStart('/')

  $pairs = New-Object System.Collections.Generic.List[string]
  foreach ($k in $Query.Keys) { $pairs.Add("$k=$($Query[$k])") }
  $ub.Query = ($pairs -join "&")

  return $ub.Uri.AbsoluteUri
}

function Get-ContentTemplate {
  param([Parameter(Mandatory)][string]$TemplateId)

  if ([string]::IsNullOrWhiteSpace($TemplateId)) {
    throw "TemplateId vacío o nulo. No se puede consultar contentTemplates."
  }

  $apiVersion = "2025-09-01"
  $expand = "properties/mainTemplate"
  $wsRid = Get-WorkspaceResourceId

  $path = "$wsRid/providers/Microsoft.SecurityInsights/contentTemplates/$TemplateId"
  $url = Build-SentinelUrl -Path $path -Query @{
    "api-version" = $apiVersion
    "`$expand"    = $expand
  }

  if ($VerboseOutput) {
    Write-Host "🔎 GET contentTemplate URL:"
    Write-Host $url
  }

  return Az-Rest -Method get -Url $url
}

function List-WorkbookTemplates {
  $apiVersion = "2025-09-01"
  $expand = "properties/mainTemplate"
  $wsRid = Get-WorkspaceResourceId

  $path = "$wsRid/providers/Microsoft.SecurityInsights/contentTemplates"
  $url = Build-SentinelUrl -Path $path -Query @{
    "api-version" = $apiVersion
    "`$expand"    = $expand
  }

  $resp = Az-Rest -Method get -Url $url
  $items = @()
  if ($resp.value) { $items = $resp.value }

  $workbookTemplates = $items | Where-Object {
    $_.properties.contentKind -eq "WorkbookTemplate" -or $_.properties.contentKind -eq "Workbook"
  }

  if (-not [string]::IsNullOrWhiteSpace($DisplayNameFilter)) {
    if ($DisplayNameFilterMode -eq "contains") {
      $workbookTemplates = $workbookTemplates | Where-Object { $_.properties.displayName -like "*$DisplayNameFilter*" }
    } else {
      $workbookTemplates = $workbookTemplates | Where-Object { $_.properties.displayName -eq $DisplayNameFilter }
    }
  }

  return $workbookTemplates
}

function Ensure-Folder([string]$path) {
  $dir = Split-Path -Parent $path
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Export-CsvTemplates($templates, [string]$path) {
  Ensure-Folder $path
  $rows = $templates | ForEach-Object {
    [pscustomobject]@{
      templateId      = $_.name
      displayName     = $_.properties.displayName
      contentKind     = $_.properties.contentKind
      packageName     = $_.properties.packageName
      packageVersion  = $_.properties.packageVersion
      version         = $_.properties.version
    }
  }
  $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
}

function List-ExistingWorkbooks {
  $list = Az-Json -Args @("resource","list","-g",$ResourceGroupName,"--resource-type","Microsoft.Insights/workbooks")
  if (-not $list) { return @() }

  return $list | ForEach-Object {
    [pscustomobject]@{
      id          = $_.id
      name        = $_.name
      location    = $_.location
      displayName = $_.properties.displayName
    }
  }
}

function Find-WorkbookByDisplayName($workbooks, [string]$displayName, [string]$mode) {
  if ([string]::IsNullOrWhiteSpace($displayName)) { return $null }
  if ($mode -eq "contains") {
    return $workbooks | Where-Object { $_.displayName -and ($_.displayName -like "*$displayName*") } | Select-Object -First 1
  } else {
    return $workbooks | Where-Object { $_.displayName -eq $displayName } | Select-Object -First 1
  }
}

# ✅ PARCHE: asegurar name + displayName + (CRÍTICO) location en Microsoft.Insights/workbooks
function Patch-ArmTemplateForWorkbook {
  param(
    [Parameter(Mandatory)][object]$TemplateObject,
    [string]$TargetWorkbookName,
    [string]$NewWorkbookName,
    [string]$OverrideDisplayName,
    [string]$ForceLocation
  )

  if (-not $TemplateObject.resources) { return $TemplateObject }

  foreach ($r in $TemplateObject.resources) {
    if ($r.type -eq "Microsoft.Insights/workbooks") {

      # displayName
      if (-not [string]::IsNullOrWhiteSpace($OverrideDisplayName)) {
        if (-not $r.properties) { $r | Add-Member -MemberType NoteProperty -Name properties -Value (@{}) -Force }
        $r.properties.displayName = $OverrideDisplayName
      }

      # name (update o copia nueva)
      if (-not [string]::IsNullOrWhiteSpace($TargetWorkbookName)) {
        $r.name = $TargetWorkbookName
      } elseif (-not [string]::IsNullOrWhiteSpace($NewWorkbookName)) {
        $r.name = $NewWorkbookName
      }

      # ✅ FIX del run: LocationRequired → forzamos location SI falta o viene vacío
      $needsLocation = $false
      if (-not $r.PSObject.Properties.Match("location")) { $needsLocation = $true }
      elseif ($null -eq $r.location) { $needsLocation = $true }
      elseif ([string]::IsNullOrWhiteSpace([string]$r.location)) { $needsLocation = $true }

      if ($needsLocation) {
        $r | Add-Member -MemberType NoteProperty -Name location -Value $ForceLocation -Force
      }
    }
  }

  return $TemplateObject
}

function Build-TemplateParameters {
  param([Parameter(Mandatory)][object]$TemplateObject)

  $params = @{}
  $workspaceRid = Get-WorkspaceResourceId
  $tplParams = $TemplateObject.parameters

  if ($tplParams) {
    foreach ($pName in $tplParams.PSObject.Properties.Name) {
      switch -Regex ($pName) {
        '^workspace$'               { $params[$pName] = @{ value = $WorkspaceName }; break }
        '^workspaceName$'           { $params[$pName] = @{ value = $WorkspaceName }; break }
        '^workspaceId$'             { $params[$pName] = @{ value = $workspaceRid }; break }
        '^workspaceResourceId$'     { $params[$pName] = @{ value = $workspaceRid }; break }
        '^workspace-location$'      { $params[$pName] = @{ value = $Location }; break }
        '^workspaceLocation$'       { $params[$pName] = @{ value = $Location }; break }
        '^location$'                { $params[$pName] = @{ value = $Location }; break }
        '^resourceGroup(Name)?$'    { $params[$pName] = @{ value = $ResourceGroupName }; break }
        '^subscriptionId$'          { $params[$pName] = @{ value = $SubscriptionId }; break }
        default { }
      }
    }
  }

  return @{ parameters = $params }
}

# ✅ FIX: comando correcto de operaciones: az deployment operation group list
function Dump-DeploymentOperations {
  param([Parameter(Mandatory)][string]$DeploymentName)

  Write-Warn "Dump de operaciones del deployment para ver el error real (ARM operations)…"
  try {
    $ops = Az-Json -Args @("deployment","operation","group","list","-g",$ResourceGroupName,"-n",$DeploymentName)
    if (-not $ops) {
      Write-Warn "No se pudieron recuperar operaciones (respuesta vacía)."
      return
    }

    $failed = $ops | Where-Object { $_.properties.provisioningState -ne "Succeeded" }
    if (-not $failed) {
      Write-Info "No se encontraron operaciones fallidas."
      return
    }

    foreach ($f in $failed) {
      $t = $f.properties.targetResource.resourceType
      $n = $f.properties.targetResource.resourceName
      $st = $f.properties.provisioningState
      $msg = $f.properties.statusMessage | ConvertTo-Json -Depth 80
      Write-Host "❌ [$st] $t/$n"
      Write-Host $msg
      Write-Host "----------------------------------------"
    }
  } catch {
    Write-Warn "Error intentando dumpear operaciones: $($_.Exception.Message)"
  }
}

# ---------------- MAIN ----------------
Assert-AzCli
Write-Info "Acción: $Action"
Write-Info "Workspace: $WorkspaceName (RG: $ResourceGroupName, Sub: ***)"

& az account set --subscription "$SubscriptionId" --only-show-errors *> $null

# ConvertTo-Json máximo 100
$JsonDepth = 100

if ($Action -eq "list") {
  Write-Step "Listando plantillas de Workbooks (contentTemplates)…"
  $templates = List-WorkbookTemplates
  Write-Ok "Encontradas $($templates.Count) plantillas (tras filtro)."
  Write-Step "Exportando CSV a: $CsvOutputPath"
  Export-CsvTemplates -templates $templates -path $CsvOutputPath
  Write-Ok "CSV generado."
  exit 0
}

# Action create
if ([string]::IsNullOrWhiteSpace($TemplateId)) { throw "Para -Action create debes indicar -TemplateId" }
if ([string]::IsNullOrWhiteSpace($Location))  { throw "Debes indicar -Location (ej: francecentral, westeurope, etc.)" }

Write-Info "Cargando templateId: $TemplateId"
$ct = Get-ContentTemplate -TemplateId $TemplateId

if (-not $ct -or -not $ct.properties -or -not $ct.properties.mainTemplate) {
  throw "No se pudo obtener properties.mainTemplate del contentTemplate $TemplateId."
}

$targetDisplayName = $WorkbookDisplayName
if ([string]::IsNullOrWhiteSpace($targetDisplayName)) { $targetDisplayName = $ct.properties.displayName }
Write-Info "WorkbookDisplayName objetivo: $targetDisplayName"

$existing = $null
$workbooks = List-ExistingWorkbooks
if ($workbooks.Count -gt 0) {
  $existing = Find-WorkbookByDisplayName -workbooks $workbooks -displayName $targetDisplayName -mode $DisplayNameFilterMode
}

if ($existing -and -not $Force -and -not $UpdateIfExists) {
  # Mensaje EXACTO que pediste
  Write-Host "ℹ️ Workbook ya existe, no se lanza deployment"
  Write-Info "Coincidencia: name=$($existing.name) displayName=$($existing.displayName) location=$($existing.location)"
  exit 0
}

$templateObj = $ct.properties.mainTemplate

$targetWorkbookName = ""
$newWorkbookName = ""
if ($existing -and $UpdateIfExists) {
  $targetWorkbookName = $existing.name
  Write-Info "UpdateIfExists activado: se actualizará el workbook existente name=$targetWorkbookName"
} else {
  $newWorkbookName = ([guid]::NewGuid().ToString())
  if ($existing -and $Force) {
    Write-Info "Force activado: se creará una COPIA nueva con name=$newWorkbookName aunque exista uno similar."
  } else {
    Write-Info "Creación: se usará name nuevo (GUID) para evitar colisiones: $newWorkbookName"
  }
}

# ✅ Aquí aplicamos el fix de LocationRequired
$templateObj = Patch-ArmTemplateForWorkbook `
  -TemplateObject $templateObj `
  -TargetWorkbookName $targetWorkbookName `
  -NewWorkbookName $newWorkbookName `
  -OverrideDisplayName $targetDisplayName `
  -ForceLocation $Location

$paramObj = Build-TemplateParameters -TemplateObject $templateObj

$tmpDir = Join-Path $PWD ".tmp"
if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null }
$templatePath = Join-Path $tmpDir "workbook-template.json"
$paramPath    = Join-Path $tmpDir "workbook-params.json"

$templateObj | ConvertTo-Json -Depth $JsonDepth | Out-File -FilePath $templatePath -Encoding UTF8
$paramObj    | ConvertTo-Json -Depth 50         | Out-File -FilePath $paramPath    -Encoding UTF8

$deploymentName = "swb-$(([guid]::NewGuid().ToString('N')).Substring(0,12))-$((Get-Date).ToString('yyyyMMddHHmmss'))"
Write-Info "Lanzando deployment: $deploymentName"

try {
  $null = Az-Json -Args @(
    "deployment","group","create",
    "-g",$ResourceGroupName,
    "-n",$deploymentName,
    "--mode","Incremental",
    "--template-file",$templatePath,
    "--parameters",$paramPath
  )
  Write-Ok "Deployment OK."
  exit 0
}
catch {
  Write-Warn "Deployment falló (mensaje genérico): $($_.Exception.Message)"
  Dump-DeploymentOperations -DeploymentName $deploymentName
  throw
}
