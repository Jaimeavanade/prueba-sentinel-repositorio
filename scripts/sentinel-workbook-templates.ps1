#!/usr/bin/env pwsh
<#
.SYNOPSIS
  List/Create Microsoft Sentinel Workbook templates (Content Hub contentTemplates) with robust deployment diagnostics.

.DESCRIPTION
  - Lists Workbook templates from Sentinel contentTemplates (expand=mainTemplate optional).
  - Creates (deploys) a Workbook from a given templateId using ARM deployment at RG scope.
  - Idempotent behavior:
      * If a workbook with same displayName exists:
          - default: SKIP (prints "ℹ️ Workbook ya existe, no se lanza deployment")
          - -UpdateIfExists: deploy/update that workbook resource
          - -Force: create a NEW COPY (new resource name GUID) even if displayName matches
  - On ARM failure: dumps deployment operations to reveal the real error (not only DeploymentFailed).

.NOTES
  Requires Azure CLI logged in (azure/login@v2 OIDC is enough) and permission to deploy.
#>

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
  try {
    $null = & az --version 2>$null
  } catch {
    throw "Azure CLI (az) no está disponible en el runner."
  }
}

function Az-Json {
  param(
    [Parameter(Mandatory)][string]$CommandLine
  )
  if ($VerboseOutput) { Write-Host "🔎 az $CommandLine" }
  $raw = & az $CommandLine --only-show-errors -o json 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Fallo ejecutando: az $CommandLine`n$raw"
  }
  if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
  return ($raw | ConvertFrom-Json -Depth 50)
}

function Az-Rest {
  param(
    [Parameter(Mandatory)][ValidateSet("get","put","post","delete","patch")]
    [string]$Method,
    [Parameter(Mandatory)][string]$Url
  )
  $cmd = "rest --method $Method --url `"$Url`""
  return Az-Json -CommandLine $cmd
}

function Get-WorkspaceResourceId {
  return "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
}

function Get-ContentTemplate {
  param([Parameter(Mandatory)][string]$TemplateId)

  # Official endpoint pattern (api-version 2025-09-01). [2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-templates/list?view=rest-securityinsights-2025-09-01)
  $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$TemplateId?api-version=2025-09-01&`$expand=properties/mainTemplate"
  return Az-Rest -Method get -Url $url
}

function List-WorkbookTemplates {
  # List installed templates; we can filter on client side for WorkbookTemplate
  $url = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=2025-09-01&`$expand=properties/mainTemplate"
  $resp = Az-Rest -Method get -Url $url

  $items = @()
  if ($resp.value) { $items = $resp.value }

  # Keep only workbook templates
  $workbookTemplates = $items | Where-Object {
    $_.properties.contentKind -eq "WorkbookTemplate" -or $_.properties.contentKind -eq "Workbook"
  }

  # Apply filter if provided
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
      templateId   = $_.name
      displayName  = $_.properties.displayName
      contentKind  = $_.properties.contentKind
      packageName  = $_.properties.packageName
      packageVersion = $_.properties.packageVersion
      version      = $_.properties.version
    }
  }
  $rows | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
}

function List-ExistingWorkbooks {
  # List workbooks in RG
  $cmd = "resource list -g `"$ResourceGroupName`" --resource-type Microsoft.Insights/workbooks"
  $list = Az-Json -CommandLine $cmd
  if (-not $list) { return @() }

  # Normalize fields; 'properties.displayName' typically present
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

function Patch-ArmTemplateForWorkbook {
  param(
    [Parameter(Mandatory)][object]$TemplateObject,
    [string]$TargetWorkbookName,          # existing workbook resource name (for update)
    [string]$NewWorkbookName,             # GUID name (for create copy)
    [string]$OverrideDisplayName          # optional
  )

  if (-not $TemplateObject.resources) { return $TemplateObject }

  foreach ($r in $TemplateObject.resources) {
    if ($r.type -eq "Microsoft.Insights/workbooks") {

      if (-not [string]::IsNullOrWhiteSpace($OverrideDisplayName)) {
        if (-not $r.properties) { $r | Add-Member -MemberType NoteProperty -Name properties -Value (@{}) -Force }
        $r.properties.displayName = $OverrideDisplayName
      }

      if (-not [string]::IsNullOrWhiteSpace($TargetWorkbookName)) {
        # update existing resource name
        $r.name = $TargetWorkbookName
      }
      elseif (-not [string]::IsNullOrWhiteSpace($NewWorkbookName)) {
        # create copy with new name
        $r.name = $NewWorkbookName
      }
    }

    # Patch dependsOn if it references old workbook name literally (rare but possible)
    if ($r.dependsOn -and ($r.dependsOn -is [System.Collections.IEnumerable])) {
      $patched = @()
      foreach ($d in $r.dependsOn) {
        $patched += $d
      }
      $r.dependsOn = $patched
    }
  }

  return $TemplateObject
}

function Build-TemplateParameters {
  param([Parameter(Mandatory)][object]$TemplateObject)

  $params = @{}

  $workspaceRid = Get-WorkspaceResourceId

  # Detect parameters and fill common ones
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

function Dump-DeploymentOperations {
  param(
    [Parameter(Mandatory)][string]$DeploymentName
  )
  Write-Warn "Dump de operaciones del deployment para ver el error real (ARM operations)…"
  try {
    $ops = Az-Json -CommandLine "deployment group operation list -g `"$ResourceGroupName`" -n `"$DeploymentName`""
    if (-not $ops) {
      Write-Warn "No se pudieron recuperar operaciones (respuesta vacía)."
      return
    }

    $failed = $ops | Where-Object { $_.properties.provisioningState -ne "Succeeded" }
    if (-not $failed) {
      Write-Info "No se encontraron operaciones fallidas (pero el deployment devolvió error)."
      return
    }

    foreach ($f in $failed) {
      $t = $f.properties.targetResource.resourceType
      $n = $f.properties.targetResource.resourceName
      $st = $f.properties.provisioningState
      $msg = $f.properties.statusMessage | ConvertTo-Json -Depth 50
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

# Set subscription (safe even if already)
$null = & az account set --subscription "$SubscriptionId" --only-show-errors 2>$null

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
if ([string]::IsNullOrWhiteSpace($TemplateId)) {
  throw "Para -Action create debes indicar -TemplateId"
}

if ([string]::IsNullOrWhiteSpace($Location)) {
  throw "Debes indicar -Location (por ejemplo: francecentral / westeurope / etc.)"
}

Write-Info "Cargando templateId: $TemplateId"
$ct = Get-ContentTemplate -TemplateId $TemplateId

if (-not $ct -or -not $ct.properties -or -not $ct.properties.mainTemplate) {
  throw "No se pudo obtener properties.mainTemplate del contentTemplate $TemplateId (¿falta `$expand=properties/mainTemplate o no está instalado?)."
}

# Determine target displayName
$targetDisplayName = $WorkbookDisplayName
if ([string]::IsNullOrWhiteSpace($targetDisplayName)) {
  $targetDisplayName = $ct.properties.displayName
}
Write-Info "WorkbookDisplayName objetivo: $targetDisplayName"

# Existing workbook detection
$existing = $null
$workbooks = List-ExistingWorkbooks
if ($workbooks.Count -gt 0) {
  $existing = Find-WorkbookByDisplayName -workbooks $workbooks -displayName $targetDisplayName -mode $DisplayNameFilterMode
}

if ($existing -and -not $Force -and -not $UpdateIfExists) {
  # REQUIRED message by you:
  Write-Host "ℹ️ Workbook ya existe, no se lanza deployment"
  Write-Info "Coincidencia: name=$($existing.name) displayName=$($existing.displayName) location=$($existing.location)"
  exit 0
}

# Prepare ARM template object
$templateObj = $ct.properties.mainTemplate

# Choose workbook resource name strategy
$targetWorkbookName = ""
$newWorkbookName = ""
if ($existing -and $UpdateIfExists) {
  $targetWorkbookName = $existing.name
  Write-Info "UpdateIfExists activado: se actualizará el workbook existente name=$targetWorkbookName"
} else {
  # Create new copy to avoid collisions with fixed names in templates
  $newWorkbookName = ([guid]::NewGuid().ToString())
  if ($existing -and $Force) {
    Write-Info "Force activado: se creará una COPIA nueva con name=$newWorkbookName aunque exista uno similar."
  } else {
    Write-Info "Creación: se usará name nuevo (GUID) para evitar colisiones: $newWorkbookName"
  }
}

# Patch template: workbook name + optional displayName override
$templateObj = Patch-ArmTemplateForWorkbook -TemplateObject $templateObj -TargetWorkbookName $targetWorkbookName -NewWorkbookName $newWorkbookName -OverrideDisplayName $targetDisplayName

# Build parameters file based on template.parameters
$paramObj = Build-TemplateParameters -TemplateObject $templateObj

# Write temp files
$tmpDir = Join-Path $PWD ".tmp"
if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null }
$templatePath = Join-Path $tmpDir "workbook-template.json"
$paramPath    = Join-Path $tmpDir "workbook-params.json"

$templateObj | ConvertTo-Json -Depth 100 | Out-File -FilePath $templatePath -Encoding UTF8
$paramObj    | ConvertTo-Json -Depth 50  | Out-File -FilePath $paramPath -Encoding UTF8

# Deploy
$deploymentName = "swb-$([guid]::NewGuid().ToString('N').Substring(0,12))-$((Get-Date).ToString('yyyyMMddHHmmss'))"
Write-Info "Lanzando deployment: $deploymentName"
try {
  $cmd = "deployment group create -g `"$ResourceGroupName`" -n `"$deploymentName`" --mode Incremental --template-file `"$templatePath`" --parameters `"$paramPath`""
  $result = Az-Json -CommandLine $cmd
  Write-Ok "Deployment OK."
  if ($existing -and $UpdateIfExists) {
    Write-Ok "Workbook actualizado: $($existing.id)"
  } else {
    # Find created workbook
    $after = List-ExistingWorkbooks
    $created = Find-WorkbookByDisplayName -workbooks $after -displayName $targetDisplayName -mode "equals"
    if ($created) {
      Write-Ok "Workbook creado: $($created.id)"
    } else {
      Write-Info "No he podido resolver el id del workbook creado por displayName (puede haber duplicados o displayName diferente en la plantilla)."
    }
  }
  exit 0
}
catch {
  # Surface generic deployment failed + dump operations (real error)
  $msg = $_.Exception.Message
  Write-Warn "Deployment falló (mensaje genérico): $msg"
  Dump-DeploymentOperations -DeploymentName $deploymentName
  throw
}
