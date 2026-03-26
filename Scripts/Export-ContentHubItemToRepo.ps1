<#
.SYNOPSIS
  Exporta un Content Item instalado desde Content Hub, pero guardando el recurso REAL desplegado
  en formatos compatibles con Microsoft Sentinel Repositories.

.DESCRIPTION
  1) Localiza el item instalado en Microsoft.SecurityInsights/contentTemplates por displayName exacto
  2) Detecta contentKind + packageName (solución)
  3) Exporta el recurso deployable real según contentKind:
     - AnalyticsRule*  -> Microsoft.SecurityInsights/alertRules (scope: workspace)  [1](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/alertrules)
     - Workbook*       -> Microsoft.Insights/workbooks (RG)                       [3](https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/workbooks)
     - HuntingQuery*   -> Microsoft.OperationalInsights/workspaces/savedSearches  [5](https://github.com/Azure/Azure-Sentinel/blob/master/Tools/ARM-Templates/HuntingQuery/HuntingQuery.json)
     - Parser*         -> (por defecto) savedSearches (Category Parsers)
     - Playbook*       -> Microsoft.Logic/workflows (RG)
  4) Lo guarda en la carpeta del repo por tipo + solución:
     Analytics rules/<Solución>/<Nombre>.json
     Hunting/<Solución>/<Nombre>.json
     Parsers/<Solución>/<Nombre>.json
     Playbooks/<Solución>/<Nombre>.json
     Workbooks/<Solución>/<Nombre>.json

.REQUIREMENTS
  - Azure CLI autenticado (en Actions: azure/login OIDC)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $false)]
  [string]$ContentName,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,

  [Parameter(Mandatory = $false)]
  [ValidateSet("AnalyticsRule","HuntingQuery","Parser","Playbook","Workbook")]
  [string]$ExpectedType,

  [switch]$ListOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------------
# Auth + REST helpers
# -----------------------------
function Get-ArmToken {
  param([string]$SubscriptionId)
  az account set --subscription $SubscriptionId | Out-Null
  $t = az account get-access-token --resource "https://management.azure.com/" --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) { throw "Token ARM inválido. Asegúrate de azure/login (OIDC) o az login." }
  return $t
}

function Invoke-ArmRest {
  param(
    [Parameter(Mandatory=$true)][string]$Method,
    [Parameter(Mandatory=$true)][string]$Uri,
    [Parameter(Mandatory=$true)][string]$Token
  )
  $headers = @{
    Authorization = "Bearer $Token"
    "Content-Type" = "application/json"
  }
  return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
}

# -----------------------------
# String helpers
# -----------------------------
function Escape-ODataString {
  param([string]$s)
  if ($null -eq $s) { return "" }
  return $s -replace "'", "''"
}

function Normalize-DisplayName {
  param([string]$s)
  if (-not $s) { return "" }
  $t = $s.Trim()
  $t = $t -replace "[\u2013\u2014\u2212]", "-"
  $t = [regex]::Replace($t, "\s+", " ")
  return $t.ToLowerInvariant()
}

function Sanitize-Name {
  param([string]$Name)
  if (-not $Name) { return "Unknown" }
  $invalid = [Regex]::Escape(([IO.Path]::GetInvalidFileNameChars() -join ""))
  $safe = [Regex]::Replace($Name, "[$invalid]", "_").Trim()
  if ($safe.Length -gt 180) { $safe = $safe.Substring(0,180).Trim() }
  return $safe
}

# -----------------------------
# Repo folder mapping
# -----------------------------
function Map-ContentKindToFolder {
  param([string]$contentKind)

  $k = ($contentKind ?? "").ToLowerInvariant()
  if ($k -match "analyticsrule") { return "Analytics rules" }
  if ($k -match "huntingquery")  { return "Hunting" }
  if ($k -match "parser")        { return "Parsers" }
  if ($k -match "playbook")      { return "Playbooks" }
  if ($k -match "workbook")      { return "Workbooks" }
  return "Unknown"
}

function Map-ExpectedTypeCheck {
  param([string]$contentKind, [string]$ExpectedType)
  if (-not $ExpectedType) { return }
  $k = ($contentKind ?? "")
  if ($k -notmatch $ExpectedType) {
    throw "El item encontrado es contentKind='$k' pero esperabas '$ExpectedType'. Abortado."
  }
}

# -----------------------------
# ARM template builders
# -----------------------------
function New-ArmTemplate {
  param(
    [Parameter(Mandatory=$true)][object[]]$Resources,
    [Parameter(Mandatory=$false)][hashtable]$Parameters = @{}
  )

  return @{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    parameters = $Parameters
    resources = $Resources
  }
}

function Remove-ReadOnlyFields {
  param([hashtable]$obj)

  foreach ($p in @("id","etag")) {
    if ($obj.ContainsKey($p)) { $obj.Remove($p) | Out-Null }
  }
  return $obj
}

# -----------------------------
# MAIN
# -----------------------------
$token = Get-ArmToken -SubscriptionId $SubscriptionId

$siBase = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# 1) Listar soluciones instaladas (contentPackages) (solo para debug/solución)
$packagesUri = "$siBase/contentPackages?api-version=$ApiVersion"
$packages = Invoke-ArmRest -Method GET -Uri $packagesUri -Token $token
$installedPackages = @()
if ($packages.value) { $installedPackages = @($packages.value) }

Write-Host "== Soluciones instaladas (contentPackages) =="
if ($installedPackages.Count -gt 0) {
  $installedPackages | Select-Object @{n="displayName";e={$_.properties.displayName}}, @{n="version";e={$_.properties.version}} |
    Format-Table -AutoSize | Out-String | Write-Host
}

# 2) ListOnly -> listar contentTemplates instalados
if ($ListOnly -or -not $ContentName) {
  $tplUri = "$siBase/contentTemplates?api-version=$ApiVersion&`$top=200"
  $tpl = Invoke-ArmRest -Method GET -Uri $tplUri -Token $token
  Write-Host "== Content items instalados (contentTemplates) =="
  if ($tpl.value) {
    $tpl.value |
      Select-Object @{n="displayName";e={$_.properties.displayName}},
                    @{n="contentKind";e={$_.properties.contentKind}},
                    @{n="packageName";e={$_.properties.packageName}},
                    @{n="name";e={$_.name}} |
      Sort-Object displayName |
      Format-Table -AutoSize | Out-String | Write-Host
  }
  exit 0
}

# 3) Encontrar el contentTemplate por displayName EXACTO (primero $filter, luego $search + match local)
$requestedNorm = Normalize-DisplayName $ContentName
$literal = Escape-ODataString $ContentName

$candidates = @()
try {
  $filter = [Uri]::EscapeDataString("properties/displayName eq '$literal'")
  $expand = [Uri]::EscapeDataString("properties/mainTemplate")
  $uri = "$siBase/contentTemplates?api-version=$ApiVersion&`$expand=$expand&`$filter=$filter&`$top=50"
  $r = Invoke-ArmRest -Method GET -Uri $uri -Token $token
  if ($r.value) { $candidates = @($r.value) }
} catch {
  Write-Host "WARN: $filter exacto falló. Fallback a $search."
}

if ($candidates.Count -eq 0) {
  $expand = [Uri]::EscapeDataString("properties/mainTemplate")
  $search = [Uri]::EscapeDataString($ContentName)
  $uri = "$siBase/contentTemplates?api-version=$ApiVersion&`$expand=$expand&`$search=$search&`$top=200"
  $r = Invoke-ArmRest -Method GET -Uri $uri -Token $token
  if ($r.value) { $candidates = @($r.value) }
}

if ($candidates.Count -eq 0) { throw "No se encontró ningún contentTemplate instalado para '$ContentName'." }

$exact = @($candidates | Where-Object { $_.properties.displayName -and (Normalize-DisplayName $_.properties.displayName) -eq $requestedNorm })
if ($exact.Count -ne 1) {
  Write-Host "No hay coincidencia EXACTA para '$ContentName'. Sugerencias (top 10):"
  $candidates |
    Where-Object { $_.properties.displayName } |
    Select-Object -First 10 |
    ForEach-Object {
      [pscustomobject]@{
        displayName = $_.properties.displayName
        contentKind = $_.properties.contentKind
        packageName = $_.properties.packageName
      }
    } | Format-Table -AutoSize | Out-String | Write-Host

  throw "Abortado para evitar exportar un item incorrecto. Usa el displayName exacto mostrado."
}

$template = $exact[0]
$displayName = $template.properties.displayName
$contentKind = $template.properties.contentKind
$packageName = $template.properties.packageName
if (-not $packageName) { $packageName = "UnknownSolution" }

Write-Host "Seleccionado (Content Hub): '$displayName' | contentKind='$contentKind' | packageName='$packageName'"

# Guardarraíl opcional
Map-ExpectedTypeCheck -contentKind $contentKind -ExpectedType $ExpectedType

# 4) Determinar carpeta y paths
$targetFolder = Map-ContentKindToFolder -contentKind $contentKind
if ($targetFolder -eq "Unknown") { throw "No se pudo mapear contentKind '$contentKind' a carpeta de repo." }

$solutionSafe = Sanitize-Name $packageName
$fileSafe     = Sanitize-Name $displayName
$destDir  = Join-Path $RepoRoot (Join-Path $targetFolder $solutionSafe)
$destFile = Join-Path $destDir ("$fileSafe.json")
New-Item -ItemType Directory -Path $destDir -Force | Out-Null

# 5) Exportar el recurso REAL desplegado con resource types válidos
#    - Analytics rules: Microsoft.SecurityInsights/alertRules (scope workspace) [1](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/alertrules)
#    - Workbooks: Microsoft.Insights/workbooks [3](https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/workbooks)
#    - Hunting queries: savedSearches (ARM clásico) [5](https://github.com/Azure/Azure-Sentinel/blob/master/Tools/ARM-Templates/HuntingQuery/HuntingQuery.json)

$workspaceIdExpr = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]"

if ($contentKind -match "AnalyticsRule") {

  # Listar alertRules y hacer match exacto por properties.displayName
  $rulesUri = "$siBase/alertRules?api-version=$ApiVersion&`$top=500"
  $rules = Invoke-ArmRest -Method GET -Uri $rulesUri -Token $token
  $allRules = @()
  if ($rules.value) { $allRules = @($rules.value) }

  $rule = $allRules | Where-Object { $_.properties.displayName -and (Normalize-DisplayName $_.properties.displayName) -eq $requestedNorm } | Select-Object -First 1
  if (-not $rule) {
    Write-Host "No se encontró alertRule desplegada con displayName='$displayName'. Sugerencias (top 10):"
    $allRules | Where-Object { $_.properties.displayName } | Select-Object -First 10 -ExpandProperty properties | Select-Object displayName |
      Format-Table -AutoSize | Out-String | Write-Host
    throw "No existe la Analytics Rule desplegada (alertRules) con ese nombre. ¿Está instalada pero no creada/activada?"
  }

  # Construir recurso ARM deployable
  $res = @{
    type = "Microsoft.SecurityInsights/alertRules"
    apiVersion = $ApiVersion
    name = $rule.name
    scope = $workspaceIdExpr
    kind = $rule.kind
    properties = $rule.properties
  }

  $res = Remove-ReadOnlyFields $res

  $arm = New-ArmTemplate -Resources @($res) -Parameters @{
    workspaceName = @{ type = "string" }
  }

  $arm | ConvertTo-Json -Depth 200 | Out-File -FilePath $destFile -Encoding UTF8
  Write-Host "Export OK (deployable): $destFile"
}
elseif ($contentKind -match "Workbook") {

  # Workbooks están en RG: Microsoft.Insights/workbooks [3](https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/workbooks)
  $wbUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/workbooks?api-version=2023-06-01"
  $wbs = Invoke-ArmRest -Method GET -Uri $wbUri -Token $token
  $all = @()
  if ($wbs.value) { $all = @($wbs.value) }

  $wb = $all | Where-Object { $_.properties.displayName -and (Normalize-DisplayName $_.properties.displayName) -eq $requestedNorm } | Select-Object -First 1
  if (-not $wb) {
    Write-Host "No se encontró workbook desplegado con displayName='$displayName'. Sugerencias (top 10):"
    $all | Where-Object { $_.properties.displayName } | Select-Object -First 10 -ExpandProperty properties | Select-Object displayName |
      Format-Table -AutoSize | Out-String | Write-Host
    throw "No existe el Workbook desplegado con ese nombre en el RG '$ResourceGroupName'."
  }

  $res = @{
    type = "Microsoft.Insights/workbooks"
    apiVersion = "2023-06-01"
    name = $wb.name
    location = $wb.location
    kind = $wb.kind
    properties = $wb.properties
    tags = $wb.tags
  }

  $res = Remove-ReadOnlyFields $res

  $arm = New-ArmTemplate -Resources @($res)
  $arm | ConvertTo-Json -Depth 200 | Out-File -FilePath $destFile -Encoding UTF8
  Write-Host "Export OK (deployable): $destFile"
}
elseif ($contentKind -match "HuntingQuery") {

  # Hunting queries suelen ser savedSearches (Category = "Hunting Queries") [5](https://github.com/Azure/Azure-Sentinel/blob/master/Tools/ARM-Templates/HuntingQuery/HuntingQuery.json)
  $ssUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/savedSearches?api-version=2020-08-01"
  $ss = Invoke-ArmRest -Method GET -Uri $ssUri -Token $token
  $all = @()
  if ($ss.value) { $all = @($ss.value) }

  $match = $all | Where-Object {
    $_.properties.DisplayName -and (Normalize-DisplayName $_.properties.DisplayName) -eq $requestedNorm -and
    ($_.properties.Category -eq "Hunting Queries" -or $_.properties.Category -eq "Hunting queries" -or $_.properties.Category -eq "Hunting")
  } | Select-Object -First 1

  if (-not $match) {
    Write-Host "No se encontró savedSearch (Hunting Queries) con DisplayName='$displayName'. Sugerencias (top 10):"
    $all | Where-Object { $_.properties.DisplayName } | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{ DisplayName=$_.properties.DisplayName; Category=$_.properties.Category } } |
      Format-Table -AutoSize | Out-String | Write-Host
    throw "No existe el Hunting Query desplegado (savedSearches) con ese nombre."
  }

  $res = @{
    type = "Microsoft.OperationalInsights/workspaces/savedSearches"
    apiVersion = "2020-08-01"
    name = "$WorkspaceName/$($match.name)"
    properties = $match.properties
  }

  $res = Remove-ReadOnlyFields $res

  $arm = New-ArmTemplate -Resources @($res) -Parameters @{
    workspaceName = @{ type = "string"; defaultValue = $WorkspaceName }
  }

  $arm | ConvertTo-Json -Depth 200 | Out-File -FilePath $destFile -Encoding UTF8
  Write-Host "Export OK (deployable): $destFile"
}
elseif ($contentKind -match "Parser") {

  # Parsers (muchos se materializan como savedSearches/funciones). Intentamos Category="Parsers".
  $ssUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/savedSearches?api-version=2020-08-01"
  $ss = Invoke-ArmRest -Method GET -Uri $ssUri -Token $token
  $all = @()
  if ($ss.value) { $all = @($ss.value) }

  $match = $all | Where-Object {
    $_.properties.DisplayName -and (Normalize-DisplayName $_.properties.DisplayName) -eq $requestedNorm -and
    ($_.properties.Category -eq "Parsers" -or $_.properties.Category -eq "Parser" -or $_.properties.Category -eq "Functions")
  } | Select-Object -First 1

  if (-not $match) {
    Write-Host "No se encontró savedSearch (Parsers) con DisplayName='$displayName'. Sugerencias (top 10):"
    $all | Where-Object { $_.properties.DisplayName } | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{ DisplayName=$_.properties.DisplayName; Category=$_.properties.Category } } |
      Format-Table -AutoSize | Out-String | Write-Host
    throw "No existe el Parser desplegado como savedSearches con ese nombre en el workspace."
  }

  $res = @{
    type = "Microsoft.OperationalInsights/workspaces/savedSearches"
    apiVersion = "2020-08-01"
    name = "$WorkspaceName/$($match.name)"
    properties = $match.properties
  }

  $res = Remove-ReadOnlyFields $res

  $arm = New-ArmTemplate -Resources @($res) -Parameters @{
    workspaceName = @{ type = "string"; defaultValue = $WorkspaceName }
  }

  $arm | ConvertTo-Json -Depth 200 | Out-File -FilePath $destFile -Encoding UTF8
  Write-Host "Export OK (deployable): $destFile"
}
elseif ($contentKind -match "Playbook") {

  # Playbooks son Logic Apps: Microsoft.Logic/workflows
  $wfUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Logic/workflows?api-version=2019-05-01"
  $wfs = Invoke-ArmRest -Method GET -Uri $wfUri -Token $token
  $all = @()
  if ($wfs.value) { $all = @($wfs.value) }

  # Intentar match por name exacto (muchas veces el nombre del recurso coincide con el "playbook name" del portal)
  $wf = $all | Where-Object { $_.name -and $_.name.Trim().ToLowerInvariant() -eq $requestedNorm } | Select-Object -First 1
  if (-not $wf) {
    # fallback: si alguien creó con displayName diferente, mostramos sugerencias
    Write-Host "No se encontró workflow con name='$displayName'. Sugerencias (top 15 nombres de playbook en el RG):"
    $all | Select-Object -First 15 -ExpandProperty name | ForEach-Object { [pscustomobject]@{ workflowName=$_ } } |
      Format-Table -AutoSize | Out-String | Write-Host
    throw "No existe el Playbook (Logic workflow) con ese nombre EXACTO en el RG '$ResourceGroupName'."
  }

  $res = @{
    type = "Microsoft.Logic/workflows"
    apiVersion = "2019-05-01"
    name = $wf.name
    location = $wf.location
    identity = $wf.identity
    properties = $wf.properties
    tags = $wf.tags
  }

  $res = Remove-ReadOnlyFields $res
  $arm = New-ArmTemplate -Resources @($res)
  $arm | ConvertTo-Json -Depth 300 | Out-File -FilePath $destFile -Encoding UTF8
  Write-Host "Export OK (deployable): $destFile"
}
else {
  throw "contentKind '$contentKind' no soportado para export deployable."
}

Write-Host "Ruta final repo: $destFile"
Write-Host "Carpeta: $targetFolder | Solución: $packageName"

# Outputs para GitHub Actions
if ($env:GITHUB_OUTPUT) {
  "exported_path=$destFile" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
  "exported_folder=$targetFolder" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
  "exported_solution=$packageName" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
