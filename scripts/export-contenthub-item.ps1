<#
.SYNOPSIS
  Exporta un Content Item instalado desde Microsoft Sentinel Content Hub y lo vuelca al repo
  en la carpeta correcta según ContentType y Solution (packageName).

.DESCRIPTION
  - Lista/consulta contentTemplates (installed templates) y contentPackages (installed solutions) vía ARM REST.
  - Busca por displayName (ContentName).
  - Obtiene mainTemplate ($expand=properties/mainTemplate) del contentTemplate encontrado.
  - Normaliza la plantilla para repositorios:
      * Deja solo el/los resource(s) principales del tipo pedido
      * Fuerza resource type según mapping solicitado
      * Elimina recursos auxiliares (metadata, deployments anidados, etc.)
  - Guarda en:
      Analytics rules/<Solution>/<ContentName>.json
      Hunting/<Solution>/<ContentName>.json
      Parsers/<Solution>/<ContentName>.json
      Workbooks/<Solution>/<ContentName>.json
      Playbooks/<Solution>/<ContentName>.json
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ContentName,
  [Parameter(Mandatory=$true)]
  [ValidateSet("Analytics rule","Hunting query","Parser","Workbook","Playbook")]
  [string]$ContentType,

  [Parameter(Mandatory=$true)][string]$SubscriptionId,
  [Parameter(Mandatory=$true)][string]$ResourceGroupName,
  [Parameter(Mandatory=$true)][string]$WorkspaceName,

  [Parameter(Mandatory=$false)][string]$ApiVersion = "2025-09-01",
  [Parameter(Mandatory=$false)][switch]$Overwrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) { throw "Token ARM inválido. Revisa azure/login." }
  return $t
}

function Invoke-ArmGet {
  param([Parameter(Mandatory=$true)][string]$Uri)
  $headers = @{ Authorization = "Bearer $script:ArmToken" }
  Write-Host "GET $Uri"
  $resp = Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
  return $resp
}

function Sanitize-PathPart {
  param([Parameter(Mandatory=$true)][string]$Name)
  $invalid = [System.IO.Path]::GetInvalidFileNameChars() + [char[]]@('/','\')
  $out = $Name
  foreach ($c in $invalid) { $out = $out.Replace($c,'-') }
  $out = $out.Trim()
  if ([string]::IsNullOrWhiteSpace($out)) { $out = "Unknown" }
  return $out
}

function Get-FolderAndResourceType {
  param([string]$ContentType)
  switch ($ContentType) {
    "Analytics rule" { return @{ Folder="Analytics rules"; ResourceType="Microsoft.SecurityInsights/alertRules" } }
    "Hunting query"  { return @{ Folder="Hunting";        ResourceType="Microsoft.SecurityInsights/huntingQueries" } }
    "Parser"         { return @{ Folder="Parsers";        ResourceType="Microsoft.SecurityInsights/parsers" } }
    "Workbook"       { return @{ Folder="Workbooks";      ResourceType="Microsoft.Insights/workbooks" } }
    "Playbook"       { return @{ Folder="Playbooks";      ResourceType="Microsoft.Logic/workflows" } }
  }
  throw "ContentType no soportado: $ContentType"
}

function Select-MainResources {
  param(
    [Parameter(Mandatory=$true)]$TemplateObj,
    [Parameter(Mandatory=$true)][string]$WantedResourceType
  )

  if (-not $TemplateObj.resources) { throw "mainTemplate no contiene 'resources'." }

  $resources = @($TemplateObj.resources)

  # Quita auxiliares típicos
  $resources = $resources | Where-Object {
    $_.type -and
    ($_.type -notmatch "Microsoft\.SecurityInsights/metadata") -and
    ($_.type -notmatch "Microsoft\.Resources/deployments")
  }

  # Heurística: localizar el resource principal
  # A veces viene como workspaces/providers/<x> o como *Templates.
  $main = $resources | Where-Object {
    $_.type -eq $WantedResourceType -or
    $_.type -like "*/$($WantedResourceType.Split('/')[-1])" -or
    ($WantedResourceType -eq "Microsoft.SecurityInsights/alertRules" -and $_.type -match "AlertRule") -or
    ($WantedResourceType -eq "Microsoft.SecurityInsights/huntingQueries" -and $_.type -match "Hunting") -or
    ($WantedResourceType -eq "Microsoft.SecurityInsights/parsers" -and $_.type -match "Parser") -or
    ($WantedResourceType -eq "Microsoft.Insights/workbooks" -and $_.type -match "workbook") -or
    ($WantedResourceType -eq "Microsoft.Logic/workflows" -and $_.type -match "Microsoft\.Logic/workflows")
  }

  if (-not $main -or $main.Count -eq 0) {
    throw "No se encontró resource principal en mainTemplate para tipo solicitado: $WantedResourceType"
  }

  # si hay varios, intenta quedarte con el que tenga properties.displayName == ContentName
  $exact = $main | Where-Object { $_.properties -and $_.properties.displayName -and $_.properties.displayName -eq $script:ContentName }
  if ($exact -and $exact.Count -ge 1) { return @($exact) }

  return @($main | Select-Object -First 1)
}

function Normalize-TemplateForRepo {
  param(
    [Parameter(Mandatory=$true)]$ContentTemplate,    # objeto contentTemplate (REST)
    [Parameter(Mandatory=$true)]$MainTemplate,       # ContentTemplate.properties.mainTemplate
    [Parameter(Mandatory=$true)][string]$WantedResourceType
  )

  $contentId = $ContentTemplate.properties.contentId
  if (-not $contentId) { $contentId = $ContentTemplate.name }

  # Plantilla final “limpia” (repositorios)
  $out = [ordered]@{
    '$schema' = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
    contentVersion = "1.0.0.0"
    parameters = [ordered]@{
      workspace = [ordered]@{ type="string"; metadata=@{ description="Log Analytics Workspace name (Sentinel)" } }
      workspaceLocation = [ordered]@{ type="string"; metadata=@{ description="Workspace location" } }
    }
    resources = @()
  }

  $map = Get-FolderAndResourceType -ContentType $script:ContentType
  $scopeExpr = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]"

  $mainResources = Select-MainResources -TemplateObj $MainTemplate -WantedResourceType $WantedResourceType

  foreach ($r in $mainResources) {
    $nr = [ordered]@{}
    # apiVersion: intenta conservar el que venía en el mainTemplate
    if ($r.apiVersion) { $nr.apiVersion = $r.apiVersion } else { $nr.apiVersion = "2025-09-01" }

    $nr.type = $WantedResourceType

    if ($WantedResourceType -like "Microsoft.SecurityInsights/*") {
      $nr.scope = $scopeExpr
      # Nombre determinístico para evitar colisiones y que sea estable en repo
      $nr.name  = "[guid(parameters('workspace'), '$contentId')]"
      $nr.location = "[parameters('workspaceLocation')]"
    }
    elseif ($WantedResourceType -eq "Microsoft.Insights/workbooks") {
      # Workbooks van a nivel RG
      $nr.name = "[guid(resourceGroup().id, '$contentId')]"
      $nr.location = "[resourceGroup().location]"
    }
    elseif ($WantedResourceType -eq "Microsoft.Logic/workflows") {
      $nr.name = (Sanitize-PathPart $script:ContentName)
      $nr.location = "[resourceGroup().location]"
    }

    # Copia properties (lo importante)
    if ($r.kind) { $nr.kind = $r.kind }
    if ($r.properties) { $nr.properties = $r.properties } else { $nr.properties = @{} }

    # Asegurar displayName coherente si existe
    if ($nr.properties.displayName) { $nr.properties.displayName = $script:ContentName }

    $out.resources += $nr
  }

  return $out
}

# ---------------- MAIN ----------------

$script:ArmToken = Get-ArmToken

$mapping = Get-FolderAndResourceType -ContentType $ContentType
$wantedResourceType = $mapping.ResourceType

# 1) Buscar contentTemplate instalado por nombre (usa $search)
# REST: Content Templates - List (installed templates) [2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-templates/list?view=rest-securityinsights-2025-09-01)
$tplListUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersion&`$search=$([uri]::EscapeDataString($ContentName))&`$top=50"
$tplList = Invoke-ArmGet -Uri $tplListUri

$all = @()
if ($tplList.value) { $all += $tplList.value }

# Elige el match exacto por displayName
$match = $all | Where-Object { $_.properties -and $_.properties.displayName -and $_.properties.displayName -eq $ContentName } | Select-Object -First 1
if (-not $match) {
  # fallback: contiene
  $match = $all | Where-Object { $_.properties -and $_.properties.displayName -and $_.properties.displayName -like "*$ContentName*" } | Select-Object -First 1
}
if (-not $match) { throw "No se encontró contentTemplate instalado con displayName='$ContentName'." }

# 2) Obtener mainTemplate expandido del contentTemplate encontrado
# (List soporta $expand=properties/mainTemplate) [2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-templates/list?view=rest-securityinsights-2025-09-01)
$matchName = $match.name
$tplExpandUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$ApiVersion&`$filter=name%20eq%20'$matchName'&`$expand=properties/mainTemplate&`$top=1"
$tplExpanded = Invoke-ArmGet -Uri $tplExpandUri

$ct = $tplExpanded.value | Select-Object -First 1
if (-not $ct) { $ct = $match }

if (-not $ct.properties.mainTemplate) {
  throw "El contentTemplate no trae properties.mainTemplate. Reintenta con otra API version o revisa permisos."
}

# 3) Deducir solución (packageName) para carpeta
$solution = $ct.properties.packageName
if (-not $solution) { $solution = $ct.properties.source.name }
if (-not $solution) { $solution = "Unknown Solution" }

$solutionSafe = Sanitize-PathPart $solution
$fileSafe = Sanitize-PathPart $ContentName

# 4) Normalizar plantilla para repositorios y forzar resource type solicitado
$finalTemplate = Normalize-TemplateForRepo -ContentTemplate $ct -MainTemplate $ct.properties.mainTemplate -WantedResourceType $wantedResourceType

# 5) Ruta de salida
$outDir = Join-Path -Path (Get-Location) -ChildPath (Join-Path $mapping.Folder $solutionSafe)
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$outFile = Join-Path $outDir "$fileSafe.json"

if ((Test-Path $outFile) -and (-not $Overwrite)) {
  throw "El fichero ya existe y Overwrite=false: $outFile"
}

$finalTemplate | ConvertTo-Json -Depth 100 | Out-File -FilePath $outFile -Encoding utf8
Write-Host "OK -> $outFile"
Write-Host "   ContentType=$ContentType"
Write-Host "   Solution=$solution"
Write-Host "   ResourceType=$wantedResourceType"
