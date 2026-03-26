<#
.SYNOPSIS
Exporta una Analytics Rule instalada en Microsoft Sentinel desde Content Hub
y la guarda en el repositorio como ARM template compatible con Sentinel Repositories.

.DESCRIPTION
- Lista soluciones instaladas (contentPackages)
- Lista plantillas instaladas (contentTemplates)
- Lista alertRules instaladas
- Busca por displayName EXACTO
- Detecta la solución vía alertRuleTemplateName -> contentTemplate -> packageId
- Genera ARM con:
    type  = Microsoft.SecurityInsights/alertRules
    scope = workspace
- Guarda en:
    Analytics rules/<Solución>/<DisplayName>.json
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$ContentName,

  [string]$SubscriptionId    = $env:AZURE_SUBSCRIPTION_ID,
  [string]$ResourceGroupName = $env:RESOURCE_GROUP,
  [string]$WorkspaceName     = $env:WORKSPACE_NAME,
  [string]$ApiVersion        = "2025-09-01",
  [string]$RepoRoot          = (Resolve-Path ".").Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
function Get-ArmToken {
  $t = az account get-access-token `
    --resource https://management.azure.com/ `
    --query accessToken -o tsv

  if (-not $t -or $t.Length -lt 100) {
    throw "Token ARM inválido. Azure login no realizado."
  }
  return $t
}

function Fix-NextLink {
  param([string]$NextLink)

  $fixed = $NextLink

  if ($fixed -notmatch "api-version=") {
    $sep = ($fixed -match "\?") ? "&" : "?"
    $fixed = "$fixed${sep}api-version=$ApiVersion"
  }

  $fixed = $fixed -replace "\$SkipToken", "`$skipToken"
  return $fixed
}

function Invoke-Arm {
  param(
    [ValidateSet("GET","PUT")]
    [string]$Method,
    [string]$Uri,
    $Body = $null
  )

  $args = @(
    "rest",
    "--method",$Method,
    "--uri",$Uri,
    "--headers","Authorization=Bearer $script:ArmToken",
    "Content-Type=application/json"
  )

  if ($null -ne $Body) {
    $args += "--body"
    $args += ($Body | ConvertTo-Json -Depth 100 -Compress)
  }

  $raw = az @args 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw $raw
  }

  return ($raw | ConvertFrom-Json)
}

function Get-AllPages {
  param([string]$Uri)

  $items = @()
  $next = $Uri

  while ($next) {
    $resp = Invoke-Arm -Method GET -Uri $next
    if ($resp.value) { $items += $resp.value }
    if ($resp.nextLink) {
      $next = Fix-NextLink $resp.nextLink
    } else {
      $next = $null
    }
  }

  return $items
}

function Sanitize-FileName {
  param([string]$Name)
  $invalid = [IO.Path]::GetInvalidFileNameChars()
  ($Name.ToCharArray() | ForEach-Object {
    if ($invalid -contains $_) { "-" } else { $_ }
  }) -join ""
}

# ------------------------------------------------------------
# Validaciones
# ------------------------------------------------------------
if (-not $SubscriptionId)    { throw "Falta AZURE_SUBSCRIPTION_ID" }
if (-not $ResourceGroupName) { throw "Falta RESOURCE_GROUP" }
if (-not $WorkspaceName)     { throw "Falta WORKSPACE_NAME" }

$script:ArmToken = Get-ArmToken

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

Write-Host "== Content Hub: soluciones instaladas =="

# ------------------------------------------------------------
# 1. contentPackages (SIN $top)
# ------------------------------------------------------------
$packagesResp = Invoke-Arm `
  -Method GET `
  -Uri "$base/contentPackages?api-version=$ApiVersion"

$packages = @($packagesResp.value)

$packageIdToName = @{}
foreach ($p in $packages) {
  if ($p.name -and $p.properties.displayName) {
    $packageIdToName[$p.name] = $p.properties.displayName
  }
}

Write-Host "Soluciones instaladas: $($packageIdToName.Count)"

# ------------------------------------------------------------
# 2. contentTemplates (paginado)
# ------------------------------------------------------------
$templates = Get-AllPages `
  -Uri "$base/contentTemplates?api-version=$ApiVersion"

$templatesById = @{}
foreach ($t in $templates) {
  $templatesById[$t.name] = $t
}

Write-Host "Plantillas instaladas: $($templates.Count)"

# ------------------------------------------------------------
# 3. alertRules (paginado)
# ------------------------------------------------------------
$rules = Get-AllPages `
  -Uri "$base/alertRules?api-version=$ApiVersion"

$rule = $rules | Where-Object {
  $_.properties.displayName -and
  $_.properties.displayName.ToLower() -eq $ContentName.ToLower()
} | Select-Object -First 1

if (-not $rule) {
  throw "No se encontró Analytics Rule con displayName EXACTO: '$ContentName'"
}

Write-Host "Rule encontrada: $($rule.properties.displayName)"

# ------------------------------------------------------------
# 4. Detectar solución
# ------------------------------------------------------------
$solutionName = "Unknown"

$templateId = $rule.properties.alertRuleTemplateName
if ($templateId -and $templatesById.ContainsKey($templateId)) {
  $tpl = $templatesById[$templateId]
  $pkgId = $tpl.properties.packageId
  if ($pkgId -and $packageIdToName.ContainsKey($pkgId)) {
    $solutionName = $packageIdToName[$pkgId]
  }
}

Write-Host "Solución detectada: $solutionName"

# ------------------------------------------------------------
# 5. ARM template
# ------------------------------------------------------------
$props = $rule.properties | ConvertTo-Json -Depth 100 | ConvertFrom-Json

foreach ($ro in @("createdTimeUtc","lastModifiedUtc","createdBy","lastModifiedBy")) {
  if ($props.PSObject.Properties.Name -contains $ro) {
    $props.PSObject.Properties.Remove($ro)
  }
}

$arm = @{
  '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
  contentVersion = '1.0.0.0'
  parameters = @{
    workspace = @{ type = 'string' }
  }
  resources = @(
    @{
      type = 'Microsoft.SecurityInsights/alertRules'
      apiVersion = $ApiVersion
      name = $rule.name
      kind = $rule.kind
      scope = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]"
      properties = $props
    }
  )
}

# ------------------------------------------------------------
# 6. Guardar en repo
# ------------------------------------------------------------
$targetDir = Join-Path $RepoRoot "Analytics rules/$solutionName"
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

$fileName = (Sanitize-FileName $rule.properties.displayName) + ".json"
$targetPath = Join-Path $targetDir $fileName

[System.IO.File]::WriteAllText(
  $targetPath,
  ($arm | ConvertTo-Json -Depth 100),
  (New-Object System.Text.UTF8Encoding($false))
)

Write-Host "✅ Export completado:"
Write-Host $targetPath

if ($env:GITHUB_OUTPUT) {
  "solution_name=$solutionName" | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
  "output_path=$targetPath"     | Out-File $env:GITHUB_OUTPUT -Append -Encoding utf8
}
