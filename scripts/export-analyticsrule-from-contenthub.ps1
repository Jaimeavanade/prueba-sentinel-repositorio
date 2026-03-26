<#
.SYNOPSIS
Exporta una Analytics Rule instalada en Microsoft Sentinel (alertRules) por Display Name,
detecta la solución de Content Hub a la que pertenece y la guarda como ARM template
compatible con Sentinel Repositories.

.DESCRIPTION
- Lista soluciones instaladas (contentPackages)  [SIN $top - evita BadRequest OData]
- Lista plantillas instaladas (contentTemplates) con paginación robusta
- Lista alertRules instaladas con paginación robusta
- Busca la alertRule por properties.displayName EXACTO (case-insensitive)
- Detecta la solución: alertRuleTemplateName -> contentTemplates[templateId].properties.packageId -> contentPackages[packageId].properties.displayName
- Genera un ARM template con:
    resources[0].type = Microsoft.SecurityInsights/alertRules
    resources[0].scope = workspace
- Guarda en:
    Analytics rules/<Nombre Solución>/<DisplayName>.json

REQUISITOS
- azure/login (OIDC) ya ejecutado en el job
- Secrets: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID
- Variables: RESOURCE_GROUP, WORKSPACE_NAME

.NOTES
- API version por defecto: 2025-09-01
- nextLink puede venir sin api-version o con $SkipToken: se corrige (patrón ya usado en scripts internos). [1](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={de506d0d-e4ee-4270-8873-e1ea6b67e29b}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ContentName,

  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId    = $env:AZURE_SUBSCRIPTION_ID,

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName = $env:RESOURCE_GROUP,

  [Parameter(Mandatory = $false)]
  [string]$WorkspaceName     = $env:WORKSPACE_NAME,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion        = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string]$RepoRoot          = (Resolve-Path ".").Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegúrate de haber ejecutado azure/login (OIDC) antes."
  }
  return $t
}

function Fix-NextLink {
  param(
    [Parameter(Mandatory=$true)][string]$NextLink,
    [Parameter(Mandatory=$true)][string]$ApiVersion
  )

  $fixed = $NextLink

  # Añadir api-version si viene ausente
  if ($fixed -notmatch "api-version=") {
    $sep = ($fixed -match "\?") ? "&" : "?"
    $fixed = "$fixed${sep}api-version=$ApiVersion"
  }

  # Normalizar $SkipToken -> $skipToken si aparece
  $fixed = $fixed -replace "\$SkipToken", "`$skipToken"
  return $fixed
}

function Invoke-Arm {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","DELETE")]
    [string]$Method,

    [Parameter(Mandatory=$true)]
    [string]$Uri,

    [Parameter(Mandatory=$false)]
    $Body = $null
  )

  $max = 6
  $delay = 2
  for ($i=1; $i -le $max; $i++) {
    try {
      $args = @(
        "rest",
        "--method",$Method,
        "--uri",$Uri,
        "--headers","Authorization=Bearer $script:ArmToken","Content-Type=application/json"
      )

      if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Depth 100 -Compress
        $args += @("--body",$json)
      }

      $raw = az @args 2>&1
      if ($LASTEXITCODE -ne 0) { throw $raw }

      return ($raw | ConvertFrom-Json)
    }
    catch {
      if ($i -eq $max) { throw }
      Write-Host "WARN: Error en llamada REST (intento $i/$max). Reintentando en $delay s. Detalle: $($_.Exception.Message)"
      Start-Sleep -Seconds $delay
      $delay = [Math]::Min($delay*2, 20)
    }
  }
}

function Get-AllPages {
  param(
    [Parameter(Mandatory=$true)][string]$Uri,
    [Parameter(Mandatory=$true)][string]$ApiVersion
  )

  $items = @()
  $next = $Uri

  while ($next) {
    $resp = Invoke-Arm -Method GET -Uri $next
    if ($resp.value) { $items += @($resp.value) }

    if ($resp.nextLink) {
      $next = Fix-NextLink -NextLink $resp.nextLink -ApiVersion $ApiVersion
    } else {
      $next = $null
    }
  }

  return $items
}

function Sanitize-FileName {
  param([Parameter(Mandatory=$true)][string]$Name)
  $invalid = [IO.Path]::GetInvalidFileNameChars()
  $sb = New-Object System.Text.StringBuilder
  foreach ($ch in $Name.ToCharArray()) {
    if ($invalid -contains $ch) { [void]$sb.Append("-") }
    else { [void]$sb.Append($ch) }
  }
  $out = $sb.ToString().Trim()
  if ([string]::IsNullOrWhiteSpace($out)) { $out = "Unnamed-Rule" }
  return $out
}

# ------------------------------------------------------------
# Validaciones
# ------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($SubscriptionId))    { throw "Falta AZURE_SUBSCRIPTION_ID (env o input)." }
if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) { throw "Falta RESOURCE_GROUP (vars)." }
if ([string]::IsNullOrWhiteSpace($WorkspaceName))     { throw "Falta WORKSPACE_NAME (vars)." }

$script:ArmToken = Get-ArmToken

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

Write-Host "== Inventario Content Hub (instalado) =="

# ------------------------------------------------------------
# 1) contentPackages (soluciones instaladas)
#    IMPORTANTE: NO usar $top aquí para evitar errores OData en algunos tenants/APIs
# ------------------------------------------------------------
$packagesResp = Invoke-Arm -Method GET -Uri "$base/contentPackages?api-version=$ApiVersion"
$packages = @($packagesResp.value)

$packageIdToName = @{}
foreach ($p in $packages) {
  if ($p.name -and $p.properties.displayName) {
    $packageIdToName[$p.name] = $p.properties.displayName
  }
}

Write-Host ("Soluciones instaladas: {0}" -f $packageIdToName.Count)

# ------------------------------------------------------------
# 2) contentTemplates (plantillas instaladas)
# ------------------------------------------------------------
$templates = Get-AllPages -Uri "$base/contentTemplates?api-version=$ApiVersion" -ApiVersion $ApiVersion
$tplById = @{}
foreach ($t in $templates) {
  if ($t.name) { $tplById[$t.name] = $t }
}
Write-Host ("Plantillas instaladas: {0}" -f $templates.Count)

# ------------------------------------------------------------
# 3) alertRules (reglas activas instaladas)
# ------------------------------------------------------------
$rules = Get-AllPages -Uri "$base/alertRules?api-version=$ApiVersion" -ApiVersion $ApiVersion
Write-Host ("AlertRules instaladas: {0}" -f $rules.Count)

$matchesExact = $rules | Where-Object {
  $_.properties.displayName -and
  ($_.properties.displayName).ToLowerInvariant() -eq $ContentName.ToLowerInvariant()
}

if (-not $matchesExact -or $matchesExact.Count -eq 0) {
  $matchesContains = $rules | Where-Object {
    $_.properties.displayName -and
    ($_.properties.displayName).ToLowerInvariant().Contains($ContentName.ToLowerInvariant())
  } | Select-Object -First 10

  Write-Host "ERROR: No se encontró ninguna alertRule instalada con displayName EXACTO: '$ContentName'"
  if ($matchesContains.Count -gt 0) {
    Write-Host "Sugerencias (hasta 10) por coincidencia parcial:"
    $matchesContains | ForEach-Object { Write-Host (" - " + $_.properties.displayName) }
  }
  throw "No encontrada la Analytics Rule por displayName exacto."
}

$rule = $matchesExact | Select-Object -First 1

# ------------------------------------------------------------
# 4) Detectar solución Content Hub
# ------------------------------------------------------------
$templateId = $rule.properties.alertRuleTemplateName
$solutionName = "Unknown"
$contentKind  = "AnalyticsRule"

if ($templateId -and $tplById.ContainsKey($templateId)) {
  $tpl = $tplById[$templateId]
  if ($tpl.properties.contentKind) { $contentKind = [string]$tpl.properties.contentKind }

  $pkgId = $tpl.properties.packageId
  if ($pkgId -and $packageIdToName.ContainsKey($pkgId)) {
    $solutionName = $packageIdToName[$pkgId]
  } elseif ($pkgId) {
    $solutionName = [string]$pkgId
  }
}

Write-Host ("Encontrada rule: {0} | kind={1} | templateId={2} | solución={3}" -f $rule.properties.displayName, $rule.kind, $templateId, $solutionName)

# ------------------------------------------------------------
# 5) Construir ARM template con Microsoft.SecurityInsights/alertRules
# ------------------------------------------------------------
$props = $rule.properties | ConvertTo-Json -Depth 100 | ConvertFrom-Json

# Quitar campos típicamente read-only si apareciesen
foreach ($ro in @("lastModifiedUtc","createdTimeUtc","modifiedTimeUtc","createdBy","lastModifiedBy")) {
  if ($props.PSObject.Properties.Name -contains $ro) {
    $props.PSObject.Properties.Remove($ro)
  }
}

$arm = [ordered]@{
  '$schema'      = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
  contentVersion = '1.0.0.0'
  parameters     = [ordered]@{
    workspace = [ordered]@{
      type     = 'string'
      metadata = @{ description = 'Log Analytics workspace name' }
    }
  }
  resources      = @(
    [ordered]@{
      type       = 'Microsoft.SecurityInsights/alertRules'
      apiVersion = $ApiVersion
      name       = [string]$rule.name
      kind       = [string]$rule.kind
      scope      = "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]"
      properties = $props
    }
  )
}

# ------------------------------------------------------------
# 6) Guardar en repo (ruta requerida)
# ------------------------------------------------------------
$targetDir = Join-Path $RepoRoot ("Analytics rules/{0}" -f $solutionName)
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

$fileName = (Sanitize-FileName -Name $rule.properties.displayName) + ".json"
$targetPath = Join-Path $targetDir $fileName

# Guardar UTF-8 sin BOM
$armJson = $arm | ConvertTo-Json -Depth 100
[System.IO.File]::WriteAllText($targetPath, $armJson, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "OK: Export guardado en: $targetPath"

# Outputs para GitHub Actions
if ($env:GITHUB_OUTPUT) {
  "solution_name=$solutionName" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
  "content_kind=$contentKind"   | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
  "output_path=$targetPath"     | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
