<#
.SYNOPSIS
  Exporta una Analytics Rule instalada (Microsoft Sentinel) por Display Name, detecta la solución de Content Hub y la guarda en el repo
  como ARM template con recurso type Microsoft.SecurityInsights/alertRules y scope al workspace.

.DESCRIPTION
  1) Lista soluciones instaladas (contentPackages) y plantillas instaladas (contentTemplates)
  2) Busca la alertRule instalada (alertRules) cuyo properties.displayName coincide con -ContentName
  3) Determina la solución: alertRuleTemplateName -> contentTemplates[templateId].properties.packageId -> contentPackages[packageId].properties.displayName
  4) Genera ARM template siguiendo el esquema base (deploymentTemplate.json) pero con recurso:
        type: Microsoft.SecurityInsights/alertRules
        scope: [resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]
  5) Guarda en: Analytics rules/<Solución>/<ContentName>.json

.NOTES
  - Requiere que el job haya hecho azure/login (OIDC) para que "az account get-access-token" funcione.
  - API version usada: 2025-09-01 (Sentinel REST)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ContentName,

  [Parameter(Mandatory = $false)]
  [string]$SubscriptionId = $env:AZURE_SUBSCRIPTION_ID,

  [Parameter(Mandatory = $false)]
  [string]$ResourceGroupName = $env:RESOURCE_GROUP,

  [Parameter(Mandatory = $false)]
  [string]$WorkspaceName = $env:WORKSPACE_NAME,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01",

  [Parameter(Mandatory = $false)]
  [string]$RepoRoot = (Resolve-Path ".").Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegúrate de haber ejecutado azure/login (OIDC) antes."
  }
  return $t
}

function Fix-NextLink {
  param([Parameter(Mandatory=$true)][string]$NextLink, [Parameter(Mandatory=$true)][string]$ApiVersion)

  $fixed = $NextLink

  # Algunos nextLink vienen sin api-version
  if ($fixed -notmatch "api-version=") {
    $sep = ($fixed -match "\?") ? "&" : "?"
    $fixed = "$fixed${sep}api-version=$ApiVersion"
  }

  # Normaliza $SkipToken -> $skipToken si aparece
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
      $args = @("rest","--method",$Method,"--uri",$Uri,"--headers","Authorization=Bearer $script:ArmToken","Content-Type=application/json")
      if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Depth 100 -Compress
        $args += @("--body",$json)
      }
      $raw = az @args 2>&1
      if ($LASTEXITCODE -ne 0) { throw $raw }

      # az rest devuelve JSON ya, pero como string. Convertimos.
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
  param([Parameter(Mandatory=$true)][string]$Uri)

  $items = @()
  $next = $Uri

  while ($next) {
    $resp = Invoke-Arm -Method GET -Uri $next
    if ($resp.value) {
      $items += @($resp.value)
    }
    if ($resp.nextLink) {
      $next = Fix-NextLink -NextLink $resp.nextLink -ApiVersion $script:ApiVersion
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
  # Evita nombres vacíos o espacios finales
  $out = $sb.ToString().Trim()
  if ([string]::IsNullOrWhiteSpace($out)) { $out = "Unnamed-Rule" }
  return $out
}

# Validación básica de inputs
if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { throw "Falta SubscriptionId (AZURE_SUBSCRIPTION_ID)." }
if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) { throw "Falta ResourceGroupName (RESOURCE_GROUP)." }
if ([string]::IsNullOrWhiteSpace($WorkspaceName)) { throw "Falta WorkspaceName (WORKSPACE_NAME)." }

$script:ApiVersion = $ApiVersion
$script:ArmToken = Get-ArmToken

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

Write-Host "== Inventario Content Hub (instalado) =="
# 1) Soluciones instaladas (contentPackages)
$packagesUri = "$base/contentPackages?api-version=$ApiVersion&`$top=500"
$packages = Get-AllPages -Uri $packagesUri

# Mapa packageId -> displayName
$packageIdToName = @{}
foreach ($p in $packages) {
  if ($p.name -and $p.properties.displayName) {
    $packageIdToName[$p.name] = $p.properties.displayName
  }
}

$solutions = $packages | Where-Object { $_.properties.contentKind -eq "Solution" -or $_.properties.packageKind -eq "Solution" }
Write-Host ("Soluciones instaladas (estimado): {0}" -f ($solutions.Count))

# 2) Plantillas instaladas (contentTemplates)
$tplUri = "$base/contentTemplates?api-version=$ApiVersion&`$top=500"
$templates = Get-AllPages -Uri $tplUri

# Mapa templateId -> template
$tplById = @{}
foreach ($t in $templates) {
  if ($t.name) { $tplById[$t.name] = $t }
}

# Resumen de plantillas por solución (solo informativo)
$tplGrouped = $templates | Group-Object { $_.properties.packageId }
Write-Host ("Plantillas instaladas total: {0}" -f $templates.Count)
Write-Host "Top 10 soluciones por nº de plantillas instaladas:"
$tplGrouped |
  Sort-Object Count -Descending |
  Select-Object -First 10 |
  ForEach-Object {
    $pid = $_.Name
    $solName = $packageIdToName.ContainsKey($pid) ? $packageIdToName[$pid] : $pid
    Write-Host (" - {0} => {1}" -f $solName, $_.Count)
  }

Write-Host ""
Write-Host "== Buscar Analytics Rule instalada por DisplayName =="

# 3) Alert Rules instaladas (alertRules)
$rulesUri = "$base/alertRules?api-version=$ApiVersion&`$top=500"
$rules = Get-AllPages -Uri $rulesUri

# Match exacto (case-insensitive)
$matchesExact = $rules | Where-Object { $_.properties.displayName -and ($_.properties.displayName).ToLowerInvariant() -eq $ContentName.ToLowerInvariant() }

if (-not $matchesExact -or $matchesExact.Count -eq 0) {
  # Fallback: contiene (para ayudar a diagnosticar)
  $matchesContains = $rules | Where-Object { $_.properties.displayName -and ($_.properties.displayName).ToLowerInvariant().Contains($ContentName.ToLowerInvariant()) }
  $top = $matchesContains | Select-Object -First 10

  Write-Host "ERROR: No se encontró ninguna alertRule instalada con displayName EXACTO: '$ContentName'"
  if ($top.Count -gt 0) {
    Write-Host "Sugerencias (hasta 10) por coincidencia parcial:"
    $top | ForEach-Object { Write-Host (" - " + $_.properties.displayName) }
  } else {
    Write-Host "No hay coincidencias parciales tampoco."
  }
  throw "No encontrada la Analytics Rule por displayName exacto."
}

# Si hay varias iguales, cogemos la primera (raro, pero posible)
$rule = $matchesExact | Select-Object -First 1

# Determinar contentKind/solución
$templateId = $rule.properties.alertRuleTemplateName
$solutionName = "Unknown"
$contentKind = "AnalyticsRule"

$tpl = $null
if ($templateId -and $tplById.ContainsKey($templateId)) {
  $tpl = $tplById[$templateId]
  if ($tpl.properties.contentKind) { $contentKind = [string]$tpl.properties.contentKind }

  $pkgId = $tpl.properties.packageId
  if ($pkgId -and $packageIdToName.ContainsKey($pkgId)) {
    $solutionName = $packageIdToName[$pkgId]
  } elseif ($pkgId) {
    $solutionName = [string]$pkgId
  }
} else {
  # Si no hay templateName (custom rule), dejamos Unknown
  $solutionName = "Unknown"
}

Write-Host ("Encontrada rule: {0} | kind={1} | templateId={2} | solución={3}" -f $rule.properties.displayName, $rule.kind, $templateId, $solutionName)

# 4) Preparar carpeta destino
if ($contentKind -ne "AnalyticsRule" -and $contentKind -ne "AnalyticsRuleTemplate") {
  Write-Host "WARN: contentKind detectado '$contentKind'. Aun así, se exportará como alertRule."
}

$targetDir = Join-Path $RepoRoot ("Analytics rules/{0}" -f $solutionName)
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

$fileName = (Sanitize-FileName -Name $rule.properties.displayName) + ".json"
$targetPath = Join-Path $targetDir $fileName

# 5) Construir ARM template con recurso Microsoft.SecurityInsights/alertRules
# Limpieza de propiedades (evitar campos de solo lectura si aparecen)
$props = $rule.properties | ConvertTo-Json -Depth 100 | ConvertFrom-Json
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

# Guardar UTF-8 (sin BOM)
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
