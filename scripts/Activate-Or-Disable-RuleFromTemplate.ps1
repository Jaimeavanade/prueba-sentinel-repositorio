<#
.SYNOPSIS
Activa (crea desde template) o deshabilita una regla de Analíticas en Microsoft Sentinel usando el Display Name.

.DESCRIPTION
- action=enable: busca Rule template (Analytics > Rule templates) por displayName y crea la regla (Scheduled) habilitada.
- action=disable: busca regla existente (Analytics > Active rules) por displayName y la marca enabled=false.
- action=list: lista Rule templates instaladas (opcionalmente filtrando por texto).

NOTAS
- Nombre recomendado:
  Azure Portal > Microsoft Sentinel > Analytics > Rule templates > Name
- Si no encuentra coincidencia exacta, sugiere candidatos.

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $SubscriptionId,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $ResourceGroupName,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string] $WorkspaceName,

  [Parameter(Mandatory=$true)]
  [ValidateSet("enable","disable","list")]
  [string] $Action,

  [Parameter(Mandatory=$false)]
  [string] $RuleName = "",

  [Parameter(Mandatory=$false)]
  [string] $Search = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ----------------------------
# Helpers
# ----------------------------
function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido o vacío. Revisa que azure/login (OIDC) se haya ejecutado y permisos del SP."
  }
  return $t
}

function Get-ErrorBodyFromException {
  param([Parameter(Mandatory=$true)] $Exception)

  try {
    if ($Exception.Response -and $Exception.Response.GetResponseStream) {
      $reader = New-Object System.IO.StreamReader($Exception.Response.GetResponseStream())
      $body = $reader.ReadToEnd()
      if ($body) { return $body }
    }
  } catch { }
  return $null
}

function Invoke-ArmRest {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","PATCH","DELETE")] [string] $Method,
    [Parameter(Mandatory=$true)] [string] $Uri,
    [Parameter(Mandatory=$false)] [object] $Body
  )

  if (-not $script:ArmToken) {
    $script:ArmToken = Get-ArmToken
  }

  $headers = @{
    Authorization = "Bearer $script:ArmToken"
    "Content-Type" = "application/json"
  }

  try {
    if ($null -ne $Body) {
      $json = $Body | ConvertTo-Json -Depth 80
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
    } else {
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
  }
  catch {
    $bodyText = Get-ErrorBodyFromException -Exception $_.Exception
    if ($bodyText) {
      throw "Fallo REST ($Method). Uri=$Uri. Body=$bodyText"
    }
    throw
  }
}

function Normalize-Text([string]$s) {
  if ($null -eq $s) { return "" }
  return ($s.Trim() -replace "\s+", " ")
}

function Find-TemplateByName {
  param(
    [Parameter(Mandatory=$true)] [object[]] $Templates,
    [Parameter(Mandatory=$true)] [string] $Name
  )

  $needleRaw = $Name
  $needle = Normalize-Text $Name

  # 1) Exacto (case-sensitive)
  $m = $Templates | Where-Object { $_.properties.displayName -eq $needleRaw } | Select-Object -First 1
  if ($m) { return @{ match=$m; mode="exact(case-sensitive)" } }

  # 2) Exacto normalizado (case-insensitive)
  $m = $Templates | Where-Object { (Normalize-Text $_.properties.displayName).ToLower() -eq $needle.ToLower() } | Select-Object -First 1
  if ($m) { return @{ match=$m; mode="exact(normalized, case-insensitive)" } }

  # 3) Contains (case-insensitive)
  $m = $Templates | Where-Object { (Normalize-Text $_.properties.displayName).ToLower().Contains($needle.ToLower()) } | Select-Object -First 1
  if ($m) { return @{ match=$m; mode="contains(case-insensitive)" } }

  return @{ match=$null; mode="not-found" }
}

function Print-Candidates {
  param(
    [Parameter(Mandatory=$true)] [object[]] $Templates,
    [Parameter(Mandatory=$true)] [string] $Name,
    [int] $Top = 30
  )

  $needle = (Normalize-Text $Name).ToLower()

  $cands = $Templates |
    ForEach-Object {
      $dn = Normalize-Text $_.properties.displayName
      [pscustomobject]@{
        displayName = $dn
        kind        = $_.kind
        severity    = $_.properties.severity
        score       = if ($dn.ToLower().Contains($needle)) { 2 }
                      elseif ($needle.Length -gt 0 -and $dn.ToLower().Contains(($needle.Split(" ")[0]))) { 1 }
                      else { 0 }
      }
    } |
    Where-Object { $_.score -gt 0 } |
    # ✅ FIX: Sort-Object correcto con múltiples propiedades y desc sólo en score
    Sort-Object -Property @{Expression='score';Descending=$true}, @{Expression='displayName';Descending=$false} |
    Select-Object -First $Top

  if (-not $cands -or $cands.Count -eq 0) {
    Write-Host "No hay candidatos por contains. Usa Action=list para listar todas las plantillas."
    return
  }

  Write-Host ""
  Write-Host "=== CANDIDATOS (copiar/pegar displayName) ==="
  $i = 0
  foreach ($c in $cands) {
    $i++
    Write-Host ("{0}. {1} | kind={2} | severity={3}" -f $i, $c.displayName, $c.kind, $c.severity)
  }
  Write-Host "==========================================="
}

# ----------------------------
# Config
# ----------------------------
$ApiVersion_Templates = "2023-11-01"
$ApiVersion_Rules     = "2023-11-01"

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

Write-Host "==> Acción: $Action"
Write-Host "==> RuleName (DisplayName): $RuleName"
Write-Host "==> Workspace: $WorkspaceName | RG: $ResourceGroupName | Sub: $SubscriptionId"

# Token ARM (fail fast)
$script:ArmToken = Get-ArmToken

# ----------------------------
# 0) List templates
# ----------------------------
if ($Action -eq "list") {
  $templatesUri = "${base}/alertRuleTemplates?api-version=$ApiVersion_Templates"
  $templates = Invoke-ArmRest -Method GET -Uri $templatesUri

  $all = @($templates.value)
  Write-Host "Total Rule templates instaladas: $($all.Count)"

  if (-not [string]::IsNullOrWhiteSpace($Search)) {
    $s = (Normalize-Text $Search).ToLower()
    $all = $all | Where-Object { (Normalize-Text $_.properties.displayName).ToLower().Contains($s) }
    Write-Host "Filtradas por Search='$Search': $($all.Count)"
  }

  Write-Host ""
  $all |
    Sort-Object -Property @{Expression={ Normalize-Text $_.properties.displayName }; Descending=$false } |
    ForEach-Object {
      $dn = Normalize-Text $_.properties.displayName
      $sev = $_.properties.severity
      Write-Host ("- {0} | severity={1}" -f $dn, $sev)
    }

  exit 0
}

# ----------------------------
# 1) Enable from template
# ----------------------------
if ($Action -eq "enable") {

  if ([string]::IsNullOrWhiteSpace($RuleName)) {
    throw "RuleName es obligatorio para Action=enable."
  }

  $templatesUri = "${base}/alertRuleTemplates?api-version=$ApiVersion_Templates"
  $templates = Invoke-ArmRest -Method GET -Uri $templatesUri
  $tplList = @($templates.value)

  $found = Find-TemplateByName -Templates $tplList -Name $RuleName
  $match = $found.match

  if (-not $match) {
    Write-Host "No se encontró Rule template por nombre exacto/normalizado/contains."
    Print-Candidates -Templates $tplList -Name $RuleName -Top 30
    throw "No se encontró ningún Rule template con displayName compatible con '$RuleName'. Revisa que la solución esté instalada o usa Action=list."
  }

  Write-Host "✅ Template encontrado (modo: $($found.mode))"
  $templateId = $match.name
  Write-Host "Encontrado templateId: $templateId"

  $newRuleGuid = (New-Guid).Guid
  $createRuleUri = "${base}/alertRules/${newRuleGuid}?api-version=$ApiVersion_Rules"

  $p = $match.properties

  $ruleProps = @{
    displayName         = $p.displayName
    description         = $p.description
    severity            = $p.severity
    enabled             = $true
    query               = $p.query
    queryFrequency      = $p.queryFrequency
    queryPeriod         = $p.queryPeriod
    triggerOperator     = $p.triggerOperator
    triggerThreshold    = $p.triggerThreshold
    suppressionDuration = $p.suppressionDuration
    suppressionEnabled  = $p.suppressionEnabled
    tactics             = $p.tactics
    techniques          = $p.techniques
  }

  $body = @{
    kind       = "Scheduled"
    properties = $ruleProps
  }

  Write-Host "Creando regla Scheduled desde template..."
  $created = Invoke-ArmRest -Method PUT -Uri $createRuleUri -Body $body

  Write-Host "✅ Regla creada/activada: $($created.properties.displayName) (id: $newRuleGuid)"
  exit 0
}

# ----------------------------
# 2) Disable existing rule
# ----------------------------
if ($Action -eq "disable") {

  if ([string]::IsNullOrWhiteSpace($RuleName)) {
    throw "RuleName es obligatorio para Action=disable."
  }

  $rulesUri = "${base}/alertRules?api-version=$ApiVersion_Rules"
  $rules = Invoke-ArmRest -Method GET -Uri $rulesUri
  $ruleList = @($rules.value)

  $needle = (Normalize-Text $RuleName).ToLower()
  $rule = $ruleList | Where-Object { (Normalize-Text $_.properties.displayName).ToLower() -eq $needle } | Select-Object -First 1

  if (-not $rule) {
    $rule = $ruleList | Where-Object { (Normalize-Text $_.properties.displayName).ToLower().Contains($needle) } | Select-Object -First 1
  }

  if (-not $rule) {
    throw "No se encontró ninguna regla activa con displayName='$RuleName'. Revisa Analytics > Active rules."
  }

  $ruleId = $rule.name
  Write-Host "Encontrada reglaId: $ruleId. Marcando enabled=false..."

  $patchUri = "${base}/alertRules/${ruleId}?api-version=$ApiVersion_Rules"
  $patchBody = @{
    properties = @{
      enabled = $false
    }
  }

  $updated = Invoke-ArmRest -Method PATCH -Uri $patchUri -Body $patchBody
  Write-Host "✅ Regla deshabilitada: $($updated.properties.displayName)"
  exit 0
}

throw "Action no soportada: $Action"
