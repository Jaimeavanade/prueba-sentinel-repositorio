<#
.SYNOPSIS
  Crea o habilita una Analytics Rule de Microsoft Sentinel a partir de un template (Content Hub) usando su displayName.

.DESCRIPTION
  - Lista alertRuleTemplates del workspace (templates instalados).
  - Busca un template por displayName con matching tolerante (normalización + contains + sugerencias).
  - Si ya existe una alertRule con ese displayName y kind:
      * Enable  -> la habilita (enabled=true)
      * Skip    -> no hace nada
      * Replace -> la reemplaza usando el template como base y la habilita
  - Si no existe, crea una nueva alertRule (Scheduled o NRT) copiando propiedades del template y activándola.

  NotFoundBehavior:
    - WarnAndExit0 (default): NO falla el job; imprime sugerencias y sale 0.
    - Fail: falla el job (throw).
    - WarnOnly: imprime sugerencias y sale 0.

  Auth:
    - Requiere azure/login (OIDC) o az login previo.
    - El script obtiene token ARM con Azure CLI: az account get-access-token --resource https://management.azure.com/

.PARAMETER SubscriptionId
.PARAMETER ResourceGroupName
.PARAMETER WorkspaceName
.PARAMETER DisplayName
.PARAMETER IfExists
  Enable | Skip | Replace
.PARAMETER NotFoundBehavior
  WarnAndExit0 | Fail | WarnOnly
.PARAMETER ApiVersion
  Por defecto 2025-09-01
.PARAMETER Suggestions
  Número de sugerencias a mostrar si no hay match (default 15).
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory = $true)]
  [string]$SubscriptionId,

  [Parameter(Mandatory = $true)]
  [string]$ResourceGroupName,

  [Parameter(Mandatory = $true)]
  [string]$WorkspaceName,

  [Parameter(Mandatory = $true)]
  [string]$DisplayName,

  [Parameter(Mandatory = $false)]
  [ValidateSet("Enable","Skip","Replace")]
  [string]$IfExists = "Enable",

  [Parameter(Mandatory = $false)]
  [ValidateSet("WarnAndExit0","Fail","WarnOnly")]
  [string]$NotFoundBehavior = "WarnAndExit0",

  [Parameter(Mandatory = $false)]
  [int]$Suggestions = 15,

  [Parameter(Mandatory = $false)]
  [string]$ApiVersion = "2025-09-01"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Has-Prop {
  param(
    [Parameter(Mandatory=$true)][object]$Obj,
    [Parameter(Mandatory=$true)][string]$Name
  )
  return ($null -ne $Obj -and $Obj.PSObject -and ($Obj.PSObject.Properties.Name -contains $Name))
}

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) {
    throw "Token ARM inválido. Asegúrate de estar autenticado (azure/login OIDC o az login)."
  }
  return $t
}

function Normalize-NextLink {
  param(
    [Parameter(Mandatory = $false)][string]$NextLink,
    [Parameter(Mandatory = $true)][string]$ApiVersion
  )
  if ([string]::IsNullOrWhiteSpace($NextLink)) { return $null }
  if ($NextLink -notmatch "api-version=") {
    if ($NextLink -match "\?") { return "$NextLink&api-version=$ApiVersion" }
    return "$NextLink?api-version=$ApiVersion"
  }
  return $NextLink
}

function Invoke-ArmGet {
  param([Parameter(Mandatory = $true)][string]$Uri)

  $headers = @{ Authorization = "Bearer $script:ArmToken" }
  try {
    return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers -ContentType "application/json"
  } catch {
    $msg = $_.Exception.Message
    throw "GET falló: $Uri`n$msg"
  }
}

function Invoke-ArmPut {
  param(
    [Parameter(Mandatory = $true)][string]$Uri,
    [Parameter(Mandatory = $true)][object]$Body
  )

  $headers = @{ Authorization = "Bearer $script:ArmToken" }
  $json = $Body | ConvertTo-Json -Depth 100

  try {
    return Invoke-RestMethod -Method PUT -Uri $Uri -Headers $headers -Body $json -ContentType "application/json"
  } catch {
    $msg = $_.Exception.Message
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
      $msg = "$msg`n$($_.ErrorDetails.Message)"
    }
    throw "PUT falló: $Uri`n$msg`nBody:`n$json"
  }
}

function Remove-ReadOnlyProps {
  param([hashtable]$Props)
  foreach ($k in @("lastModifiedUtc","createdTimeUtc","createdBy","lastModifiedBy","systemData","etag")) {
    if ($Props.ContainsKey($k)) { [void]$Props.Remove($k) }
  }
}

function Get-AllPaged {
  param(
    [Parameter(Mandatory=$true)][string]$FirstUri,
    [Parameter(Mandatory=$true)][string]$ApiVersion
  )

  $all = @()
  $uri = $FirstUri

  while (-not [string]::IsNullOrWhiteSpace($uri)) {
    $r = Invoke-ArmGet -Uri $uri
    if ($r -and (Has-Prop $r 'value') -and $r.value) { $all += $r.value }

    $next = $null
    if ($r -and (Has-Prop $r 'nextLink')) {
      $next = $r.nextLink
    }
    $uri = Normalize-NextLink -NextLink $next -ApiVersion $ApiVersion
  }

  return $all
}

function Normalize-Name {
  param([string]$s)
  if ([string]::IsNullOrWhiteSpace($s)) { return "" }
  $s2 = $s -replace [char]0x00A0, ' '
  $s2 = $s2 -replace '\s+', ' '
  return $s2.Trim().ToLowerInvariant()
}

function LevenshteinDistance {
  param(
    [Parameter(Mandatory=$true)][string]$a,
    [Parameter(Mandatory=$true)][string]$b
  )
  if ($a -eq $b) { return 0 }
  if ([string]::IsNullOrWhiteSpace($a)) { return $b.Length }
  if ([string]::IsNullOrWhiteSpace($b)) { return $a.Length }

  $n = $a.Length
  $m = $b.Length
  $d = New-Object 'int[,]' ($n + 1), ($m + 1)

  for ($i = 0; $i -le $n; $i++) { $d[$i,0] = $i }
  for ($j = 0; $j -le $m; $j++) { $d[0,$j] = $j }

  for ($i = 1; $i -le $n; $i++) {
    for ($j = 1; $j -le $m; $j++) {
      $cost = if ($a[$i-1] -eq $b[$j-1]) { 0 } else { 1 }
      $del = $d[$i-1,$j] + 1
      $ins = $d[$i,$j-1] + 1
      $sub = $d[$i-1,$j-1] + $cost
      $min = $del
      if ($ins -lt $min) { $min = $ins }
      if ($sub -lt $min) { $min = $sub }
      $d[$i,$j] = $min
    }
  }
  return $d[$n,$m]
}

function Show-Suggestions {
  param(
    [Parameter(Mandatory=$true)][array]$Templates,
    [Parameter(Mandatory=$true)][string]$TargetDisplayName,
    [Parameter(Mandatory=$true)][int]$Top
  )

  $targetN = Normalize-Name $TargetDisplayName
  $targetFlat = ($targetN -replace ' ','')

  $items = foreach ($t in $Templates) {
    $dn = $null
    if ($t -and (Has-Prop $t 'properties') -and $t.properties -and (Has-Prop $t.properties 'displayName')) {
      $dn = $t.properties.displayName
    }
    if ([string]::IsNullOrWhiteSpace($dn)) { continue }

    $dnN = Normalize-Name $dn
    $dnFlat = ($dnN -replace ' ', '')
    $dist = LevenshteinDistance -a $targetFlat -b $dnFlat

    [pscustomobject]@{
      Distance    = $dist
      Kind        = if (Has-Prop $t 'kind') { $t.kind } else { "" }
      TemplateId  = if (Has-Prop $t 'name') { $t.name } else { "" }
      DisplayName = $dn
    }
  }

  $topMatches = $items | Sort-Object Distance, Kind, DisplayName | Select-Object -First $Top
  if ($topMatches) {
    Write-Warning "Sugerencias (Top $Top) para '$TargetDisplayName' (menor distancia = más cercano):"
    foreach ($s in $topMatches) {
      Write-Warning (" - d={0} | kind={1} | id={2} | name={3}" -f $s.Distance, $s.Kind, $s.TemplateId, $s.DisplayName)
    }
  } else {
    Write-Warning "No hay sugerencias disponibles."
  }
}

Write-Host "== Sentinel | Enable/Create Analytics Rule from Content Hub template =="
Write-Host "SubscriptionId : $SubscriptionId"
Write-Host "ResourceGroup  : $ResourceGroupName"
Write-Host "WorkspaceName  : $WorkspaceName"
Write-Host "DisplayName    : $DisplayName"
Write-Host "IfExists       : $IfExists"
Write-Host "NotFoundBehavior: $NotFoundBehavior"
Write-Host "ApiVersion     : $ApiVersion"
Write-Host ""

$script:ArmToken = Get-ArmToken
$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# 1) Templates instalados
Write-Host "-> Listando alertRuleTemplates..."
$templates = Get-AllPaged -FirstUri "$base/alertRuleTemplates?api-version=$ApiVersion" -ApiVersion $ApiVersion
Write-Host ("   Templates encontrados: {0}" -f $templates.Count)

# 2) Matching tolerante
$target = Normalize-Name $DisplayName
$targetFlat = ($target -replace ' ','')

# exacto normalizado
$matches = @(
  $templates | Where-Object {
    $t = $_
    if (-not (Has-Prop $t 'properties')) { return $false }
    if (-not (Has-Prop $t.properties 'displayName')) { return $false }
    (Normalize-Name $t.properties.displayName) -eq $target
  }
)

# contains normalizado
if ($matches.Count -eq 0) {
  $matches = @(
    $templates | Where-Object {
      $t = $_
      if (-not (Has-Prop $t 'properties')) { return $false }
      if (-not (Has-Prop $t.properties 'displayName')) { return $false }
      (Normalize-Name $t.properties.displayName) -like "*$target*"
    }
  )
}

# contains ignorando espacios
if ($matches.Count -eq 0) {
  $matches = @(
    $templates | Where-Object {
      $t = $_
      if (-not (Has-Prop $t 'properties')) { return $false }
      if (-not (Has-Prop $t.properties 'displayName')) { return $false }
      $dnFlat = ((Normalize-Name $t.properties.displayName) -replace ' ','')
      $dnFlat -like "*$targetFlat*"
    }
  )
}

if ($matches.Count -eq 0) {
  Write-Warning "No se encontró ningún alertRuleTemplate por displayName '$DisplayName' usando matching tolerante."
  Show-Suggestions -Templates $templates -TargetDisplayName $DisplayName -Top $Suggestions

  switch ($NotFoundBehavior) {
    "Fail" { throw "No se encontró template para '$DisplayName'." }
    "WarnOnly" {
      Write-Warning "NotFoundBehavior=WarnOnly -> no se crea/habilita nada y el job termina OK."
      exit 0
    }
    default {
      Write-Warning "NotFoundBehavior=WarnAndExit0 -> no se crea/habilita nada y el job termina OK."
      exit 0
    }
  }
}

if ($matches.Count -gt 1) {
  Write-Warning ("Se encontraron {0} templates candidatos. Usando el primero:" -f $matches.Count)
  $matches | Select-Object -First ([Math]::Min(10, $matches.Count)) | ForEach-Object {
    Write-Warning (" - kind={0} | id={1} | name={2}" -f $_.kind, $_.name, $_.properties.displayName)
  }
}

$template = $matches[0]
$kind = if (Has-Prop $template 'kind') { $template.kind } else { "" }

Write-Host "-> Template seleccionado:"
Write-Host ("   template.name  : {0}" -f $template.name)
Write-Host ("   template.kind  : {0}" -f $kind)
Write-Host ("   displayName    : {0}" -f $template.properties.displayName)

if ($kind -notin @("Scheduled","NRT")) {
  throw "Template kind '$kind' no soportado por este script (solo Scheduled y NRT)."
}

# 3) Buscar rule existente (matching tolerante contra el displayName del template ya seleccionado)
Write-Host ""
Write-Host "-> Comprobando si ya existe alertRule con ese displayName (matching tolerante)..."
$rules = Get-AllPaged -FirstUri "$base/alertRules?api-version=$ApiVersion" -ApiVersion $ApiVersion

$templateDnNorm = Normalize-Name $template.properties.displayName

$existing = @(
  $rules | Where-Object {
    $r = $_
    if (-not (Has-Prop $r 'properties')) { return $false }
    if (-not (Has-Prop $r.properties 'displayName')) { return $false }
    if (-not (Has-Prop $r 'kind')) { return $false }

    (Normalize-Name $r.properties.displayName) -eq $templateDnNorm -and $r.kind -eq $kind
  }
)

if ($existing.Count -gt 1) {
  Write-Warning ("Hay {0} alertRules existentes con ese displayName+kind. Se usará la primera: {1}" -f $existing.Count, $existing[0].name)
}
$existingRule = if ($existing.Count -ge 1) { $existing[0] } else { $null }

# propiedades permitidas
$allowedKeys = @(
  "displayName","description","severity",
  "query","queryFrequency","queryPeriod",
  "triggerOperator","triggerThreshold",
  "suppressionDuration","suppressionEnabled",
  "tactics","techniques",
  "eventGroupingSettings","customDetails","entityMappings",
  "alertDetailsOverride","incidentConfiguration",
  "templateVersion"
)

function Build-PropsFromTemplate {
  param([Parameter(Mandatory=$true)]$Template)

  $props = @{}

  foreach ($k in $allowedKeys) {
    if (Has-Prop $Template.properties $k) {
      $props[$k] = $Template.properties.$k
    }
  }

  # obligatorias / recomendadas
  $props["displayName"] = $Template.properties.displayName
  $props["enabled"] = $true
  $props["alertRuleTemplateName"] = $Template.name

  # ✅ FIX: templateVersion solo si existe
  if (Has-Prop $Template.properties 'templateVersion') {
    $props["templateVersion"] = $Template.properties.templateVersion
  }

  Remove-ReadOnlyProps -Props $props
  return $props
}

if ($existingRule) {
  Write-Host ("   Existe ruleId: {0}" -f $existingRule.name)

  switch ($IfExists) {

    "Skip" {
      Write-Host "==> IfExists=Skip: no se realiza ninguna acción."
      exit 0
    }

    "Enable" {
      $ruleId = $existingRule.name
      $getUri = "$base/alertRules/$ruleId?api-version=$ApiVersion"
      $current = Invoke-ArmGet -Uri $getUri

      $props = @{}
      foreach ($p in $current.properties.PSObject.Properties) { $props[$p.Name] = $p.Value }

      $props["enabled"] = $true
      $props["alertRuleTemplateName"] = $template.name

      # ✅ FIX: templateVersion solo si existe en template
      if (Has-Prop $template.properties 'templateVersion') {
        $props["templateVersion"] = $template.properties.templateVersion
      }

      Remove-ReadOnlyProps -Props $props

      $body = @{
        kind       = $current.kind
        properties = $props
      }

      $putUri = "$base/alertRules/$ruleId?api-version=$ApiVersion"
      if ($PSCmdlet.ShouldProcess($ruleId, "Habilitar alertRule existente")) {
        $out = Invoke-ArmPut -Uri $putUri -Body $body
        Write-Host ("✅ Regla habilitada: {0}" -f $out.id)
        Write-Host ("::notice title=Sentinel AlertRule Enabled::{0}" -f $out.id)
      }
      exit 0
    }

    "Replace" {
      $ruleId = $existingRule.name
      $props = Build-PropsFromTemplate -Template $template

      $body = @{
        kind       = $kind
        properties = $props
      }

      $putUri = "$base/alertRules/$ruleId?api-version=$ApiVersion"
      if ($PSCmdlet.ShouldProcess($ruleId, "Reemplazar alertRule existente desde template")) {
        $out = Invoke-ArmPut -Uri $putUri -Body $body
        Write-Host ("✅ Regla reemplazada y habilitada: {0}" -f $out.id)
        Write-Host ("::notice title=Sentinel AlertRule Replaced::{0}" -f $out.id)
      }
      exit 0
    }
  }
}

# 4) No existe: crear nueva
Write-Host ""
Write-Host "-> No existe alertRule con ese displayName. Creando nueva regla desde template..."
$ruleId = [guid]::NewGuid().ToString()

$props = Build-PropsFromTemplate -Template $template

$body = @{
  kind       = $kind
  properties = $props
}

$putUri = "$base/alertRules/$ruleId?api-version=$ApiVersion"
if ($PSCmdlet.ShouldProcess($ruleId, "Crear alertRule desde template '$($template.properties.displayName)'")) {
  $out = Invoke-ArmPut -Uri $putUri -Body $body
  Write-Host ("✅ Regla creada y habilitada: {0}" -f $out.id)
  Write-Host ("::notice title=Sentinel AlertRule Created::{0}" -f $out.id)
}

Write-Host ""
Write-Host "FIN."
