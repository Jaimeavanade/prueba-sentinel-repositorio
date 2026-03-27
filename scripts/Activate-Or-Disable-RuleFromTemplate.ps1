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
  [string] $Search = "",

  # ✅ NUEVO: activar por TemplateId directamente
  [Parameter(Mandatory=$false)]
  [string] $TemplateId = "",

  # ✅ NUEVO: si no hay match por nombre, escoger candidato N (1..N)
  [Parameter(Mandatory=$false)]
  [int] $PickCandidate = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
  $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
  if (-not $t -or $t.Trim().Length -lt 100) { throw "Token ARM inválido o vacío. Revisa azure/login (OIDC) y permisos." }
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
  } catch {}
  return $null
}

function Invoke-ArmRest {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","PATCH","DELETE")] [string] $Method,
    [Parameter(Mandatory=$true)] [string] $Uri,
    [Parameter(Mandatory=$false)] [object] $Body
  )
  if (-not $script:ArmToken) { $script:ArmToken = Get-ArmToken }

  $headers = @{ Authorization="Bearer $script:ArmToken"; "Content-Type"="application/json" }

  try {
    if ($null -ne $Body) {
      $json = $Body | ConvertTo-Json -Depth 80
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json
    } else {
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
  } catch {
    $bodyText = Get-ErrorBodyFromException -Exception $_.Exception
    if ($bodyText) { throw "Fallo REST ($Method). Uri=$Uri. Body=$bodyText" }
    throw
  }
}

function Normalize-Text([string]$s) {
  if ($null -eq $s) { return "" }
  return ($s.Trim() -replace "\s+", " ")
}

function Has-Prop {
  param([Parameter(Mandatory=$true)] $Obj, [Parameter(Mandatory=$true)] [string] $PropName)
  return $null -ne $Obj -and $null -ne $Obj.PSObject -and ($Obj.PSObject.Properties.Name -contains $PropName)
}

function Get-PropValue {
  param([Parameter(Mandatory=$true)] $Obj, [Parameter(Mandatory=$true)] [string] $PropName, $Default=$null)
  if (Has-Prop $Obj $PropName) { return $Obj.$PropName }
  return $Default
}

function Normalize-StringArray {
  param($Value)
  if ($null -eq $Value) { return @() }

  $arr = @()
  if ($Value -is [string]) { $arr = @($Value) }
  elseif ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) { foreach($x in $Value){ $arr += $x } }
  else { $arr = @($Value) }

  $arr = @(
    $arr | Where-Object { $null -ne $_ } |
      ForEach-Object { $_.ToString().Trim() } |
      Where-Object { $_ -ne "" } |
      ForEach-Object { $_.Replace(" ", "") } |
      Select-Object -Unique
  )
  return $arr
}

function Build-Candidates {
  param([Parameter(Mandatory=$true)] [object[]] $Templates, [Parameter(Mandatory=$true)] [string] $Name)

  $needle = (Normalize-Text $Name).ToLower()

  $cands = $Templates | ForEach-Object {
    $dn  = ""
    $sev = "N/A"
    $knd = if (Has-Prop $_ "kind") { $_.kind } else { "N/A" }
    $tid = if (Has-Prop $_ "name") { $_.name } else { "" }

    if (Has-Prop $_ "properties") {
      if (Has-Prop $_.properties "displayName") { $dn = Normalize-Text $_.properties.displayName }
      if (Has-Prop $_.properties "severity") { $sev = $_.properties.severity }
    }

    $score = 0
    if (-not [string]::IsNullOrWhiteSpace($dn)) {
      $dnLower = $dn.ToLower()
      if ($dnLower.Contains($needle)) { $score = 2 }
      elseif ($needle.Length -gt 0) {
        $firstToken = $needle.Split(" ")[0]
        if ($firstToken -and $dnLower.Contains($firstToken)) { $score = 1 }
      }
    }

    [pscustomobject]@{
      templateId  = $tid
      displayName = $dn
      kind        = $knd
      severity    = $sev
      score       = $score
    }
  } |
  Where-Object { $_.score -gt 0 -and -not [string]::IsNullOrWhiteSpace($_.displayName) } |
  Sort-Object -Property @{Expression='score';Descending=$true}, @{Expression='displayName';Descending=$false}

  return @($cands)
}

function Print-Candidates {
  param([object[]] $Candidates, [int] $Top = 30)
  $shown = $Candidates | Select-Object -First $Top
  if (-not $shown -or $shown.Count -eq 0) {
    Write-Host "No hay candidatos. Usa Action=list con Search para listar plantillas."
    return
  }
  Write-Host ""
  Write-Host "=== CANDIDATOS (puedes usar pickCandidate o templateId) ==="
  $i = 0
  foreach ($c in $shown) {
    $i++
    Write-Host ("{0}. {1} | templateId={2} | kind={3} | severity={4}" -f $i, $c.displayName, $c.templateId, $c.kind, $c.severity)
  }
  Write-Host "=========================================================="
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

$script:ArmToken = Get-ArmToken

# ----------------------------
# LIST
# ----------------------------
if ($Action -eq "list") {
  $templatesUri = "${base}/alertRuleTemplates?api-version=$ApiVersion_Templates"
  $templates = Invoke-ArmRest -Method GET -Uri $templatesUri
  $all = @($templates.value)

  Write-Host "Total Rule templates instaladas: $($all.Count)"

  if (-not [string]::IsNullOrWhiteSpace($Search)) {
    $s = (Normalize-Text $Search).ToLower()
    $all = $all | Where-Object {
      (Has-Prop $_ "properties") -and (Has-Prop $_.properties "displayName") -and
      ((Normalize-Text $_.properties.displayName).ToLower().Contains($s))
    }
    Write-Host "Filtradas por Search='$Search': $($all.Count)"
  }

  Write-Host ""
  $all |
    ForEach-Object {
      if ((Has-Prop $_ "properties") -and (Has-Prop $_.properties "displayName")) {
        $dn  = Normalize-Text $_.properties.displayName
        $sev = if (Has-Prop $_.properties "severity") { $_.properties.severity } else { "N/A" }
        $knd = if (Has-Prop $_ "kind") { $_.kind } else { "N/A" }
        $tid = if (Has-Prop $_ "name") { $_.name } else { "" }
        [pscustomobject]@{ displayName=$dn; templateId=$tid; kind=$knd; severity=$sev }
      }
    } |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_.displayName) } |
    Sort-Object -Property @{Expression='displayName';Descending=$false} |
    ForEach-Object { Write-Host ("- {0} | templateId={1} | kind={2} | severity={3}" -f $_.displayName, $_.templateId, $_.kind, $_.severity) }

  exit 0
}

# ----------------------------
# ENABLE
# ----------------------------
if ($Action -eq "enable") {

  $templatesUri = "${base}/alertRuleTemplates?api-version=$ApiVersion_Templates"
  $templates = Invoke-ArmRest -Method GET -Uri $templatesUri
  $tplList = @($templates.value)

  $match = $null

  # 1) Si nos dan templateId, lo usamos directo
  if (-not [string]::IsNullOrWhiteSpace($TemplateId)) {
    $match = $tplList | Where-Object { (Has-Prop $_ "name") -and ($_.name -eq $TemplateId) } | Select-Object -First 1
    if (-not $match) { throw "No se encontró templateId='$TemplateId' en alertRuleTemplates." }
    Write-Host "✅ Template encontrado por templateId: $TemplateId"
  }
  else {
    if ([string]::IsNullOrWhiteSpace($RuleName)) { throw "RuleName o TemplateId es obligatorio para Action=enable." }

    # 2) Buscar por nombre exacto/normalizado/contains
    $needleRaw = $RuleName
    $needle = Normalize-Text $RuleName

    $match = $tplList | Where-Object {
      (Has-Prop $_ "properties") -and (Has-Prop $_.properties "displayName") -and ($_.properties.displayName -eq $needleRaw)
    } | Select-Object -First 1

    if (-not $match) {
      $match = $tplList | Where-Object {
        (Has-Prop $_ "properties") -and (Has-Prop $_.properties "displayName") -and
        ((Normalize-Text $_.properties.displayName).ToLower() -eq $needle.ToLower())
      } | Select-Object -First 1
      if ($match) { Write-Host "✅ Template encontrado (modo: exact(normalized, case-insensitive))" }
    }

    if (-not $match) {
      $match = $tplList | Where-Object {
        (Has-Prop $_ "properties") -and (Has-Prop $_.properties "displayName") -and
        ((Normalize-Text $_.properties.displayName).ToLower().Contains($needle.ToLower()))
      } | Select-Object -First 1
      if ($match) { Write-Host "✅ Template encontrado (modo: contains(case-insensitive))" }
    }

    # 3) Si no hay match, construir candidatos y permitir PickCandidate
    if (-not $match) {
      Write-Host "No se encontró Rule template por nombre exacto/normalizado/contains."
      $cands = Build-Candidates -Templates $tplList -Name $RuleName
      Print-Candidates -Candidates $cands -Top 30

      if ($PickCandidate -gt 0) {
        if ($PickCandidate -gt $cands.Count) {
          throw "PickCandidate=$PickCandidate fuera de rango. Hay $($cands.Count) candidatos."
        }
        $picked = $cands[$PickCandidate - 1]
        Write-Host "✅ Seleccionado candidato #$PickCandidate: $($picked.displayName) (templateId=$($picked.templateId))"
        $match = $tplList | Where-Object { (Has-Prop $_ "name") -and ($_.name -eq $picked.templateId) } | Select-Object -First 1
      }

      if (-not $match) {
        throw "No se encontró ningún Rule template compatible con '$RuleName'. Revisa que la solución esté instalada o usa Action=list."
      }
    }
  }

  $templateId = $match.name
  $p = $match.properties
  Write-Host "Encontrado templateId: $templateId"
  Write-Host "Creando regla Scheduled desde template..."

  $newRuleGuid = (New-Guid).Guid
  $createRuleUri = "${base}/alertRules/${newRuleGuid}?api-version=$ApiVersion_Rules"

  $tacticsArr    = Normalize-StringArray (Get-PropValue $p "tactics" $null)
  $techniquesArr = Normalize-StringArray (Get-PropValue $p "techniques" $null)

  $ruleProps = @{
    displayName         = (Get-PropValue $p "displayName" "")
    description         = (Get-PropValue $p "description" "")
    severity            = (Get-PropValue $p "severity" "Medium")
    enabled             = $true
    query               = (Get-PropValue $p "query" "")
    queryFrequency      = (Get-PropValue $p "queryFrequency" "PT1H")
    queryPeriod         = (Get-PropValue $p "queryPeriod" "PT1H")
    triggerOperator     = (Get-PropValue $p "triggerOperator" "GreaterThan")
    triggerThreshold    = (Get-PropValue $p "triggerThreshold" 0)
    suppressionDuration = (Get-PropValue $p "suppressionDuration" "PT0H")
    suppressionEnabled  = (Get-PropValue $p "suppressionEnabled" $false)
    tactics             = $tacticsArr
    techniques          = $techniquesArr
  }

  if ($ruleProps.tactics.Count -eq 0)    { $ruleProps.Remove("tactics") }
  if ($ruleProps.techniques.Count -eq 0) { $ruleProps.Remove("techniques") }

  $body = @{ kind="Scheduled"; properties=$ruleProps }

  $created = Invoke-ArmRest -Method PUT -Uri $createRuleUri -Body $body
  Write-Host "✅ Regla creada/activada: $($created.properties.displayName) (id: $newRuleGuid)"
  exit 0
}

# ----------------------------
# DISABLE
# ----------------------------
if ($Action -eq "disable") {
  if ([string]::IsNullOrWhiteSpace($RuleName)) { throw "RuleName es obligatorio para Action=disable." }

  $rulesUri = "${base}/alertRules?api-version=$ApiVersion_Rules"
  $rules = Invoke-ArmRest -Method GET -Uri $rulesUri
  $ruleList = @($rules.value)

  $needle = (Normalize-Text $RuleName).ToLower()

  $rule = $ruleList | Where-Object {
    (Has-Prop $_ "properties") -and (Has-Prop $_.properties "displayName") -and
    ((Normalize-Text $_.properties.displayName).ToLower() -eq $needle)
  } | Select-Object -First 1

  if (-not $rule) {
    $rule = $ruleList | Where-Object {
      (Has-Prop $_ "properties") -and (Has-Prop $_.properties "displayName") -and
      ((Normalize-Text $_.properties.displayName).ToLower().Contains($needle))
    } | Select-Object -First 1
  }

  if (-not $rule) { throw "No se encontró ninguna regla activa con displayName='$RuleName'." }

  $ruleId = $rule.name
  Write-Host "Encontrada reglaId: $ruleId. Marcando enabled=false..."

  $patchUri = "${base}/alertRules/${ruleId}?api-version=$ApiVersion_Rules"
  $patchBody = @{ properties = @{ enabled = $false } }

  $updated = Invoke-ArmRest -Method PATCH -Uri $patchUri -Body $patchBody
  Write-Host "✅ Regla deshabilitada: $($updated.properties.displayName)"
  exit 0
}

throw "Action no soportada: $Action"
