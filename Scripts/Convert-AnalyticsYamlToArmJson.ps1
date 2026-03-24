param(
  [Parameter(Mandatory = $true)]
  [string]$InputYamlPath,

  [Parameter(Mandatory = $true)]
  [string]$OutputJsonPath,

  [Parameter(Mandatory = $false)]
  [string]$RuleIdSeed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module $Name -Force
}

function Get-YamlValue {
  param(
    [Parameter(Mandatory=$false)] $Obj,
    [Parameter(Mandatory=$true)] [string] $Key
  )
  if ($null -eq $Obj) { return $null }

  if ($Obj -is [System.Collections.IDictionary]) {
    if ($Obj.Contains($Key)) { return $Obj[$Key] }
    return $null
  }

  $p = $Obj.PSObject.Properties[$Key]
  if ($null -ne $p) { return $p.Value }
  return $null
}

function New-DeterministicGuidFromString {
  param([Parameter(Mandatory=$true)][string]$Name)

  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Name)
  $sha1 = [System.Security.Cryptography.SHA1]::Create()
  try { $hash = $sha1.ComputeHash($bytes) }
  finally { $sha1.Dispose() }

  $g = $hash[0..15]
  $g[6] = ($g[6] -band 0x0F) -bor 0x50
  $g[8] = ($g[8] -band 0x3F) -bor 0x80

  return ([Guid]::new($g)).ToString()
}

function Normalize-Operator {
  param([string]$op)
  if ([string]::IsNullOrWhiteSpace($op)) { return $null }
  switch ($op.ToLowerInvariant()) {
    "gt" { "GreaterThan" }
    "ge" { "GreaterThanOrEqual" }
    "lt" { "LessThan" }
    "le" { "LessThanOrEqual" }
    "eq" { "Equals" }
    "ne" { "NotEquals" }
    default { $op }
  }
}

function To-Iso8601Duration {
  param([string]$v)
  if ([string]::IsNullOrWhiteSpace($v)) { return $null }
  if ($v -match '^P') { return $v }
  if ($v -match '^(\d+)\s*([smhd])$') {
    $n = $Matches[1]
    switch ($Matches[2].ToLowerInvariant()) {
      "s" { return "PT${n}S" }
      "m" { return "PT${n}M" }
      "h" { return "PT${n}H" }
      "d" { return "P${n}D" }
    }
  }
  return $v
}

# ----- MAIN -----
Ensure-Module -Name "powershell-yaml"

$raw = Get-Content $InputYamlPath -Raw
if ([string]::IsNullOrWhiteSpace($raw)) {
  Write-Host "SKIP_EMPTY: $InputYamlPath"
  exit 0
}

# Normaliza BOM/tabs/CRLF
$raw = $raw -replace "^\uFEFF",""
$raw = $raw -replace "`t","  "
$raw = $raw -replace "`r`n","`n"

# 1) Intento YAML
$yaml = $null
try {
  $obj = ConvertFrom-Yaml -Yaml $raw
  $yaml = $obj
  if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
    if ($obj.Count -gt 0) { $yaml = $obj[0] }
  }
} catch {
  $yaml = $null
}

# 2) Fallback: si no parsea YAML, prueba JSON (a veces tus ".yaml" son JSON renombrado)
if ($null -eq $yaml) {
  try {
    $j = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($j.resources -and $j.resources.Count -gt 0 -and $j.resources[0].type -match "Microsoft\.SecurityInsights/alertRules") {
      # Convertir este ARM "UI-import" a Repos-compatible
      $seed = $RuleIdSeed
      if ([string]::IsNullOrWhiteSpace($seed)) { $seed = $InputYamlPath }
      $guid = New-DeterministicGuidFromString -Name $seed

      foreach ($r in $j.resources) {
        if ($r.type -match "Microsoft\.SecurityInsights/alertRules") {
          $r.apiVersion = "2023-02-01"
          $r.name = $guid
          if (-not $r.kind) { $r.kind = "Scheduled" }
          if (-not $r.properties) { $r.properties = @{} }
          $r.properties.alertRuleTemplateName = $guid
          if (-not $r.properties.techniques -and $r.properties.relevantTechniques) {
            $r.properties.techniques = $r.properties.relevantTechniques
          }
        }
      }

      if ($j.parameters) { $j.PSObject.Properties.Remove("parameters") }

      $outDir = Split-Path -Parent $OutputJsonPath
      if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

      $j | ConvertTo-Json -Depth 80 | Out-File -FilePath $OutputJsonPath -Encoding utf8
      Write-Host "OK_JSON_FALLBACK: $OutputJsonPath"
      exit 0
    }
  } catch {
    # ignore
  }

  Write-Host "FAIL_PARSE: YAML parse returned null for file: $InputYamlPath"
  exit 3
}

# Campos YAML normales
$displayName = Get-YamlValue $yaml "name"
if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = Get-YamlValue $yaml "displayName" }
if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = [IO.Path]::GetFileNameWithoutExtension($InputYamlPath) }

$kind = Get-YamlValue $yaml "kind"
if ([string]::IsNullOrWhiteSpace($kind)) { $kind = "Scheduled" }

$seed2 = Get-YamlValue $yaml "id"
if ([string]::IsNullOrWhiteSpace($seed2)) { $seed2 = $RuleIdSeed }
if ([string]::IsNullOrWhiteSpace($seed2)) { $seed2 = $InputYamlPath }

$ruleGuid = New-DeterministicGuidFromString -Name $seed2

$resource = @{
  type       = "Microsoft.SecurityInsights/alertRules"
  apiVersion = "2023-02-01"
  name       = $ruleGuid
  kind       = $kind
  properties = @{
    displayName           = $displayName
    description           = Get-YamlValue $yaml "description"
    severity              = Get-YamlValue $yaml "severity"
    enabled               = $true
    query                 = Get-YamlValue $yaml "query"
    queryFrequency        = To-Iso8601Duration (Get-YamlValue $yaml "queryFrequency")
    queryPeriod           = To-Iso8601Duration (Get-YamlValue $yaml "queryPeriod")
    triggerOperator       = Normalize-Operator (Get-YamlValue $yaml "triggerOperator")
    triggerThreshold      = Get-YamlValue $yaml "triggerThreshold"
    tactics               = Get-YamlValue $yaml "tactics"
    techniques            = (Get-YamlValue $yaml "techniques") ?? (Get-YamlValue $yaml "relevantTechniques")
    alertRuleTemplateName = $ruleGuid
  }
}

$template = @{
  '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
  contentVersion = "1.0.0.0"
  parameters     = @{}
  resources      = @($resource)
}

$outDir2 = Split-Path -Parent $OutputJsonPath
if ($outDir2 -and -not (Test-Path $outDir2)) { New-Item -ItemType Directory -Force -Path $outDir2 | Out-Null }

$template | ConvertTo-Json -Depth 80 | Out-File -FilePath $OutputJsonPath -Encoding utf8
Write-Host "OK: $OutputJsonPath"
exit 0
