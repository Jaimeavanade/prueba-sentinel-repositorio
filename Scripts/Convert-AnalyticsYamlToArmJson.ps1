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

# ✅ IMPORTANTE: Obj NO puede ser Mandatory porque a veces puede ser $null
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

# GUID determinístico desde string (siempre válido)
function New-DeterministicGuidFromString {
  param([Parameter(Mandatory=$true)][string]$Name)

  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Name)
  $sha1 = [System.Security.Cryptography.SHA1]::Create()
  try { $hash = $sha1.ComputeHash($bytes) }
  finally { $sha1.Dispose() }

  $g = $hash[0..15]
  $g[6] = ($g[6] -band 0x0F) -bor 0x50  # v5
  $g[8] = ($g[8] -band 0x3F) -bor 0x80  # RFC4122

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
  if ($v -match '^P') { return $v } # ya ISO8601
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

# ---------------- MAIN ----------------
Ensure-Module -Name "powershell-yaml"

if (-not (Test-Path $InputYamlPath)) {
  throw "InputYamlPath not found: $InputYamlPath"
}

$yamlRaw = Get-Content $InputYamlPath -Raw

# ✅ CLAVE: NO usar pipeline; pasar el parámetro -Yaml
$yamlObj = ConvertFrom-Yaml -Yaml $yamlRaw

# Si devuelve lista, cogemos el primero
$yaml = $yamlObj
if ($yamlObj -is [System.Collections.IEnumerable] -and -not ($yamlObj -is [string])) {
  if ($yamlObj.Count -gt 0) { $yaml = $yamlObj[0] }
}

# ✅ Si aun así es null, el YAML es inválido (o el parser falla); evitamos reventar y damos error claro
if ($null -eq $yaml) {
  throw "YAML parse returned null for file: $InputYamlPath"
}

$displayName = Get-YamlValue $yaml "name"
if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = Get-YamlValue $yaml "displayName" }
if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = [IO.Path]::GetFileNameWithoutExtension($InputYamlPath) }

$kind = Get-YamlValue $yaml "kind"
if ([string]::IsNullOrWhiteSpace($kind)) { $kind = "Scheduled" }

$description = Get-YamlValue $yaml "description"
$severity    = Get-YamlValue $yaml "severity"
$query       = Get-YamlValue $yaml "query"

$queryFrequency   = To-Iso8601Duration (Get-YamlValue $yaml "queryFrequency")
$queryPeriod      = To-Iso8601Duration (Get-YamlValue $yaml "queryPeriod")
$triggerOperator  = Normalize-Operator (Get-YamlValue $yaml "triggerOperator")
$triggerThreshold = Get-YamlValue $yaml "triggerThreshold"

$tactics = Get-YamlValue $yaml "tactics"
$techniques = Get-YamlValue $yaml "techniques"
if (-not $techniques) { $techniques = Get-YamlValue $yaml "relevantTechniques" }

# Seed determinístico
$seed = Get-YamlValue $yaml "id"
if ([string]::IsNullOrWhiteSpace($seed)) { $seed = $RuleIdSeed }
if ([string]::IsNullOrWhiteSpace($seed)) { $seed = $InputYamlPath }

$ruleGuid = New-DeterministicGuidFromString -Name $seed

# ARM Repositories compatible
$resource = @{
  type       = "Microsoft.SecurityInsights/alertRules"
  apiVersion = "2023-02-01"
  name       = $ruleGuid
  kind       = $kind
  properties = @{
    displayName           = $displayName
    description           = $description
    severity              = $severity
    enabled               = $true
    query                 = $query
    queryFrequency        = $queryFrequency
    queryPeriod           = $queryPeriod
    triggerOperator       = $triggerOperator
    triggerThreshold      = $triggerThreshold
    tactics               = $tactics
    techniques            = $techniques

    # REQUIRED by Sentinel Repositories
    alertRuleTemplateName = $ruleGuid
  }
}

$template = @{
  '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
  contentVersion = "1.0.0.0"
  parameters     = @{}
  resources      = @($resource)
}

$outDir = Split-Path -Parent $OutputJsonPath
if ($outDir -and -not (Test-Path $outDir)) {
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

# ✅ SOBREESCRIBE SIEMPRE
$template | ConvertTo-Json -Depth 80 | Out-File -FilePath $OutputJsonPath -Encoding utf8

Write-Host "✅ OK: $OutputJsonPath | kind=$kind | guid=$ruleGuid"
