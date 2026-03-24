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

# ---------- Helpers ----------

function Ensure-Module {
  param([string]$Name)
  if (-not (Get-Module -ListAvailable -Name $Name)) {
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module $Name -Force
}

# Lee YAML tanto si es Hashtable como PSCustomObject
function Get-YamlValue {
  param($Obj, [string]$Key)

  if ($null -eq $Obj) { return $null }

  if ($Obj -is [System.Collections.IDictionary]) {
    if ($Obj.Contains($Key)) { return $Obj[$Key] }
    return $null
  }

  $p = $Obj.PSObject.Properties[$Key]
  if ($p) { return $p.Value }
  return $null
}

# GUID determinístico (no cambia entre runs)
function New-DeterministicGuid {
  param([Guid]$NamespaceGuid, [string]$Name)

  $nsBytes = $NamespaceGuid.ToByteArray()
  $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($Name)

  $sha1 = [System.Security.Cryptography.SHA1]::Create()
  try { $hash = $sha1.ComputeHash($nsBytes + $nameBytes) }
  finally { $sha1.Dispose() }

  $bytes = $hash[0..15]
  $bytes[6] = ($bytes[6] -band 0x0F) -bor 0x50
  $bytes[8] = ($bytes[8] -band 0x3F) -bor 0x80

  return ([Guid]::new($bytes)).ToString()
}

function Normalize-Operator {
  param([string]$op)
  if (-not $op) { return $null }
  switch ($op.ToLower()) {
    "gt" { "GreaterThan" }
    "ge" { "GreaterThanOrEqual" }
    "lt" { "LessThan" }
    "le" { "LessThanOrEqual" }
    "eq" { "Equals" }
    "ne" { "NotEquals" }
    default { $op }
  }
}

function To-Iso8601 {
  param([string]$v)
  if (-not $v) { return $null }
  if ($v -match '^P') { return $v }
  if ($v -match '^(\d+)([smhd])$') {
    $n = $Matches[1]
    switch ($Matches[2]) {
      "s" { return "PT${n}S" }
      "m" { return "PT${n}M" }
      "h" { return "PT${n}H" }
      "d" { return "P${n}D" }
    }
  }
  return $v
}

# ---------- Start ----------

Ensure-Module powershell-yaml

$yamlRaw = Get-Content $InputYamlPath -Raw
$yamlObj = ConvertFrom-Yaml $yamlRaw

if ($yamlObj -is [System.Collections.IEnumerable] -and $yamlObj.Count -gt 0) {
  $yaml = $yamlObj[0]
} else {
  $yaml = $yamlObj
}

$displayName = Get-YamlValue $yaml "name"
if (-not $displayName) { $displayName = Get-YamlValue $yaml "displayName" }
if (-not $displayName) { $displayName = [IO.Path]::GetFileNameWithoutExtension($InputYamlPath) }

$kind = Get-YamlValue $yaml "kind"
if (-not $kind) { $kind = "Scheduled" }

$seed = Get-YamlValue $yaml "id"
if (-not $seed) { $seed = $RuleIdSeed }
if (-not $seed) { $seed = $InputYamlPath }

$namespace = [Guid]"11111111-2222-3333-4444-555555555555"
$ruleGuid = New-DeterministicGuid $namespace $seed

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
    queryFrequency        = To-Iso8601 (Get-YamlValue $yaml "queryFrequency")
    queryPeriod           = To-Iso8601 (Get-YamlValue $yaml "queryPeriod")
    triggerOperator       = Normalize-Operator (Get-YamlValue $yaml "triggerOperator")
    triggerThreshold      = Get-YamlValue $yaml "triggerThreshold"
    tactics               = Get-YamlValue $yaml "tactics"
    techniques            = (Get-YamlValue $yaml "techniques") ?? (Get-YamlValue $yaml "relevantTechniques")

    # 🔑 CLAVE PARA REPOSITORIES
    alertRuleTemplateName = $ruleGuid
  }
}

$template = @{
  '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
  contentVersion = "1.0.0.0"
  parameters     = @{}
  resources      = @($resource)
}

$outDir = Split-Path $OutputJsonPath -Parent
if (-not (Test-Path $outDir)) {
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

# ✅ SIEMPRE SOBREESCRIBE
$template | ConvertTo-Json -Depth 50 | Out-File $OutputJsonPath -Encoding utf8

Write-Host "✅ OK: $OutputJsonPath ($kind)"
