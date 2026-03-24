<#
.SYNOPSIS
  Convert Microsoft Sentinel Analytics Rule YAML to ARM JSON compatible with Microsoft Sentinel Repositories.

.DESCRIPTION
  Generates Repository-compatible ARM JSON:
    - resources[].type = Microsoft.SecurityInsights/alertRules
    - resources[].name = GUID literal (no expressions)
    - properties.alertRuleTemplateName = same GUID
    - apiVersion fixed to stable '2023-02-01'
  Also normalizes operators and time formats.

.PARAMETER InputYamlPath
  Path to a single YAML file.

.PARAMETER OutputJsonPath
  Output JSON path.

.PARAMETER RuleIdSeed
  Optional seed string to create deterministic GUID. If not provided, uses YAML 'id' if exists, otherwise InputYamlPath.
#>

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

# --- Deterministic GUID (UUIDv5-like using SHA1) ---
function New-DeterministicGuid {
  param(
    [Parameter(Mandatory = $true)][Guid]$NamespaceGuid,
    [Parameter(Mandatory = $true)][string]$Name
  )
  $nsBytes = $NamespaceGuid.ToByteArray()
  $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($Name)

  $sha1 = [System.Security.Cryptography.SHA1]::Create()
  try {
    $hash = $sha1.ComputeHash(($nsBytes + $nameBytes))
  } finally {
    $sha1.Dispose()
  }

  # First 16 bytes become GUID with version 5 and RFC4122 variant
  $newBytes = $hash[0..15]

  # Set version to 5 (0101)
  $newBytes[6] = ($newBytes[6] -band 0x0F) -bor 0x50
  # Set variant to RFC4122 (10xx)
  $newBytes[8] = ($newBytes[8] -band 0x3F) -bor 0x80

  return [Guid]::new($newBytes).ToString()
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
    default { $op }  # if already in ARM style, keep it
  }
}

function Convert-ToIso8601Duration {
  param([string]$value)
  if ([string]::IsNullOrWhiteSpace($value)) { return $null }

  # If already ISO 8601 duration (PT.. or P..), return as-is
  if ($value -match '^(P(T)?).+') { return $value }

  # YAML style examples: 5m, 1h, 1d, 30s
  if ($value -match '^(\d+)\s*([smhd])$') {
    $n = [int]$Matches[1]
    $u = $Matches[2].ToLowerInvariant()
    switch ($u) {
      "s" { return "PT${n}S" }
      "m" { return "PT${n}M" }
      "h" { return "PT${n}H" }
      "d" { return "P${n}D" }
    }
  }

  # If unknown format, return as-is (better than breaking)
  return $value
}

# --- Modules ---
Ensure-Module -Name "powershell-yaml"

# --- Load YAML ---
if (-not (Test-Path $InputYamlPath)) {
  throw "InputYamlPath not found: $InputYamlPath"
}

$yamlRaw = Get-Content $InputYamlPath -Raw
$yaml = $yamlRaw | ConvertFrom-Yaml

# --- Pull core fields with fallbacks ---
$displayName = $yaml.name
if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $yaml.displayName }
if ([string]::IsNullOrWhiteSpace($displayName)) {
  $displayName = [IO.Path]::GetFileNameWithoutExtension($InputYamlPath)
}

$description = $yaml.description
$severity = $yaml.severity
$query = $yaml.query

# Scheduled/NRT/etc. (default to Scheduled)
$kind = $yaml.kind
if ([string]::IsNullOrWhiteSpace($kind)) { $kind = "Scheduled" }

# Operators / times
$triggerOperator = Normalize-Operator $yaml.triggerOperator
$triggerThreshold = $yaml.triggerThreshold
$queryFrequency = Convert-ToIso8601Duration $yaml.queryFrequency
$queryPeriod = Convert-ToIso8601Duration $yaml.queryPeriod
$suppressionDuration = Convert-ToIso8601Duration $yaml.suppressionDuration

# Techniques and tactics
$tactics = $yaml.tactics
$techniques = $yaml.techniques
if (-not $techniques) { $techniques = $yaml.relevantTechniques }

# Determine deterministic GUID seed:
# Prefer YAML 'id' if present; else use user RuleIdSeed; else use relative path.
$seed = $null
if ($yaml.id) { $seed = [string]$yaml.id }
elseif ($RuleIdSeed) { $seed = $RuleIdSeed }
else { $seed = $InputYamlPath.Replace("\","/").ToLowerInvariant() }

# Namespace GUID constant for your repo (any fixed GUID works)
$namespace = [Guid]"11111111-2222-3333-4444-555555555555"
$ruleGuid = New-DeterministicGuid -NamespaceGuid $namespace -Name $seed

# --- Build Repositories-compatible ARM template ---
$resource = @{
  type       = "Microsoft.SecurityInsights/alertRules"
  apiVersion = "2023-02-01"
  name       = $ruleGuid
  kind       = $kind
  properties = @{
    displayName          = $displayName
    description          = $description
    severity             = $severity
    enabled              = $true
    query                = $query
    queryFrequency       = $queryFrequency
    queryPeriod          = $queryPeriod
    triggerOperator      = $triggerOperator
    triggerThreshold     = $triggerThreshold
    tactics              = $tactics
    techniques           = $techniques

    # REQUIRED by Repositories
    alertRuleTemplateName = $ruleGuid
  }
}

# Optional fields if exist
if ($yaml.templateVersion) { $resource.properties.templateVersion = [string]$yaml.templateVersion }
elseif ($yaml.version) { $resource.properties.templateVersion = [string]$yaml.version }

if ($yaml.entityMappings) { $resource.properties.entityMappings = $yaml.entityMappings }
if ($yaml.customDetails) { $resource.properties.customDetails = $yaml.customDetails }
if ($yaml.eventGroupingSettings) { $resource.properties.eventGroupingSettings = $yaml.eventGroupingSettings }
if ($yaml.incidentConfiguration) { $resource.properties.incidentConfiguration = $yaml.incidentConfiguration }
if ($yaml.alertDetailsOverride) { $resource.properties.alertDetailsOverride = $yaml.alertDetailsOverride }
if ($suppressionDuration) { $resource.properties.suppressionDuration = $suppressionDuration }
if ($null -ne $yaml.suppressionEnabled) { $resource.properties.suppressionEnabled = [bool]$yaml.suppressionEnabled }

# Create top-level template
$template = @{
  '$schema'       = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
  contentVersion  = "1.0.0.0"
  parameters      = @{}   # IMPORTANT: no workspaceName param for repositories
  resources       = @($resource)
}

# Ensure output folder exists
$outDir = Split-Path -Parent $OutputJsonPath
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

# Write JSON
$template | ConvertTo-Json -Depth 50 | Out-File -FilePath $OutputJsonPath -Encoding utf8

Write-Host "✅ Repositories-compatible ARM JSON created:"
Write-Host "   $OutputJsonPath"
Write-Host "   Rule GUID: $ruleGuid"
