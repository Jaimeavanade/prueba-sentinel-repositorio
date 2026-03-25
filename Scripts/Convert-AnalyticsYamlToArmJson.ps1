#Requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

### ============================
### Helpers
### ============================

function Remove-Diacritics {
  param([string]$Text)
  $normalized = $Text.Normalize([Text.NormalizationForm]::FormD)
  $sb = [System.Text.StringBuilder]::new()
  foreach ($c in $normalized.ToCharArray()) {
    if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -ne 'NonSpacingMark') {
      [void]$sb.Append($c)
    }
  }
  $sb.ToString()
}

function New-RuleSlug {
  param([string]$BaseName, [string]$Path)
  $base = (Remove-Diacritics $BaseName) -replace '[^A-Za-z0-9]+','-'
  $base = $base.Trim('-')
  $hash = (Get-FileHash -Algorithm SHA1 $Path).Hash.Substring(0,8)
  return "$base-$hash"
}

function Convert-DurationToIsoUpper {
  param([string]$v)
  if ([string]::IsNullOrWhiteSpace($v)) { return $null }
  if ($v -match '^[Pp]') { return $v.ToUpperInvariant() }
  if ($v -match '^(\d+)[mM]$') { return "PT$($Matches[1])M" }
  if ($v -match '^(\d+)[hH]$') { return "PT$($Matches[1])H" }
  if ($v -match '^(\d+)[dD]$') { return "P$($Matches[1])D" }
  return $v.ToUpperInvariant()
}

function Extract-QueryFromYamlRaw {
  param([string]$YamlRaw)
  $lines = $YamlRaw -split "`r?`n"
  $i = 0
  while ($i -lt $lines.Count) {
    if ($lines[$i] -match '^\s*query\s*:\s*\|') {
      $indent = ($lines[$i] -replace '^(\s*).*','$1').Length
      $i++
      $out = @()
      while ($i -lt $lines.Count -and
             ($lines[$i].Trim() -eq '' -or
              ($lines[$i] -replace '^(\s*).*','$1').Length -gt $indent)) {
        $out += ($lines[$i] -replace "^\s{$indent,}",'')
        $i++
      }
      return ($out -join "`n").Trim()
    }
    $i++
  }
  return $null
}

### ============================
### Core
### ============================

function Convert-OneYamlToArmJson {
  param([string]$InputFilePath, [string]$OutputFilePath)

  $raw = Get-Content $InputFilePath -Raw -Encoding UTF8
  $y = ConvertFrom-Yaml $raw

  ### displayName = nombre del archivo
  $displayName = [IO.Path]::GetFileNameWithoutExtension($InputFilePath)

  ### query (parser o bloque)
  $query = $y.query
  if ([string]::IsNullOrWhiteSpace($query)) {
    $query = Extract-QueryFromYamlRaw $raw
  }
  if ([string]::IsNullOrWhiteSpace($query)) {
    throw "No se pudo obtener query"
  }

  ### FIX ✅ defaults obligatorios
  $queryFrequency = Convert-DurationToIsoUpper $y.queryFrequency
  if (-not $queryFrequency) { $queryFrequency = "PT5M" }

  $queryPeriod = Convert-DurationToIsoUpper $y.queryPeriod
  if (-not $queryPeriod) { $queryPeriod = "PT5M" }

  $slug = New-RuleSlug $displayName $InputFilePath

  $template = @{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    parameters = @{ workspace = @{ type = 'string' } }
    resources = @(@{
      type = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
      apiVersion = '2023-02-01-preview'
      kind = 'Scheduled'
      name = "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/Custom-$slug')]"
      properties = @{
        displayName = $displayName
        enabled = $true
        query = $query
        queryFrequency = $queryFrequency
        queryPeriod = $queryPeriod
        severity = ($y.severity ?? 'Medium')
        triggerOperator = 'GreaterThan'
        triggerThreshold = 0
      }
    })
  }

  $dir = Split-Path $OutputFilePath
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory $dir -Force | Out-Null }

  $template | ConvertTo-Json -Depth 50 | Set-Content $OutputFilePath -Encoding UTF8
}

### ============================
### Runner
### ============================

$input = "Detections/Custom/YAML"
$output = "Detections/Custom/ARM"

Get-ChildItem $input -Recurse -Include *.yaml,*.yml | ForEach-Object {
  $rel = $_.FullName.Substring((Resolve-Path $input).Path.Length).TrimStart('\','/')
  $out = Join-Path $output ($rel -replace '\.ya?ml$','.json')
  Write-Host "➡️ Procesando $($_.Name)"
  Convert-OneYamlToArmJson $_.FullName $out
}

Write-Host "✅ Conversión finalizada correctamente"
``
