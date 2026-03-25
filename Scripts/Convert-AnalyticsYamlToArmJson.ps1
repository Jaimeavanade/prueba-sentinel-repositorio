#Requires -Version 7.2
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Remove-Diacritics {
  param([string]$Text)
  $normalized = $Text.Normalize([Text.NormalizationForm]::FormD)
  $sb = [System.Text.StringBuilder]::new()
  foreach ($c in $normalized.ToCharArray()) {
    if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -ne 'NonSpacingMark') {
      [void]$sb.Append($c)
    }
  }
  $sb.ToString().Normalize([Text.NormalizationForm]::FormC)
}

function New-RuleSlug {
  param([string]$BaseName, [string]$Path)
  $base = (Remove-Diacritics $BaseName).Trim()
  $base = $base -replace '[\s_]+', '-'
  $base = $base -replace '[^A-Za-z0-9\-]', ''
  $base = $base -replace '\-+', '-'
  $base = $base.Trim('-')
  if ([string]::IsNullOrWhiteSpace($base)) { $base = "Rule" }
  $hash = (Get-FileHash -Algorithm SHA1 $Path).Hash.Substring(0,8)
  return "$base-$hash"
}

function Convert-DurationToIsoUpper {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

  $v = $Value.Trim()

  # ISO8601 ya
  if ($v -match '^[Pp]') { return $v.ToUpperInvariant() }

  # Formatos simples típicos
  if ($v -match '^(\d+)\s*[mM]$') { return ("PT{0}M" -f $Matches[1]) }
  if ($v -match '^(\d+)\s*[hH]$') { return ("PT{0}H" -f $Matches[1]) }
  if ($v -match '^(\d+)\s*[dD]$') { return ("P{0}D" -f $Matches[1]) }

  # fallback: mayúsculas
  return $v.ToUpperInvariant()
}

function Extract-QueryFromYamlRaw {
  param([string]$YamlRaw)

  $lines = $YamlRaw -split "`r?`n"
  $headerRegex = '^(?<indent>\s*)query\s*:\s*\|(?<ind>\d+)?(?<chomp>[+-])?\s*$'

  $idx = -1
  $baseIndent = 0
  for ($i=0; $i -lt $lines.Length; $i++) {
    if ($lines[$i] -match $headerRegex) {
      $idx = $i
      $baseIndent = $Matches['indent'].Length
      break
    }
  }
  if ($idx -lt 0) { return $null }

  # Detectar indent real del bloque
  $contentIndent = $null
  for ($j=$idx+1; $j -lt $lines.Length; $j++) {
    if ($lines[$j] -match '^\s*$') { continue }
    $leading = ($lines[$j] -replace '^(?<sp>\s*).*$', '${sp}').Length
    if ($leading -le $baseIndent) { return "" }
    $contentIndent = $leading
    break
  }
  if ($null -eq $contentIndent) { return "" }

  $out = New-Object System.Collections.Generic.List[string]
  for ($k=$idx+1; $k -lt $lines.Length; $k++) {
    $l = $lines[$k]
    if ($l -match '^\s*$') { $out.Add(""); continue }

    $leading = ($l -replace '^(?<sp>\s*).*$', '${sp}').Length
    if ($leading -lt $contentIndent) { break }

    $out.Add($l.Substring([Math]::Min($contentIndent, $l.Length)))
  }

  ($out -join "`n").TrimEnd()
}

function Ensure-OutputFilePath {
  param(
    [Parameter(Mandatory)][string]$InputFilePath,
    [Parameter(Mandatory)][string]$OutputFilePath
  )

  # Si la ruta de salida apunta a un directorio, adjuntar nombre de archivo .json
  if (Test-Path -LiteralPath $OutputFilePath -PathType Container) {
    $leaf = (Split-Path -Leaf $InputFilePath) -replace '\.ya?ml$', '.json'
    return (Join-Path $OutputFilePath $leaf)
  }

  # Si termina en / o \ (parece carpeta), adjuntar nombre
  if ($OutputFilePath -match '[\\/]\s*$') {
    $leaf = (Split-Path -Leaf $InputFilePath) -replace '\.ya?ml$', '.json'
    return (Join-Path $OutputFilePath $leaf)
  }

  return $OutputFilePath
}

function Convert-OneYamlToArmJson {
  param(
    [Parameter(Mandatory)][string]$InputFilePath,
    [Parameter(Mandatory)][string]$OutputFilePath
  )

  $yamlRaw = Get-Content -Path $InputFilePath -Raw -Encoding UTF8
  $y = ConvertFrom-Yaml -Yaml $yamlRaw
  if ($null -eq $y) { throw "YAML vacío o no parseable: $InputFilePath" }

  # displayName = nombre del fichero YAML
  $displayName = [IO.Path]::GetFileNameWithoutExtension($InputFilePath).Trim()

  # query: desde parser o extraída del bloque |...
  $query = $null
  if ($y.PSObject.Properties.Name -contains 'query' -and -not [string]::IsNullOrWhiteSpace([string]$y.query)) {
    $query = [string]$y.query
  } else {
    $query = Extract-QueryFromYamlRaw -YamlRaw $yamlRaw
  }
  if ([string]::IsNullOrWhiteSpace($query)) {
    throw "No se pudo obtener 'query' (ni parseada ni por bloque |...). Archivo: $InputFilePath"
  }

  # queryFrequency/queryPeriod: defaults si faltan
  $queryFrequency = $null
  if ($y.PSObject.Properties.Name -contains 'queryFrequency') {
    $queryFrequency = Convert-DurationToIsoUpper ([string]$y.queryFrequency)
  }
  if (-not $queryFrequency) { $queryFrequency = "PT5M" }

  $queryPeriod = $null
  if ($y.PSObject.Properties.Name -contains 'queryPeriod') {
    $queryPeriod = Convert-DurationToIsoUpper ([string]$y.queryPeriod)
  }
  if (-not $queryPeriod) { $queryPeriod = "PT5M" }

  $severity = "Medium"
  if ($y.PSObject.Properties.Name -contains 'severity' -and -not [string]::IsNullOrWhiteSpace([string]$y.severity)) {
    $severity = [string]$y.severity
  }

  $slug = New-RuleSlug -BaseName $displayName -Path $InputFilePath

  $template = [pscustomobject]@{
    '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
    contentVersion = '1.0.0.0'
    parameters = [pscustomobject]@{
      workspace = [pscustomobject]@{ type = 'string' }
    }
    resources = @(
      [pscustomobject]@{
        type = 'Microsoft.OperationalInsights/workspaces/providers/alertRules'
        apiVersion = '2023-02-01-preview'
        kind = 'Scheduled'
        name = "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/Custom-$slug')]"
        properties = [pscustomobject]@{
          displayName     = $displayName
          description     = ([string]($y.description ?? "")).TrimEnd()
          severity        = $severity
          enabled         = $true
          query           = $query
          queryFrequency  = $queryFrequency
          queryPeriod     = $queryPeriod
          triggerOperator = 'GreaterThan'
          triggerThreshold= 0
          suppressionEnabled = $false
        }
      }
    )
  }

  # ✅ FIX CRÍTICO: asegurar que OutputFilePath es fichero, no carpeta
  $OutputFilePath = Ensure-OutputFilePath -InputFilePath $InputFilePath -OutputFilePath $OutputFilePath

  # Crear carpeta destino
  $outDir = Split-Path -Parent $OutputFilePath
  if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

  # Escribir JSON (Set-Content sobre fichero)
  $template | ConvertTo-Json -Depth 80 | Set-Content -Path $OutputFilePath -Encoding UTF8 -Force
}

# ==========================
# MAIN
# ==========================
$InputFolder  = "Detections/Custom/YAML"
$OutputFolder = "Detections/Custom/ARM"

$root = (Resolve-Path $InputFolder).Path

Get-ChildItem -Path $InputFolder -Recurse -File -Include *.yaml, *.yml | ForEach-Object {
  $inPath = $_.FullName
  $rel = $inPath.Substring($root.Length).TrimStart('\','/')
  $outPath = Join-Path $OutputFolder ($rel -replace '\.ya?ml$', '.json')

  Write-Host "➡️ Procesando: $($_.Name)"
  Convert-OneYamlToArmJson -InputFilePath $inPath -OutputFilePath $outPath
}

Write-Host "✅ Conversión finalizada"
