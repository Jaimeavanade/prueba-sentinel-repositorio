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

  if ($v -match '^[Pp]') { return $v.ToUpperInvariant() }

  # formatos simples típicos
  if ($v -match '^(\d+)\s*[mM]$') { return ("PT{0}M" -f $Matches[1]) }
  if ($v -match '^(\d+)\s*[hH]$') { return ("PT{0}H" -f $Matches[1]) }
  if ($v -match '^(\d+)\s*[dD]$') { return ("P{0}D" -f $Matches[1]) }

  return $v.ToUpperInvariant()
}

function Ensure-OutputFilePath {
  param(
    [Parameter(Mandatory)][string]$InputFilePath,
    [Parameter(Mandatory)][string]$OutputFilePath
  )

  if (Test-Path -LiteralPath $OutputFilePath -PathType Container) {
    $leaf = (Split-Path -Leaf $InputFilePath) -replace '\.ya?ml$', '.json'
    return (Join-Path $OutputFilePath $leaf)
  }

  if ($OutputFilePath -match '[\\/]\s*$') {
    $leaf = (Split-Path -Leaf $InputFilePath) -replace '\.ya?ml$', '.json'
    return (Join-Path $OutputFilePath $leaf)
  }

  return $OutputFilePath
}

function Normalize-QueryText {
  param([string]$q)
  if ([string]::IsNullOrWhiteSpace($q)) { return $q }

  $q = $q.Trim()

  # Normalizar secuencias típicas de YAML quoted con continuaciones:
  #   \r\n\   -> salto de línea real
  #   \n\     -> salto de línea real
  $q = $q -replace '\\r\\n\\\s*', "`n"
  $q = $q -replace '\\n\\\s*', "`n"

  # Por si vienen sin la barra de continuación
  $q = $q -replace '\\r\\n', "`n"
  $q = $q -replace '\\n', "`n"

  # Convertir escapes de comillas dobles \" -> "
  $q = $q -replace '\\"', '"'

  # Normalizar finales
  return $q.TrimEnd()
}

function Extract-QuotedScalar {
  param(
    [string[]]$Lines,
    [int]$StartIndex,
    [string]$Remainder
  )

  $rem = $Remainder.TrimStart()
  if ($rem.Length -lt 1) { return $null }

  $quote = $rem[0]
  if ($quote -ne '"' -and $quote -ne "'") { return $null }

  $sb = [System.Text.StringBuilder]::new()

  # Consumimos desde el primer carácter tras la comilla
  $current = $rem.Substring(1)
  $i = $StartIndex

  while ($true) {
    for ($p = 0; $p -lt $current.Length; $p++) {
      $ch = $current[$p]

      if ($quote -eq '"') {
        # En double-quoted, \" escapa
        if ($ch -eq '"' ) {
          $prevIsEscape = ($p -gt 0 -and $current[$p-1] -eq '\')
          if (-not $prevIsEscape) {
            # fin de string
            return $sb.ToString()
          }
        }
        [void]$sb.Append($ch)
      }
      else {
        # En single-quoted, '' representa una comilla simple; fin es ' no duplicada
        if ($ch -eq "'") {
          $nextIsAlsoQuote = ($p + 1 -lt $current.Length -and $current[$p+1] -eq "'")
          if ($nextIsAlsoQuote) {
            [void]$sb.Append("'")
            $p++ # saltar la segunda
            continue
          } else {
            return $sb.ToString()
          }
        }
        [void]$sb.Append($ch)
      }
    }

    # si no cerró en esta línea, pasamos a la siguiente
    $i++
    if ($i -ge $Lines.Length) { break }
    [void]$sb.Append("`n")
    $current = $Lines[$i]
  }

  return $sb.ToString()
}

function Extract-BlockScalar {
  param(
    [string[]]$Lines,
    [int]$HeaderIndex,
    [int]$BaseIndent
  )

  # Detectar indent real del bloque
  $contentIndent = $null
  for ($j=$HeaderIndex+1; $j -lt $Lines.Length; $j++) {
    if ($Lines[$j] -match '^\s*$') { continue }
    $leading = ($Lines[$j] -replace '^(?<sp>\s*).*$', '${sp}').Length
    if ($leading -le $BaseIndent) { return "" }
    $contentIndent = $leading
    break
  }
  if ($null -eq $contentIndent) { return "" }

  $out = New-Object System.Collections.Generic.List[string]
  for ($k=$HeaderIndex+1; $k -lt $Lines.Length; $k++) {
    $l = $Lines[$k]
    if ($l -match '^\s*$') { $out.Add(""); continue }
    $leading = ($l -replace '^(?<sp>\s*).*$', '${sp}').Length
    if ($leading -lt $contentIndent) { break }

    $out.Add($l.Substring([Math]::Min($contentIndent, $l.Length)))
  }

  ($out -join "`n").TrimEnd()
}

function Extract-QueryFromYamlRaw {
  <#
    Soporta:
      query: |-, |, |+, |2+, |2-
      query: >-, >, >+, >2+, >2-
      query: "...."  (quoted, multi-línea)
      query: '....'  (quoted, multi-línea)
  #>
  param([Parameter(Mandatory)][string]$YamlRaw)

  $lines = $YamlRaw -split "`r?`n"

  for ($i=0; $i -lt $lines.Length; $i++) {

    # Captura "query: <algo>"
    if ($lines[$i] -match '^(?<indent>\s*)query\s*:\s*(?<rest>.+)?$') {
      $indentLen = $Matches['indent'].Length
      $rest = ($Matches['rest'] ?? "").TrimEnd()

      # Caso bloque literal/folded: |... o >...
      if ($rest -match '^[\|>](\d+)?([+-])?\s*$') {
        $block = Extract-BlockScalar -Lines $lines -HeaderIndex $i -BaseIndent $indentLen
        return $block
      }

      # Caso quoted scalar: "...." o '....'
      $q = Extract-QuotedScalar -Lines $lines -StartIndex $i -Remainder $rest
      if ($null -ne $q) {
        return $q
      }

      # Caso inline simple (raro pero por si acaso)
      if (-not [string]::IsNullOrWhiteSpace($rest)) {
        return $rest.Trim()
      }
    }
  }

  return $null
}

function Convert-OneYamlToArmJson {
  param(
    [Parameter(Mandatory)][string]$InputFilePath,
    [Parameter(Mandatory)][string]$OutputFilePath
  )

  $yamlRaw = Get-Content -Path $InputFilePath -Raw -Encoding UTF8
  $y = ConvertFrom-Yaml -Yaml $yamlRaw
  if ($null -eq $y) { throw "YAML vacío o no parseable: $InputFilePath" }

  $displayName = [IO.Path]::GetFileNameWithoutExtension($InputFilePath).Trim()
  if ([string]::IsNullOrWhiteSpace($displayName)) { throw "Nombre de archivo inválido: $InputFilePath" }

  # query: primero parser, luego extractor raw (que ahora soporta quoted y block)
  $query = $null
  if ($y.PSObject.Properties.Name -contains 'query' -and -not [string]::IsNullOrWhiteSpace([string]$y.query)) {
    $query = [string]$y.query
  } else {
    $query = Extract-QueryFromYamlRaw -YamlRaw $yamlRaw
  }
  $query = Normalize-QueryText -q $query

  if ([string]::IsNullOrWhiteSpace($query)) {
    throw "No se pudo obtener 'query' (ni parseada ni por extracción raw). Archivo: $InputFilePath"
  }

  # queryFrequency/queryPeriod (defaults si faltan)
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
          displayName = $displayName
          description = (($y.description ?? "") -as [string]).TrimEnd()
          severity = $severity
          enabled = $true
          query = $query
          queryFrequency = $queryFrequency
          queryPeriod = $queryPeriod
          triggerOperator = 'GreaterThan'
          triggerThreshold = 0
          suppressionEnabled = $false
        }
      }
    )
  }

  $OutputFilePath = Ensure-OutputFilePath -InputFilePath $InputFilePath -OutputFilePath $OutputFilePath

  $outDir = Split-Path -Parent $OutputFilePath
  if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

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
