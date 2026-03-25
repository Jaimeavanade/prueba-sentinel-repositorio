#Requires -Version 7.2
<#
.SYNOPSIS
  Convierte reglas analíticas de Microsoft Sentinel en YAML (custom) a ARM JSON.

.DESCRIPTION
  - Lee .yaml/.yml desde Detections/Custom/YAML (por defecto)
  - Genera ARM templates JSON en Detections/Custom/ARM (por defecto)
  - Normaliza duraciones a ISO 8601 ESTRICTO en MAYÚSCULAS:
      queryFrequency, queryPeriod, suppressionDuration, lookbackDuration, etc.
  - properties.displayName (ARM) = SIEMPRE el campo 'name' del YAML
  - Construye el resource name ARM:
      [concat(parameters('workspace'), '/Microsoft.SecurityInsights/Custom-<Slug>')]

.NOTES
  Requiere el módulo powershell-yaml (ConvertFrom-Yaml).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Remove-Diacritics {
  param([Parameter(Mandatory)][string]$Text)
  $normalized = $Text.Normalize([Text.NormalizationForm]::FormD)
  $sb = [System.Text.StringBuilder]::new()
  foreach ($c in $normalized.ToCharArray()) {
    if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -ne [Globalization.UnicodeCategory]::NonSpacingMark) {
      [void]$sb.Append($c)
    }
  }
  $sb.ToString().Normalize([Text.NormalizationForm]::FormC)
}

function New-RuleSlug {
  param(
    [Parameter(Mandatory)][string]$NameFromYaml,
    [Parameter(Mandatory)][string]$InputFilePath
  )

  $base = (Remove-Diacritics $NameFromYaml).Trim()
  $base = $base -replace '[\s_]+', '-'            # espacios/underscore -> guión
  $base = $base -replace '[^A-Za-z0-9\-]', ''     # quitar caracteres raros
  $base = $base -replace '\-+', '-'               # colapsar guiones
  $base = $base.Trim('-')

  if ([string]::IsNullOrWhiteSpace($base)) {
    $base = "Rule"
  }

  # Sufijo corto determinista para evitar colisiones
  $hash = (Get-FileHash -Algorithm SHA1 -Path $InputFilePath).Hash.Substring(0,8)
  return "$base-$hash"
}

function Convert-DurationToIsoUpper {
  <#
    Acepta:
      - ISO8601 (cualquier casing) -> lo devuelve en MAYÚSCULAS
      - Formatos YAML típicos: 5m, 1h, 2d, 1h30m, 2d1h30m, 15s, 1w, 2w3d4h5m6s
    Devuelve:
      - ISO8601 ESTRICTO en MAYÚSCULAS (P..T..)
  #>
  param([AllowNull()][string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

  $v = $Value.Trim()

  # Ya parece ISO 8601 (P...) -> forzar MAYÚSCULAS
  if ($v -match '^[Pp]') {
    return $v.ToUpperInvariant()
  }

  # Normalizar sin espacios
  $compact = ($v -replace '\s+', '').ToLowerInvariant()

  # Secuencia de grupos número+unidad (w,d,h,m,s)
  if ($compact -notmatch '^(\d+[wdhms])+$') {
    throw "Duración no reconocida: '$Value' (se esperaba ISO8601 o formato tipo '5m', '1h30m', '2d1h')."
  }

  $weeks=0; $days=0; $hours=0; $mins=0; $secs=0

  [regex]::Matches($compact, '(\d+)([wdhms])') | ForEach-Object {
    $n = [int]$_.Groups[1].Value
    switch ($_.Groups[2].Value) {
      'w' { $weeks += $n }
      'd' { $days  += $n }
      'h' { $hours += $n }
      'm' { $mins  += $n }
      's' { $secs  += $n }
    }
  }

  $datePart = ""
  if ($weeks -gt 0) { $datePart += "${weeks}W" }
  if ($days  -gt 0) { $datePart += "${days}D" }

  $timePart = ""
  if ($hours -gt 0) { $timePart += "${hours}H" }
  if ($mins  -gt 0) { $timePart += "${mins}M" }
  if ($secs  -gt 0) { $timePart += "${secs}S" }

  if ([string]::IsNullOrWhiteSpace($datePart) -and [string]::IsNullOrWhiteSpace($timePart)) {
    throw "Duración inválida (vacía tras parseo): '$Value'"
  }

  $iso = "P" + $datePart
  if (-not [string]::IsNullOrWhiteSpace($timePart)) {
    $iso += "T" + $timePart
  }

  return $iso.ToUpperInvariant()
}

function Map-TriggerOperator {
  param([AllowNull()][string]$Op)
  if ([string]::IsNullOrWhiteSpace($Op)) { return $null }

  $o = $Op.Trim()
  $map = @{
    'gt' = 'GreaterThan'
    'lt' = 'LessThan'
    'eq' = 'Equal'
    'ne' = 'NotEqual'
    'GreaterThan' = 'GreaterThan'
    'LessThan'    = 'LessThan'
    'Equal'       = 'Equal'
    'NotEqual'    = 'NotEqual'
  }

  if ($map.ContainsKey($o)) { return $map[$o] }
  $lower = $o.ToLowerInvariant()
  if ($map.ContainsKey($lower)) { return $map[$lower] }
  return $o
}

function Convert-OneYamlToArmJson {
  param(
    [Parameter(Mandatory)][string]$InputFilePath,
    [Parameter(Mandatory)][string]$OutputFilePath,
    [string]$NamePrefix = "Custom-",
    [switch]$EnabledByDefault
  )

  if (-not (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)) {
    throw "No se encuentra ConvertFrom-Yaml. Instala el módulo 'powershell-yaml' (el workflow ya lo hace)."
  }

  $yamlRaw = Get-Content -Path $InputFilePath -Raw -Encoding UTF8
  $y = ConvertFrom-Yaml -Yaml $yamlRaw

  if ($null -eq $y) {
    throw "El YAML no se pudo parsear o está vacío. Archivo: $InputFilePath"
  }

  # --------------------------------------------------------------------
  # displayName ARM: SIEMPRE usar el campo 'name' del YAML (obligatorio)
  # --------------------------------------------------------------------
  $displayName = $null
  if ($y.PSObject.Properties.Name -contains 'name') {
    $displayName = [string]$y.name
  }
  if ([string]::IsNullOrWhiteSpace($displayName)) {
    throw "El YAML no contiene el campo obligatorio 'name' (requerido para asignar displayName). Archivo: $InputFilePath"
  }
  $displayName = $displayName.Trim()

  # Campos base
  $description = ""
  if ($y.PSObject.Properties.Name -contains 'description' -and $null -ne $y.description) {
    $description = ([string]$y.description).TrimEnd()
  }

  $severity = "Medium"
  if ($y.PSObject.Properties.Name -contains 'severity' -and -not [string]::IsNullOrWhiteSpace([string]$y.severity)) {
    $severity = [string]$y.severity
  }

  $query = $null
  if ($y.PSObject.Properties.Name -contains 'query') {
    $query = [string]$y.query
  }
  if ([string]::IsNullOrWhiteSpace($query)) {
    throw "El YAML no contiene 'query' (obligatorio). Archivo: $InputFilePath"
  }

  # Duraciones (ISO estricto MAYÚSCULAS)
  $queryFrequency = $null
  if ($y.PSObject.Properties.Name -contains 'queryFrequency') {
    $queryFrequency = Convert-DurationToIsoUpper ([string]$y.queryFrequency)
  }

  $queryPeriod = $null
  if ($y.PSObject.Properties.Name -contains 'queryPeriod') {
    $queryPeriod = Convert-DurationToIsoUpper ([string]$y.queryPeriod)
  }

  # enabled
  $enabled = $null
  if ($y.PSObject.Properties.Name -contains 'enabled') {
    $enabled = $y.enabled
  }
  if ($null -eq $enabled) {
    $enabled = [bool]$EnabledByDefault
  } else {
    $enabled = [bool]$enabled
  }

  # trigger
  $triggerOperator = $null
  if ($y.PSObject.Properties.Name -contains 'triggerOperator') {
    $triggerOperator = Map-TriggerOperator ([string]$y.triggerOperator)
  }

  $triggerThreshold = 0
  if ($y.PSObject.Properties.Name -contains 'triggerThreshold' -and $null -ne $y.triggerThreshold) {
    $triggerThreshold = [int]$y.triggerThreshold
  }

  # suppression
  $suppressionDuration = $null
  if ($y.PSObject.Properties.Name -contains 'suppressionDuration') {
    $suppressionDuration = Convert-DurationToIsoUpper ([string]$y.suppressionDuration)
  }

  $suppressionEnabled = $false
  if ($y.PSObject.Properties.Name -contains 'suppressionEnabled' -and $null -ne $y.suppressionEnabled) {
    $suppressionEnabled = [bool]$y.suppressionEnabled
  }

  # MITRE
  $tactics = @()
  if ($y.PSObject.Properties.Name -contains 'tactics' -and $null -ne $y.tactics) {
    $tactics = @($y.tactics)
  }

  $techniques = @()
  if ($y.PSObject.Properties.Name -contains 'techniques' -and $null -ne $y.techniques) {
    $techniques = @($y.techniques)
  } elseif ($y.PSObject.Properties.Name -contains 'relevantTechniques' -and $null -ne $y.relevantTechniques) {
    $techniques = @($y.relevantTechniques)
  }

  # ARM resource name: Custom-<slug>
  $slug = New-RuleSlug -NameFromYaml $displayName -InputFilePath $InputFilePath
  $armRuleName = "$NamePrefix$slug"

  # incidentConfiguration + lookbackDuration normalizado si existe
  $incidentConfiguration = $null
  if ($y.PSObject.Properties.Name -contains 'incidentConfiguration' -and $null -ne $y.incidentConfiguration) {
    $incidentConfiguration = $y.incidentConfiguration | ConvertTo-Json -Depth 50 | ConvertFrom-Json
    if ($null -ne $incidentConfiguration.groupingConfiguration -and
        $null -ne $incidentConfiguration.groupingConfiguration.lookbackDuration) {
      $incidentConfiguration.groupingConfiguration.lookbackDuration =
        Convert-DurationToIsoUpper ([string]$incidentConfiguration.groupingConfiguration.lookbackDuration)
    }
  } else {
    # Default razonable (similar a tu ejemplo)
    $incidentConfiguration = [pscustomobject]@{
      createIncident = $true
      groupingConfiguration = [pscustomobject]@{
        enabled = $false
        reopenClosedIncident = $false
        lookbackDuration = (Convert-DurationToIsoUpper "5h")
        matchingMethod = "AllEntities"
      }
    }
  }

  # eventGroupingSettings
  $eventGroupingSettings = $null
  if ($y.PSObject.Properties.Name -contains 'eventGroupingSettings' -and $null -ne $y.eventGroupingSettings) {
    $eventGroupingSettings = $y.eventGroupingSettings | ConvertTo-Json -Depth 50 | ConvertFrom-Json
  } else {
    $eventGroupingSettings = [pscustomobject]@{ aggregationKind = "SingleAlert" }
  }

  # entityMappings, customDetails
  $entityMappings = @()
  if ($y.PSObject.Properties.Name -contains 'entityMappings' -and $null -ne $y.entityMappings) {
    $entityMappings = @($y.entityMappings)
  }

  $customDetails = [pscustomobject]@{}
  if ($y.PSObject.Properties.Name -contains 'customDetails' -and $null -ne $y.customDetails) {
    $customDetails = $y.customDetails | ConvertTo-Json -Depth 50 | ConvertFrom-Json
  }

  # Validaciones mínimas: queryFrequency/queryPeriod obligatorios en Scheduled
  if ([string]::IsNullOrWhiteSpace($queryFrequency)) {
    throw "Falta queryFrequency (o no se pudo convertir). Archivo: $InputFilePath"
  }
  if ([string]::IsNullOrWhiteSpace($queryPeriod)) {
    throw "Falta queryPeriod (o no se pudo convertir). Archivo: $InputFilePath"
  }

  # Construir plantilla ARM
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
        name = "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/$armRuleName')]"
        kind = 'Scheduled'
        properties = [pscustomobject]@{
          displayName = $displayName
          description = $description
          severity = $severity
          enabled = $enabled
          query = $query
          queryFrequency = $queryFrequency
          queryPeriod = $queryPeriod
          triggerOperator = $triggerOperator
          triggerThreshold = $triggerThreshold
          suppressionDuration = $suppressionDuration
          suppressionEnabled = $suppressionEnabled
          tactics = $tactics
          techniques = $techniques
          incidentConfiguration = $incidentConfiguration
          eventGroupingSettings = $eventGroupingSettings
          entityMappings = $entityMappings
          customDetails = $customDetails
        }
      }
    )
  }

  # Asegurar carpeta destino
  $outDir = Split-Path -Parent $OutputFilePath
  if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

  # Serializar JSON
  $json = $template | ConvertTo-Json -Depth 100
  Set-Content -Path $OutputFilePath -Value $json -Encoding UTF8
}

function Convert-AnalyticsYamlFolderToArmJson {
  param(
    [string]$InputFolder  = "Detections/Custom/YAML",
    [string]$OutputFolder = "Detections/Custom/ARM",
    [string]$NamePrefix   = "Custom-",
    [switch]$EnabledByDefault,
    [string]$ReportPath   = "conversion_report.txt"
  )

  if (-not (Test-Path $InputFolder)) {
    throw "No existe la carpeta de entrada: $InputFolder"
  }

  $yamlFiles = @(Get-ChildItem -Path $InputFolder -Recurse -File -Include *.yaml, *.yml)
  Write-Host "Encontrados $($yamlFiles.Count) YAML(s) en '$InputFolder'"

  $ok = 0
  $fail = 0
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("Conversion report - $(Get-Date -Format o)")
  $lines.Add("InputFolder: $InputFolder")
  $lines.Add("OutputFolder: $OutputFolder")
  $lines.Add("NamePrefix: $NamePrefix")
  $lines.Add("")

  foreach ($f in $yamlFiles) {
    $inPath = $f.FullName

    # Mantener estructura relativa desde InputFolder
    $root = (Resolve-Path $InputFolder).Path
    $rel  = $inPath.Substring($root.Length).TrimStart('\','/')
    $outFile = Join-Path $OutputFolder ($rel -replace '\.ya?ml$', '.json')

    try {
      Write-Host "➡️  Procesando: $inPath"
      Convert-OneYamlToArmJson -InputFilePath $inPath -OutputFilePath $outFile -NamePrefix $NamePrefix -EnabledByDefault:$EnabledByDefault
      $ok++
      $lines.Add("OK  : $rel -> $($rel -replace '\.ya?ml$', '.json')")
    }
    catch {
      $fail++
      $lines.Add("FAIL: $rel")
      $lines.Add("      $($_.Exception.Message)")
      $lines.Add("")
      Write-Host "❌ Error en $inPath => $($_.Exception.Message)" -ForegroundColor Red
    }
  }

  $lines.Add("")
  $lines.Add("SUMMARY: OK=$ok FAIL=$fail TOTAL=$($yamlFiles.Count)")
  Set-Content -Path $ReportPath -Value ($lines -join [Environment]::NewLine) -Encoding UTF8

  if ($fail -gt 0) {
    throw "Conversión finalizada con errores. Revisa '$ReportPath' (FAIL=$fail)."
  }

  Write-Host "✅ Conversión completada: OK=$ok / TOTAL=$($yamlFiles.Count). Report: $ReportPath"
}

# Permite ejecutar el script directamente sin importar funciones
if ($MyInvocation.InvocationName -ne '.') {
  Convert-AnalyticsYamlFolderToArmJson
}
