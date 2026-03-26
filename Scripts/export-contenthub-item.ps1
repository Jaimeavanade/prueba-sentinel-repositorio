#!/usr/bin/env pwsh
# scripts/export-contenthub-item.ps1
# Exporta un Content Item instalado en Sentinel y lo guarda en la estructura del repo
# compatible con Microsoft Sentinel Repositories.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ContentName,

    # Content type tal cual lo ves en el portal (opcional, pero útil si hay ambigüedad)
    [ValidateSet("", "Analytics rule", "Hunting query", "Parser", "Workbook")]
    [string] $ContentType = "",

    # Si quieres listar soluciones instaladas
    [switch] $ListInstalled
)

$ErrorActionPreference = "Stop"

function Require-Env([string]$Name) {
    if (-not $env:$Name -or [string]::IsNullOrWhiteSpace($env:$Name)) {
        throw "Falta la variable/secret '$Name'."
    }
}

function Invoke-AzRestGet([string]$Url) {
    $raw = az rest --method get --url $Url --only-show-errors
    if (-not $raw) { throw "Respuesta vacía desde az rest: $Url" }
    return ($raw | ConvertFrom-Json -Depth 100)
}

function Normalize-FileName([string]$Name) {
    # Windows/GitHub-safe
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $safe = ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } }) -join ''
    # evita espacios raros al final
    return $safe.Trim()
}

function Remove-NonDeployableFields([object]$Obj) {
    # Quita campos que suelen romper Repositories / deploy (id, etag, systemData, etc.)
    $clone = $Obj | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
    foreach ($p in @("id","etag","systemData")) {
        if ($clone.PSObject.Properties.Name -contains $p) { $clone.PSObject.Properties.Remove($p) }
    }
    return $clone
}

# Requeridos para apuntar a la instancia de Sentinel
Require-Env "AZURE_SUBSCRIPTION_ID"
Require-Env "SENTINEL_RESOURCE_GROUP"
Require-Env "SENTINEL_WORKSPACE_NAME"

$sub = $env:AZURE_SUBSCRIPTION_ID
$rg  = $env:SENTINEL_RESOURCE_GROUP
$ws  = $env:SENTINEL_WORKSPACE_NAME

# API versions
$apiSI = "2025-09-01" # SecurityInsights latest estable para estos endpoints. [4](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/alertrules)[2](https://learn.microsoft.com/en-us/rest/api/securityinsights/content-templates/list?view=rest-securityinsights-2025-09-01)
$apiWB = "2023-04-01" # Workbooks (si tu tenant exige otra, lo ajustamos)

if ($ListInstalled) {
    $packagesUrl = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/contentPackages?api-version=$apiSI"
    $pkgs = Invoke-AzRestGet $packagesUrl
    Write-Host "=== Soluciones (Content Packages) instaladas ==="
    $pkgs.value |
        Sort-Object { $_.properties.packageName } |
        Select-Object @{n="packageName";e={$_.properties.packageName}},
                      @{n="packageVersion";e={$_.properties.packageVersion}},
                      @{n="packageId";e={$_.name}} |
        Format-Table -AutoSize
    return
}

# 1) Encontrar el template instalado para deducir solución y tipo (contentKind)
$encodedName = [uri]::EscapeDataString($ContentName)
$templatesUrl = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/contentTemplates?api-version=$apiSI&`$search=$encodedName&`$top=50"
$templates = Invoke-AzRestGet $templatesUrl

$matches = @($templates.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() })

if ($matches.Count -eq 0) {
    Write-Host "No encontré un contentTemplate instalado con displayName exacto: '$ContentName'."
    $suggest = @($templates.value | Select-Object -First 10 | ForEach-Object { $_.properties.displayName })
    if ($suggest.Count -gt 0) {
        Write-Host "Sugerencias (top 10 por búsqueda aproximada):"
        $suggest | ForEach-Object { Write-Host " - $_" }
    }
    throw "No hay coincidencia exacta. Prueba a copiar/pegar el nombre exacto del portal."
}

if ($matches.Count -gt 1 -and [string]::IsNullOrWhiteSpace($ContentType)) {
    Write-Host "Hay varias coincidencias exactas para '$ContentName'. Indica ContentType en el workflow para desambiguar:"
    $matches | ForEach-Object {
        Write-Host (" - packageName: {0} | contentKind: {1}" -f $_.properties.packageName, $_.properties.contentKind)
    }
    throw "Ambigüedad: especifica ContentType."
}

# si hay varios, filtramos por contentKind según ContentType si vino informado
$template = $matches[0]
if ($matches.Count -gt 1 -and -not [string]::IsNullOrWhiteSpace($ContentType)) {
    $wantedKind =
        switch ($ContentType) {
            "Analytics rule" { "AnalyticsRule" }
            "Hunting query"  { "HuntingQuery" }
            "Parser"         { "Parser" }
            "Workbook"       { "Workbook" }
            default          { "" }
        }

    $filtered = @($matches | Where-Object { $_.properties.contentKind -eq $wantedKind })
    if ($filtered.Count -eq 1) { $template = $filtered[0] }
}

$solutionName = $template.properties.packageName
if ([string]::IsNullOrWhiteSpace($solutionName)) { $solutionName = "Standalone" }

# Normalizamos contentKind a tu nomenclatura del portal
$kind = $template.properties.contentKind
if ([string]::IsNullOrWhiteSpace($kind) -and -not [string]::IsNullOrWhiteSpace($ContentType)) {
    $kind = $ContentType
}

$normalizedType =
    switch -Regex ($kind) {
        "AnalyticsRule" { "Analytics rule" ; break }
        "HuntingQuery"  { "Hunting query"  ; break }
        "Parser"        { "Parser"        ; break }
        "Workbook"      { "Workbook"      ; break }
        default         { $ContentType }
    }

if ([string]::IsNullOrWhiteSpace($normalizedType)) {
    throw "No pude determinar el Content type. Indícalo explícitamente en el workflow (Analytics rule / Hunting query / Parser / Workbook)."
}

# 2) Exportar el recurso REAL instalado (deployable) según tipo
$exported = $null

switch ($normalizedType) {
    "Analytics rule" {
        $url = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/alertRules?api-version=$apiSI"
        $list = Invoke-AzRestGet $url
        $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
        if (-not $exported) { throw "No encontré la Analytics rule instalada (alertRules) con displayName '$ContentName'." }
        # Forzamos type válido por si viniera raro
        $exported.type = "Microsoft.SecurityInsights/alertRules"
        break
    }
    "Hunting query" {
        $url = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/huntingQueries?api-version=$apiSI"
        $list = Invoke-AzRestGet $url
        $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
        if (-not $exported) { throw "No encontré la Hunting query instalada (huntingQueries) con displayName '$ContentName'." }
        $exported.type = "Microsoft.SecurityInsights/huntingQueries"
        break
    }
    "Parser" {
        $url = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws/providers/Microsoft.SecurityInsights/parsers?api-version=$apiSI"
        $list = Invoke-AzRestGet $url
        $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
        if (-not $exported) { throw "No encontré el Parser instalado (parsers) con displayName '$ContentName'." }
        $exported.type = "Microsoft.SecurityInsights/parsers"
        break
    }
    "Workbook" {
        $url = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/workbooks?api-version=$apiWB"
        $list = Invoke-AzRestGet $url
        $exported = @($list.value | Where-Object { $_.properties.displayName -and $_.properties.displayName.ToLower() -eq $ContentName.ToLower() }) | Select-Object -First 1
        if (-not $exported) { throw "No encontré el Workbook instalado (workbooks) con displayName '$ContentName' en el RG '$rg'." }
        $exported.type = "Microsoft.Insights/workbooks"
        break
    }
    default { throw "Tipo no soportado: $normalizedType" }
}

# 3) Limpieza para Repositories (quita id/etag/systemData, etc.)
$finalObj = Remove-NonDeployableFields $exported

# 4) Carpeta destino según tu mapeo
$rootFolder =
    switch ($normalizedType) {
        "Analytics rule" { "Analytics rules" }
        "Hunting query"  { "Hunting" }
        "Parser"         { "Parsers" }
        "Workbook"       { "Workbooks" }
    }

$repoRoot = $env:GITHUB_WORKSPACE
if ([string]::IsNullOrWhiteSpace($repoRoot)) { $repoRoot = (Get-Location).Path }

$destDir = Join-Path $repoRoot $rootFolder
$destDir = Join-Path $destDir $solutionName
New-Item -ItemType Directory -Path $destDir -Force | Out-Null

$fileName = (Normalize-FileName $ContentName) + ".json"
$destPath = Join-Path $destDir $fileName

# 5) Guardar JSON (UTF-8)
($finalObj | ConvertTo-Json -Depth 200) | Out-File -FilePath $destPath -Encoding utf8

Write-Host "Export OK:"
Write-Host " - ContentName : $ContentName"
Write-Host " - ContentType : $normalizedType"
Write-Host " - Solution    : $solutionName"
Write-Host " - Path        : $destPath"

# Outputs para GitHub Actions (si se usa)
if ($env:GITHUB_OUTPUT) {
    "content_type=$normalizedType" | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    "solution_name=$solutionName"  | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
    "file_path=$destPath"          | Out-File -FilePath $env:GITHUB_OUTPUT -Append -Encoding utf8
}
