[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SubscriptionId,
    [Parameter(Mandatory=$true)][string]$ResourceGroup,
    [Parameter(Mandatory=$true)][string]$WorkspaceName,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Analytics rules","Hunting queries","Parsers","Workbooks","Playbooks")]
    [string]$ContentType,

    [Parameter(Mandatory=$true)][string]$SolutionName,
    [Parameter(Mandatory=$true)][string]$ItemName,

    [string]$ApiVersion = "2025-09-01",
    [string]$OutputRoot = ".",
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------- VALIDACIONES ----------
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) {
    throw "ResourceGroup vacío. Revisa vars.RESOURCE_GROUP."
}
if ([string]::IsNullOrWhiteSpace($WorkspaceName)) {
    throw "WorkspaceName vacío. Revisa vars.WORKSPACE_NAME."
}

Write-Host "ResourceGroup : $ResourceGroup"
Write-Host "WorkspaceName: $WorkspaceName"
Write-Host "ContentType  : $ContentType"
Write-Host "SolutionName : $SolutionName"
Write-Host "ItemName     : $ItemName"
Write-Host "ApiVersion   : $ApiVersion"

# ---------- AUTH ----------
$token = az account get-access-token `
    --resource https://management.azure.com/ `
    --query accessToken -o tsv

if (-not $token -or $token.Length -lt 100) {
    throw "No se pudo obtener token ARM."
}

$headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
}

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"

# ---------- MAPEOS ----------
$typeMap = @{
    "analytics rules" = "Microsoft.SecurityInsights/alertRules"
    "hunting queries" = "Microsoft.SecurityInsights/huntingQueries"
    "parsers"         = "Microsoft.SecurityInsights/parsers"
    "workbooks"       = "Microsoft.Insights/workbooks"
    "playbooks"       = "Microsoft.Logic/workflows"
}

$targetType = $typeMap[$ContentType.ToLowerInvariant()]
if (-not $targetType) { throw "No hay mapeo para ContentType='$ContentType'." }

# Tipos “template” típicos dentro del packagedContent ARM (para poder encontrarlos)
$templateTypeHints = @{
    "analytics rules" = @("Microsoft.SecurityInsights/AlertRuleTemplates","Microsoft.SecurityInsights/alertRuleTemplates","AlertRuleTemplates")
    "hunting queries" = @("Microsoft.SecurityInsights/HuntingQuery","Microsoft.SecurityInsights/huntingQueries","Hunting")
    "parsers"         = @("Microsoft.SecurityInsights/Parsers","Microsoft.SecurityInsights/parsers","Parser")
    "workbooks"       = @("Microsoft.Insights/workbooks","workbooks")
    "playbooks"       = @("Microsoft.Logic/workflows","workflows","Logic")
}

# ---------- 1) LISTAR PAQUETES (SIN ODATA) ----------
$listUri = "$base/contentProductPackages?api-version=$ApiVersion"
Write-Host "GET $listUri"

$packages = Invoke-RestMethod -Method GET -Uri $listUri -Headers $headers

$solution = $packages.value |
    Where-Object {
        $_.properties.contentKind -eq "Solution" -and
        $_.properties.displayName -eq $SolutionName
    } |
    Select-Object -First 1

if (-not $solution) {
    $names = ($packages.value | Where-Object { $_.properties.contentKind -eq "Solution" } | ForEach-Object { $_.properties.displayName }) -join " | "
    throw "No se encontró la solución '$SolutionName'. Disponibles: $names"
}

$packageId = $solution.name
Write-Host "Solución encontrada → packageId=$packageId"

# ---------- 2) GET DEL PAQUETE ----------
# ✅ IMPORTANTE: ${packageId} antes de ?api-version evita el bug '$packageId?api'
$getPkgUri = "$base/contentProductPackages/${packageId}?api-version=$ApiVersion"
Write-Host "GET $getPkgUri"

$pkg = Invoke-RestMethod -Method GET -Uri $getPkgUri -Headers $headers

$pc = $pkg.properties.packagedContent
if (-not $pc) {
    throw "packagedContent vacío para '$SolutionName'"
}

# ---------- 3) DETECTAR FORMA DE packagedContent ----------
function Has-Prop($obj, $name) {
    return ($null -ne $obj) -and ($obj.PSObject.Properties.Name -contains $name)
}

$exportTemplateObj = $null

# Caso B: packagedContent es un ARM template (tiene resources)
if (Has-Prop $pc "resources") {
    Write-Host "packagedContent detectado como ARM template (tiene resources)."

    $resources = @($pc.resources)
    if (-not $resources -or $resources.Count -eq 0) {
        throw "El ARM packagedContent no trae resources."
    }

    # Buscar recurso objetivo por displayName
    $wanted = $resources | Where-Object {
        (Has-Prop $_ "properties") -and
        (Has-Prop $_.properties "displayName") -and
        ($_.properties.displayName -eq $ItemName)
    } | Select-Object -First 1

    if (-not $wanted) {
        # Fallback contains
        $wanted = $resources | Where-Object {
            (Has-Prop $_ "properties") -and
            (Has-Prop $_.properties "displayName") -and
            ($_.properties.displayName -like "*$ItemName*")
        } | Select-Object -First 1
    }

    if (-not $wanted) {
        $sample = ($resources | Where-Object { Has-Prop $_ "properties" -and (Has-Prop $_.properties "displayName") } |
            Select-Object -First 30 | ForEach-Object { $_.properties.displayName }) -join " | "
        throw "No se encontró item '$ItemName' dentro del ARM. Ejemplos (top 30): $sample"
    }

    # Mantener metadata si existe en el template (para no romper esquema si viene)
    $metadata = $resources | Where-Object { $_.type -like "*providers/metadata*" }

    $newResources = @()
    if ($metadata) { $newResources += @($metadata) }
    $newResources += $wanted

    # Clonar plantilla base y quedarnos solo con los recursos necesarios
    $exportTemplateObj = $pc | ConvertTo-Json -Depth 200 | ConvertFrom-Json -Depth 200
    $exportTemplateObj.resources = @($newResources)

    # Reescribir type del recurso principal (NO metadata)
    $mainRes = @($exportTemplateObj.resources | Where-Object { $_.type -notlike "*providers/metadata*" } | Select-Object -First 1)
    if (-not $mainRes -or $mainRes.Count -eq 0) { throw "No se pudo localizar el recurso principal tras filtrar resources." }

    $oldType = $mainRes[0].type
    $mainRes[0].type = $targetType
    Write-Host "Type reescrito: '$oldType' -> '$targetType'"

} else {
    # Caso A: packagedContent es una lista (enumerable)
    Write-Host "packagedContent NO tiene 'resources'. Se intentará tratar como lista de items."

    $items = @($pc)
    if (-not $items -or $items.Count -eq 0) {
        throw "packagedContent no es ARM y no es lista usable."
    }

    # Buscar item por properties.displayName (si existe)
    $item = $items |
        Where-Object { Has-Prop $_ "properties" -and Has-Prop $_.properties "displayName" -and $_.properties.displayName -eq $ItemName } |
        Select-Object -First 1

    if (-not $item) {
        $item = $items |
            Where-Object { Has-Prop $_ "properties" -and Has-Prop $_.properties "displayName" -and $_.properties.displayName -like "*$ItemName*" } |
            Select-Object -First 1
    }

    if (-not $item) {
        throw "No se encontró el item '$ItemName' en la lista de packagedContent."
    }

    # mainTemplate
    $main = $null
    if (Has-Prop $item.properties "mainTemplate" -and $item.properties.mainTemplate) {
        $main = $item.properties.mainTemplate
    } elseif (Has-Prop $item.properties "packagedContent" -and $item.properties.packagedContent) {
        $main = $item.properties.packagedContent
    }

    if (-not $main) {
        throw "El item '$ItemName' no tiene mainTemplate ni packagedContent."
    }

    # Convertir a ARM y reescribir type del recurso principal
    $exportTemplateObj = $main | ConvertTo-Json -Depth 200 | ConvertFrom-Json -Depth 200

    if (-not (Has-Prop $exportTemplateObj "resources") -or -not $exportTemplateObj.resources) {
        throw "mainTemplate no parece un ARM template (sin resources)."
    }

    $mainRes = $exportTemplateObj.resources | Where-Object { $_.type -notlike "*providers/metadata*" } | Select-Object -First 1
    if (-not $mainRes) { throw "No se encontró recurso principal en resources." }

    $oldType = $mainRes.type
    $mainRes.type = $targetType
    Write-Host "Type reescrito: '$oldType' -> '$targetType'"
}

if (-not $exportTemplateObj) {
    throw "No se generó el ARM template final a exportar."
}

# ---------- 4) GUARDAR ----------
$outDir  = Join-Path $OutputRoot (Join-Path $ContentType $SolutionName)
$outFile = Join-Path $outDir ($ItemName + ".json")

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

if ((Test-Path $outFile) -and -not $Force) {
    throw "El archivo ya existe: $outFile (usa Force=true)."
}

$exportTemplateObj | ConvertTo-Json -Depth 200 |
    Out-File -FilePath $outFile -Encoding utf8 -Force

Write-Host "✅ Export OK → $outFile"
