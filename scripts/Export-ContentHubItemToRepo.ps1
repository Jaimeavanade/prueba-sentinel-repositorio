<#
.SYNOPSIS
Exporta un item del Microsoft Sentinel Content Hub (catálogo) a un ARM JSON "repo-ready" para Microsoft Sentinel Repositories.

.DESCRIPTION
- Autenticación: token ARM vía Azure CLI (az account get-access-token). Robustísimo con OIDC en GitHub Actions. [1](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={de506d0d-e4ee-4270-8873-e1ea6b67e29b}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})[2](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={76cb4b0d-c260-40b5-a696-431b5d386673}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})
- Fuente: contentProductTemplates (catálogo).
  IMPORTANTE: Evita $search y $filter en la llamada (en algunos tenants/implementaciones devuelve 400).
  Se pagina con nextLink / $skipToken y se filtra localmente en PowerShell por displayName y contentKind.
- Extrae properties.mainTemplate (o properties.packagedContent si aparece).
- Reescribe el "type" del recurso principal para Repositories:
    Analytics rules -> Microsoft.SecurityInsights/alertRules
    Hunting queries -> Microsoft.SecurityInsights/huntingQueries
    Parsers         -> Microsoft.SecurityInsights/parsers
    Workbooks       -> Microsoft.Insights/workbooks
    Playbooks       -> Microsoft.Logic/workflows
- Guarda en: <ContentType>/<SolutionName>/<ItemName>.json (UTF-8 sin BOM)

.PARAMETER CatalogTemplateId
Opcional: si conoces el templateId del catálogo (contentProductTemplates/{id}), lo usas directamente sin búsqueda.

#>

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

    [Parameter(Mandatory=$false)][string]$CatalogTemplateId = "",

    [Parameter(Mandatory=$false)][string]$ApiVersion = "2025-09-01",
    [Parameter(Mandatory=$false)][string]$OutputRoot = ".",
    [Parameter(Mandatory=$false)][switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------ Helpers (Auth/REST) ------------------------

function Get-ArmToken {
    # Patrón que ya usas en scripts de catálogo/reinstall: token ARM por az CLI. [1](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={de506d0d-e4ee-4270-8873-e1ea6b67e29b}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})[2](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={76cb4b0d-c260-40b5-a696-431b5d386673}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})
    $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
    if (-not $t -or $t.Trim().Length -lt 100) {
        throw "Token ARM inválido. Asegúrate de haber hecho azure/login (OIDC) antes."
    }
    return $t
}

function Invoke-ArmGet {
    param([Parameter(Mandatory=$true)][string]$Uri)

    $headers = @{
        Authorization = "Bearer $script:ArmToken"
        "Content-Type" = "application/json"
    }

    try {
        return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
    } catch {
        $body = $null
        try {
            if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $body = $reader.ReadToEnd()
            }
        } catch {}
        if ($body) { throw "Fallo GET. Uri=$Uri. Body=$body" }
        throw "Fallo GET. Uri=$Uri. Error=$($_.Exception.Message)"
    }
}

function Normalize-NextLink {
    <#
      Arregla nextLink cuando:
      - viene sin api-version
      - usa $SkipToken en lugar de $skipToken
    #>
    param(
        [Parameter(Mandatory=$true)][string]$NextLink,
        [Parameter(Mandatory=$true)][string]$ApiVersion
    )

    $fixed = $NextLink
    $fixed = $fixed -replace '\$SkipToken', '`$skipToken'

    if ($fixed -notmatch 'api-version=') {
        if ($fixed -match '\?') { $fixed = "$fixed&api-version=$ApiVersion" }
        else { $fixed = "$fixed?api-version=$ApiVersion" }
    }
    return $fixed
}

# ------------------------ Helpers (Mapping) ------------------------

function Get-RepoResourceTypeFromContentType {
    param([Parameter(Mandatory=$true)][string]$ContentType)

    switch ($ContentType.ToLowerInvariant()) {
        'analytics rules' { return 'Microsoft.SecurityInsights/alertRules' }
        'hunting queries' { return 'Microsoft.SecurityInsights/huntingQueries' }
        'parsers'         { return 'Microsoft.SecurityInsights/parsers' }
        'workbooks'       { return 'Microsoft.Insights/workbooks' }
        'playbooks'       { return 'Microsoft.Logic/workflows' }
        default { throw "ContentType '$ContentType' no soportado." }
    }
}

function Get-ApiContentKindFromContentType {
    param([Parameter(Mandatory=$true)][string]$ContentType)

    # contentKind en catálogo
    switch ($ContentType.ToLowerInvariant()) {
        'analytics rules' { return 'AnalyticsRule' }
        'hunting queries' { return 'HuntingQuery' }
        'parsers'         { return 'Parser' }
        'workbooks'       { return 'Workbook' }
        'playbooks'       { return 'Playbook' }
        default { throw "ContentType '$ContentType' no soportado." }
    }
}

function Update-ArmTemplateMainResourceTypeForRepositories {
    param(
        [Parameter(Mandatory=$true)][string]$ArmJson,
        [Parameter(Mandatory=$true)][string]$ContentType
    )

    $targetType = Get-RepoResourceTypeFromContentType -ContentType $ContentType
    $armObj = $ArmJson | ConvertFrom-Json -Depth 200

    if (-not $armObj.resources -or $armObj.resources.Count -eq 0) {
        throw "ARM JSON no contiene 'resources'."
    }

    # Cambiar SOLO el recurso principal, no metadata/deployments.
    $mainResource = $armObj.resources |
        Where-Object {
            $_.type -and
            $_.type -notlike '*providers/metadata*' -and
            $_.type -notlike 'Microsoft.Resources/deployments'
        } |
        Select-Object -First 1

    if (-not $mainResource) {
        throw "No se encontró un recurso principal para actualizar el 'type'."
    }

    $old = $mainResource.type
    $mainResource.type = $targetType

    Write-Host "✅ Reescrito resource type principal: '$old' -> '$targetType'"
    return ($armObj | ConvertTo-Json -Depth 200)
}

function Sanitize-FileName {
    param([Parameter(Mandatory=$true)][string]$Name)
    [System.IO.Path]::GetInvalidFileNameChars() | ForEach-Object { $Name = $Name.Replace($_,' ') }
    return $Name.Trim()
}

# ------------------------ Helpers (Catalog search) ------------------------

function Get-AllProductTemplates {
    param(
        [Parameter(Mandatory=$true)][string]$BaseUri,
        [Parameter(Mandatory=$true)][string]$ApiVersion
    )

    $items = @()

    # Primera página (SIN $search/$filter para evitar 400 en algunos entornos)
    $uri = "$BaseUri/contentProductTemplates?api-version=$ApiVersion&`$top=200"
    Write-Host "GET catalog templates (list): $uri"

    while ($true) {
        $resp = Invoke-ArmGet -Uri $uri

        if ($resp.value) {
            $items += @($resp.value)
        }

        if ($resp.nextLink) {
            $uri = Normalize-NextLink -NextLink $resp.nextLink -ApiVersion $ApiVersion
            Write-Host "GET catalog templates (next): $uri"
            continue
        }

        break
    }

    return $items
}

function Resolve-TemplateIdFromCatalog {
    param(
        [Parameter(Mandatory=$true)][string]$BaseUri,
        [Parameter(Mandatory=$true)][string]$ItemName,
        [Parameter(Mandatory=$true)][string]$ContentKind,
        [Parameter(Mandatory=$true)][string]$ApiVersion
    )

    $all = Get-AllProductTemplates -BaseUri $BaseUri -ApiVersion $ApiVersion
    if (-not $all -or $all.Count -eq 0) {
        throw "El catálogo devolvió 0 templates."
    }

    $candidates = $all | Where-Object { $_.properties -and $_.properties.contentKind -eq $ContentKind -and $_.properties.displayName }

    if (-not $candidates -or $candidates.Count -eq 0) {
        $kinds = ($all | ForEach-Object { $_.properties.contentKind } | Where-Object { $_ } | Select-Object -Unique) -join ", "
        throw "No hay templates con contentKind='$ContentKind'. Kinds devueltos: $kinds"
    }

    # Preferir match exacto (case-insensitive) y luego contains
    $exact = $candidates | Where-Object { $_.properties.displayName -ieq $ItemName } | Select-Object -First 1
    if ($exact) { return $exact.name }

    $contains = $candidates | Where-Object { $_.properties.displayName -ilike "*$ItemName*" } | Select-Object -First 1
    if ($contains) { return $contains.name }

    # fallback: el primero (para debug rápido)
    return ($candidates | Select-Object -First 1).name
}

# ------------------------ MAIN ------------------------

if ([string]::IsNullOrWhiteSpace($WorkspaceName)) { throw "WorkspaceName vacío." }
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { throw "ResourceGroup vacío." }

$script:ArmToken = Get-ArmToken

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"
$contentKind = Get-ApiContentKindFromContentType -ContentType $ContentType

$templateId = $CatalogTemplateId
if ([string]::IsNullOrWhiteSpace($templateId)) {
    $templateId = Resolve-TemplateIdFromCatalog -BaseUri $base -ItemName $ItemName -ContentKind $contentKind -ApiVersion $ApiVersion
}

Write-Host "ℹ️ TemplateId catálogo usado: $templateId"

# Obtener el template completo
$getUri = "$base/contentProductTemplates/$templateId?api-version=$ApiVersion"
Write-Host "GET catalog template (get): $getUri"
$full = Invoke-ArmGet -Uri $getUri

if (-not $full.properties) { throw "Respuesta sin properties para templateId=$templateId" }

$main = $null
if ($full.properties.PSObject.Properties.Name -contains 'mainTemplate' -and $full.properties.mainTemplate) {
    $main = $full.properties.mainTemplate
} elseif ($full.properties.PSObject.Properties.Name -contains 'packagedContent' -and $full.properties.packagedContent) {
    $main = $full.properties.packagedContent
}

if (-not $main) {
    throw "El template no trae mainTemplate ni packagedContent. templateId=$templateId"
}

# Serializar y reescribir type
$jsonString = $main | ConvertTo-Json -Depth 200
$jsonString = Update-ArmTemplateMainResourceTypeForRepositories -ArmJson $jsonString -ContentType $ContentType

# Ruta de salida
$folder1 = $ContentType
$folder2 = Sanitize-FileName $SolutionName
$file    = (Sanitize-FileName $ItemName) + ".json"

$outDir  = Join-Path $OutputRoot (Join-Path $folder1 $folder2)
$outFile = Join-Path $outDir $file

if (-not (Test-Path $outDir)) {
    [System.IO.Directory]::CreateDirectory($outDir) | Out-Null
}

if ((Test-Path $outFile) -and -not $Force) {
    throw "El archivo ya existe: $outFile (usa -Force para sobreescribir)"
}

[System.IO.File]::WriteAllText($outFile, $jsonString, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "✅ Export guardado en: $outFile"
