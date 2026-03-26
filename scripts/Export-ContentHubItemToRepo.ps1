<#
.SYNOPSIS
Exporta un item del Content Hub (catálogo) a un ARM JSON "repo-ready" para Microsoft Sentinel Repositories.
- Busca el template en contentProductTemplates (catálogo) por displayName
- Extrae properties.mainTemplate (o packagedContent)
- Reescribe el "type" del recurso principal para que sea compatible con Repositories
- Guarda en <ContentType>/<SolutionName>/<ItemName>.json

.NOTES
- Token ARM vía Azure CLI (az account get-access-token), robusto con OIDC en GitHub Actions. [1](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={de506d0d-e4ee-4270-8873-e1ea6b67e29b}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})[2](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={76cb4b0d-c260-40b5-a696-431b5d386673}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})
- Se evita $filter en contentProductTemplates porque provoca 400 Bad Request (como en tu job #27). 
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SubscriptionId,
    [Parameter(Mandatory=$true)][string]$ResourceGroup,
    [Parameter(Mandatory=$true)][string]$WorkspaceName,

    # Nombre de carpeta en repo:
    [Parameter(Mandatory=$true)]
    [ValidateSet("Analytics rules","Hunting queries","Parsers","Workbooks","Playbooks")]
    [string]$ContentType,

    # Carpeta solución en repo (p.e. "Azure Key Vault")
    [Parameter(Mandatory=$true)][string]$SolutionName,

    # DisplayName del item (p.e. "Mass secret retrieval from Azure Key Vault")
    [Parameter(Mandatory=$true)][string]$ItemName,

    # Opcional: si ya conoces el templateId del catálogo, pásalo y se salta la búsqueda
    [Parameter(Mandatory=$false)][string]$CatalogTemplateId = "",

    # API version Sentinel
    [Parameter(Mandatory=$false)][string]$ApiVersion = "2025-09-01",

    # Root salida repo
    [Parameter(Mandatory=$false)][string]$OutputRoot = ".",

    [Parameter(Mandatory=$false)][switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
    # Patrón robusto usado en scripts internos de Content Hub catálogo/reinstall. [1](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={de506d0d-e4ee-4270-8873-e1ea6b67e29b}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})[2](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={76cb4b0d-c260-40b5-a696-431b5d386673}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})
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

    # contentKind en APIs de Sentinel (catálogo)
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

    # No tocar metadata (en tus exports aparece un resource de metadata aparte).
    $mainResource = $armObj.resources |
        Where-Object {
            $_.type -and
            $_.type -ne 'Microsoft.OperationalInsights/workspaces/providers/metadata' -and
            $_.type -notlike '*providers/metadata' -and
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
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($c in $invalid) { $Name = $Name.Replace($c, ' ') }
    return $Name.Trim()
}

function Find-CatalogTemplateIdByDisplayName {
    param(
        [Parameter(Mandatory=$true)][string]$BaseUri,
        [Parameter(Mandatory=$true)][string]$ItemName,
        [Parameter(Mandatory=$true)][string]$ContentKind,
        [Parameter(Mandatory=$true)][string]$ApiVersion
    )

    $search = [System.Uri]::EscapeDataString($ItemName)

    # ✅ IMPORTANTE: NO usar $filter en contentProductTemplates. En tu job dio 400 con ese filtro. 
    $listUri = "$BaseUri/contentProductTemplates?api-version=$ApiVersion&`$search=$search&`$top=200"
    Write-Host "GET catalog templates (list): $listUri"

    $list = Invoke-ArmGet -Uri $listUri

    if (-not $list.value -or $list.value.Count -eq 0) {
        throw "No se encontraron templates en el catálogo para '$ItemName'."
    }

    # ✅ Filtrar por contentKind en PowerShell (evita 400)
    $candidates = $list.value | Where-Object { $_.properties.contentKind -eq $ContentKind }

    if (-not $candidates -or $candidates.Count -eq 0) {
        # Debug útil
        $kinds = ($list.value | Select-Object -ExpandProperty properties | Select-Object -ExpandProperty contentKind -Unique) -join ", "
        throw "Se encontró '$ItemName' pero ningún template con contentKind='$ContentKind'. Kinds devueltos: $kinds"
    }

    # Match exacto por displayName
    $exact = $candidates | Where-Object { $_.properties.displayName -eq $ItemName } | Select-Object -First 1
    if ($exact) { return $exact.name }

    # Match parcial
    $contains = $candidates | Where-Object { $_.properties.displayName -like "*$ItemName*" } | Select-Object -First 1
    if ($contains) { return $contains.name }

    # Fallback
    return ($candidates | Select-Object -First 1).name
}

# -------------------- MAIN --------------------
if ([string]::IsNullOrWhiteSpace($WorkspaceName)) { throw "WorkspaceName vacío." }
if ([string]::IsNullOrWhiteSpace($ResourceGroup)) { throw "ResourceGroup vacío." }

$script:ArmToken = Get-ArmToken

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"
$kind = Get-ApiContentKindFromContentType -ContentType $ContentType

$templateId = $CatalogTemplateId
if ([string]::IsNullOrWhiteSpace($templateId)) {
    $templateId = Find-CatalogTemplateIdByDisplayName -BaseUri $base -ItemName $ItemName -ContentKind $kind -ApiVersion $ApiVersion
}

# Get por ID del catálogo
$getUri = "$base/contentProductTemplates/$templateId?api-version=$ApiVersion"
Write-Host "GET catalog template (get): $getUri"
$full = Invoke-ArmGet -Uri $getUri

$p = $full.properties
if (-not $p) { throw "Respuesta sin properties para templateId=$templateId" }

# mainTemplate es lo estándar; packagedContent puede venir en algunos casos
$main = $null
if ($p.PSObject.Properties.Name -contains 'mainTemplate' -and $p.mainTemplate) {
    $main = $p.mainTemplate
} elseif ($p.PSObject.Properties.Name -contains 'packagedContent' -and $p.packagedContent) {
    $main = $p.packagedContent
}

if (-not $main) {
    throw "El template no trae mainTemplate ni packagedContent. templateId=$templateId"
}

$jsonString = $main | ConvertTo-Json -Depth 200

# Reescribir type a repo-ready
$jsonString = Update-ArmTemplateMainResourceTypeForRepositories -ArmJson $jsonString -ContentType $ContentType

# Ruta destino
$folder1 = $ContentType
$folder2 = Sanitize-FileName $SolutionName
$file    = (Sanitize-FileName $ItemName) + ".json"

$outDir  = Join-Path $OutputRoot (Join-Path $folder1 $folder2)
$outFile = Join-Path $outDir $file

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

if ((Test-Path $outFile) -and -not $Force) {
    throw "El archivo ya existe: $outFile (usa -Force para sobreescribir)"
}

# Guardar UTF-8 sin BOM
[System.IO.File]::WriteAllText($outFile, $jsonString, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "✅ Export guardado en: $outFile"
Write-Host "ℹ️ TemplateId catálogo usado: $templateId"
