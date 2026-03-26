<#
.SYNOPSIS
Exporta un item desde Microsoft Sentinel (plantilla/artefacto) a un ARM JSON “repo-ready”
reescribiendo el resource "type" principal para que sea compatible con Microsoft Sentinel Repositories.

.DESCRIPTION
- Requiere que el workflow haya hecho azure/login con enable-AzPSSession: true
- Descarga el recurso vía ARM REST
- Reescribe SOLO el "type" del recurso principal (no metadata)
- Guarda el JSON en <ContentType>/<SolutionName>/<ItemName>.json con UTF-8 sin BOM

MAPEO DE TYPES (repo-ready):
Analytics rules -> Microsoft.SecurityInsights/alertRules
Hunting queries -> Microsoft.SecurityInsights/huntingQueries
Parsers         -> Microsoft.SecurityInsights/parsers
Workbooks       -> Microsoft.Insights/workbooks
Playbooks       -> Microsoft.Logic/workflows

NOTA: En tu JSON exportado aparece también un type de metadata que no debemos tocar. [2]()
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Analytics rules","Hunting queries","Parsers","Workbooks","Playbooks")]
    [string]$ContentType,

    [Parameter(Mandatory = $true)]
    [string]$SolutionName,

    [Parameter(Mandatory = $true)]
    [string]$ItemName,

    # Debe ser el path relativo bajo providers/Microsoft.SecurityInsights/
    # Ejemplos típicos:
    #   AlertRuleTemplates/<id>
    #   HuntingQueryTemplates/<id>
    #   ParserTemplates/<id>
    #   WorkbookTemplates/<id>
    #   AutomationRules/<id>  (si lo usas)
    [Parameter(Mandatory = $true)]
    [string]$TemplateId,

    [Parameter(Mandatory = $false)]
    [string]$ApiVersion = "2023-11-01-preview",

    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = ".",

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-RepoResourceTypeFromContentType {
    param([Parameter(Mandatory=$true)][string]$ContentType)

    switch ($ContentType.ToLowerInvariant()) {
        'analytics rules' { return 'Microsoft.SecurityInsights/alertRules' }
        'hunting queries' { return 'Microsoft.SecurityInsights/huntingQueries' }
        'parsers'         { return 'Microsoft.SecurityInsights/parsers' }
        'workbooks'       { return 'Microsoft.Insights/workbooks' }
        'playbooks'       { return 'Microsoft.Logic/workflows' }
        default { throw "ContentType '$ContentType' no soportado para mapear resource type." }
    }
}

function Get-ArmToken {
    try {
        $ctx = Get-AzContext
        if (-not $ctx) { throw "No hay contexto Az. ¿Has ejecutado azure/login con enable-AzPSSession?" }

        $tok = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
        if ([string]::IsNullOrWhiteSpace($tok)) { throw "Token ARM vacío" }
        return $tok
    } catch {
        throw "No se pudo obtener token ARM con Az. Detalle: $($_.Exception.Message)"
    }
}

function Invoke-ArmRest {
    param(
        [Parameter(Mandatory=$true)][ValidateSet("GET","PUT","POST","DELETE")][string]$Method,
        [Parameter(Mandatory=$true)][string]$Uri
    )

    $headers = @{
        Authorization = "Bearer $script:ArmToken"
        "Content-Type" = "application/json"
    }

    try {
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    } catch {
        $body = $null
        try {
            if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $body = $reader.ReadToEnd()
            }
        } catch {}

        if ($body) { throw "Fallo REST ($Method) Uri=$Uri Body=$body" }
        throw "Fallo REST ($Method) Uri=$Uri Error=$($_.Exception.Message)"
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
        throw "ARM JSON no contiene 'resources'. No se puede actualizar el type."
    }

    # En tu ejemplo hay un recurso de metadata "Microsoft.OperationalInsights/workspaces/providers/metadata" que NO se toca. [2]()
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

# ---------------- Main ----------------

if ([string]::IsNullOrWhiteSpace($WorkspaceName)) {
    throw "WorkspaceName vacío. Revisa vars.WORKSPACE_NAME en GitHub Actions."
}

$script:ArmToken = Get-ArmToken

# ✅ FIX CRÍTICO: usar ${TemplateId} para evitar que PowerShell intente leer $TemplateId?api
# Este es EXACTAMENTE el error que te sale en el job #25. [1](https://avanade-my.sharepoint.com/personal/j_velazquez_santos_avanade_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={dcde3f4e-f42d-4456-93b2-470a520e4bb2}&wd=target%28/Segittur.one/%29&wdpartid={69559b1d-d9a0-48f2-888f-ee1a91c8e801}{1}&wdsectionfileid={cfe6086a-3179-430a-9536-53117009c186})
$templateUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/${TemplateId}?api-version=$ApiVersion"

Write-Host "GET template: $templateUri"
$template = Invoke-ArmRest -Method GET -Uri $templateUri

$jsonString = $template | ConvertTo-Json -Depth 200

# Reescribir type a repo-ready
$jsonString = Update-ArmTemplateMainResourceTypeForRepositories -ArmJson $jsonString -ContentType $ContentType

# Construir ruta de salida
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
