<#
.SYNOPSIS
Exporta un item del Content Hub (template) a un ARM JSON en formato compatible con Microsoft Sentinel Repositories,
reescribiendo el resource "type" del recurso principal según el tipo de contenido.

.DESCRIPTION
- Obtiene token ARM (requiere que el workflow haya hecho azure/login con enable-AzPSSession: true)
- Descarga el contenido del item (ARM template) desde Azure Management REST
- Guarda el JSON en la ruta del repo
- Reescribe el "type" del recurso principal:
    Analytics rules -> Microsoft.SecurityInsights/alertRules
    Hunting queries -> Microsoft.SecurityInsights/huntingQueries
    Parsers         -> Microsoft.SecurityInsights/parsers
    Workbooks       -> Microsoft.Insights/workbooks
    Playbooks       -> Microsoft.Logic/workflows

.NOTES
- No modifica recursos de metadata tipo:
  Microsoft.OperationalInsights/workspaces/providers/metadata
- En tu JSON exportado se ven ambos types (principal template + metadata), por eso se filtra. [1]()
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName,

    # Tipo de contenido (tal cual nombre de carpeta):
    # "Analytics rules", "Hunting queries", "Parsers", "Workbooks", "Playbooks"
    [Parameter(Mandatory = $true)]
    [ValidateSet("Analytics rules","Hunting queries","Parsers","Workbooks","Playbooks")]
    [string]$ContentType,

    # Nombre de solución (ej: "Azure Key Vault") para carpeta de segundo nivel
    [Parameter(Mandatory = $true)]
    [string]$SolutionName,

    # Nombre del item/plantilla (ej: "Mass secret retrieval from Azure Key Vault")
    [Parameter(Mandatory = $true)]
    [string]$ItemName,

    # Identificador del item en Content Hub.
    # Puedes usar: templateId / contentId / name según tu flujo.
    # Este script asume que es el "name" del recurso template (último segmento del URI).
    [Parameter(Mandatory = $true)]
    [string]$TemplateId,

    # API version para SecurityInsights (ajusta si usas otra)
    [Parameter(Mandatory = $false)]
    [string]$ApiVersion = "2023-11-01-preview",

    # Root de salida en el repo (por defecto, el propio repo)
    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = ".",

    # Si quieres sobreescribir sin preguntar
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
    # Intenta obtener token desde Az (azure/login con enable-AzPSSession)
    try {
        $ctx = Get-AzContext
        if (-not $ctx) { throw "No hay contexto Az. ¿Has ejecutado azure/login con enable-AzPSSession?" }
        $tok = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
        if ([string]::IsNullOrWhiteSpace($tok)) { throw "Token vacío" }
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
        if ($body) {
            throw "Fallo REST ($Method) Uri=$Uri Body=$body"
        }
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

    # NO tocar metadata. En tu JSON exportado aparece "Microsoft.OperationalInsights/workspaces/providers/metadata". [1]()
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
    $Name = $Name.Trim()
    return $Name
}

# ---------------- Main ----------------
$script:ArmToken = Get-ArmToken

# URI para obtener el template del Content Hub.
# Nota: el endpoint exacto puede variar según tu enfoque.
# Este ejemplo asume que estás exportando un "AlertRuleTemplate / HuntingQueryTemplate / ParserTemplate / WorkbookTemplate / PlaybookTemplate"
# desde la workspace (no del catálogo). Si tú lo sacas del catálogo, ajusta aquí el endpoint.
$templateUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/$TemplateId?api-version=$ApiVersion"

Write-Host "GET template: $templateUri"
$template = Invoke-ArmRest -Method GET -Uri $templateUri

# Convertimos a JSON (con suficiente profundidad)
$jsonString = $template | ConvertTo-Json -Depth 200

# Reescribe el type del recurso principal al formato repo-friendly
$jsonString = Update-ArmTemplateMainResourceTypeForRepositories -ArmJson $jsonString -ContentType $ContentType

# Construye ruta:
# <ContentType>/<SolutionName>/<ItemName>.json
$folder1 = $ContentType
$folder2 = Sanitize-FileName $SolutionName
$file   = (Sanitize-FileName $ItemName) + ".json"

$outDir  = Join-Path $OutputRoot (Join-Path $folder1 $folder2)
$outFile = Join-Path $outDir $file

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

if ((Test-Path $outFile) -and -not $Force) {
    throw "El archivo ya existe: $outFile (usa -Force para sobreescribir)"
}

# Guardar con UTF8 sin BOM (recomendado para repos)
[System.IO.File]::WriteAllText($outFile, $jsonString, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "✅ Export guardado en: $outFile"
