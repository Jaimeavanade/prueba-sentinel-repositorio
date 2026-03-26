<#
.SYNOPSIS
Exporta un item del Content Hub (catálogo) a un ARM JSON "repo-ready"
compatible con Microsoft Sentinel Repositories.

.DESCRIPTION
- Lista contentProductTemplates SIN usar $search ni $filter (evita 400).
- Filtra en PowerShell por displayName + contentKind.
- Obtiene properties.mainTemplate (o packagedContent).
- Reescribe el resource "type" al formato esperado por Repositories.
- Guarda en <ContentType>/<SolutionName>/<ItemName>.json
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

    [Parameter(Mandatory=$false)][string]$ApiVersion = "2025-09-01",
    [Parameter(Mandatory=$false)][string]$OutputRoot = ".",
    [Parameter(Mandatory=$false)][switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-ArmToken {
    $t = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
    if (-not $t -or $t.Length -lt 100) {
        throw "Token ARM inválido. Revisa azure/login (OIDC)."
    }
    return $t
}

function Invoke-ArmGet {
    param([string]$Uri)

    $headers = @{
        Authorization = "Bearer $script:ArmToken"
        "Content-Type" = "application/json"
    }

    try {
        return Invoke-RestMethod -Method GET -Uri $Uri -Headers $headers
    } catch {
        throw "Fallo GET. Uri=$Uri. Error=$($_.Exception.Message)"
    }
}

function Get-RepoResourceTypeFromContentType {
    switch ($ContentType.ToLowerInvariant()) {
        'analytics rules' { 'Microsoft.SecurityInsights/alertRules' }
        'hunting queries' { 'Microsoft.SecurityInsights/huntingQueries' }
        'parsers'         { 'Microsoft.SecurityInsights/parsers' }
        'workbooks'       { 'Microsoft.Insights/workbooks' }
        'playbooks'       { 'Microsoft.Logic/workflows' }
    }
}

function Get-ApiContentKindFromContentType {
    switch ($ContentType.ToLowerInvariant()) {
        'analytics rules' { 'AnalyticsRule' }
        'hunting queries' { 'HuntingQuery' }
        'parsers'         { 'Parser' }
        'workbooks'       { 'Workbook' }
        'playbooks'       { 'Playbook' }
    }
}

function Update-ArmTemplateMainResourceType {
    param([string]$Json)

    $arm = $Json | ConvertFrom-Json -Depth 200
    $targetType = Get-RepoResourceTypeFromContentType

    $res = $arm.resources |
        Where-Object {
            $_.type -and
            $_.type -notlike '*providers/metadata*' -and
            $_.type -notlike 'Microsoft.Resources/deployments'
        } |
        Select-Object -First 1

    if (-not $res) {
        throw "No se encontró recurso principal para cambiar el type."
    }

    $res.type = $targetType
    return ($arm | ConvertTo-Json -Depth 200)
}

function Sanitize-Name($s) {
    [IO.Path]::GetInvalidFileNameChars() | ForEach-Object { $s = $s.Replace($_,' ') }
    $s.Trim()
}

# ---------------- MAIN ----------------

$script:ArmToken = Get-ArmToken

$base = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"
$kind = Get-ApiContentKindFromContentType

$listUri = "$base/contentProductTemplates?api-version=$ApiVersion&`$top=200"
Write-Host "GET templates catalog: $listUri"

$list = Invoke-ArmGet -Uri $listUri

$candidates = $list.value |
    Where-Object {
        $_.properties.contentKind -eq $kind -and
        $_.properties.displayName
    }

$match = $candidates |
    Where-Object { $_.properties.displayName -eq $ItemName } |
    Select-Object -First 1

if (-not $match) {
    throw "No se encontró template con displayName='$ItemName' y contentKind='$kind'."
}

$templateId = $match.name
Write-Host "TemplateId seleccionado: $templateId"

$getUri = "$base/contentProductTemplates/$templateId?api-version=$ApiVersion"
$tpl = Invoke-ArmGet -Uri $getUri

$main = $tpl.properties.mainTemplate
if (-not $main) {
    throw "El template no contiene mainTemplate."
}

$json = $main | ConvertTo-Json -Depth 200
$json = Update-ArmTemplateMainResourceType -Json $json

$outDir = Join-Path $OutputRoot (Join-Path $ContentType (Sanitize-Name $SolutionName))
$outFile = Join-Path $outDir ((Sanitize-Name $ItemName) + ".json")

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

if ((Test-Path $outFile) -and -not $Force) {
    throw "El archivo ya existe: $outFile"
}

[IO.File]::WriteAllText($outFile, $json, (New-Object Text.UTF8Encoding($false)))

Write-Host "✅ Export generado: $outFile"
