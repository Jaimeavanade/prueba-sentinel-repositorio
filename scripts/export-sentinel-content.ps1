param (
    [Parameter(Mandatory = $true)]
    [string]$ContentName,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName
)

Write-Host "🔐 Autenticando contra Azure..."

Connect-AzAccount `
    -ServicePrincipal `
    -Tenant $env:AZURE_TENANT_ID `
    -ApplicationId $env:AZURE_CLIENT_ID `
    -Credential (New-Object PSCredential(
        $env:AZURE_CLIENT_ID,
        (ConvertTo-SecureString $env:AZURE_CLIENT_SECRET -AsPlainText -Force)
    ))

Set-AzContext -Subscription $SubscriptionId

Write-Host "🔍 Buscando Analytics Rule: $ContentName"

$rules = Get-AzSentinelAlertRule `
    -ResourceGroupName $ResourceGroup `
    -WorkspaceName $WorkspaceName

$rule = $rules | Where-Object { $_.DisplayName -eq $ContentName }

if (-not $rule) {
    Write-Error "❌ No se encontró la Analytics Rule con nombre exacto: $ContentName"
    exit 1
}

Write-Host "✅ Regla encontrada"
Write-Host "📦 Solución Content Hub: $($rule.Properties.SolutionName)"

$solutionName = if ($rule.Properties.SolutionName) {
    $rule.Properties.SolutionName
} else {
    "UnknownSolution"
}

# Construcción del JSON compatible con Sentinel
$export = @{
    type       = "Microsoft.SecurityInsights/alertRules"
    apiVersion = "2023-02-01-preview"
    name       = $rule.Name
    properties = $rule.Properties
}

# Normalizar nombre de archivo
$sanitizedName = $ContentName -replace '[\\/:*?"<>|]', '_'

$folderPath = "Analytics rules/$solutionName"
$filePath   = "$folderPath/$sanitizedName.json"

New-Item -ItemType Directory -Force -Path $folderPath | Out-Null

$export | ConvertTo-Json -Depth 20 | Out-File -Encoding UTF8 $filePath

Write-Host "📁 Archivo exportado correctamente:"
Write-Host "➡️  $filePath"
