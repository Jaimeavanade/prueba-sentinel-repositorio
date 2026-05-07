#!/usr/bin/env bash
set -euo pipefail

# Requiere que el workflow exporte estas variables:
#   RESOURCE_GROUP
#   WORKSPACE_NAME
RG="${RESOURCE_GROUP:?Falta vars.RESOURCE_GROUP / env RESOURCE_GROUP}"
WS="${WORKSPACE_NAME:?Falta vars.WORKSPACE_NAME / env WORKSPACE_NAME}"

# Nombre exacto solicitado
DIAG_NAME="LAQueryLogs ${WS}"

echo "==> Suscripción activa:"
az account show --query "{name:name, id:id, tenantId:tenantId}" -o jsonc

echo "==> Obteniendo Resource ID del Log Analytics Workspace: ${WS} (RG: ${RG})"
WS_ID="$(az resource show \
  -g "${RG}" \
  -n "${WS}" \
  --resource-type "Microsoft.OperationalInsights/workspaces" \
  --query id -o tsv)"

if [[ -z "${WS_ID}" ]]; then
  echo "ERROR: No se ha encontrado el workspace '${WS}' en el RG '${RG}'."
  exit 1
fi

echo "==> Workspace ID: ${WS_ID}"

echo "==> Comprobando categorías disponibles de Diagnostic settings en el workspace..."
CATS="$(az monitor diagnostic-settings categories list --resource "${WS_ID}" --query "[].name" -o tsv || true)"
echo "    Categorías: ${CATS:-<no devuelto>}"

# Azure suele exponer la categoría como "Audit" (case-sensitive en algunos contextos).
# Nos quedamos con "Audit" siempre, que es el objetivo real.
CATEGORY="Audit"

LOGS_JSON="$(cat <<JSON
[
  {
    "category": "${CATEGORY}",
    "enabled": true,
    "retentionPolicy": { "enabled": false, "days": 0 }
  }
]
JSON
)"

echo "==> Verificando si ya existe el Diagnostic setting '${DIAG_NAME}'..."
if az monitor diagnostic-settings show --name "${DIAG_NAME}" --resource "${WS_ID}" >/dev/null 2>&1; then
  echo "    Existe. Lo recreamos para garantizar estado deseado (idempotencia simple)."
  az monitor diagnostic-settings delete --name "${DIAG_NAME}" --resource "${WS_ID}"
fi

echo "==> Creando Diagnostic setting '${DIAG_NAME}' enviando a sí mismo (workspace destino = mismo WS)..."
az monitor diagnostic-settings create \
  --name "${DIAG_NAME}" \
  --resource "${WS_ID}" \
  --workspace "${WS_ID}" \
  --logs "${LOGS_JSON}" \
  -o none

echo "==> Resultado final:"
az monitor diagnostic-settings show --name "${DIAG_NAME}" --resource "${WS_ID}" -o jsonc

echo "OK: Diagnostic setting creado/actualizado. (LAQueryLogs habilitado con categoría Audit)"
