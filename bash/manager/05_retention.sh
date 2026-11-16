#!/usr/bin/env bash
# 05_retention.sh — suppression automatique des alertes anciennes (politique ISM de l'indexer)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf
URL="https://${MANAGER_IP}:9200"

body=$(cat <<JSON
{"policy":{"description":"Wazuh : suppression des alertes apres ${RETENTION_DAYS} jours",
 "default_state":"hot",
 "states":[
  {"name":"hot","actions":[],"transitions":[{"state_name":"delete","conditions":{"min_index_age":"${RETENTION_DAYS}d"}}]},
  {"name":"delete","actions":[{"delete":{}}],"transitions":[]}],
 "ism_template":[{"index_patterns":["wazuh-alerts-4.x-*","wazuh-archives-4.x-*"],"priority":100}]}}
JSON
)
log_info "Création de la politique de rétention (${RETENTION_DAYS} jours)"
resp=$(indexer_curl -X PUT "$URL/_plugins/_ism/policies/wazuh-retention" -H 'Content-Type: application/json' -d "$body")
echo "$resp" | grep -q '"_id"\|already exists' || { echo "$resp"; die "Création de la politique échouée"; }
log_info "Application aux index existants"
indexer_curl -X POST "$URL/_plugins/_ism/add/wazuh-alerts-4.x-*" -H 'Content-Type: application/json' -d '{"policy_id":"wazuh-retention"}' | head -c 300; echo
log_ok "Rétention active. Vérifier : Dashboard > Index Management > Policies"
