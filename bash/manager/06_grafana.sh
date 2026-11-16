#!/usr/bin/env bash
# 06_grafana.sh — Grafana + plugin OpenSearch + utilisateur indexer lecture seule + dashboard
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf
[[ "$GRAFANA_ENABLE" == "true" ]] || { log_warn "GRAFANA_ENABLE=false : étape ignorée."; exit 0; }
IDX="https://${MANAGER_IP}:9200"
PLUGIN="grafana-opensearch-datasource"

# ---- 1. Installation ----
if ! systemctl list-unit-files | grep -q '^grafana-server'; then
  apt-get install -y apt-transport-https wget gpg >/dev/null
  mkdir -p /etc/apt/keyrings
  wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor > /etc/apt/keyrings/grafana.gpg
  echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
  apt-get update -qq; apt-get install -y grafana >/dev/null
fi

# ---- 2. Plugin (voir docs/DEPANNAGE pour le mode hors-ligne) ----
if [[ ! -d /var/lib/grafana/plugins/$PLUGIN ]]; then
  grafana-cli plugins install "$PLUGIN" || die "Plugin non installable (réseau bloqué ?). Voir la documentation, section Dépannage."
fi

# ---- 3. Mot de passe admin Grafana (plus de admin/admin) ----
GPW="$(secret_get GRAFANA_ADMIN_PASSWORD || true)"
[[ -n "$GPW" ]] || { GPW="$(gen_password)"; secret_set GRAFANA_ADMIN_PASSWORD "$GPW"; }
systemctl enable --now grafana-server; sleep 5
grafana-cli admin reset-admin-password "$GPW" >/dev/null

# ---- 4. Utilisateur indexer en LECTURE SEULE pour Grafana ----
RO_PW="$(secret_get GRAFANA_RO_PASSWORD || true)"
[[ -n "$RO_PW" ]] || { RO_PW="$(gen_password)"; secret_set GRAFANA_RO_PASSWORD "$RO_PW"; }
indexer_curl -X PUT "$IDX/_plugins/_security/api/roles/grafana_read" -H 'Content-Type: application/json' -d \
 '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["wazuh-alerts-*"],"allowed_actions":["read"]}]}' >/dev/null
indexer_curl -X PUT "$IDX/_plugins/_security/api/internalusers/grafana_ro" -H 'Content-Type: application/json' -d \
 "{\"password\":\"${RO_PW}\",\"backend_roles\":[]}" >/dev/null
indexer_curl -X PUT "$IDX/_plugins/_security/api/rolesmapping/grafana_read" -H 'Content-Type: application/json' -d \
 '{"users":["grafana_ro"]}' >/dev/null
log_ok "Utilisateur indexer grafana_ro (lecture seule sur wazuh-alerts-*)"

# ---- 5. Datasource provisionnée (certificat vérifié, pas de tlsSkipVerify) ----
mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards/wazuh
CA="$(sed 's/^/        /' /etc/wazuh-indexer/certs/root-ca.pem)"
cat > /etc/grafana/provisioning/datasources/wazuh-opensearch.yaml <<YAML
apiVersion: 1
datasources:
  - name: Wazuh-OpenSearch
    uid: wazuh-opensearch
    type: grafana-opensearch-datasource
    access: proxy
    url: ${IDX}
    basicAuth: true
    basicAuthUser: grafana_ro
    isDefault: true
    editable: false
    jsonData:
      flavor: opensearch
      version: "${OPENSEARCH_DS_VERSION}"
      database: "wazuh-alerts-4.x-*"
      timeField: "@timestamp"
      pplEnabled: false
      tlsAuthWithCACert: true
      timeInterval: "10s"
    secureJsonData:
      basicAuthPassword: "${RO_PW}"
      tlsCACert: |
${CA}
YAML
chown root:grafana /etc/grafana/provisioning/datasources/wazuh-opensearch.yaml
chmod 640 /etc/grafana/provisioning/datasources/wazuh-opensearch.yaml

# ---- 6. Dashboards ----
cat > /etc/grafana/provisioning/dashboards/wazuh.yaml <<YAML
apiVersion: 1
providers:
  - name: "Wazuh"
    folder: "Wazuh"
    type: file
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards/wazuh
YAML
cp "$BUNDLE_ROOT"/configs/grafana/dashboards/*.json /var/lib/grafana/dashboards/wazuh/
chown -R grafana:grafana /var/lib/grafana/dashboards

systemctl restart grafana-server; sleep 5
systemctl is-active --quiet grafana-server || die "Grafana ne démarre pas : journalctl -u grafana-server -n 30"
log_ok "Grafana : http://${MANAGER_IP}:3000  (admin / mot de passe dans $SECRETS_FILE : GRAFANA_ADMIN_PASSWORD)"
log_warn "Grafana est en HTTP : le placer derrière un reverse proxy HTTPS avant tout usage hors segment administration."
