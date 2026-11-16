#!/usr/bin/env bash
# 03_manager_config.sh — enrôlement par mot de passe, liste blanche AR, groupes d'agents, règles
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf
systemctl is-active --quiet wazuh-manager || die "wazuh-manager n'est pas actif (étape 01 ?)"
backup_file "$OSSEC_CONF"; BAK="$LAST_BACKUP"

# ---- 1. Enrôlement des agents protégé par mot de passe (port 1515) ----
AUTH_PW="$(secret_get AUTHD_PASSWORD || true)"
[[ -n "$AUTH_PW" ]] || { AUTH_PW="$(gen_password)"; secret_set AUTHD_PASSWORD "$AUTH_PW"; }
install -o root -g wazuh -m 640 /dev/null /var/ossec/etc/authd.pass
printf '%s' "$AUTH_PW" > /var/ossec/etc/authd.pass
ossec_set_tag use_password yes
log_ok "Enrôlement par mot de passe activé (stocké dans $SECRETS_FILE : AUTHD_PASSWORD)"

# ---- 2. Liste blanche Active Response : jamais bloquer ces IP ----
for ip in "$MANAGER_IP" $ADMIN_CIDRS $WHITELIST_EXTRA; do
  ossec_insert_in_block global "<white_list>${ip}</white_list>"
done

# ---- 3. Commandes / Active Response / listes de hashes (bloc complet) ----
ossec_append_block "$BUNDLE_ROOT/configs/manager/manager_blocks.xml"
ossec_insert_in_block ruleset "<list>etc/lists/malware-sha256</list>"

# ---- 4. Liste de hashes vide valide, règles et décodeurs ----
install -d -o wazuh -g wazuh /var/ossec/etc/lists
[[ -f /var/ossec/etc/lists/malware-sha256 ]] || \
  echo "0000000000000000000000000000000000000000000000000000000000000000:placeholder" > /var/ossec/etc/lists/malware-sha256
chown wazuh:wazuh /var/ossec/etc/lists/malware-sha256; chmod 640 /var/ossec/etc/lists/malware-sha256

sed "s#__YARA_REGEX__#${YARA_SCAN_PATHS_REGEX}#g" "$BUNDLE_ROOT/configs/manager/bundle_rules.xml" > /tmp/bundle_rules.xml
deploy_rules /tmp/bundle_rules.xml /var/ossec/etc/rules; rm -f /tmp/bundle_rules.xml
deploy_rules "$BUNDLE_ROOT/configs/manager/bundle_decoders.xml" /var/ossec/etc/decoders

# ---- 5. Groupes d'agents + configuration centralisée ----
for g in "$BUNDLE_ROOT"/configs/groups/*/; do
  name="$(basename "$g")"
  /var/ossec/bin/agent_groups -q -a -g "$name" 2>/dev/null || true
  install -o root -g wazuh -m 660 "$g/agent.conf" "/var/ossec/etc/shared/$name/agent.conf"
  log_ok "Groupe $name configuré"
done
# Règles YARA distribuées à tous les agents du groupe feat-yara
install -d -o root -g wazuh /var/ossec/etc/shared/feat-yara
install -o root -g wazuh -m 660 "$BUNDLE_ROOT/configs/yara/bundle_rules.yar" /var/ossec/etc/shared/feat-yara/yara_rules.yar

# ---- 6. Test + redémarrage (restauration automatique si invalide) ----
safe_restart_manager "$BAK" || die "Échec : configuration restaurée. Détails : /tmp/wazuh-config-test.log"
log_ok "Étape 03 terminée."
echo "  Mot de passe d'enrôlement : sudo grep AUTHD_PASSWORD $SECRETS_FILE"
echo "  Groupes : /var/ossec/bin/agent_groups -l"
