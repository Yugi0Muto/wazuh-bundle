#!/usr/bin/env bash
# 99_verify.sh — recette automatique du serveur Wazuh (lecture seule, ne modifie rien)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf
P=0; F=0; W=0
pass(){ log_ok "$*"; P=$((P+1)); }; fail(){ log_err "$*"; F=$((F+1)); }; warn(){ log_warn "$*"; W=$((W+1)); }

echo "== Services"
for s in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do systemctl is-active --quiet $s && pass "$s actif" || fail "$s inactif"; done
[[ "$GRAFANA_ENABLE" == "true" ]] && { systemctl is-active --quiet grafana-server && pass "grafana-server actif" || fail "grafana-server inactif"; }
[[ "$SMS_ENABLE" == "true" ]] && { systemctl is-active --quiet wazuh-sms-alerter && pass "wazuh-sms-alerter actif" || fail "wazuh-sms-alerter inactif"; }

echo "== Ports en écoute"
for p in 1514 1515 443 9200; do ss -tlnH | awk '{print $4}' | grep -Eq "[:.]${p}$" && pass "port $p" || fail "port $p absent"; done

echo "== Pare-feu"
nft list table inet wazuh_bundle >/dev/null 2>&1 && pass "table nftables wazuh_bundle chargée" || fail "pare-feu bundle absent (étape 02)"
systemctl is-enabled --quiet nftables 2>/dev/null && pass "nftables persistant au démarrage" || warn "nftables non activé au démarrage"

echo "== Configuration Wazuh"
wazuh_config_test && pass "ossec.conf valide (wazuh-analysisd -t)" || fail "ossec.conf invalide : /tmp/wazuh-config-test.log"
grep -q "<use_password>yes</use_password>" $OSSEC_CONF && pass "enrôlement par mot de passe" || fail "enrôlement SANS mot de passe"
grep -q "<white_list>${MANAGER_IP}</white_list>" $OSSEC_CONF && pass "liste blanche AR renseignée" || fail "liste blanche AR absente"
grep -q "<name>firewall-drop</name>" $OSSEC_CONF && pass "commande firewall-drop définie" || fail "commande firewall-drop absente de ossec.conf"
grep -q "<rules_id>5763</rules_id>" $OSSEC_CONF && pass "Active Response brute force (5763)" || fail "Active Response 5763 absente"
[[ -f /var/ossec/etc/rules/bundle_rules.xml && -f /var/ossec/etc/decoders/bundle_decoders.xml ]] && pass "règles et décodeurs du bundle déployés" || fail "règles/décodeurs du bundle absents"
for g in seg-dmz seg-servers seg-employees os-linux os-windows role-web role-db role-admin feat-yara opt-whodata; do
  [[ -f /var/ossec/etc/shared/$g/agent.conf ]] && pass "groupe $g" || fail "groupe $g absent"; done

echo "== Détection (test logique sans agent)"
out="$(echo 'wazuh-yara: INFO - Scan result: EICAR_Test_File /tmp/eicar.txt' | /var/ossec/bin/wazuh-logtest 2>&1 || true)"
echo "$out" | grep -q "100511" && pass "règle 100511 (YARA) se déclenche sur un résultat YARA" || warn "logtest : règle 100511 non confirmée (vérifier manuellement avec wazuh-logtest)"
n=$(grep -c ':$' /var/ossec/etc/lists/malware-sha256 2>/dev/null || echo 0); (( n > 1 )) && pass "liste de hashes : $n entrées" || warn "liste de hashes vide (lancer wazuh-bundle-update-malware)"
[[ -s /var/ossec/etc/shared/feat-yara/yara_rules.yar ]] && pass "règles YARA centralisées" || fail "règles YARA absentes"

echo "== Indexer"
st="$(indexer_curl "https://${MANAGER_IP}:9200/_cluster/health" 2>/dev/null | grep -o '"status":"[a-z]*"' | cut -d'"' -f4)"
case "$st" in green) pass "cluster indexer : green";; yellow) warn "cluster indexer : yellow (normal en mono-nœud si des répliques sont configurées)";; *) fail "cluster indexer illisible (mot de passe/CA ?)";; esac
indexer_curl "https://${MANAGER_IP}:9200/_plugins/_ism/policies/wazuh-retention" 2>/dev/null | grep -q '"_id"' && pass "politique de rétention en place" || warn "pas de politique de rétention (étape 05)"

echo "== Agents"
/var/ossec/bin/agent_control -l 2>/dev/null | sed -n '1,40p'
act=$(/var/ossec/bin/agent_control -l 2>/dev/null | grep -c "Active" || true); (( act > 1 )) && pass "$act agents actifs (hors manager)" || warn "aucun agent actif"

echo "== Exploitation"
[[ -f /etc/cron.d/wazuh-bundle-backup ]] && pass "sauvegarde planifiée" || warn "sauvegarde non planifiée (étape 09)"
[[ -f /etc/cron.d/wazuh-bundle-malware ]] && pass "mise à jour malware planifiée" || warn "mise à jour malware non planifiée (étape 04)"
use=$(df --output=pcent /var | tail -1 | tr -dc '0-9'); (( use < 80 )) && pass "disque /var : ${use}%" || warn "disque /var : ${use}% (>80%)"

echo; echo "Résultat : $P OK, $W avertissements, $F échecs"; (( F == 0 ))
