#!/usr/bin/env bash
# 02_firewall.sh — pare-feu nftables du serveur Wazuh, par segment
# Protection anti-verrouillage : annulation automatique après 90 s sans confirmation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf
command -v nft >/dev/null || apt-get install -y nftables >/dev/null

join() { local IFS=,; echo "$*"; }
admin_set="$(join $ADMIN_CIDRS)"
agent_set="$(join $SERVERS_CIDR $EMPLOYEES_CIDR $DMZ_CIDR)"

RULES=/etc/nftables.conf
backup_file "$RULES"
cat > /tmp/nft.new <<NFT
#!/usr/sbin/nft -f
# Généré par wazuh-bundle — ne pas éditer à la main (modifier bundle.conf puis relancer l'étape 02)
flush ruleset
table inet wazuh_bundle {
  set admin4  { type ipv4_addr; flags interval; elements = { ${admin_set} } }
  set agents4 { type ipv4_addr; flags interval; elements = { ${agent_set} } }

  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif "lo" accept
    meta l4proto icmp icmp type echo-request limit rate 10/second accept
    meta l4proto ipv6-icmp accept
    # Administration : SSH, Dashboard Wazuh, Grafana
    ip saddr @admin4 tcp dport { 22, 443, 3000 } accept
    # Agents (serveurs, employés, DMZ) : événements 1514 et enrôlement 1515
    ip saddr @agents4 tcp dport { 1514, 1515 } accept
    # Tout le reste est journalisé (limité) puis refusé
    limit rate 5/minute log prefix "nft-wazuh-drop: " counter drop
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output priority 0; policy accept; }
}
NFT
nft -c -f /tmp/nft.new || die "Règles nftables invalides."

log_warn "Application des règles. Si la session SSH est coupée, tout est annulé automatiquement dans 90 secondes."
( sleep 90; nft delete table inet wazuh_bundle 2>/dev/null; logger "wazuh-bundle: pare-feu annulé (pas de confirmation)" ) &
GUARD=$!
nft -f /tmp/nft.new
echo
read -rp "La connexion fonctionne-t-elle toujours (SSH + Dashboard depuis un poste admin) ? Taper OUI : " ans
if [[ "$ans" == "OUI" ]]; then
  kill "$GUARD" 2>/dev/null || true
  install -m 600 /tmp/nft.new "$RULES"; rm -f /tmp/nft.new
  systemctl enable --now nftables >/dev/null
  log_ok "Pare-feu actif et persistant ($RULES)."
else
  kill "$GUARD" 2>/dev/null || true
  nft delete table inet wazuh_bundle 2>/dev/null || true
  die "Pare-feu annulé. Vérifier ADMIN_CIDRS dans bundle.conf."
fi
cat <<MSG

Flux à faire ouvrir par l'équipe réseau (voir documentation, section Flux) :
  Employés/Serveurs/DMZ -> $MANAGER_IP : TCP 1514, TCP 1515
  Postes admin          -> $MANAGER_IP : TCP 22, 443, 3000
  $MANAGER_IP -> Internet (HTTPS 443) : packages.wazuh.com, apt.grafana.com, GitHub (règles YARA), abuse.ch
  $MANAGER_IP -> relais SMTP / API SMS selon les options activées
MSG
