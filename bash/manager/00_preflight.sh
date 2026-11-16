#!/usr/bin/env bash
# 00_preflight.sh — contrôles AVANT installation (ne modifie rien)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf
fail=0; ok(){ log_ok "$*"; }; ko(){ log_err "$*"; fail=1; }

. /etc/os-release
case "${ID}-${VERSION_ID%%.*}" in debian-12|debian-13|ubuntu-22|ubuntu-24) ok "OS supporté : $PRETTY_NAME";; *) ko "OS non validé : $PRETTY_NAME";; esac

ram_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
(( ram_mb >= 7500 )) && ok "RAM : ${ram_mb} Mo" || ko "RAM ${ram_mb} Mo (< 8 Go recommandé en production)"
cpus=$(nproc); (( cpus >= 4 )) && ok "CPU : $cpus" || ko "CPU $cpus (< 4 recommandé)"
disk_gb=$(df -BG --output=avail /var | tail -1 | tr -dc '0-9'); (( disk_gb >= 100 )) && ok "Disque /var libre : ${disk_gb} Go" || ko "Disque /var libre ${disk_gb} Go (< 100 Go)"

ip a | grep -qw "$MANAGER_IP" && ok "MANAGER_IP $MANAGER_IP présent sur cette machine" || ko "MANAGER_IP $MANAGER_IP n'est PAS configurée sur cette machine"
if grep -Eq 'dhcp' /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null; then log_warn "Interface en DHCP ? L'IP du manager doit être FIXE (agents et certificats en dépendent)."; fi

for p in 443 1514 1515 9200 55000 3000; do
  ss -tulnH | awk '{print $5}' | grep -Eq "[:.]${p}$" && ko "Port $p déjà utilisé" || ok "Port $p libre"
done

curl -sI -m 10 https://packages.wazuh.com >/dev/null && ok "Accès HTTPS packages.wazuh.com" || ko "Pas d'accès HTTPS à packages.wazuh.com (proxy/pare-feu sortant ?)"
[[ "$GRAFANA_ENABLE" == "true" ]] && { curl -sI -m 10 https://apt.grafana.com >/dev/null && ok "Accès apt.grafana.com" || ko "Pas d'accès à apt.grafana.com"; }

timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes && ok "Horloge synchronisée (NTP)" || ko "Horloge NON synchronisée : installer chrony/systemd-timesyncd (les alertes seraient mal datées)"
command -v python3 >/dev/null && ok "python3 présent" || ko "python3 manquant"
systemctl is-active --quiet ufw 2>/dev/null && log_warn "ufw actif : le script 02 utilise nftables ; désactiver ufw pour éviter les conflits."

echo; (( fail == 0 )) && { log_ok "Préflight OK."; exit 0; } || { log_err "Préflight : corriger les points ci-dessus."; exit 1; }
