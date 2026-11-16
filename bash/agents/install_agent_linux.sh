#!/usr/bin/env bash
# install_agent_linux.sh — installe et enrôle un agent Wazuh Linux
# La configuration (FIM, logs) vient du MANAGER via les groupes : rien à éditer sur l'agent.
#
# Exemple (serveur web en DMZ) :
#   sudo ./install_agent_linux.sh --manager-ip 10.10.10.20 --segment dmz --role web \
#        --name dmz-web01 --yara
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() { cat <<U
Usage : sudo $0 --manager-ip IP --segment dmz|servers|employees --role web|db|admin|generic --name NOM
        [--version 4.14.x-1] [--yara] [--whodata] [--password-file FICHIER] [--deb-path FICHIER.deb]

  --segment  segment réseau de la machine (groupe seg-*)
  --role     rôle applicatif (groupe role-*) ; "generic" = aucun rôle particulier
  --version  version de l'agent (défaut : WAZUH_VERSION de bundle.conf). Doit être <= version du manager.
  --yara     active l'analyse malware YARA (installe yara + jq, groupe feat-yara)
  --whodata  active whodata (installe auditd, groupe opt-whodata)
  Mot de passe d'enrôlement : --password-file, sinon variable WAZUH_REG_PASSWORD, sinon saisie masquée.
  --deb-path paquet .deb local (machines sans accès Internet : miroir interne)
U
exit 1; }

MANAGER_IP=""; SEGMENT=""; ROLE=""; NAME=""; VERSION=""; YARA=0; WHODATA=0; PWFILE=""; DEB=""
while [[ $# -gt 0 ]]; do case "$1" in
  --manager-ip) MANAGER_IP="$2"; shift 2;; --segment) SEGMENT="$2"; shift 2;; --role) ROLE="$2"; shift 2;;
  --name) NAME="$2"; shift 2;; --version) VERSION="$2"; shift 2;; --yara) YARA=1; shift;; --whodata) WHODATA=1; shift;;
  --password-file) PWFILE="$2"; shift 2;; --deb-path) DEB="$2"; shift 2;; -h|--help) usage;; *) echo "Argument inconnu : $1"; usage;;
esac; done

[[ "${EUID}" -eq 0 ]] || { echo "Lancer en root."; exit 1; }
[[ -n "$MANAGER_IP" && -n "$SEGMENT" && -n "$ROLE" && -n "$NAME" ]] || usage
[[ "$SEGMENT" =~ ^(dmz|servers|employees)$ ]] || { echo "segment invalide"; usage; }
[[ "$ROLE" =~ ^(web|db|admin|generic)$ ]]     || { echo "role invalide"; usage; }
if [[ -z "$VERSION" && -f "$SCRIPT_DIR/../../bundle.conf" ]]; then VERSION="$(grep '^WAZUH_VERSION=' "$SCRIPT_DIR/../../bundle.conf" | cut -d'"' -f2)"; fi
[[ -n "$VERSION" ]] || { echo "Version inconnue : utiliser --version (ex: 4.14.1-1)."; exit 1; }

if [[ -n "$PWFILE" ]]; then REGPW="$(cat "$PWFILE")"
elif [[ -n "${WAZUH_REG_PASSWORD:-}" ]]; then REGPW="$WAZUH_REG_PASSWORD"
else read -rsp "Mot de passe d'enrôlement Wazuh : " REGPW; echo; fi
[[ -n "$REGPW" ]] || { echo "Mot de passe vide."; exit 1; }

if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent'; then
  echo "[WARN] Un agent est déjà installé ($(dpkg-query -W -f='${Version}' wazuh-agent)). Rien n'est modifié."
  echo "       Pour réinstaller : apt-get purge wazuh-agent puis relancer ce script."; exit 0
fi

echo "[INFO] Test de joignabilité du manager ($MANAGER_IP:1514 et :1515)"
for p in 1514 1515; do timeout 5 bash -c "</dev/tcp/$MANAGER_IP/$p" 2>/dev/null \
  && echo "  port $p OK" || { echo "[FAIL] $MANAGER_IP:$p injoignable (pare-feu entre le segment et le serveur Wazuh ?)"; exit 1; }; done

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y curl gpg iptables >/dev/null
[[ -f /var/log/auth.log ]] || { echo "[INFO] /var/log/auth.log absent : installation de rsyslog"; apt-get install -y rsyslog >/dev/null; systemctl enable --now rsyslog; }
(( YARA ))    && apt-get install -y yara jq >/dev/null
(( WHODATA )) && { apt-get install -y auditd audispd-plugins >/dev/null; systemctl enable --now auditd; }

GROUPS_CSV="seg-${SEGMENT},os-linux"
[[ "$ROLE" != "generic" ]] && GROUPS_CSV="${GROUPS_CSV},role-${ROLE}"
(( YARA ))    && GROUPS_CSV="${GROUPS_CSV},feat-yara"
(( WHODATA )) && GROUPS_CSV="${GROUPS_CSV},opt-whodata"

if [[ -n "$DEB" ]]; then
  echo "[INFO] Installation depuis $DEB"
  WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$NAME" WAZUH_AGENT_GROUP="$GROUPS_CSV" WAZUH_REGISTRATION_PASSWORD="$REGPW" dpkg -i "$DEB"
else
  curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  echo "[INFO] Installation wazuh-agent=$VERSION (groupes : $GROUPS_CSV)"
  WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$NAME" WAZUH_AGENT_GROUP="$GROUPS_CSV" WAZUH_REGISTRATION_PASSWORD="$REGPW" \
    apt-get install -y "wazuh-agent=${VERSION}"
fi
apt-mark hold wazuh-agent >/dev/null   # pas de mise à jour automatique : le manager est mis à jour en premier

if (( YARA )); then
  install -o root -g wazuh -m 750 "$SCRIPT_DIR/yara.sh" /var/ossec/active-response/bin/yara.sh
  echo "[INFO] yara.sh installé (les règles arrivent depuis le manager via le groupe feat-yara)"
fi

systemctl daemon-reload; systemctl enable wazuh-agent >/dev/null; systemctl restart wazuh-agent
echo "[INFO] Attente de la connexion au manager (60 s max)..."
for _ in $(seq 1 30); do
  grep -q "Connected to the server" /var/ossec/logs/ossec.log 2>/dev/null && { echo "[ OK ] Agent $NAME connecté (groupes : $GROUPS_CSV)"; 
    echo "       Côté manager : /var/ossec/bin/agent_control -l"; exit 0; }
  sleep 2
done
echo "[FAIL] Pas de connexion. Journal : tail -30 /var/ossec/logs/ossec.log (mot de passe ? groupes inexistants ? pare-feu ?)"; exit 1
