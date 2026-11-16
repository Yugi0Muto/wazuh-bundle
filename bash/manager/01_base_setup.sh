#!/usr/bin/env bash
# 01_base_setup.sh — SSH (durcissement sûr) + Wazuh all-in-one
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf

# ---- 1. SSH : drop-in, test avant rechargement, jamais de verrouillage ----
if [[ "$SSH_HARDEN" == "true" ]]; then
  log_info "Durcissement SSH"
  sudo_users="$(getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v '^root$' || true)"
  if [[ -z "$sudo_users" ]]; then
    log_warn "Aucun compte sudo non-root : durcissement SSH IGNORÉ (créer un compte admin d'abord)."
  else
    mkdir -p /etc/ssh/sshd_config.d
    {
      echo "PermitRootLogin no"
      echo "MaxAuthTries 4"
      echo "LoginGraceTime 30"
      if [[ "$SSH_DISABLE_PASSWORD" == "true" ]]; then
        has_key=0
        for u in $sudo_users; do h="$(getent passwd "$u" | cut -d: -f6)"; [[ -s "$h/.ssh/authorized_keys" ]] && has_key=1; done
        if (( has_key )); then echo "PasswordAuthentication no"; else log_warn "Pas de clé SSH trouvée : mot de passe conservé."; fi
      fi
    } > /etc/ssh/sshd_config.d/00-wazuh-bundle.conf
    if sshd -t; then systemctl reload ssh 2>/dev/null || systemctl reload sshd; log_ok "SSH durci (comptes sudo : $(echo $sudo_users | tr '\n' ' '))"
    else rm -f /etc/ssh/sshd_config.d/00-wazuh-bundle.conf; log_err "sshd -t invalide : drop-in supprimé."; fi
  fi
fi

# ---- 2. Wazuh ----
if systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-manager'; then
  log_warn "wazuh-manager déjà installé : installation ignorée."
else
  apt-get update -qq; apt-get install -y curl gpg jq python3 >/dev/null
  WORK="$(mktemp -d /tmp/wazuh-install-XXXXXX)"; cd "$WORK"
  log_info "Téléchargement de l'installateur Wazuh ${WAZUH_BRANCH}"
  curl -fsSLO "https://packages.wazuh.com/${WAZUH_BRANCH}/wazuh-install.sh"
  log_info "Installation all-in-one (10-20 min)..."
  bash wazuh-install.sh -a 2>&1 | tee "/var/log/wazuh-bundle-install.log"
  [[ -f wazuh-install-files.tar ]] || die "wazuh-install-files.tar absent : voir /var/log/wazuh-bundle-install.log"

  mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"
  install -m 600 wazuh-install-files.tar "$SECRETS_DIR/wazuh-install-files.tar"
  tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt > "$SECRETS_DIR/wazuh-passwords.txt"
  chmod 600 "$SECRETS_DIR/wazuh-passwords.txt"
  pw="$(grep -A1 "indexer_username: 'admin'" "$SECRETS_DIR/wazuh-passwords.txt" | grep indexer_password | sed "s/.*'\(.*\)'.*/\1/")"
  [[ -n "$pw" ]] || die "Mot de passe admin introuvable dans wazuh-passwords.txt"
  secret_set INDEXER_ADMIN_PASSWORD "$pw"
  cd /; rm -rf "$WORK"
fi

ver="$(dpkg-query -W -f='${Version}' wazuh-manager)"
conf_set WAZUH_VERSION "$ver"
log_ok "Wazuh $ver installé (WAZUH_VERSION enregistré dans bundle.conf — les agents DOIVENT être en version <= manager)."
echo "  Dashboard : https://${MANAGER_IP}   (utilisateur admin)"
echo "  Mots de passe : $SECRETS_DIR/wazuh-passwords.txt (root uniquement)"
log_warn "Copier ce fichier dans le coffre de mots de passe de l'entreprise puis le supprimer du serveur si la politique l'exige."
