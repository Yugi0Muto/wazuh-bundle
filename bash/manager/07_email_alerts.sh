#!/usr/bin/env bash
# 07_email_alerts.sh — alertes email via Postfix (relais SMTP de l'entreprise)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf
[[ "$EMAIL_ENABLE" == "true" ]] || { log_warn "EMAIL_ENABLE=false : étape ignorée."; exit 0; }

DEBIAN_FRONTEND=noninteractive apt-get install -y postfix libsasl2-modules mailutils >/dev/null
backup_file /etc/postfix/main.cf
postconf -e "inet_interfaces = loopback-only"
postconf -e "relayhost = [${SMTP_RELAY%%:*}]:${SMTP_RELAY##*:}"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
if [[ -n "$SMTP_USER" ]]; then
  read -rsp "Mot de passe SMTP de ${SMTP_USER} : " SMTP_PW; echo
  [[ -n "$SMTP_PW" ]] || die "Mot de passe vide."
  printf '[%s]:%s %s:%s\n' "${SMTP_RELAY%%:*}" "${SMTP_RELAY##*:}" "$SMTP_USER" "$SMTP_PW" > /etc/postfix/sasl_passwd
  chmod 600 /etc/postfix/sasl_passwd; postmap /etc/postfix/sasl_passwd; chmod 600 /etc/postfix/sasl_passwd.db
  postconf -e "smtp_sasl_auth_enable = yes" "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd" "smtp_sasl_security_options = noanonymous"
fi
systemctl restart postfix
echo "Test d'envoi Wazuh $(date)" | mail -s "[WAZUH] test email" -r "$EMAIL_FROM" "$EMAIL_TO" && log_ok "Email de test envoyé à $EMAIL_TO (vérifier la réception : mailq, /var/log/mail.log)"

backup_file "$OSSEC_CONF"; BAK="$LAST_BACKUP"
ossec_set_tag email_notification yes
ossec_set_tag smtp_server localhost
ossec_set_tag email_from "$EMAIL_FROM"
ossec_set_tag email_to "$EMAIL_TO"
ossec_set_tag email_maxperhour 30
ossec_set_tag email_alert_level "$EMAIL_ALERT_LEVEL"
safe_restart_manager "$BAK" || die "Configuration restaurée."
log_ok "Alertes email actives (niveau >= $EMAIL_ALERT_LEVEL, max 30/heure)."
