#!/usr/bin/env bash
# 08_sms_alerts.sh — alertes SMS (daemon systemd, utilisateur dédié, clé hors du script)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf
[[ "$SMS_ENABLE" == "true" ]] || { log_warn "SMS_ENABLE=false : étape ignorée."; exit 0; }

AT_KEY="$(secret_get AT_API_KEY || true)"
if [[ -z "$AT_KEY" ]]; then read -rsp "Clé API Africa's Talking : " AT_KEY; echo; [[ -n "$AT_KEY" ]] || die "Clé vide."; secret_set AT_API_KEY "$AT_KEY"; fi

id wazuh-sms >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -g wazuh wazuh-sms
install -d -m 750 -o root -g wazuh /etc/wazuh-bundle
install -m 640 -o root -g wazuh /dev/null /etc/wazuh-bundle/sms.env
cat > /etc/wazuh-bundle/sms.env <<ENV
AT_USERNAME=${SMS_USERNAME}
AT_API_KEY=${AT_KEY}
SMS_TO="${SMS_TO}"
SMS_ALERT_LEVEL=${SMS_ALERT_LEVEL}
SMS_MAX_PER_HOUR=${SMS_MAX_PER_HOUR}
SMS_DEDUP_SECONDS=${SMS_DEDUP_SECONDS}
ENV
chown root:wazuh /etc/wazuh-bundle/sms.env; chmod 640 /etc/wazuh-bundle/sms.env
install -m 755 "$BUNDLE_ROOT/configs/manager/wazuh-sms-alerter.py" /usr/local/bin/wazuh-sms-alerter.py
install -m 644 "$BUNDLE_ROOT/configs/manager/wazuh-sms-alerter.service" /etc/systemd/system/wazuh-sms-alerter.service
systemctl daemon-reload; systemctl enable --now wazuh-sms-alerter; sleep 3
systemctl is-active --quiet wazuh-sms-alerter && log_ok "Service wazuh-sms-alerter actif (niveau >= ${SMS_ALERT_LEVEL})" \
  || die "Service KO : journalctl -u wazuh-sms-alerter -n 30"
[[ "$SMS_USERNAME" == "sandbox" ]] && log_warn "Mode sandbox : l'API répond mais AUCUN SMS n'est livré. Passer en production (SMS_USERNAME + clé de production)."
