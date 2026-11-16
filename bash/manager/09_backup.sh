#!/usr/bin/env bash
# 09_backup.sh — sauvegarde quotidienne de la configuration (pas des données d'alertes)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
require_root; load_conf

cat > /usr/local/sbin/wazuh-bundle-backup <<SH
#!/usr/bin/env bash
set -euo pipefail
DEST="${BACKUP_DIR}"; KEEP=${BACKUP_KEEP_DAYS}
umask 077; mkdir -p "\$DEST"; chmod 700 "\$DEST"
F="\$DEST/wazuh-config-\$(hostname)-\$(date +%Y%m%d-%H%M).tar.gz"
paths=(/var/ossec/etc /var/ossec/api/configuration /var/ossec/active-response/bin /etc/wazuh-indexer /etc/wazuh-dashboard /etc/filebeat /etc/nftables.conf /etc/wazuh-bundle ${SECRETS_DIR})
[ -d /etc/grafana ] && paths+=(/etc/grafana /var/lib/grafana/grafana.db)
existing=(); for p in "\${paths[@]}"; do [ -e "\$p" ] && existing+=("\$p"); done
tar -czf "\$F" "\${existing[@]}" 2>/dev/null || [ \$? -eq 1 ]
find "\$DEST" -name 'wazuh-config-*.tar.gz' -mtime +\$KEEP -delete
logger "wazuh-bundle-backup: \$F"
SH
chmod 750 /usr/local/sbin/wazuh-bundle-backup
echo '30 2 * * * root /usr/local/sbin/wazuh-bundle-backup' > /etc/cron.d/wazuh-bundle-backup
chmod 644 /etc/cron.d/wazuh-bundle-backup
/usr/local/sbin/wazuh-bundle-backup && ls -lh "$BACKUP_DIR" | tail -2
log_ok "Sauvegarde quotidienne 02:30, rétention ${BACKUP_KEEP_DAYS} jours dans $BACKUP_DIR"
log_warn "Ces archives contiennent des CLÉS et des MOTS DE PASSE : copie hors serveur chiffrée obligatoire (ex: rsync/sftp vers le NAS de sauvegarde)."
