#!/bin/bash
# Wazuh Active Response — analyse YARA d'un fichier (Linux) — wazuh-bundle
# Installé par install_agent_linux.sh dans /var/ossec/active-response/bin/yara.sh
# Reçoit en entrée (stdin) l'alerte FIM au format JSON.
LOG_FILE="${YARA_LOG_FILE:-/var/ossec/logs/active-responses.log}"
MAX_SIZE=$((100*1024*1024))   # fichiers > 100 Mo ignorés
log() { echo "wazuh-yara: $1 - $2" >> "$LOG_FILE"; }

read -r INPUT_JSON
command -v jq >/dev/null 2>&1 || { log ERROR "jq absent (apt install jq)"; exit 1; }

ACTION=$(echo "$INPUT_JSON"     | jq -r '.command // "add"')
YARA_PATH=$(echo "$INPUT_JSON"  | jq -r '.parameters.extra_args[1] // empty')
YARA_RULES=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[3] // empty')
FILENAME=$(echo "$INPUT_JSON"   | jq -r '.parameters.alert.syscheck.path // empty')

[[ "$ACTION" == "add" ]] || exit 0
[[ -n "$YARA_PATH" && -n "$YARA_RULES" ]] || { log ERROR "Yara path and rules parameters are mandatory."; exit 1; }
[[ -x "$YARA_PATH/yara" ]] || { log ERROR "binaire yara introuvable dans $YARA_PATH (apt install yara)"; exit 1; }
[[ -r "$YARA_RULES" ]]     || { log ERROR "fichier de règles introuvable : $YARA_RULES"; exit 1; }
[[ -n "$FILENAME" && "$FILENAME" != -* ]] || exit 0     # pas de chemin, ou chemin ressemblant à une option
[[ -f "$FILENAME" ]] || exit 0                          # supprimé entre-temps
size=$(stat -c %s -- "$FILENAME" 2>/dev/null || echo 0)
(( size <= MAX_SIZE )) || { log INFO "fichier ignoré (trop gros) $FILENAME"; exit 0; }

base="$(basename -- "$FILENAME")"; ext=""
[[ "$base" == *.* ]] && ext=".${base##*.}"

# Variables externes attendues par certaines règles communautaires (signature-base...)
out="$(timeout 60 "$YARA_PATH/yara" -w \
      -d filename="$base" -d filepath="$FILENAME" -d extension="$ext" -d filetype="" -d owner="" \
      "$YARA_RULES" "$FILENAME" 2>&1)"
rc=$?
if (( rc != 0 && rc != 124 )) && [[ -n "$out" && "$out" != *" $FILENAME"* ]]; then
  log ERROR "yara a échoué (code $rc) : $(echo "$out" | head -1)"; exit 1
fi
(( rc == 124 )) && { log ERROR "timeout YARA sur $FILENAME"; exit 1; }

while IFS= read -r line; do
  [[ -n "$line" ]] && log INFO "Scan result: $line"
done <<< "$out"
exit 0
