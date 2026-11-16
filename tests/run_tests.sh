#!/usr/bin/env bash
# tests/run_tests.sh — tests statiques et fonctionnels du bundle (sans Wazuh, sans root)
# Prérequis : bash, python3, xmllint (libxml2-utils), yara, jq ; shellcheck facultatif.
#   ./tests/run_tests.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
export LC_ALL=C.UTF-8
PASS=0; FAIL=0
t() { # t "nom" commande...
  local name="$1"; shift
  if out="$("$@" 2>&1)"; then echo "  [OK]   $name"; PASS=$((PASS+1)); else echo "  [FAIL] $name"; echo "$out" | sed 's/^/         /' | head -15; FAIL=$((FAIL+1)); fi
}
need() { command -v "$1" >/dev/null || { echo "[SKIP-FATAL] outil manquant : $1"; exit 2; }; }
for c in python3 xmllint yara jq; do need "$c"; done
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
SCRIPTS=(install.sh bash/lib/common.sh bash/manager/*.sh bash/agents/*.sh)

echo "== 1. Syntaxe des scripts"
for f in "${SCRIPTS[@]}"; do t "bash -n $f" bash -n "$f"; done
t "python SMS compile" python3 -m py_compile configs/manager/wazuh-sms-alerter.py
if command -v shellcheck >/dev/null; then t "shellcheck (niveau warning)" shellcheck -S warning -x "${SCRIPTS[@]}"; else echo "  [SKIP] shellcheck absent"; fi

echo "== 2. XML et JSON"
wrap() { { echo "<r>"; cat "$1"; echo "</r>"; } | xmllint --noout -; }
sed 's#__YARA_REGEX__#^/(var/www|tmp)/#' configs/manager/bundle_rules.xml > "$TMP/rules.xml"
t "bundle_rules.xml" xmllint --noout "$TMP/rules.xml"
t "bundle_decoders.xml" wrap configs/manager/bundle_decoders.xml
t "manager_blocks.xml" wrap configs/manager/manager_blocks.xml
for g in configs/groups/*/agent.conf; do t "groupe $(basename "$(dirname "$g")")" wrap "$g"; done
t "dashboard Grafana (JSON)" python3 -c "import json,sys; d=json.load(open('configs/grafana/dashboards/wazuh-soc.json')); assert len(d['panels'])>0"
ids="$(grep -o 'rule id="[0-9]*"' configs/manager/bundle_rules.xml | sort | uniq -d)"
t "identifiants de règles uniques" test -z "$ids"

echo "== 3. Configuration"
t "bundle.conf.example sourçable" bash -c 'set -u; source bundle.conf.example; : "$MANAGER_IP" "$RETENTION_DAYS" "$SMS_MAX_PER_HOUR"'
t "load_conf refuse A_COMPLETER" bash -c 'cp bundle.conf.example '"$TMP"'/b.conf; BUNDLE_CONF='"$TMP"'/b.conf; source bash/lib/common.sh; ! (load_conf) 2>/dev/null'
t "secret_set/secret_get" bash -c 'source bash/lib/common.sh; SECRETS_DIR='"$TMP"'/s; SECRETS_FILE=$SECRETS_DIR/secrets.env; secret_set K "a b\"c\$d"; [[ "$(secret_get K)" == "a b\"c\$d" ]]'

echo "== 4. YARA"
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TMP/eicar.txt"
printf '<?php eval(base64_decode($_POST["x"])); ?>' > "$TMP/shell.php"
echo "bonjour" > "$TMP/clean.txt"
t "règles YARA compilent" yara -w configs/yara/bundle_rules.yar /dev/null
t "EICAR détecté" bash -c 'yara -w configs/yara/bundle_rules.yar '"$TMP"'/eicar.txt | grep -q EICAR_Test_File'
t "webshell PHP détecté" bash -c 'yara -w configs/yara/bundle_rules.yar '"$TMP"'/shell.php | grep -q PHP_Webshell'
t "fichier propre non détecté" bash -c '[[ -z "$(yara -w configs/yara/bundle_rules.yar '"$TMP"'/clean.txt)" ]]'

echo "== 5. Script Active Response yara.sh"
run_ar() { # run_ar fichier -> écrit dans $TMP/ar.log
  echo "{\"command\":\"add\",\"parameters\":{\"extra_args\":[\"-yara_path\",\"$(dirname "$(command -v yara)")\",\"-yara_rules\",\"$ROOT/configs/yara/bundle_rules.yar\"],\"alert\":{\"syscheck\":{\"path\":\"$1\"}}}}" \
   | YARA_LOG_FILE="$TMP/ar.log" bash bash/agents/yara.sh
}
: > "$TMP/ar.log"
t "yara.sh : exécution sur EICAR" run_ar "$TMP/eicar.txt"
t "yara.sh : résultat au format du décodeur" grep -Eq '^wazuh-yara: INFO - Scan result: EICAR_Test_File '"$TMP"'/eicar.txt$' "$TMP/ar.log"
: > "$TMP/ar.log"; run_ar "$TMP/clean.txt"; run_ar "$TMP/absent.txt"
t "yara.sh : rien pour fichier propre/absent" test ! -s "$TMP/ar.log"
t "décodeur (regex) compatible avec la sortie" python3 - "$TMP/eicar.txt" <<'PY'
import re,sys
line="wazuh-yara: INFO - Scan result: EICAR_Test_File /tmp/eicar.txt"
assert re.search(r"wazuh-yara: (\S+) - Scan result: (\S+) (\S+)", line)
PY

echo "== 6. Mise à jour hashes + YARA (simulation locale)"
mkdir -p "$TMP/sim"
python3 -c "
import hashlib
print('# test'); [print(hashlib.sha256(str(i).encode()).hexdigest().upper()) for i in range(80)]" > "$TMP/sim/hashes.txt"
printf 'MALWARE_HASH_URL="file://%s/sim/hashes.txt"\nABUSECH_AUTH_KEY=""\nBASE_RULES="%s/configs/yara/bundle_rules.yar"\n' "$TMP" "$ROOT" > "$TMP/sim/update.env"
printf 'rule Extra_Ok { condition: false }\n' > "$TMP/sim/ok.yar"
printf 'rule Cassee { condition: \n' > "$TMP/sim/bad.yar"
printf 'file://%s/sim/ok.yar\nfile://%s/sim/bad.yar\nfile://%s/sim/absent.yar\n' "$TMP" "$TMP" "$TMP" > "$TMP/sim/sources.txt"
mkdir -p "$TMP/sim/out"
run_upd() { ENV_FILE="$TMP/sim/update.env" SOURCES_FILE="$TMP/sim/sources.txt" LIST="$TMP/sim/out/list" SHARED="$TMP/sim/out/yara.yar" \
  LIST_OPTS="-m 640" SHARED_OPTS="-m 660" RESTART_CMD="touch $TMP/sim/restarted" bash bash/manager/update_malware.sh > "$TMP/sim/upd.log" 2>&1; }
t "update_malware.sh s'exécute" run_upd
t "liste de hashes : 80 entrées au format CDB" bash -c '[[ "$(wc -l < '"$TMP"'/sim/out/list)" == 80 ]] && grep -Eq "^[a-f0-9]{64}:$" '"$TMP"'/sim/out/list'
t "source YARA valide ajoutée" grep -q "Extra_Ok" "$TMP/sim/out/yara.yar"
t "source YARA cassée ignorée" bash -c '! grep -q Cassee '"$TMP"'/sim/out/yara.yar'
t "jeu final YARA compile" yara -w "$TMP/sim/out/yara.yar" /dev/null
t "manager redémarré (liste modifiée)" test -f "$TMP/sim/restarted"
rm -f "$TMP/sim/restarted"; run_upd
t "2e exécution : pas de redémarrage inutile" test ! -f "$TMP/sim/restarted"

echo "== 7. Daemon SMS (déduplication, niveau, plafond)"
t "test_sms.py" python3 tests/test_sms.py

echo; echo "Résultat : $PASS OK, $FAIL échec(s)"; (( FAIL == 0 ))
