#!/usr/bin/env bash
# common.sh — fonctions partagées (sourcé par tous les scripts)
BUNDLE_ROOT="${BUNDLE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
CONF_FILE="${BUNDLE_CONF:-$BUNDLE_ROOT/bundle.conf}"
SECRETS_DIR="/root/.wazuh-bundle"
SECRETS_FILE="$SECRETS_DIR/secrets.env"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
ASSUME_YES="${ASSUME_YES:-0}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[FAIL]${NC} $*" >&2; }
die()      { log_err "$*"; exit 1; }

require_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Lancer en root (sudo -i)."; }
pause()    { [[ "$ASSUME_YES" == "1" ]] || read -rp "Entrée pour continuer..." _; }
confirm()  { # confirm "question" -> 0 si oui
  [[ "$ASSUME_YES" == "1" ]] && return 0
  local a; read -rp "$1 [o/N] " a; [[ "$a" =~ ^[oOyY]$ ]]
}

load_conf() {
  [[ -f "$CONF_FILE" ]] || die "bundle.conf introuvable ($CONF_FILE). Faire : cp bundle.conf.example bundle.conf"
  # shellcheck disable=SC1090
  source "$CONF_FILE"
  if grep -v '^[[:space:]]*#' "$CONF_FILE" | grep -q "A_COMPLETER"; then
    log_err "bundle.conf contient encore des valeurs A_COMPLETER :"
    grep -n "A_COMPLETER" "$CONF_FILE" | grep -v ':[[:space:]]*#' >&2
    exit 1
  fi
}

# ---------- secrets (fichier root 600, jamais dans les logs) ----------
secret_set() { # secret_set CLE VALEUR
  mkdir -p "$SECRETS_DIR"; chmod 700 "$SECRETS_DIR"; touch "$SECRETS_FILE"; chmod 600 "$SECRETS_FILE"
  sed -i "/^$1=/d" "$SECRETS_FILE"
  printf '%s=%q\n' "$1" "$2" >> "$SECRETS_FILE"
}
secret_get() { # secret_get CLE
  [[ -f "$SECRETS_FILE" ]] || return 1
  # shellcheck disable=SC1090
  ( set +u; source "$SECRETS_FILE"; printf '%s' "${!1:-}" )
}
conf_set() { # conf_set CLE VALEUR  (dans bundle.conf)
  if grep -q "^$1=" "$CONF_FILE"; then sed -i "s|^$1=.*|$1=\"$2\"|" "$CONF_FILE"
  else echo "$1=\"$2\"" >> "$CONF_FILE"; fi
}
gen_password() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24; }

# ---------- fichiers ----------
backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    LAST_BACKUP="${f}.bak.$(date +%Y%m%d-%H%M%S)"
    cp -p "$f" "$LAST_BACKUP"; log_info "Sauvegarde : $LAST_BACKUP"
  fi
}
fix_ossec_permissions() { chown root:wazuh "$OSSEC_CONF"; chmod 660 "$OSSEC_CONF"; }

# ---------- ossec.conf : modifications strictes ----------
ossec_append_block() { # $1 = fichier source ; insère avant le dernier </ossec_config> (idempotent)
  [[ -f "$1" ]] || die "Fichier introuvable : $1"
  python3 - "$OSSEC_CONF" "$1" <<'PY' || return 1
import sys
t, a = sys.argv[1], sys.argv[2]
c = open(t).read(); add = open(a).read().strip()
if add in c: print("INFO : bloc deja present"); sys.exit(0)
m = "</ossec_config>"; i = c.rfind(m)
if i < 0: sys.exit("ERREUR : </ossec_config> introuvable")
open(t, "w").write(c[:i] + "\n" + add + "\n\n" + c[i:])
print("Bloc ajoute")
PY
  fix_ossec_permissions
}
ossec_insert_in_block() { # $1=balise  $2=ligne XML ; insère dans un bloc existant
  python3 - "$OSSEC_CONF" "$1" "$2" <<'PY' || return 1
import sys, re
t, tag, line = sys.argv[1:4]
c = open(t).read()
if line.strip() in c: print("INFO : deja present :", line.strip()); sys.exit(0)
m = re.search(r'</%s>' % re.escape(tag), c)
if not m: sys.exit("ERREUR : bloc <%s> introuvable dans ossec.conf" % tag)
open(t, "w").write(c[:m.start()] + "  " + line.strip() + "\n  " + c[m.start():])
print("Ajoute dans <%s> : %s" % (tag, line.strip()))
PY
  fix_ossec_permissions
}
ossec_set_tag() { # $1=balise $2=valeur ; ECHOUE si la balise n'existe pas
  python3 - "$OSSEC_CONF" "$1" "$2" <<'PY' || return 1
import sys, re
t, tag, val = sys.argv[1:4]
c = open(t).read()
pat = re.compile(r'(<%s>)[^<]*(</%s>)' % (re.escape(tag), re.escape(tag)))
if not pat.search(c): sys.exit("ERREUR : balise <%s> absente de ossec.conf" % tag)
open(t, "w").write(pat.sub(lambda m: m.group(1) + val + m.group(2), c, count=1))
print("<%s> = %s" % (tag, val))
PY
  fix_ossec_permissions
}

wazuh_config_test() { /var/ossec/bin/wazuh-analysisd -t >/tmp/wazuh-config-test.log 2>&1; }

safe_restart_manager() { # $1 = sauvegarde ossec.conf à restaurer si la config est invalide
  if ! wazuh_config_test; then
    log_err "Configuration invalide :"; tail -15 /tmp/wazuh-config-test.log >&2
    if [[ -n "${1:-}" && -f "$1" ]]; then cp -p "$1" "$OSSEC_CONF"; fix_ossec_permissions; log_warn "ossec.conf restauré depuis $1"; fi
    return 1
  fi
  systemctl restart wazuh-manager; sleep 5
  if systemctl is-active --quiet wazuh-manager; then log_ok "wazuh-manager actif"
  else log_err "wazuh-manager ne démarre pas : journalctl -xeu wazuh-manager | tail -30"; return 1; fi
}

deploy_rules() { install -o wazuh -g wazuh -m 640 "$1" "$2/$(basename "$1")"; }

indexer_curl() { # indexer_curl <args curl...>
  local pw; pw="$(secret_get INDEXER_ADMIN_PASSWORD)"
  curl -sS --cacert /etc/wazuh-indexer/certs/root-ca.pem -u "admin:${pw}" "$@"
}
