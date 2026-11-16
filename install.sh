#!/usr/bin/env bash
# install.sh — assistant d'installation du serveur Wazuh (à lancer SUR le serveur, en root)
#   ./install.sh            menu interactif
#   ./install.sh --all      enchaîne 00 -> 09 puis 99 (le pare-feu demande une confirmation)
#   ./install.sh --step 03  une seule étape
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MGR="$SCRIPT_DIR/bash/manager"
source "$SCRIPT_DIR/bash/lib/common.sh"
require_root

declare -A LABEL=(
 [00]="Préflight (contrôles, ne modifie rien)"        [01]="Installation Wazuh + durcissement SSH"
 [02]="Pare-feu nftables par segment"                  [03]="Configuration manager (enrôlement, groupes, règles)"
 [04]="Détection malware (YARA + hashes)"              [05]="Rétention des alertes"
 [06]="Grafana + dashboard"                            [07]="Alertes email"
 [08]="Alertes SMS"                                    [09]="Sauvegardes"
 [99]="Recette automatique" )
ORDER=(00 01 02 03 04 05 06 07 08 09 99)

run_step() {
  local n="$1" script; script="$(ls "$MGR/${n}_"*.sh 2>/dev/null | head -1)"
  [[ -n "$script" ]] || { log_err "Étape $n inconnue"; return 1; }
  echo; log_info "══ Étape $n : ${LABEL[$n]} ══"
  if bash "$script"; then log_ok "Étape $n : terminée"; else log_err "Étape $n : ÉCHEC (voir messages ci-dessus)"; return 1; fi
}

case "${1:-}" in
  --all)  for n in "${ORDER[@]}"; do run_step "$n" || exit 1; done; exit 0;;
  --step) run_step "${2:?numero de l etape}"; exit $?;;
esac

while true; do
  clear; echo "╔════════════════════════════════════════════╗"; echo "║   WAZUH BUNDLE v2 — installation serveur   ║"; echo "╚════════════════════════════════════════════╝"
  for n in "${ORDER[@]}"; do printf "  %s) %s\n" "$n" "${LABEL[$n]}"; done
  echo "  a) Tout exécuter dans l'ordre     q) Quitter"; echo
  read -rp "Choix : " c
  case "$c" in
    q) exit 0;;
    a) for n in "${ORDER[@]}"; do run_step "$n" || break; done; pause;;
    *) [[ -n "${LABEL[$c]:-}" ]] && { run_step "$c" || true; pause; } || { echo "Choix invalide"; sleep 1; };;
  esac
done
