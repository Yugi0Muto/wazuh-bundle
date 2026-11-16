# wazuh-bundle v2 — déploiement Wazuh en production

Bundle d'installation et de configuration d'un SIEM Wazuh (all-in-one) pour une entreprise
organisée en trois segments : **SERVEURS**, **EMPLOYÉS**, **DMZ**.

> Statut : première version à **recetter**. Chaque étape est idempotente et s'arrête à la
> première erreur. Voir `RECETTE.md` pour le plan de test.

## Contenu
| Étape | Script | Rôle |
|---|---|---|
| 00 | `00_preflight.sh` | Contrôles (OS, RAM, disque, ports, NTP, réseau). Ne modifie rien. |
| 01 | `01_base_setup.sh` | Durcissement SSH sûr + installation Wazuh all-in-one |
| 02 | `02_firewall.sh` | Pare-feu nftables par segment, avec annulation automatique (90 s) |
| 03 | `03_manager_config.sh` | Enrôlement par mot de passe, liste blanche, groupes, règles |
| 04 | `04_malware_detection.sh` | YARA + liste de hashes, mise à jour quotidienne |
| 05 | `05_retention.sh` | Suppression des alertes > N jours |
| 06 | `06_grafana.sh` | Grafana, utilisateur indexer lecture seule, dashboard |
| 07 | `07_email_alerts.sh` | Email via relais SMTP interne |
| 08 | `08_sms_alerts.sh` | SMS (Africa's Talking), dédup + plafond |
| 09 | `09_backup.sh` | Sauvegarde quotidienne de la configuration |
| 99 | `99_verify.sh` | Recette automatique |

Agents : `bash/agents/install_agent_linux.sh`, `bash/agents/install_agent_windows.ps1`.

## Démarrage rapide (serveur Debian/Ubuntu neuf)
```bash
sudo -i
apt-get update && apt-get install -y git
git clone https://github.com/VOTRE_COMPTE/wazuh-bundle.git /opt/wazuh-bundle
cd /opt/wazuh-bundle
git checkout v2.0.0            # en production : toujours un tag, jamais la branche principale
cp bundle.conf.example bundle.conf && chmod 600 bundle.conf
nano bundle.conf               # remplir TOUTES les valeurs A_COMPLETER
bash install.sh --step 00      # préflight ; corriger jusqu'à "Préflight OK"
bash install.sh                # menu, ou : bash install.sh --all
```
**Ne pas faire** `curl ... | sudo bash` : ces scripts s'exécutent en root, relire le code avant de les lancer.

## Démarrage (archive ZIP)
```bash
sudo -i
cd wazuh-bundle-v2
cp bundle.conf.example bundle.conf && chmod 600 bundle.conf
nano bundle.conf            # remplir TOUTES les valeurs A_COMPLETER
bash install.sh --step 00   # corriger jusqu'à "Préflight OK"
bash install.sh             # menu, ou : bash install.sh --all
```

## Configuration centralisée par groupes
Un agent appartient à plusieurs groupes ; la configuration est poussée par le manager.
`seg-dmz|servers|employees` + `os-linux|windows` + `role-web|db|admin` + `feat-yara` + `opt-whodata`.
Modifier `configs/groups/<groupe>/agent.conf` puis relancer l'étape 03.

## Fichiers sensibles (jamais dans Git)
`bundle.conf` (contient des adresses internes) et `/root/.wazuh-bundle/` (mots de passe).

## Tests (sans Wazuh, sans root)
```bash
sudo apt-get install -y yara jq shellcheck libxml2-utils
bash tests/run_tests.sh
```
Vérifie : syntaxe et shellcheck, XML/JSON, règles YARA (EICAR, webshell), script Active Response,
mise à jour des hashes/règles (simulation), daemon SMS. Exécutés aussi par GitHub Actions à chaque push.
Les tests ne remplacent pas la recette sur un vrai serveur (`RECETTE.md`).

## Publication : bonnes pratiques
- `bundle.conf` et les secrets sont exclus par `.gitignore` : ne jamais les forcer (`git add -f`).
- Dépôt **privé** recommandé si la configuration décrit votre architecture réelle.
- Versionner par tags (`v2.0.1`...) et déployer uniquement des tags testés.
- Choisir une licence (fichier `LICENSE`) avant de rendre le dépôt public.
