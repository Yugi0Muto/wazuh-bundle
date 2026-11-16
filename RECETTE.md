# Plan de recette (à dérouler après installation)

Renseigner OK / KO / commentaire pour chaque ligne.

| # | Test | Commande / action | Résultat attendu |
|---|---|---|---|
| 1 | Préflight | `./install.sh --step 00` | « Préflight OK » |
| 2 | Recette serveur | `./install.sh --step 99` | 0 échec |
| 3 | Pare-feu : admin | Ouvrir `https://IP` depuis un poste ADMIN | Page de connexion |
| 4 | Pare-feu : non-admin | Même URL depuis un poste employé | Refusé / timeout |
| 5 | Agent Linux DMZ | `install_agent_linux.sh ... --segment dmz --role web --yara` | « Agent connecté » |
| 6 | Agent Linux serveurs | idem `--segment servers --role db` | Connecté |
| 7 | Agent Windows employé | `install_agent_windows.ps1 ... -Segment employees` | Connecté |
| 8 | Groupes | `/var/ossec/bin/agent_groups -l` ; `agent_groups -s -i <ID>` | Groupes attendus par agent |
| 9 | Config poussée | Sur l'agent : `ls /var/ossec/etc/shared/` | `yara_rules.yar` présent (agent feat-yara) |
| 10 | FIM | Modifier `/etc/hosts` sur un agent | Alerte 550 (ou 100502 selon chemin) |
| 11 | YARA | `printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /var/www/eicar.txt` | Alerte 100511 niveau 12 |
| 12 | Hash malveillant | Ajouter le SHA256 d'un fichier test dans `etc/lists/malware-sha256`, redémarrer, créer le fichier | Alerte 100500 niveau 14 |
| 13 | Defender | Fichier EICAR sur un poste Windows | Alerte 100540 (sinon ajuster la règle) |
| 14 | Brute force + AR | 6 échecs SSH depuis un poste NON whitelisté | Alerte 5763, IP bloquée 10 min (`iptables -L`) |
| 15 | Liste blanche | Même test depuis une IP whitelistée | AUCUN blocage |
| 16 | Email | Alerte niveau >= EMAIL_ALERT_LEVEL | Email reçu |
| 17 | SMS | Alerte niveau >= SMS_ALERT_LEVEL | SMS reçu (hors sandbox) ; 2e identique ignorée |
| 18 | Grafana | `http://IP:3000` | Dashboard « Wazuh — Vue SOC » avec données |
| 19 | Rétention | Dashboard > Index Management | Politique `wazuh-retention` |
| 20 | Sauvegarde | `ls -l /var/backups/wazuh` | Archive du jour |
| 21 | Redémarrage | `reboot` | Tous les services reviennent (`./install.sh --step 99`) |
