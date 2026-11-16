#!/usr/bin/env python3
"""Wazuh SMS alerter — Africa's Talking (API REST, sans dépendance externe).

Lit /var/ossec/logs/alerts/alerts.json en continu et envoie un SMS pour chaque
alerte de niveau >= SMS_ALERT_LEVEL, avec :
  - déduplication (même agent + même règle dans SMS_DEDUP_SECONDS)
  - plafond horaire (SMS_MAX_PER_HOUR) ; un SMS de synthèse signale les alertes supprimées
  - gestion de la rotation du fichier d'alertes
Configuration par variables d'environnement (EnvironmentFile du service systemd).
"""
import json, os, sys, time, urllib.parse, urllib.request

ALERTS = "/var/ossec/logs/alerts/alerts.json"
USER   = os.environ["AT_USERNAME"]
KEY    = os.environ["AT_API_KEY"]
TO     = os.environ["SMS_TO"].split()
LEVEL  = int(os.environ.get("SMS_ALERT_LEVEL", "12"))
MAXH   = int(os.environ.get("SMS_MAX_PER_HOUR", "20"))
DEDUP  = int(os.environ.get("SMS_DEDUP_SECONDS", "300"))
URL = ("https://api.sandbox.africastalking.com/version1/messaging" if USER == "sandbox"
       else "https://api.africastalking.com/version1/messaging")

seen, sent_ts, suppressed = {}, [], 0

def log(msg): print(msg, flush=True)

def send(text):
    data = urllib.parse.urlencode({"username": USER, "to": ",".join(TO), "message": text[:160]}).encode()
    req = urllib.request.Request(URL, data=data, headers={"apiKey": KEY, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            body = json.loads(r.read().decode())
        for rcpt in body.get("SMSMessageData", {}).get("Recipients", []):
            log(f"SMS -> {rcpt.get('number')} status={rcpt.get('status')} cost={rcpt.get('cost')}")
        return True
    except Exception as e:
        log(f"[ERREUR] envoi SMS : {e}")
        return False

def allowed(alert):
    global suppressed
    now = time.time()
    key = (alert.get("agent", {}).get("name", "?"), alert.get("rule", {}).get("id", "?"))
    for k in [k for k, t in seen.items() if now - t > DEDUP]: del seen[k]
    if key in seen: suppressed += 1; return False
    sent_ts[:] = [t for t in sent_ts if now - t < 3600]
    if len(sent_ts) >= MAXH: suppressed += 1; return False
    seen[key] = now
    return True

def fmt(a):
    r = a.get("rule", {})
    return f"[WAZUH L{r.get('level','?')}] {a.get('agent',{}).get('name','?')} {a.get('timestamp','')[11:16]} {r.get('description','')}"

def follow():
    global suppressed
    f, ino, first, last_summary = None, None, True, time.time()
    while True:
        try:
            st = os.stat(ALERTS)
            if f is None or st.st_ino != ino:
                if f: f.close()
                f = open(ALERTS, "r"); ino = st.st_ino
                if first: f.seek(0, 2)      # au démarrage : ne pas rejouer l'historique
                first = False               # après rotation : lire le nouveau fichier depuis le début
        except FileNotFoundError:
            time.sleep(5); continue
        line = f.readline()
        if not line:
            if suppressed and time.time() - last_summary > 3600:
                if send(f"[WAZUH] {suppressed} alerte(s) supprimee(s) (doublons/plafond) sur 1h. Voir le dashboard."):
                    suppressed = 0
                last_summary = time.time()
            time.sleep(1); continue
        try:
            a = json.loads(line)
            if int(a.get("rule", {}).get("level", 0)) >= LEVEL and allowed(a):
                if send(fmt(a)): sent_ts.append(time.time())
        except (json.JSONDecodeError, ValueError):
            continue

if __name__ == "__main__":
    log(f"wazuh-sms-alerter démarré (niveau >= {LEVEL}, max {MAXH}/h, dédup {DEDUP}s, {URL})")
    follow()
