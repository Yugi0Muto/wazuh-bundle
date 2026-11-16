import os, sys, tempfile, threading, time, json, importlib.util
HERE=os.path.dirname(os.path.abspath(__file__))
ALERTS=os.path.join(tempfile.mkdtemp(),"alerts.json"); open(ALERTS,"w").close()
os.environ.update(AT_USERNAME="sandbox", AT_API_KEY="x", SMS_TO="+241000", SMS_ALERT_LEVEL="10", SMS_MAX_PER_HOUR="3", SMS_DEDUP_SECONDS="300")
spec=importlib.util.spec_from_file_location("sms",os.path.join(HERE,"..","configs","manager","wazuh-sms-alerter.py")); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.ALERTS=ALERTS; out=[]
m.send=lambda t:(out.append(t) or True)
threading.Thread(target=m.follow,daemon=True).start(); time.sleep(1.5)
def al(agent,rid,lvl): return json.dumps({"timestamp":"2026-11-16T10:00:00","agent":{"name":agent},"rule":{"id":rid,"level":lvl,"description":"d"+rid}})+"\n"
with open(ALERTS,"a") as f:
    for a in [al("a","1",12),al("a","1",12),al("a","2",5),al("b","1",12),al("c","3",13),al("d","4",13),al("e","5",13)]: f.write(a)
time.sleep(3)
print(len(out),"SMS:",out)
assert len(out)==3, "attendu 3 SMS (dedup + niveau + plafond)"
assert all("d2" not in t for t in out), "regle de niveau 5 ne doit pas envoyer de SMS"
print("OK")
