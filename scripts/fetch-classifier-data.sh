#!/bin/sh
# Fetch public prompt-injection datasets (Apache-2.0) into
# internal/classifier/data/external.jsonl. Requires python3 + network.
set -e
cd "$(dirname "$0")/.."
python3 - <<'PY'
import csv, json, urllib.request, time
out=open('internal/classifier/data/external.jsonl','w'); na=nb=0
def w(t,l):
    global na,nb
    t=(t or '').strip()
    if 3<=len(t)<=6000:
        out.write(json.dumps({"text":t,"label":l},ensure_ascii=False)+"\n")
        na+=l==1; nb+=l==0
for sp in ("train","test"):
    u=f"https://huggingface.co/datasets/jackhhao/jailbreak-classification/resolve/main/balanced/jailbreak_dataset_{sp}_balanced.csv"
    for row in csv.DictReader(urllib.request.urlopen(u,timeout=60).read().decode('utf-8','replace').splitlines()):
        w(row.get('prompt',''),1 if row.get('type','').lower()=='jailbreak' else 0)
for sp in ("train","test"):
    off=0
    while True:
        u=f"https://datasets-server.huggingface.co/rows?dataset=deepset/prompt-injections&config=default&split={sp}&offset={off}&length=100"
        try: d=json.load(urllib.request.urlopen(u,timeout=60))
        except Exception: break
        rows=d.get('rows',[])
        if not rows: break
        for r in rows: w(r['row'].get('text',''),int(r['row'].get('label',0)))
        off+=len(rows); time.sleep(0.2)
        if off>=d.get('num_rows_total',0): break
out.close(); print(f"external.jsonl attack={na} benign={nb}")
PY
