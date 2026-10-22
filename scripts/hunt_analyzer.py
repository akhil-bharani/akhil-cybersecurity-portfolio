#!/usr/bin/env python3
"""Deterministic correlation of synthetic hunt telemetry. Standard library only."""
import argparse, collections, datetime, json, pathlib

def load(path):
    return [json.loads(line) for line in pathlib.Path(path).read_text().splitlines() if line.strip()]

def analyze(events):
    by_host=collections.defaultdict(list)
    for x in events: by_host[x['host']].append(x)
    findings=[]
    for host, xs in sorted(by_host.items()):
        xs.sort(key=lambda x:x['timestamp'])
        suspicious_ps=any(x['source']=='sysmon' and x['event']=='1' and x.get('parent')=='WINWORD.EXE' and x.get('image')=='powershell.exe' for x in xs)
        suspicious_domain=any(x.get('domain')=='cdn-assets.support-example.test' for x in xs)
        if suspicious_ps and suspicious_domain:
            findings.append({'host':host,'rule':'office_powershell_plus_unusual_domain','evidence':[x['timestamp'] for x in xs if x.get('parent')=='WINWORD.EXE' or x.get('domain')=='cdn-assets.support-example.test']})
        if any(x['source']=='file' and x.get('count',0)>100 for x in xs) and any(x.get('bytes_out',0)>10000000 for x in xs):
            findings.append({'host':host,'rule':'file_read_burst_plus_large_egress','evidence':[x['timestamp'] for x in xs if x['source']=='file' or x.get('bytes_out',0)>10000000]})
    return {'events':len(events),'hosts':len(by_host),'findings':findings,'sources':dict(collections.Counter(x['source'] for x in events))}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('input',nargs='?',default='evidence/hunt-2026-031/events.jsonl');a=parser.parse_args()
    print(json.dumps(analyze(load(a.input)),indent=2))
if __name__=='__main__':main()
