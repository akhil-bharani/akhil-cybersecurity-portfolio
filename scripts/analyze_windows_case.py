#!/usr/bin/env python3
"""Read-only synthetic evidence triage; not a forensic parser or KAPE replacement."""
import argparse,csv,json
from collections import Counter
from pathlib import Path

def analyze(path):
    with Path(path).open(newline='',encoding='utf-8') as f:
        events=list(csv.DictReader(f))
    events.sort(key=lambda r:r['timestamp_utc'])
    indicators={'powershell':[],'persistence':[],'possible_archive':[],'deletion':[],'orphan_shortcut':[]}
    for e in events:
        s=(e['details']+' '+e['source']).lower()
        if 'powershell' in s or e['event_id']=='4104': indicators['powershell'].append(e['timestamp_utc'])
        if e['event_id']=='4698': indicators['persistence'].append(e['timestamp_utc'])
        if '7z' in s or 'cachepack.7z' in s: indicators['possible_archive'].append(e['timestamp_utc'])
        if 'in_use=false' in s or e['event_id']=='DELETE': indicators['deletion'].append(e['timestamp_utc'])
        if 'target_exists=false' in s: indicators['orphan_shortcut'].append(e['timestamp_utc'])
    return {'event_count':len(events),'sources':dict(Counter(e['source'] for e in events)), 'first_seen':events[0]['timestamp_utc'] if events else None,'last_seen':events[-1]['timestamp_utc'] if events else None,'indicators':indicators,'timeline':[{'time':e['timestamp_utc'],'source':e['source'],'event':e['event_id'],'note':e['analyst_note']} for e in events]}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('csv',nargs='?',default='evidence/windows-dfir/events.csv');a=p.parse_args()
    print(json.dumps(analyze(a.csv),indent=2))
