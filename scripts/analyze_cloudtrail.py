#!/usr/bin/env python3
"""Offline synthetic CloudTrail triage; no AWS access or dependencies."""
import argparse, collections, hashlib, json, pathlib

def analyze(path):
    raw=pathlib.Path(path).read_bytes()
    data=json.loads(raw)
    events=sorted(data['Records'] if isinstance(data,dict) else data,key=lambda e:e['eventTime'])
    counts=collections.Counter(e['eventName'] for e in events)
    keys=collections.defaultdict(list)
    findings=[]
    for e in events:
        identity=e.get('userIdentity',{})
        keys[identity.get('accessKeyId','UNKNOWN')].append(e)
        name=e['eventName']; params=e.get('requestParameters',{})
        if name=='AuthorizeSecurityGroupIngress' and '0.0.0.0/0' in json.dumps(params) and not e.get('errorCode'):
            findings.append({'eventID':e['eventID'],'finding':'Public ingress rule created','confidence':'high'})
        if name in ('GetSecretValue','GetObject','AssumeRole') and not e.get('errorCode'):
            findings.append({'eventID':e['eventID'],'finding':'Successful '+name+' API event; downstream impact unverified','confidence':'high'})
        if name in ('CreateAccessKey','StopLogging','SendCommand') and e.get('errorCode'):
            findings.append({'eventID':e['eventID'],'finding':'Failed '+name+' attempt','confidence':'high'})
    return {'sha256':hashlib.sha256(raw).hexdigest(),'events':len(events),'first':events[0]['eventTime'] if events else None,'last':events[-1]['eventTime'] if events else None,'event_counts':dict(sorted(counts.items())),'identity_keys':{k:{'events':len(v),'sources':sorted(set(x['sourceIPAddress'] for x in v))} for k,v in sorted(keys.items())},'findings':findings,'limitations':['API success does not prove exfiltration','No session revocation confirmation','Synthetic incomplete CloudTrail-style records']}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('file');args=p.parse_args()
    print(json.dumps(analyze(args.file),indent=2))
