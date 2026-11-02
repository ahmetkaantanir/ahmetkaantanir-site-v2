"""Versioned declarative detection rules; no executable code or arbitrary SQL."""
import hashlib
import json
import re
from collections import defaultdict,deque
from datetime import datetime,timedelta
from integrations.platform import validate_sigma,sigma_matches


def validate_rule(rule):
    if not isinstance(rule,dict) or set(rule)-{'id','title','detection','severity','mitre','threshold','window_seconds','group_by'}:
        raise ValueError('Unsupported rule fields')
    if not re.fullmatch(r'USR-[A-Z0-9-]{1,40}',str(rule.get('id',''))):
        raise ValueError('Custom rule ID must start with USR- followed by uppercase letters, digits or hyphens')
    if not isinstance(rule.get('title'),str) or not 1<=len(rule['title'])<=120:
        raise ValueError('Rule title must contain 1-120 characters')
    validate_sigma(rule)
    if rule.get('severity','medium') not in {'low','medium','high','critical'}:
        raise ValueError('Invalid severity')
    if rule.get('mitre') and not re.fullmatch(r'T\d{4}(?:\.\d{3})?',str(rule['mitre'])):
        raise ValueError('Invalid MITRE technique reference')
    if rule.get('group_by','ip') not in {'ip','user','host'}:
        raise ValueError('group_by must be ip, user or host')
    for key,default,low,high in [('threshold',1,1,1000),('window_seconds',300,30,3600)]:
        value=rule.get(key,default)
        if type(value) is not int or not low<=value<=high:
            raise ValueError('Invalid '+key)
    return rule


def evaluate(rule,events,version=1):
    matches=[e for e in events if sigma_matches(e,rule['detection']['selection'])]
    threshold=rule.get('threshold',1);groups=[]
    if threshold==1:
        groups=[[e] for e in matches[:100]]
    else:
        by_entity=defaultdict(list)
        for e in matches:
            if e.get('timestamp') and e.get(rule.get('group_by','ip')):
                by_entity[e[rule.get('group_by','ip')]].append(e)
        for records in by_entity.values():
            records.sort(key=lambda e:datetime.fromisoformat(e['timestamp'].replace('Z','+00:00')))
            window=deque()
            for e in records:
                t=datetime.fromisoformat(e['timestamp'].replace('Z','+00:00'))
                while window and t-datetime.fromisoformat(window[0]['timestamp'].replace('Z','+00:00'))>timedelta(seconds=rule.get('window_seconds',300)):
                    window.popleft()
                window.append(e)
                if len(window)>=threshold:
                    groups.append(list(window));break
    alerts=[]
    for group in groups[:100]:
        ids=[e['event_id'] for e in group][:100]
        alerts.append({'alert_id':hashlib.sha256((rule['id']+':'+str(version)+':'+','.join(ids)).encode()).hexdigest()[:20],
            'rule_id':rule['id'],'rule_version':version,'severity':rule.get('severity','medium'),
            'mitre':rule.get('mitre'),'ip':group[-1].get('ip'),'reason':rule['title']+' · declarative indicator; validate source context.',
            'event_ids':ids,'timestamp':group[-1].get('timestamp')})
    return alerts


def evaluate_rules(db,events):
    alerts=[]
    rows=db.execute('SELECT v.payload_json,v.version FROM lab_rules r JOIN lab_rule_versions v ON v.rule_id=r.id AND v.version=r.version WHERE r.active=1 LIMIT 50')
    for row in rows:
        alerts+=evaluate(json.loads(row['payload_json']),events,row['version'])
    return alerts
