"""Bounded, parameterized evidence queries shared by UI and Copilot."""
import json
from datetime import datetime, timezone

FIELDS = {'ip':'ip', 'source':'source', 'user':'user_name', 'host':"json_extract(raw_json,'$.host')",
          'outcome':"json_extract(raw_json,'$.outcome')", 'action':"json_extract(raw_json,'$.action')",
          'severity':"json_extract(raw_json,'$.severity')", 'event_id':'event_id', 'batch_id':'batch_id',
          'source_id':"json_extract(raw_json,'$.source_id')"}


def utc(value):
    if not isinstance(value, str) or len(value)>64:
        raise ValueError('A timezone-aware ISO timestamp is required')
    try:
        moment = datetime.fromisoformat(value.replace('Z','+00:00'))
        if moment.tzinfo is None:
            raise ValueError()
        return moment.astimezone(timezone.utc).isoformat().replace('+00:00','Z')
    except (ValueError, OverflowError):
        raise ValueError('A timezone-aware ISO timestamp is required') from None


def where(filters):
    if not isinstance(filters,dict) or set(filters)-set(FIELDS)-{'q','start','end','rule_id','mitre','status','synthetic','event_ids'}:
        raise ValueError('Unsupported query fields')
    clauses, args = [], []
    for name, column in FIELDS.items():
        value = filters.get(name)
        if value in (None,''):
            continue
        if not isinstance(value,(str,int)) or len(str(value))>256:
            raise ValueError('Invalid filter: '+name)
        clauses.append(column+'=?'); args.append(str(value))
    if filters.get('q'):
        if not isinstance(filters['q'],str) or len(filters['q'])>256:
            raise ValueError('Search text limit is 256 characters')
        clauses.append('instr(lower(raw_json),lower(?))>0');args.append(filters['q'])
    for key, op in [('start','>='),('end','<=')]:
        if filters.get(key):
            clauses.append('julianday(timestamp) '+op+' julianday(?)');args.append(utc(filters[key]))
    if filters.get('start') and filters.get('end') and datetime.fromisoformat(utc(filters['start']).replace('Z','+00:00'))>datetime.fromisoformat(utc(filters['end']).replace('Z','+00:00')):
        raise ValueError('start must not be after end')
    if filters.get('event_ids') is not None:
        ids=filters['event_ids']
        if not isinstance(ids,list) or not 1<=len(ids)<=100 or any(not isinstance(i,str) or len(i)>100 for i in ids):
            raise ValueError('event_ids must contain 1-100 bounded IDs')
        clauses.append('event_id IN (SELECT value FROM json_each(?))');args.append(json.dumps(ids))
    for key, array in [('rule_id','detection_rules'),('mitre','mitre')]:
        if filters.get(key):
            if not isinstance(filters[key],str) or len(filters[key])>80:
                raise ValueError('Invalid '+key)
            clauses.append("EXISTS (SELECT 1 FROM json_each(json_extract(raw_json,'$."+array+"')) WHERE value=?)")
            args.append(filters[key])
    if filters.get('synthetic') not in (None,''):
        if type(filters['synthetic']) is not bool:
            raise ValueError('synthetic must be a boolean')
        clauses.append("COALESCE(json_extract(raw_json,'$.synthetic'),0)=?");args.append(int(filters['synthetic']))
    if filters.get('status') not in (None, ''):
        if not isinstance(filters['status'], str) or filters['status'] not in {'new','investigating','resolved','false_positive'}:
            raise ValueError('Invalid case status')
        clauses.append('event_id IN (SELECT value FROM soc_cases,json_each(evidence_json) WHERE status=?)')
        args.append(filters['status'])
    return (' WHERE '+' AND '.join(clauses) if clauses else ''), args


def search_events(db, filters, limit=200, offset=0, order='desc'):
    for name, value in [('limit', limit), ('offset', offset)]:
        if type(value) is not int and not (isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 10):
            raise ValueError(name+' must be an integer')
    if not isinstance(order, str) or order not in {'asc', 'desc'}:
        raise ValueError('order must be asc or desc')
    limit = max(1,min(int(limit),500));offset=max(0,min(int(offset),1000000))
    clause,args = where(filters)
    total = db.execute('SELECT COUNT(*) FROM soc_events'+clause,args).fetchone()[0]
    direction = 'ASC' if order=='asc' else 'DESC'
    rows = db.execute('SELECT id,batch_id,raw_json FROM soc_events'+clause+' ORDER BY julianday(timestamp) '+direction+',id '+direction+' LIMIT ? OFFSET ?',args+[limit,offset])
    return {'items':[{**json.loads(r['raw_json']),'row_id':r['id'],'batch_id':r['batch_id']} for r in rows],
            'total':total,'limit':limit,'offset':offset,'has_more':offset+limit<total,'filters':filters,'time_basis':'source_timestamp'}
