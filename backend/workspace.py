"""V7 authenticated workspace API. The parent SOC guard protects every route."""
import hashlib
import json
import sqlite3
import time
import uuid
from collections import Counter
from datetime import datetime,timedelta,timezone

from flask import Blueprint,Response,g,jsonify,request,stream_with_context

from backend.query import search_events,where,utc
from backend.storage import custody,verify_custody,now
from backend.rules import validate_rule,evaluate
from backend import cloud_sync
from backend.copilot import investigate,TOOLS
from integrations.client import IntegrationError,fetch_json,origin
from soc_engine import RULES


def create_workspace_blueprint(connection,audit):
    bp=Blueprint('workspace',__name__,url_prefix='/workspace')

    def actor():return g.soc_principal['name']
    def payload():
        p=request.get_json(silent=True)
        if not isinstance(p,dict):raise ValueError('JSON object required')
        return p
    def bounded(db):
        deadline=time.monotonic()+3
        db.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
        return db
    def text(value,name,limit=120,empty=False):
        if not isinstance(value,str) or len(value)>limit or (not empty and not value.strip()):
            raise ValueError('Invalid '+name)
        return value.strip()
    def record_query(db,filters,count):
        db.execute('INSERT INTO lab_query_history(actor,at,filters_json,result_count) VALUES (?,?,?,?)',
            (actor(),now(),json.dumps(filters,ensure_ascii=False),count))
    def context(value):
        if not isinstance(value,dict) or set(value)-{'filters','event_id','case_id','source','project_id'}:
            raise ValueError('Invalid investigation context')
        where(value.get('filters',{}))
        if len(json.dumps(value))>5000:raise ValueError('Context limit exceeded')
        return value

    @bp.errorhandler(ValueError)
    def invalid(exc):return jsonify(error=str(exc)),400
    @bp.errorhandler(sqlite3.OperationalError)
    def db_error(exc):return jsonify(error='Query budget exceeded or storage unavailable'),503
    @bp.errorhandler(IntegrationError)
    def upstream(exc):return jsonify(error=str(exc),state='unavailable'),503

    @bp.get('/capabilities')
    def capabilities():
        return jsonify(version='7.0',principal=g.soc_principal,cloud_write=cloud_sync.configured(),
            read_only_tools=TOOLS,source_clock='UTC; unknown timestamps are excluded from timed queries',
            storage='sqlite',limits={'query_records':500,'copilot_records':200,'history_context':10000},
            persistence='Requires a persistent disk; free Render local storage is temporary')

    @bp.post('/query')
    def query():
        p=payload()
        with connection() as db:
            bounded(db)
            result=search_events(db,p.get('filters',{}),p.get('limit',100),p.get('offset',0),p.get('order','desc'))
            record_query(db,result['filters'],result['total'])
        return jsonify(result)

    @bp.get('/search')
    def global_search():
        q=text(request.args.get('q',''),'search',256)
        with connection() as db:
            bounded(db)
            result=search_events(db,{'q':q},50)
            cases=[dict(r) for r in db.execute('SELECT id,rule_id,ip,status,reason FROM soc_cases WHERE instr(lower(reason||rule_id||COALESCE(ip,\'\')),lower(?))>0 OR CAST(id AS TEXT)=? ORDER BY id DESC LIMIT 50',(q,q))]
            rules=[{'id':key,**value} for key,value in RULES.items() if q.lower() in (key+' '+value['name']+' '+str(value.get('mitre'))).lower()]
            record_query(db,{'q':q},result['total'])
        return jsonify(query=q,events=result['items'],event_total=result['total'],cases=cases,rules=rules)

    @bp.post('/analytics')
    def analytics():
        p=payload();filters=p.get('filters',{})
        clause,args=where(filters)
        with connection() as db:
            bounded(db)
            counts=dict(db.execute('SELECT COUNT(*) total,SUM(CASE WHEN timestamp IS NULL THEN 1 ELSE 0 END) missing_time,SUM(CASE WHEN json_extract(raw_json,\'$.outcome\')=\'failure\' THEN 1 ELSE 0 END) failures FROM soc_events'+clause,args).fetchone())
            timeline=[dict(r) for r in db.execute('SELECT substr(timestamp,1,13) hour,COUNT(*) events FROM soc_events'+clause+(' AND ' if clause else ' WHERE ')+'timestamp IS NOT NULL GROUP BY hour ORDER BY hour DESC LIMIT 168',args)]
            src=[dict(r) for r in db.execute('SELECT source,COUNT(*) events FROM soc_events'+clause+' GROUP BY source ORDER BY events DESC LIMIT 20',args)]
            risk=[dict(r) for r in db.execute("SELECT COALESCE(json_extract(raw_json,'$.severity'),'no_rule_match') severity,COUNT(*) events FROM soc_events"+clause+' GROUP BY severity',args)]
            top={}
            for field,column in [('ip','ip'),('user','user_name'),('host',"json_extract(raw_json,'$.host')")]:
                top[field]=[dict(r) for r in db.execute('SELECT '+column+' entity,COUNT(*) events FROM soc_events'+clause+(' AND ' if clause else ' WHERE ')+column+' IS NOT NULL GROUP BY entity ORDER BY events DESC LIMIT 10',args)]
        return jsonify(counts=counts,timeline=list(reversed(timeline)),sources=src,severities=risk,entities=top,filters=filters,
            state='ready' if counts['total'] else 'no_matching_data',scope='Filtered SOC events; timeline capped at 168 occupied hours')

    @bp.post('/loki')
    def loki():
        from backend.loki import query_logs
        p=payload()
        with connection() as db:
            data=query_logs(p.get('filters',{}),p.get('query'),db)
            record_query(db,{'source':'loki','query':data['query'],'filters':data['filters']},len(data['items']))
        return jsonify(data)

    @bp.get('/evidence/<event_id>')
    def evidence(event_id):
        with connection() as db:
            data=search_events(db,{'event_id':event_id},1)['items']
            if not data:return jsonify(error='Event not found'),404
            e=data[0]
            occurrences=[dict(r) for r in db.execute('SELECT batch_id,line,source_id FROM lab_occurrences WHERE event_id=? ORDER BY batch_id DESC LIMIT 100',(event_id,))]
            cases=[dict(r) for r in db.execute('SELECT id,rule_id,status,severity FROM soc_cases WHERE EXISTS (SELECT 1 FROM json_each(evidence_json) WHERE value=?) ORDER BY id DESC LIMIT 50',(event_id,))]
            batch=db.execute('SELECT sha256,created_at,source FROM soc_batches WHERE id=?',(e['batch_id'],)).fetchone()
            custody(db,actor(),'evidence_read',event_id)
        return jsonify(event=e,occurrences=occurrences,cases=cases,batch=dict(batch) if batch else None)

    @bp.get('/sources')
    def sources():
        with connection() as db:
            rows=[dict(r) for r in db.execute('SELECT * FROM lab_sources ORDER BY last_ingested DESC LIMIT 100')]
            collectors=[]
            for row in db.execute('SELECT * FROM lab_collectors ORDER BY last_seen DESC LIMIT 100'):
                age=(datetime.now(timezone.utc)-datetime.fromisoformat(row['last_seen'])).total_seconds()
                collectors.append({**dict(row),'metadata':json.loads(row['metadata']),'contact_state':'recent' if age<=90 else 'stale','age_seconds':round(age)})
            quality=dict(db.execute("SELECT COUNT(*) events,SUM(CASE WHEN timestamp IS NULL THEN 1 ELSE 0 END) missing_time,SUM(CASE WHEN source='unknown' THEN 1 ELSE 0 END) unparsed FROM soc_events").fetchone())
        return jsonify(sources=rows,collectors=collectors,quality=quality,heartbeat_means='Collector contact, not proof of complete source delivery')

    @bp.post('/heartbeat')
    def heartbeat():
        p=payload();version=text(p.get('version','unknown'),'version',40)
        meta=p.get('metadata',{})
        if not isinstance(meta,dict) or len(json.dumps(meta))>1000:raise ValueError('Metadata limit exceeded')
        with connection() as db:
            db.execute('INSERT INTO lab_collectors(id,version,last_seen,metadata) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,last_seen=excluded.last_seen,metadata=excluded.metadata',
                (actor(),version,now(),json.dumps(meta)))
        return jsonify(accepted=True,collector_id=actor())

    @bp.get('/sync')
    def sync_status():
        with connection() as db:return jsonify(cloud_sync.status(db))
    @bp.post('/sync')
    def sync():return jsonify(cloud_sync.flush(connection))

    @bp.get('/investigations')
    def investigations():
        with connection() as db:
            items=[{**dict(r),'context':json.loads(r['context_json'])} for r in db.execute('SELECT * FROM lab_investigations ORDER BY updated_at DESC LIMIT 100')]
        return jsonify(items=items)
    @bp.post('/investigations')
    def save_investigation():
        p=payload();title=text(p.get('title'),'title');ctx=context(p.get('context',{}));notes=text(p.get('notes',''),'notes',8000,True)
        with connection() as db:
            item=db.execute('INSERT INTO lab_investigations(title,context_json,notes,owner,created_at,updated_at) VALUES (?,?,?,?,?,?)',
                (title,json.dumps(ctx),notes,actor(),now(),now())).lastrowid
            audit(db,'investigation_saved',item)
        return jsonify(id=item),201
    @bp.patch('/investigations/<int:item>')
    def update_investigation(item):
        p=payload();ctx=context(p.get('context',{}));notes=text(p.get('notes',''),'notes',8000,True)
        with connection() as db:
            row=db.execute('SELECT owner FROM lab_investigations WHERE id=?',(item,)).fetchone()
            if not row:return jsonify(error='Investigation not found'),404
            if row['owner']!=actor() and g.soc_principal['role']!='admin':return jsonify(error='Only the owner may edit this investigation'),403
            db.execute('UPDATE lab_investigations SET context_json=?,notes=?,updated_at=? WHERE id=?',(json.dumps(ctx),notes,now(),item))
            audit(db,'investigation_updated',item)
        return jsonify(updated=item)

    @bp.route('/saved-queries',methods=['GET','POST'])
    def saved_queries():
        with connection() as db:
            if request.method=='GET':return jsonify(items=[{**dict(r),'filters':json.loads(r['filters_json'])} for r in db.execute('SELECT * FROM lab_saved_queries ORDER BY id DESC LIMIT 100')])
            p=payload();name=text(p.get('name'),'name');filters=p.get('filters',{});where(filters)
            item=db.execute('INSERT INTO lab_saved_queries(name,filters_json,owner,created_at) VALUES (?,?,?,?)',(name,json.dumps(filters),actor(),now())).lastrowid
            audit(db,'query_saved',item)
        return jsonify(id=item),201
    @bp.get('/query-history')
    def history():
        with connection() as db:return jsonify(items=[dict(r) for r in db.execute('SELECT * FROM lab_query_history WHERE actor=? ORDER BY id DESC LIMIT 100',(actor(),))])

    @bp.get('/rules')
    def rule_library():
        with connection() as db:
            custom=[{**dict(r),'rule':json.loads(r['payload_json'])} for r in db.execute('SELECT r.id,r.active,r.version,v.payload_json,v.at,v.actor FROM lab_rules r JOIN lab_rule_versions v ON r.id=v.rule_id AND r.version=v.version ORDER BY v.at DESC LIMIT 100')]
            false_positives=[dict(r) for r in db.execute("SELECT rule_id,COUNT(*) cases,SUM(CASE WHEN status='false_positive' THEN 1 ELSE 0 END) reviewed_false_positives FROM soc_cases GROUP BY rule_id")]
        return jsonify(builtin=[{'id':k,**v} for k,v in RULES.items()],custom=custom,reviews=false_positives,
            warning='Analyst false-positive labels are not an unbiased measured false-positive rate')
    @bp.post('/rules')
    def save_rule():
        p=payload();rule=validate_rule(p.get('rule'));active=p.get('active',False)
        if type(active) is not bool:raise ValueError('active must be a boolean')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT COUNT(*) FROM lab_rules').fetchone()[0]>=100 and not db.execute('SELECT 1 FROM lab_rules WHERE id=?',(rule['id'],)).fetchone():raise ValueError('Custom rule limit reached')
            if active and db.execute('SELECT COUNT(*) FROM lab_rules WHERE active=1 AND id!=?',(rule['id'],)).fetchone()[0]>=50:raise ValueError('Active rule limit reached (50)')
            version=db.execute('SELECT COALESCE(MAX(version),0)+1 FROM lab_rule_versions WHERE rule_id=?',(rule['id'],)).fetchone()[0]
            db.execute('INSERT INTO lab_rule_versions(rule_id,version,payload_json,actor,at) VALUES (?,?,?,?,?)',(rule['id'],version,json.dumps(rule),actor(),now()))
            db.execute('INSERT INTO lab_rules(id,active,version) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET active=excluded.active,version=excluded.version',(rule['id'],int(active),version))
            audit(db,'rule_version_saved',rule['id']+':'+str(version))
        return jsonify(id=rule['id'],version=version,active=active),201
    @bp.get('/rules/<rule_id>/versions')
    def rule_versions(rule_id):
        with connection() as db:return jsonify(items=[{**dict(r),'rule':json.loads(r['payload_json'])} for r in db.execute('SELECT * FROM lab_rule_versions WHERE rule_id=? ORDER BY version DESC LIMIT 100',(rule_id,))])
    @bp.post('/rules/test')
    def test_rule():
        p=payload();rule=validate_rule(p.get('rule'))
        with connection() as db:
            bounded(db);events=search_events(db,p.get('filters',{}),500,order='asc')['items']
        matches=evaluate(rule,events)
        return jsonify(alerts=matches,reviewed=len(events),scope='At most 500 selected records; rule not activated',persisted=False)

    @bp.route('/aliases',methods=['GET','POST'])
    def aliases():
        with connection() as db:
            if request.method=='GET':return jsonify(items=[dict(r) for r in db.execute('SELECT * FROM lab_entity_aliases ORDER BY id DESC LIMIT 200')])
            p=payload();kind=p.get('kind')
            if kind not in {'host','ip','user','gns3_node'}:raise ValueError('Invalid entity kind')
            value=text(p.get('value'),'value',256);alias=text(p.get('alias'),'alias',256)
            db.execute('INSERT OR IGNORE INTO lab_entity_aliases(kind,value,alias,actor,created_at) VALUES (?,?,?,?,?)',(kind,value,alias,actor(),now()))
            audit(db,'entity_alias_saved',value)
        return jsonify(saved=True),201

    @bp.route('/cases',methods=['GET','POST'])
    def create_case():
        if request.method=='GET':
            with connection() as db:
                rows=[dict(r) for r in db.execute('SELECT c.*,d.assignee,d.due_at,d.title FROM soc_cases c LEFT JOIN lab_case_details d ON d.case_id=c.id ORDER BY c.id DESC LIMIT 200')]
            for row in rows:
                row['overdue']=bool(row.get('due_at') and row['status'] in {'new','investigating'} and row['due_at']<now())
            return jsonify(items=rows,limit=200)
        p=payload();ids=p.get('event_ids')
        if not isinstance(ids,list) or not 1<=len(ids)<=100 or any(not isinstance(i,str) or len(i)>100 for i in ids):raise ValueError('Select 1-100 event IDs')
        title=text(p.get('title'),'title');severity=p.get('severity','medium')
        if severity not in {'low','medium','high','critical'}:raise ValueError('Invalid severity')
        ids=list(dict.fromkeys(ids))
        with connection() as db:
            rows=db.execute('SELECT batch_id,event_id,ip FROM soc_events WHERE event_id IN (SELECT value FROM json_each(?))',(json.dumps(ids),)).fetchall()
            if len({r['event_id'] for r in rows})!=len(ids):raise ValueError('Every selected event must exist in this workspace')
            item=db.execute('INSERT INTO soc_cases(batch_id,alert_id,rule_id,severity,ip,reason,evidence_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
                (rows[0]['batch_id'],'manual-'+uuid.uuid4().hex,'MANUAL',severity,rows[0]['ip'],title,json.dumps(ids),now(),now())).lastrowid
            db.execute('INSERT INTO lab_case_details(case_id,title,assignee) VALUES (?,?,?)',(item,title,actor()))
            custody(db,actor(),'case_created',item);audit(db,'case_created',item)
        return jsonify(id=item),201
    @bp.patch('/cases/<int:item>')
    def assign_case(item):
        p=payload();assignee=text(p.get('assignee',''),'assignee',80,True);due=utc(p['due_at']) if p.get('due_at') else None
        with connection() as db:
            if not db.execute('SELECT 1 FROM soc_cases WHERE id=?',(item,)).fetchone():return jsonify(error='Case not found'),404
            db.execute('INSERT INTO lab_case_details(case_id,assignee,due_at) VALUES (?,?,?) ON CONFLICT(case_id) DO UPDATE SET assignee=excluded.assignee,due_at=excluded.due_at',(item,assignee,due))
            custody(db,actor(),'case_assigned',item);audit(db,'case_assigned',item)
        return jsonify(updated=item)

    @bp.post('/cases/merge')
    def merge_cases():
        p=payload();ids=p.get('case_ids')
        if not isinstance(ids,list) or not 2<=len(ids)<=20 or any(type(i) is not int or i<1 for i in ids):raise ValueError('Select 2-20 case IDs')
        ids=list(dict.fromkeys(ids))
        if len(ids)<2:raise ValueError('Select different case IDs')
        title=text(p.get('title','Birleşik araştırma vakası'),'title')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            cases=db.execute('SELECT * FROM soc_cases WHERE id IN (SELECT value FROM json_each(?))',(json.dumps(ids),)).fetchall()
            if len(cases)!=len(ids):raise ValueError('Every source case must exist')
            evidence=list(dict.fromkeys(e for c in cases for e in json.loads(c['evidence_json'])))
            if len(evidence)>100:raise ValueError('Merged case limit is 100 evidence records')
            levels={'low':0,'medium':1,'high':2,'critical':3}
            severity=max((c['severity'] for c in cases),key=lambda s:levels[s])
            item=db.execute('INSERT INTO soc_cases(batch_id,alert_id,rule_id,severity,ip,reason,evidence_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
                (cases[0]['batch_id'],'merge-'+uuid.uuid4().hex,'MANUAL',severity,cases[0]['ip'],title,json.dumps(evidence),now(),now())).lastrowid
            db.executemany('INSERT INTO lab_case_links(parent_id,child_id) VALUES (?,?)',[(item,i) for i in ids])
            db.execute('INSERT INTO lab_case_details(case_id,title,assignee) VALUES (?,?,?)',(item,title,actor()))
            custody(db,actor(),'cases_merged',json.dumps({'new_case':item,'source_cases':ids}));audit(db,'cases_merged',item)
        return jsonify(id=item,source_cases=ids,evidence_count=len(evidence),original_cases_preserved=True),201

    @bp.get('/custody')
    def chain():
        with connection() as db:
            result=verify_custody(db)
            rows=[dict(r) for r in db.execute('SELECT * FROM lab_custody ORDER BY id DESC LIMIT 200')]
        return jsonify(verification=result,items=rows)

    @bp.post('/copilot')
    def copilot():
        p=payload()
        if type(p.get('use_model',False)) is not bool:raise ValueError('use_model must be a boolean')
        with connection() as db:
            if p.get('source','soc') not in {'soc','loki'}:raise ValueError('Invalid Copilot data source')
            bounded(db);result=investigate(db,p.get('question'),p.get('filters',{}),actor(),p.get('use_model',False),p.get('context',{}),p.get('source','soc'),p.get('language','tr'))
            db.set_progress_handler(None,0)
            record_query(db,result['filters'],result['counts']['matched'])
            audit(db,'copilot_query',result['counts']['matched'])
        return jsonify(result)

    @bp.get('/live')
    def live():
        try:after=max(0,int(request.args.get('after',0)))
        except (ValueError,TypeError):raise ValueError('Invalid stream cursor')
        @stream_with_context
        def generate():
            cursor=after
            for tick in range(8):
                with connection() as db:
                    rows=db.execute('SELECT id,batch_id,raw_json FROM soc_events WHERE id>? ORDER BY id LIMIT 100',(cursor,)).fetchall()
                if rows:
                    cursor=rows[-1]['id']
                    items=[{**json.loads(r['raw_json']),'row_id':r['id'],'batch_id':r['batch_id']} for r in rows]
                    yield 'id: '+str(cursor)+'\nevent: events\ndata: '+json.dumps({'items':items,'cursor':cursor})+'\n\n'
                else:yield ': heartbeat\n\n'
                if tick<7:time.sleep(2)
        return Response(generate(),mimetype='text/event-stream',headers={'Cache-Control':'no-store','X-Accel-Buffering':'no'})
    return bp
