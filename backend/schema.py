"""Additive V7 schema; existing evidence and cases are retained."""
def initialize(connection):
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS lab_fingerprints(hash TEXT PRIMARY KEY,event_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS lab_occurrences(event_id TEXT,batch_id INTEGER,line INTEGER,source_id TEXT,
            PRIMARY KEY(event_id,batch_id,line));
        CREATE TABLE IF NOT EXISTS lab_sources(id TEXT PRIMARY KEY,name TEXT,kind TEXT,last_ingested TEXT);
        CREATE TABLE IF NOT EXISTS lab_collectors(id TEXT PRIMARY KEY,version TEXT,last_seen TEXT,metadata TEXT);
        CREATE TABLE IF NOT EXISTS lab_investigations(id INTEGER PRIMARY KEY,title TEXT,context_json TEXT,notes TEXT,
            owner TEXT,created_at TEXT,updated_at TEXT);
        CREATE TABLE IF NOT EXISTS lab_saved_queries(id INTEGER PRIMARY KEY,name TEXT,filters_json TEXT,owner TEXT,created_at TEXT);
        CREATE TABLE IF NOT EXISTS lab_query_history(id INTEGER PRIMARY KEY,actor TEXT,at TEXT,filters_json TEXT,result_count INTEGER);
        CREATE TABLE IF NOT EXISTS lab_rule_versions(rule_id TEXT,version INTEGER,payload_json TEXT,actor TEXT,at TEXT,
            PRIMARY KEY(rule_id,version));
        CREATE TABLE IF NOT EXISTS lab_rules(id TEXT PRIMARY KEY,active INTEGER NOT NULL DEFAULT 0,version INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS lab_custody(id INTEGER PRIMARY KEY,at TEXT,actor TEXT,action TEXT,subject TEXT,
            previous_hash TEXT,hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS lab_entity_aliases(id INTEGER PRIMARY KEY,kind TEXT,value TEXT,alias TEXT,
            actor TEXT,created_at TEXT,UNIQUE(kind,value,alias));
        CREATE TABLE IF NOT EXISTS lab_case_details(case_id INTEGER PRIMARY KEY,assignee TEXT DEFAULT '',due_at TEXT,
            title TEXT DEFAULT '');
        CREATE TABLE IF NOT EXISTS lab_case_links(parent_id INTEGER,child_id INTEGER,PRIMARY KEY(parent_id,child_id));
        CREATE TABLE IF NOT EXISTS lab_loki_outbox(id INTEGER PRIMARY KEY,batch_id INTEGER,payload_json TEXT,
            state TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT,created_at TEXT,sent_at TEXT,attempted_at TEXT);
        CREATE TABLE IF NOT EXISTS lab_loki_exported(event_id TEXT PRIMARY KEY,batch_id INTEGER);
        CREATE TABLE IF NOT EXISTS lab_migrations(name TEXT PRIMARY KEY);
        CREATE INDEX IF NOT EXISTS ix_lab_event_id ON soc_events(event_id);
        ''')
        if not db.execute("SELECT 1 FROM lab_migrations WHERE name='fingerprints-v7'").fetchone():
            import hashlib,json
            for row in db.execute('SELECT event_id,raw_json FROM soc_events ORDER BY id'):
                raw = json.loads(row['raw_json']).get('raw','')
                db.execute('INSERT OR IGNORE INTO lab_fingerprints(hash,event_id) VALUES (?,?)',
                    (hashlib.sha256(raw.encode()).hexdigest(),row['event_id']))
            db.execute("INSERT INTO lab_migrations(name) VALUES ('fingerprints-v7')")
