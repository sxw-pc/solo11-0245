"""SQLite state and deterministic command evidence."""
import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY,purpose TEXT NOT NULL,current_gen INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS versions(secret TEXT,gen INTEGER,digest TEXT,parent INTEGER,status TEXT,PRIMARY KEY(secret,gen));
CREATE TABLE IF NOT EXISTS exposures(id TEXT PRIMARY KEY,secret TEXT,gen INTEGER,from_ts INTEGER,to_ts INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS lineage_proofs(id TEXT PRIMARY KEY,secret TEXT,old_gen INTEGER,new_gen INTEGER,purpose TEXT,old_digest TEXT,new_digest TEXT,at INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS identities(id TEXT PRIMARY KEY,namespace TEXT,uid TEXT,environment TEXT,generation INTEGER,active INTEGER);
CREATE TABLE IF NOT EXISTS policies(purpose TEXT PRIMARY KEY,fields TEXT,environments TEXT,revision INTEGER);
CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,grant_id TEXT,actor TEXT,role TEXT,until_ts INTEGER);
CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,secret TEXT,gen INTEGER,identity TEXT,uid TEXT,fields TEXT,environment TEXT,until_ts INTEGER,status TEXT,generation INTEGER);
CREATE TABLE IF NOT EXISTS revocations(id TEXT PRIMARY KEY,grant_id TEXT,generation INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY,secret TEXT,gen INTEGER,grant_id TEXT,uid TEXT,packet TEXT,status TEXT,generation INTEGER);
CREATE TABLE IF NOT EXISTS members(plan_id TEXT,uid TEXT,grant_id TEXT,packet TEXT,status TEXT,PRIMARY KEY(plan_id,uid));
CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY,plan_id TEXT,uid TEXT,kind TEXT,packet TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS reseals(id TEXT PRIMARY KEY,secret TEXT,old_gen INTEGER,new_gen INTEGER,proof_id TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS orphans(id TEXT PRIMARY KEY,secret TEXT,gen INTEGER,uid TEXT,status TEXT,isolation_receipt TEXT,cleared_at INTEGER);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,subsystem TEXT,payload TEXT,result TEXT);
"""

def connect(path):
    db = sqlite3.connect(path, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=5000")
    db.executescript(SCHEMA)
    from .revocation_effect import EFFECT_SCHEMA
    db.executescript(EFFECT_SCHEMA)
    return db

@contextmanager
def tx(db):
    nested = db.in_transaction
    db.execute("SAVEPOINT action" if nested else "BEGIN IMMEDIATE")
    try:
        yield
        db.execute("RELEASE SAVEPOINT action" if nested else "COMMIT")
    except Exception:
        if nested:
            db.execute("ROLLBACK TO SAVEPOINT action")
            db.execute("RELEASE SAVEPOINT action")
        else:
            db.execute("ROLLBACK")
        raise

def one(db, sql, args=()):
    row = db.execute(sql, args).fetchone()
    return dict(row) if row else None

def rows(db, sql, args=()):
    return [dict(row) for row in db.execute(sql, args)]

def record(db, subsystem, payload, result):
    db.execute("INSERT INTO events(subsystem,payload,result) VALUES(?,?,?)",
               (subsystem, json.dumps(payload, sort_keys=True, ensure_ascii=False),
                json.dumps(result, sort_keys=True, ensure_ascii=False)))
    return result

def invoke(db, subsystem, payload):
    from . import material, grant, delivery, revocation_effect
    modules = {
        "material": material,
        "grant": grant,
        "delivery": delivery,
        "revocation_effect": revocation_effect,
        "effect": revocation_effect,
    }
    with tx(db):
        result = modules[subsystem].run(db, payload)
        return record(db, subsystem, payload, result)

def replay(path):
    source = connect(path)
    target = connect(":memory:")
    divergent = []
    events = rows(source, "SELECT subsystem,payload,result FROM events ORDER BY seq")
    for i, event in enumerate(events, 1):
        actual = invoke(target, event["subsystem"], json.loads(event["payload"]))
        if actual != json.loads(event["result"]):
            divergent.append({"step": i, "reason": "decision", "actual": actual})
    for table in ["secrets", "versions", "exposures", "lineage_proofs", "identities", "policies", "approvals", "grants",
                  "revocations", "plans", "members", "receipts", "reseals", "orphans"]:
        before = [tuple(row) for row in source.execute("SELECT * FROM " + table + " ORDER BY rowid")]
        after = [tuple(row) for row in target.execute("SELECT * FROM " + table + " ORDER BY rowid")]
        if before != after:
            divergent.append({"table": table, "reason": "state"})
    from .revocation_effect import EFFECT_TABLE_NAMES
    for table in EFFECT_TABLE_NAMES:
        before = [tuple(row) for row in source.execute("SELECT * FROM " + table + " ORDER BY rowid")]
        after = [tuple(row) for row in target.execute("SELECT * FROM " + table + " ORDER BY rowid")]
        if before != after:
            divergent.append({"table": table, "reason": "state"})
    source.close()
    target.close()
    return {"decisions": len(events), "verified": not divergent, "divergences": divergent}
