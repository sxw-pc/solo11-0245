"""Provisional unseal request queue."""
from .store import one


def enqueue(db, ticket, grant_id, submitted_at):
    db.execute('CREATE TABLE IF NOT EXISTS unseal_queue(id TEXT PRIMARY KEY, grant_id TEXT, submitted_at INTEGER, status TEXT)')
    old=one(db,'SELECT * FROM unseal_queue WHERE id=?',(ticket,))
    if old:return {'decision':'reused'}
    grant=one(db,"SELECT * FROM grants WHERE id=? AND status='active'",(grant_id,))
    if not grant:return {'decision':'unavailable'}
    db.execute('INSERT INTO unseal_queue VALUES(?,?,?,?)',(ticket,grant_id,submitted_at,'queued'))
    return {'decision':'queued'}
