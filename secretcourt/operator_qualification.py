"""Provisional human approval qualification."""
from .store import one
from . import grant


def declare(db, credential_id, actor, role):
    db.execute('CREATE TABLE IF NOT EXISTS operator_credentials(id TEXT PRIMARY KEY,actor TEXT,role TEXT,status TEXT)')
    if one(db,'SELECT * FROM operator_credentials WHERE id=?',(credential_id,)):
        return {'decision':'reused'}
    if not actor or role not in ('security','owner'):
        return {'decision':'invalid'}
    db.execute('INSERT INTO operator_credentials VALUES(?,?,?,?)',(credential_id,actor,role,'declared'))
    return {'decision':'declared'}


def provisional_approve(db, credential_id, approval):
    if not one(db,'SELECT * FROM operator_credentials WHERE id=?',(credential_id,)):
        return {'decision':'missing_credential'}
    return grant.run(db,approval)
