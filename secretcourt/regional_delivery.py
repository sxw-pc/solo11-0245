"""Provisional regional delivery permission."""
from .store import one
from . import delivery


def permit(db, permit_id, grant_id, region):
    db.execute('CREATE TABLE IF NOT EXISTS region_permits(id TEXT PRIMARY KEY, grant_id TEXT, region TEXT, status TEXT)')
    if one(db,'SELECT * FROM region_permits WHERE id=?',(permit_id,)):
        return {'decision':'reused'}
    grant=one(db,"SELECT * FROM grants WHERE id=? AND status='active'",(grant_id,))
    if not grant or not region:return {'decision':'unavailable'}
    db.execute('INSERT INTO region_permits VALUES(?,?,?,?)',(permit_id,grant_id,region,'draft'))
    return {'decision':'drafted'}


def provisional_delivery(db, permit_id, plan):
    if not one(db,'SELECT * FROM region_permits WHERE id=?',(permit_id,)):
        return {'decision':'missing_permit'}
    return delivery.run(db,plan)
