"""Provisional environmental claim for a purchased HSM."""
from .store import one


def draft(db, claim_id, serial, kwh):
    db.execute('CREATE TABLE IF NOT EXISTS energy_claims(id TEXT PRIMARY KEY, serial TEXT, kwh INTEGER, status TEXT)')
    old=one(db,'SELECT * FROM energy_claims WHERE id=?',(claim_id,))
    if old:return {'decision':'reused','kwh':old['kwh']}
    order=one(db,'SELECT * FROM hardware_orders WHERE serial=?',(serial,))
    if not order or kwh<0:return {'decision':'unavailable'}
    db.execute('INSERT INTO energy_claims VALUES(?,?,?,?)',(claim_id,serial,kwh,'draft'))
    return {'decision':'drafted','kwh':kwh}
