"""Publish a provisional customer environmental figure."""
from .store import one
from .delivery_meter import provisional_charge


def publish(db, report_id, claim_id, secret, customer):
    db.execute('CREATE TABLE IF NOT EXISTS environment_reports(id TEXT PRIMARY KEY, claim TEXT, customer TEXT, kwh INTEGER)')
    old=one(db,'SELECT * FROM environment_reports WHERE id=?',(report_id,))
    if old:return {'decision':'reused','kwh':old['kwh']}
    claim=one(db,'SELECT * FROM energy_claims WHERE id=?',(claim_id,))
    count=provisional_charge(db,'environment:'+report_id,secret,1)
    if not claim or count['decision']=='unavailable' or count['amount']==0:return {'decision':'unavailable'}
    db.execute('INSERT INTO environment_reports VALUES(?,?,?,?)',(report_id,claim_id,customer,claim['kwh']))
    return {'decision':'issued','kwh':claim['kwh']}
