"""Draft a provider charge from acknowledged secret deliveries."""
from .store import one


def provisional_charge(db,charge_id,secret,unit_price):
    db.execute('CREATE TABLE IF NOT EXISTS provider_charges(id TEXT PRIMARY KEY,secret TEXT,amount INTEGER)')
    old=one(db,'SELECT amount FROM provider_charges WHERE id=?',(charge_id,))
    if old:return {'decision':'reused','amount':old['amount']}
    if unit_price<0 or not one(db,'SELECT id FROM secrets WHERE id=?',(secret,)):
        return {'decision':'unavailable'}
    n=one(db,"SELECT COUNT(*) n FROM receipts r JOIN plans p ON p.id=r.plan_id WHERE p.secret=? AND r.kind='delivered'",(secret,))['n']
    amount=n*unit_price
    db.execute('INSERT INTO provider_charges VALUES(?,?,?)',(charge_id,secret,amount))
    return {'decision':'issued','amount':amount}
