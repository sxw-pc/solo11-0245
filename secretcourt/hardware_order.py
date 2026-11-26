"""Provisional HSM purchase delivery ticket."""
from .store import one


def draft(db, order_id, secret_id, serial, price):
    db.execute('CREATE TABLE IF NOT EXISTS hardware_orders(id TEXT PRIMARY KEY, secret TEXT, serial TEXT, price INTEGER, status TEXT)')
    old=one(db,'SELECT * FROM hardware_orders WHERE id=?',(order_id,))
    if old:return {'decision':'reused'}
    secret=one(db,'SELECT * FROM secrets WHERE id=?',(secret_id,))
    if not secret or not serial or price<0:return {'decision':'unavailable'}
    db.execute('INSERT INTO hardware_orders VALUES(?,?,?,?,?)',(order_id,secret_id,serial,price,'draft'))
    return {'decision':'drafted'}
