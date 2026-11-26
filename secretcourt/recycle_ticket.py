"""Provisional HSM hardware material recovery ticket."""
from .store import one


def intake(db, ticket_id, serial, reported_grams):
    db.execute('CREATE TABLE IF NOT EXISTS recycle_tickets(id TEXT PRIMARY KEY,serial TEXT,reported_grams INTEGER,status TEXT)')
    if one(db,'SELECT * FROM recycle_tickets WHERE id=?',(ticket_id,)):
        return {'decision':'reused'}
    if not one(db,'SELECT * FROM hardware_orders WHERE serial=?',(serial,)) or reported_grams<0:
        return {'decision':'unavailable'}
    db.execute('INSERT INTO recycle_tickets VALUES(?,?,?,?)',(ticket_id,serial,reported_grams,'intake'))
    return {'decision':'intake'}


def certify(db, ticket_id):
    db.execute('CREATE TABLE IF NOT EXISTS recovery_certs(id TEXT PRIMARY KEY,serial TEXT,grams INTEGER)')
    ticket=one(db,'SELECT * FROM recycle_tickets WHERE id=?',(ticket_id,))
    if not ticket:return {'decision':'missing_ticket'}
    db.execute('INSERT OR IGNORE INTO recovery_certs VALUES(?,?,?)',(ticket_id,ticket['serial'],ticket['reported_grams']))
    return {'decision':'certified','grams':ticket['reported_grams']}
