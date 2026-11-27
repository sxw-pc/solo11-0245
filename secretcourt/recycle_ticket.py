"""Provisional HSM hardware material recovery ticket."""
import hashlib
import json

from .store import one


def intake(db, ticket_id, serial, reported_grams):
    db.execute('CREATE TABLE IF NOT EXISTS recycle_tickets(id TEXT PRIMARY KEY,serial TEXT,reported_grams INTEGER,status TEXT)')
    if one(db,'SELECT * FROM recycle_tickets WHERE id=?',(ticket_id,)):
        return {'decision':'reused'}
    if not one(db,'SELECT * FROM hardware_orders WHERE serial=?',(serial,)) or reported_grams<0:
        return {'decision':'unavailable'}
    db.execute('INSERT INTO recycle_tickets VALUES(?,?,?,?)',(ticket_id,serial,reported_grams,'intake'))
    return {'decision':'intake'}


def vendor_signature(ticket, signer):
    """Sign exactly what the ticket says.

    The signature only attests origin/integrity of the self-reported record;
    it is not weighing evidence and cannot make a physically impossible mass
    balance close.
    """
    body=json.dumps(
        {'id':ticket['id'],'serial':ticket['serial'],'grams':ticket['reported_grams']},
        sort_keys=True,separators=(',',':'))
    digest=hashlib.sha256(
        ('vendor-recycle-cert/v1/'+signer+'/'+body).encode('utf-8')).hexdigest()
    return {'signer':signer,'alg':'vendor-sha256','digest':digest}


def verify_vendor_signature(cert, signature):
    expected=vendor_signature(
        {'id':cert['id'],'serial':cert['serial'],'reported_grams':cert['grams']},
        signature.get('signer',''))
    return hmac_compare(expected['digest'],signature.get('digest',''))


def hmac_compare(a,b):
    import hmac
    return hmac.compare_digest(a,b or '')


def certify(db, ticket_id, signer=None):
    db.execute('CREATE TABLE IF NOT EXISTS recovery_certs(id TEXT PRIMARY KEY,serial TEXT,grams INTEGER)')
    ticket=one(db,'SELECT * FROM recycle_tickets WHERE id=?',(ticket_id,))
    if not ticket:return {'decision':'missing_ticket'}
    db.execute('INSERT OR IGNORE INTO recovery_certs VALUES(?,?,?)',(ticket_id,ticket['serial'],ticket['reported_grams']))
    result={'decision':'certified','id':ticket_id,'serial':ticket['serial'],'grams':ticket['reported_grams']}
    if signer:
        result['vendor_signature']=vendor_signature(ticket,signer)
    return result
