"""Draft a provisional breach service credit."""
from .store import one


def draft(db, claim_id, exposure_id, amount):
    db.execute('CREATE TABLE IF NOT EXISTS breach_claims(id TEXT PRIMARY KEY, exposure TEXT, amount INTEGER, status TEXT)')
    old=one(db,'SELECT * FROM breach_claims WHERE id=?',(claim_id,))
    if old:return {'decision':'reused','amount':old['amount']}
    exposure=one(db,'SELECT * FROM exposures WHERE id=?',(exposure_id,))
    if not exposure or amount<0:return {'decision':'unavailable'}
    db.execute('INSERT INTO breach_claims VALUES(?,?,?,?)',(claim_id,exposure_id,amount,'draft'))
    return {'decision':'drafted','amount':amount}
