"""Draft customer evidence export from matching command events."""
from .store import one


def draft(db, export_id, secret):
    db.execute('CREATE TABLE IF NOT EXISTS evidence_exports(id TEXT PRIMARY KEY, secret TEXT, event_count INTEGER, status TEXT)')
    old=one(db,'SELECT * FROM evidence_exports WHERE id=?',(export_id,))
    if old:return {'decision':'reused','event_count':old['event_count']}
    if not one(db,'SELECT * FROM secrets WHERE id=?',(secret,)):
        return {'decision':'missing_secret'}
    count=db.execute('SELECT count(*) FROM events WHERE payload LIKE ?',('%'+secret+'%',)).fetchone()[0]
    db.execute('INSERT INTO evidence_exports VALUES(?,?,?,?)',(export_id,secret,count,'draft'))
    return {'decision':'drafted','event_count':count}
