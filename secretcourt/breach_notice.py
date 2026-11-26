"""Provisional customer breach notice recipient list."""
from .store import one, rows


def draft(db, case_id, exposure_id):
    db.execute('CREATE TABLE IF NOT EXISTS notice_drafts(id TEXT PRIMARY KEY, exposure TEXT, recipient_count INTEGER, status TEXT)')
    old=one(db,'SELECT * FROM notice_drafts WHERE id=?',(case_id,))
    if old:return {'decision':'reused','recipient_count':old['recipient_count']}
    exposure=one(db,'SELECT * FROM exposures WHERE id=?',(exposure_id,))
    if not exposure:return {'decision':'missing_exposure'}
    grants=rows(db,'SELECT * FROM grants WHERE secret=? AND gen=?',(exposure['secret'],exposure['gen']))
    count=len(grants)
    db.execute('INSERT INTO notice_drafts VALUES(?,?,?,?)',(case_id,exposure_id,count,'draft'))
    return {'decision':'drafted','recipient_count':count}
