"""Frozen recipient roster, receipts, orphan copies, and reseal closure."""
from .store import one, rows

def run(db, r):
    op = r["op"]
    if op == "plan":
        members = r.get("members", [])
        uids = [m["uid"] for m in members]
        if not members or len(uids) != len(set(uids)) or not r.get("packet"):
            return {"decision": "invalid_roster"}
        old = one(db, "SELECT * FROM plans WHERE id=?", (r["id"],))
        if old:
            old_members = rows(db, "SELECT uid,grant_id FROM members WHERE plan_id=? ORDER BY uid", (r["id"],))
            expected = sorted([{"uid": m["uid"], "grant_id": m["grant"]} for m in members], key=lambda x: x["uid"])
            same = (old["secret"], old["gen"], old["packet"], old_members) == (r["secret"], r["gen"], r["packet"], expected)
            return {"decision": "reused" if same else "plan_identity_conflict"}
        version = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], r["gen"]))
        reseal = one(db, "SELECT * FROM reseals WHERE secret=? AND new_gen=? AND status='open'", (r["secret"], r["gen"]))
        if not version or (version["status"] != "active" and not (version["status"] == "sealed" and reseal)):
            return {"decision": "version_unavailable"}
        for member in members:
            grant = one(db, "SELECT * FROM grants WHERE id=?", (member["grant"],))
            identity = one(db, "SELECT * FROM identities WHERE id=?", (grant["identity"],)) if grant else None
            if (not grant or not identity or grant["status"] != "active" or grant["secret"] != r["secret"]
                or grant["gen"] != r["gen"] or grant["uid"] != member["uid"] or identity["uid"] != member["uid"]
                or grant["until_ts"] < r["at"] or not identity["active"]):
                return {"decision": "unlicensed_member", "uid": member["uid"]}
        db.execute("INSERT INTO plans VALUES(?,?,?,?,?,?,?,?)",
                   (r["id"], r["secret"], r["gen"], members[0]["grant"], members[0]["uid"], r["packet"], "planned", 1))
        db.executemany("INSERT INTO members VALUES(?,?,?,?,?)",
                       [(r["id"], m["uid"], m["grant"], r["packet"], "pending") for m in members])
        return {"decision": "planned", "members": sorted(uids)}
    if op == "receipt":
        old = one(db, "SELECT * FROM receipts WHERE id=?", (r["id"],))
        if old:
            same = (old["plan_id"], old["uid"], old["kind"], old["packet"], old["at"]) == (
                r["plan"], r["uid"], r["kind"], r["packet"], r["at"])
            return {"decision": "reused" if same else "receipt_identity_conflict"}
        plan = one(db, "SELECT * FROM plans WHERE id=?", (r["plan"],))
        member = one(db, "SELECT * FROM members WHERE plan_id=? AND uid=?", (r["plan"], r["uid"]))
        if not plan or not member or r["packet"] != plan["packet"]:
            return {"decision": "foreign_or_stale_receipt"}
        if r["kind"] not in ("delivered", "cleared"):
            return {"decision": "invalid_receipt_kind"}
        if r["kind"] == "delivered":
            if plan["status"] == "frozen":
                return {"decision": "plan_frozen"}
            grant = one(db, "SELECT * FROM grants WHERE id=?", (member["grant_id"],))
            identity = one(db, "SELECT * FROM identities WHERE id=?", (grant["identity"],)) if grant else None
            if not grant or grant["status"] != "active" or grant["until_ts"] < r["at"] or not identity or identity["uid"] != r["uid"]:
                return {"decision": "member_no_longer_licensed"}
        db.execute("INSERT INTO receipts VALUES(?,?,?,?,?,?)", (r["id"], r["plan"], r["uid"], r["kind"], r["packet"], r["at"]))
        db.execute("UPDATE members SET status=? WHERE plan_id=? AND uid=?", (r["kind"], r["plan"], r["uid"]))
        pending = one(db, "SELECT COUNT(*) n FROM members WHERE plan_id=? AND status='pending'", (r["plan"],))["n"]
        if r["kind"] == "delivered" and plan["status"] != "frozen":
            db.execute("UPDATE plans SET status=? WHERE id=?", ("complete" if not pending else "partial", r["plan"]))
        return {"decision": r["kind"], "pending": pending}
    if op == "orphan":
        old = one(db, "SELECT * FROM orphans WHERE id=?", (r["id"],))
        if old:
            return {"decision": "reused" if (old["secret"], old["gen"], old["uid"]) ==
                    (r["secret"], r["gen"], r["uid"]) else "orphan_identity_conflict"}
        if not one(db, "SELECT 1 FROM versions WHERE secret=? AND gen=?", (r["secret"], r["gen"])):
            return {"decision": "unknown_version"}
        db.execute("INSERT INTO orphans VALUES(?,?,?,?,?)", (r["id"], r["secret"], r["gen"], r["uid"], "quarantined"))
        reopened = db.execute("UPDATE reseals SET status='reopened' WHERE secret=? AND old_gen=? AND status='complete'",
                              (r["secret"], r["gen"])).rowcount
        return {"decision": "closure_reopened" if reopened else "quarantined"}
    if op == "resolve_orphan":
        old = one(db, "SELECT * FROM orphans WHERE id=?", (r["id"],))
        if not old:
            return {"decision": "unknown_orphan"}
        if old["status"] == "cleared":
            return {"decision": "reused"}
        if not r.get("isolation_receipt") or r.get("uid") != old["uid"]:
            return {"decision": "missing_isolation_evidence"}
        db.execute("UPDATE orphans SET status='cleared' WHERE id=?", (r["id"],))
        return {"decision": "cleared"}
    if op == "close_reseal":
        case = one(db, "SELECT * FROM reseals WHERE id=?", (r["id"],))
        if not case:
            return {"decision": "unknown_reseal"}
        if case["status"] == "complete":
            return {"decision": "reused"}
        old_members = rows(db, "SELECT m.uid,m.status FROM members m JOIN plans p ON p.id=m.plan_id WHERE p.secret=? AND p.gen=?",
                           (case["secret"], case["old_gen"]))
        if any(m["status"] != "cleared" for m in old_members):
            return {"decision": "old_copies_remain"}
        if one(db, "SELECT id FROM orphans WHERE secret=? AND gen=? AND status='quarantined'", (case["secret"], case["old_gen"])):
            return {"decision": "orphan_copy_remains"}
        new_members = rows(db, "SELECT m.uid,m.status FROM members m JOIN plans p ON p.id=m.plan_id WHERE p.secret=? AND p.gen=?",
                           (case["secret"], case["new_gen"]))
        if not new_members or any(m["status"] != "delivered" for m in new_members):
            return {"decision": "new_delivery_incomplete"}
        if set(m["uid"] for m in old_members) != set(m["uid"] for m in new_members):
            return {"decision": "roster_not_preserved"}
        db.execute("UPDATE reseals SET status='complete' WHERE id=?", (r["id"],))
        db.execute("UPDATE versions SET status='retired' WHERE secret=? AND gen=?", (case["secret"], case["old_gen"]))
        db.execute("UPDATE versions SET status='active' WHERE secret=? AND gen=?", (case["secret"], case["new_gen"]))
        return {"decision": "reseal_complete", "members": len(new_members)}
    raise ValueError(op)
