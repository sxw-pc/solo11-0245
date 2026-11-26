"""Frozen recipient roster, receipts, orphan copies, and reseal closure."""
from .store import one, rows
from . import revocation_effect


def _proof_ref(r):
    return r.get("effect_proof") or r.get("proof") or r.get("proof_id")


def _authorize_strong_clear(db, r, plan):
    """Validate the shared effective-revocation proof for a strong clearance.

    Returns ``(proof, error_decision)``; exactly one is non-None.  The proof
    must cover the plan's secret/old generation and the exact UID plus
    container generation presenting the clearance, so a same-name rebuilt
    instance cannot inherit the previous generation's conclusion.
    """
    proof_ref = _proof_ref(r)
    if not proof_ref:
        return None, {"decision": "effect_proof_required"}
    if r.get("container_gen") is None:
        return None, {"decision": "container_generation_required"}
    proof, err = revocation_effect.classify_proof(
        db, proof_ref, secret=plan["secret"], gen=plan["gen"])
    if err:
        return None, {"decision": err}
    matched = revocation_effect.valid_proof(
        db, proof_ref, secret=plan["secret"], gen=plan["gen"],
        uid=r["uid"], container_gen=r["container_gen"])
    if not matched:
        return None, {"decision": "effect_proof_generation_scope_mismatch"}
    return proof, None

def run(db, r):
    op = r["op"]
    if op in ("effect_clear", "clear_effective"):
        # Strong clearance entry point: same receipt persistence as "cleared",
        # but the shared effective-revocation proof is mandatory.
        r = dict(r)
        r["op"] = "receipt"
        r["kind"] = "cleared"
        r["strong"] = True
        op = "receipt"
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
            if plan["status"] not in ("planned", "partial"):
                return {"decision": "plan_frozen"}
            grant = one(db, "SELECT * FROM grants WHERE id=?", (member["grant_id"],))
            identity = one(db, "SELECT * FROM identities WHERE id=?", (grant["identity"],)) if grant else None
            if not grant or grant["status"] != "active" or grant["until_ts"] < r["at"] or not identity or identity["uid"] != r["uid"]:
                return {"decision": "member_no_longer_licensed"}
        else:
            previous = one(db, "SELECT 1 FROM receipts WHERE plan_id=? AND uid=? AND kind='delivered'",
                           (r["plan"], r["uid"]))
            if not previous:
                return {"decision": "copy_never_delivered"}
            proof_ref = _proof_ref(r)
            if r.get("strong") or proof_ref:
                proof, denied = _authorize_strong_clear(db, r, plan)
                if denied:
                    return denied
        db.execute("INSERT INTO receipts VALUES(?,?,?,?,?,?)", (r["id"], r["plan"], r["uid"], r["kind"], r["packet"], r["at"]))
        db.execute("UPDATE members SET status=? WHERE plan_id=? AND uid=?", (r["kind"], r["plan"], r["uid"]))
        if r["kind"] == "cleared" and _proof_ref(r):
            revocation_effect.consume_proof(
                db, _proof_ref(r), "delivery.effect_clear", r["id"], r.get("at"),
                {"plan": r["plan"], "uid": r["uid"], "container_gen": r.get("container_gen")})
        pending = one(db, "SELECT COUNT(*) n FROM members WHERE plan_id=? AND status='pending'", (r["plan"],))["n"]
        if r["kind"] == "delivered" and plan["status"] != "frozen":
            db.execute("UPDATE plans SET status=? WHERE id=?", ("complete" if not pending else "partial", r["plan"]))
        if r["kind"] == "cleared" and r.get("strong"):
            return {"decision": "effect_cleared", "pending": pending,
                    "effect_proof": _proof_ref(r)}
        return {"decision": r["kind"], "pending": pending}
    if op == "orphan":
        old = one(db, "SELECT * FROM orphans WHERE id=?", (r["id"],))
        if old:
            return {"decision": "reused" if (old["secret"], old["gen"], old["uid"]) ==
                    (r["secret"], r["gen"], r["uid"]) else "orphan_identity_conflict"}
        if not one(db, "SELECT 1 FROM versions WHERE secret=? AND gen=?", (r["secret"], r["gen"])):
            return {"decision": "unknown_version"}
        db.execute("INSERT INTO orphans VALUES(?,?,?,?,?,?,?)", (r["id"], r["secret"], r["gen"], r["uid"], "quarantined", None, None))
        reopened = db.execute("UPDATE reseals SET status='reopened' WHERE secret=? AND old_gen=? AND status='complete'",
                              (r["secret"], r["gen"])).rowcount
        if reopened:
            new_generations = rows(db, "SELECT new_gen FROM reseals WHERE secret=? AND old_gen=? AND status='reopened'",
                                   (r["secret"], r["gen"]))
            for new in new_generations:
                db.execute("UPDATE versions SET status='at_risk' WHERE secret=? AND gen=? AND status='active'",
                           (r["secret"], new["new_gen"]))
                db.execute("UPDATE grants SET status='frozen' WHERE secret=? AND gen=? AND status='active'",
                           (r["secret"], new["new_gen"]))
                db.execute("UPDATE plans SET status='frozen' WHERE secret=? AND gen=? AND status IN ('planned','partial')",
                           (r["secret"], new["new_gen"]))
        return {"decision": "closure_reopened" if reopened else "quarantined"}
    if op == "resolve_orphan":
        old = one(db, "SELECT * FROM orphans WHERE id=?", (r["id"],))
        if not old:
            return {"decision": "unknown_orphan"}
        if old["status"] == "cleared":
            same = old["uid"] == r.get("uid") and old["isolation_receipt"] == r.get("isolation_receipt")
            return {"decision": "reused" if same else "isolation_evidence_conflict"}
        if not r.get("isolation_receipt") or r.get("uid") != old["uid"]:
            return {"decision": "missing_isolation_evidence"}
        db.execute("UPDATE orphans SET status='cleared',isolation_receipt=?,cleared_at=? WHERE id=?",
                   (r["isolation_receipt"], r.get("at", 0), r["id"]))
        return {"decision": "cleared"}
    if op == "close_reseal":
        case = one(db, "SELECT * FROM reseals WHERE id=?", (r["id"],))
        if not case:
            return {"decision": "unknown_reseal"}
        if case["status"] == "complete":
            return {"decision": "reused"}
        proof_ref = _proof_ref(r)
        if proof_ref:
            proof, err = revocation_effect.classify_proof(
                db, proof_ref, secret=case["secret"], gen=case["old_gen"])
            if err:
                return {"decision": err}
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
        result = {"decision": "reseal_complete", "members": len(new_members)}
        if proof_ref:
            revocation_effect.consume_proof(
                db, proof_ref, "delivery.close_reseal", r["id"], r.get("at"),
                {"secret": case["secret"], "old_gen": case["old_gen"]})
            result["effect_proof"] = proof_ref
        return result
    raise ValueError(op)
