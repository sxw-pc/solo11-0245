"""Secret lineage, exposure, and reseal source evidence."""
from .store import one, rows
from . import revocation_effect

def run(db, r):
    op = r["op"]
    if op == "secret":
        old = one(db, "SELECT * FROM secrets WHERE id=?", (r["id"],))
        if old:
            return {"decision": "reused" if old["purpose"] == r["purpose"] else "identity_conflict"}
        db.execute("INSERT INTO secrets(id,purpose) VALUES(?,?)", (r["id"], r["purpose"]))
        return {"decision": "created"}
    if op == "seal":
        s = one(db, "SELECT * FROM secrets WHERE id=?", (r["secret"],))
        if not s or not r.get("digest") or r["gen"] < 1:
            return {"decision": "invalid_secret_or_digest"}
        old = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], r["gen"]))
        if old:
            same = old["digest"] == r["digest"] and old["parent"] == r.get("parent")
            return {"decision": "reused" if same else "seal_identity_conflict"}
        if r["gen"] != s["current_gen"] + 1 or r.get("parent") != (s["current_gen"] or None):
            return {"decision": "stale_parent"}
        previous = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], s["current_gen"]))
        if previous and previous["digest"] == r["digest"]:
            return {"decision": "unchanged_material"}
        status = "active" if r["gen"] == 1 else "sealed"
        db.execute("INSERT INTO versions VALUES(?,?,?,?,?)", (r["secret"], r["gen"], r["digest"], r.get("parent"), status))
        db.execute("UPDATE secrets SET current_gen=? WHERE id=?", (r["gen"], r["secret"]))
        return {"decision": status, "generation": r["gen"]}
    if op == "expose":
        old = one(db, "SELECT * FROM exposures WHERE id=?", (r["id"],))
        if old:
            same = (old["secret"], old["gen"], old["from_ts"], old["to_ts"]) == (
                r["secret"], r["gen"], r["from"], r["to"])
            return {"decision": "reused" if same else "exposure_identity_conflict"}
        v = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], r["gen"]))
        if not v or r["from"] > r["to"]:
            return {"decision": "invalid_exposure"}
        db.execute("INSERT INTO exposures VALUES(?,?,?,?,?,?)", (r["id"], r["secret"], r["gen"], r["from"], r["to"], "open"))
        db.execute("UPDATE versions SET status='exposed' WHERE secret=? AND gen=?", (r["secret"], r["gen"]))
        db.execute("UPDATE grants SET status='frozen' WHERE secret=? AND gen=? AND status='active'", (r["secret"], r["gen"]))
        db.execute("UPDATE plans SET status='frozen' WHERE secret=? AND gen=? AND status IN ('planned','partial')", (r["secret"], r["gen"]))
        affected = rows(db, "SELECT id FROM grants WHERE secret=? AND gen=? AND status='frozen'", (r["secret"], r["gen"]))
        return {"decision": "exposed", "frozen_grants": [x["id"] for x in affected]}
    if op == "close_exposure":
        case = one(db, "SELECT * FROM exposures WHERE id=?", (r["id"],))
        if not case:
            return {"decision": "missing_exposure"}
        if case["status"] == "closed":
            return {"decision": "reused"}
        db.execute("UPDATE exposures SET status='closed' WHERE id=?", (r["id"],))
        return {"decision": "closed_without_regrant"}
    if op == "proof":
        old = one(db, "SELECT * FROM lineage_proofs WHERE id=?", (r["id"],))
        if old:
            same = (old["secret"], old["old_gen"], old["new_gen"], old["purpose"], old["old_digest"], old["new_digest"], old["at"]) == (
                r["secret"], r["old_gen"], r["new_gen"], r["purpose"], r["old_digest"], r["new_digest"], r["at"])
            return {"decision": "reused" if same else "proof_identity_conflict"}
        secret = one(db, "SELECT * FROM secrets WHERE id=?", (r["secret"],))
        before = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], r["old_gen"]))
        after = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], r["new_gen"]))
        exposure = one(db, "SELECT MIN(from_ts) first_at FROM exposures WHERE secret=? AND gen=?", (r["secret"], r["old_gen"]))
        if (not secret or not before or not after or not exposure or exposure["first_at"] is None
            or before["status"] != "exposed" or after["status"] != "sealed"
            or r["purpose"] != secret["purpose"] or r["old_digest"] != before["digest"]
            or r["new_digest"] != after["digest"] or r["at"] < exposure["first_at"]):
            return {"decision": "invalid_lineage_proof"}
        db.execute("INSERT INTO lineage_proofs VALUES(?,?,?,?,?,?,?,?,?)",
                   (r["id"], r["secret"], r["old_gen"], r["new_gen"], r["purpose"],
                    r["old_digest"], r["new_digest"], r["at"], "verified"))
        return {"decision": "proof_verified"}
    if op == "reseal":
        old = one(db, "SELECT * FROM reseals WHERE id=?", (r["id"],))
        if old:
            return {"decision": "reused" if (old["secret"], old["old_gen"], old["new_gen"], old["proof_id"]) ==
                    (r["secret"], r["old_gen"], r["new_gen"], r["proof"]) else "reseal_identity_conflict"}
        before = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], r["old_gen"]))
        after = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], r["new_gen"]))
        s = one(db, "SELECT * FROM secrets WHERE id=?", (r["secret"],))
        if not before or not after or not s or before["status"] != "exposed" or after["status"] != "sealed":
            return {"decision": "invalid_reseal_source"}
        if after["parent"] != before["gen"] or after["digest"] == before["digest"] or s["current_gen"] != after["gen"]:
            return {"decision": "lineage_conflict"}
        proof = one(db, "SELECT * FROM lineage_proofs WHERE id=? AND status='verified'", (r["proof"],))
        if not proof or (proof["secret"], proof["old_gen"], proof["new_gen"]) != (r["secret"], r["old_gen"], r["new_gen"]):
            return {"decision": "missing_lineage_proof"}
        db.execute("INSERT INTO reseals VALUES(?,?,?,?,?,?)", (r["id"], r["secret"], r["old_gen"], r["new_gen"], r["proof"], "open"))
        return {"decision": "reseal_open"}
    if op in ("retire", "retire_version"):
        # Version retirement shares the exact same effective-revocation proof
        # as delivery clearance; a control-plane revoke or bare cleared receipt
        # is not sufficient.
        proof_ref = r.get("effect_proof") or r.get("proof") or r.get("proof_id")
        if not proof_ref:
            return {"decision": "effect_proof_required"}
        version = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], r["gen"]))
        if not version:
            return {"decision": "unknown_version"}
        proof, err = revocation_effect.classify_proof(
            db, proof_ref, secret=r["secret"], gen=r["gen"])
        if err:
            return {"decision": err}
        ref_id = "%s@%s" % (r["secret"], r["gen"])
        prior = one(db, "SELECT * FROM effect_consumption WHERE consumer='material.retire' AND ref_id=?",
                    (ref_id,))
        if version["status"] == "retired":
            if prior and prior["proof_id"] == proof_ref:
                return {"decision": "reused", "status": "retired", "effect_proof": proof_ref}
            return {"decision": "version_already_retired"}
        db.execute("UPDATE versions SET status='retired' WHERE secret=? AND gen=?", (r["secret"], r["gen"]))
        revocation_effect.consume_proof(
            db, proof_ref, "material.retire", ref_id, r.get("at"),
            {"secret": r["secret"], "gen": r["gen"]})
        return {"decision": "version_retired", "status": "retired",
                "secret": r["secret"], "gen": r["gen"], "effect_proof": proof_ref}
    raise ValueError(op)
