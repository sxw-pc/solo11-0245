"""Workload identity, purpose policy, and grant revocation."""
import json
from .store import one, rows

def run(db, r):
    op = r["op"]
    if op == "identity":
        old = one(db, "SELECT * FROM identities WHERE id=?", (r["id"],))
        if old and r["generation"] <= old["generation"]:
            same = (old["uid"], old["namespace"], old["environment"], old["generation"]) == (
                r["uid"], r["namespace"], r["environment"], r["generation"])
            return {"decision": "reused" if same else "stale_identity"}
        db.execute("INSERT INTO identities VALUES(?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET namespace=excluded.namespace,uid=excluded.uid,environment=excluded.environment,generation=excluded.generation,active=1",
                   (r["id"], r["namespace"], r["uid"], r["environment"], r["generation"]))
        if old and (old["uid"], old["namespace"], old["environment"], old["generation"]) != (
            r["uid"], r["namespace"], r["environment"], r["generation"]):
            db.execute("UPDATE grants SET status='frozen' WHERE identity=? AND status='active'", (r["id"],))
            db.execute("UPDATE plans SET status='frozen' WHERE id IN (SELECT m.plan_id FROM members m JOIN grants g ON g.id=m.grant_id WHERE g.identity=?) AND status IN ('planned','partial')", (r["id"],))
        return {"decision": "observed", "uid": r["uid"]}
    if op == "policy":
        if not r["fields"] or not r["environments"]:
            return {"decision": "empty_policy"}
        old = one(db, "SELECT * FROM policies WHERE purpose=?", (r["purpose"],))
        if old and r["revision"] <= old["revision"]:
            same = (old["revision"] == r["revision"] and json.loads(old["fields"]) == sorted(set(r["fields"]))
                    and json.loads(old["environments"]) == sorted(set(r["environments"])))
            return {"decision": "reused" if same else "stale_policy"}
        db.execute("INSERT INTO policies VALUES(?,?,?,?) ON CONFLICT(purpose) DO UPDATE SET fields=excluded.fields,environments=excluded.environments,revision=excluded.revision",
                   (r["purpose"], json.dumps(sorted(set(r["fields"]))), json.dumps(sorted(set(r["environments"]))), r["revision"]))
        frozen = []
        for grant in rows(db, "SELECT g.* FROM grants g JOIN secrets s ON s.id=g.secret WHERE s.purpose=? AND g.status='active'", (r["purpose"],)):
            if not set(json.loads(grant["fields"])).issubset(r["fields"]) or grant["environment"] not in r["environments"]:
                db.execute("UPDATE grants SET status='frozen' WHERE id=?", (grant["id"],))
                db.execute("UPDATE plans SET status='frozen' WHERE id IN (SELECT plan_id FROM members WHERE grant_id=?) AND status IN ('planned','partial')", (grant["id"],))
                frozen.append(grant["id"])
        return {"decision": "policy_active", "revision": r["revision"], "frozen_grants": frozen}
    if op == "approve":
        if r["role"] not in ("security", "owner") or not r["actor"] or r["until"] <= r["at"]:
            return {"decision": "invalid_approval"}
        old = one(db, "SELECT * FROM approvals WHERE id=?", (r["id"],))
        if old:
            same = (old["grant_id"], old["actor"], old["role"], old["until_ts"]) == (
                r["grant"], r["actor"], r["role"], r["until"])
            return {"decision": "reused" if same else "approval_identity_conflict"}
        db.execute("INSERT INTO approvals VALUES(?,?,?,?,?)", (r["id"], r["grant"], r["actor"], r["role"], r["until"]))
        return {"decision": "approved", "role": r["role"]}
    if op == "issue":
        old = one(db, "SELECT * FROM grants WHERE id=?", (r["id"],))
        if old:
            same = (old["secret"], old["gen"], old["identity"], old["uid"], json.loads(old["fields"]), old["environment"], old["until_ts"]) == (
                r["secret"], r["gen"], r["identity"], r["uid"], sorted(set(r["fields"])), r["environment"], r["until"])
            if not same:
                return {"decision": "grant_identity_conflict"}
            return {"decision": "reused" if old["status"] == "active" else "grant_inactive"}
        secret = one(db, "SELECT * FROM secrets WHERE id=?", (r["secret"],))
        version = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?", (r["secret"], r["gen"]))
        identity = one(db, "SELECT * FROM identities WHERE id=?", (r["identity"],))
        if not secret or not version or not identity or not identity["active"]:
            return {"decision": "missing_source"}
        reseal = one(db, "SELECT * FROM reseals WHERE secret=? AND new_gen=? AND status='open'", (r["secret"], r["gen"]))
        if version["status"] != "active" and not (version["status"] == "sealed" and reseal):
            return {"decision": "version_unavailable"}
        if (identity["uid"], identity["namespace"], identity["environment"]) != (
            r["uid"], r["namespace"], r["environment"]):
            return {"decision": "stale_workload_identity"}
        if r["until"] <= r["at"]:
            return {"decision": "expired_grant"}
        policy = one(db, "SELECT * FROM policies WHERE purpose=?", (secret["purpose"],))
        fields = sorted(set(r["fields"]))
        if not policy or not fields or not set(fields).issubset(json.loads(policy["fields"])) or r["environment"] not in json.loads(policy["environments"]):
            return {"decision": "scope_denied"}
        approvals = rows(db, "SELECT * FROM approvals WHERE grant_id=? AND until_ts>=?", (r["id"], r["at"]))
        valid = [a for a in approvals if a["actor"] in r.get("approvers", [])]
        if {a["role"] for a in valid} != {"security", "owner"} or len({a["actor"] for a in valid}) < 2:
            return {"decision": "missing_two_approvers"}
        db.execute("INSERT INTO grants VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (r["id"], r["secret"], r["gen"], r["identity"], r["uid"], json.dumps(fields),
                    r["environment"], r["until"], "active", 1))
        return {"decision": "granted", "uid": r["uid"], "fields": fields}
    if op == "revoke":
        grant = one(db, "SELECT * FROM grants WHERE id=?", (r["grant"],))
        if not grant:
            return {"decision": "unknown_grant"}
        old = one(db, "SELECT * FROM revocations WHERE id=?", (r["id"],))
        if old:
            return {"decision": "reused" if old["grant_id"] == r["grant"] else "revocation_identity_conflict"}
        generation = grant["generation"] + 1
        db.execute("INSERT INTO revocations VALUES(?,?,?,?)", (r["id"], r["grant"], generation, r["at"]))
        db.execute("UPDATE grants SET status='revoked',generation=? WHERE id=?", (generation, r["grant"]))
        db.execute("UPDATE plans SET status='frozen' WHERE id IN (SELECT plan_id FROM members WHERE grant_id=?) AND status IN ('planned','partial')", (r["grant"],))
        return {"decision": "revoked", "affected_plans": [x["id"] for x in rows(db, "SELECT DISTINCT p.id FROM plans p JOIN members m ON m.plan_id=p.id WHERE m.grant_id=? AND p.status='frozen'", (r["grant"],))]}
    raise ValueError(op)
