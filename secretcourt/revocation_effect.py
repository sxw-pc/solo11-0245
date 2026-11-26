"""Effective-revocation court: prove old material is actually unusable.

The control plane (``grant.revoke``) and a mere ``cleared`` receipt only prove
that a database row changed and that a packet digest was acknowledged.  A
delivered workload may still hold the old value in its process memory, on a
mount, in an external cache, or on a replica that is partitioned away.

This module is the single authority for an *effective revocation proof*.  An
effect case binds the real usable surface of every old-value copy to an
instance UID, a container generation, process memory, mounts, external
caches and the highest successful-use sequence.  Independently verified
revocation commands, container exits and KMS rotation receipts are collected,
real usage probes are evaluated, and only then is a proof issued.

``delivery.py`` clearance and ``material.py`` version retirement consume the
same :table:`effect_proofs` rows through :func:`classify_proof` /
:func:`valid_proof`.  Every conclusion is append-only evidence: late use and
corrections challenge a proof and raise incident notices, but never delete the
original conclusion.
"""
import hashlib
import json

from .store import one, rows

VALID_OUTCOMES = ("old_accepted", "old_rejected", "old_unreachable", "new_verified")
DEAD_OUTCOMES = ("old_rejected", "old_unreachable")

# DDL is kept here (single source for the effect tables); store.connect runs
# EFFECT_SCHEMA and run() defensively ensures the tables exist for raw handles.
EFFECT_TABLES = [
    """CREATE TABLE IF NOT EXISTS effect_issuers(
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, credential TEXT NOT NULL, at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS effect_cases(
        id TEXT PRIMARY KEY, grant_id TEXT, revocation_id TEXT,
        secret TEXT, gen INTEGER, uid TEXT, packet TEXT,
        opened_at INTEGER, path TEXT, status TEXT, proof_id TEXT,
        last_use_seq INTEGER NOT NULL DEFAULT 0, last_use_at INTEGER,
        stopped_at INTEGER, resumed_at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS effect_commands(
        id TEXT PRIMARY KEY, case_id TEXT, grant_id TEXT,
        console TEXT, at INTEGER, verification TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS effect_bindings(
        id TEXT PRIMARY KEY, case_id TEXT, secret TEXT, gen INTEGER,
        uid TEXT, replica TEXT, container_gen INTEGER,
        reachability TEXT NOT NULL DEFAULT 'reachable',
        surfaces TEXT NOT NULL, last_use_seq INTEGER NOT NULL DEFAULT 0,
        bound_at INTEGER, status TEXT NOT NULL DEFAULT 'bound',
        orphan_id TEXT, partition_since INTEGER, contacted_at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS effect_probes(
        id TEXT PRIMARY KEY, case_id TEXT, binding_id TEXT,
        uid TEXT, replica TEXT, container_gen INTEGER,
        seq INTEGER, at INTEGER, surface TEXT, ref TEXT,
        outcome TEXT NOT NULL, observed_by TEXT, verification TEXT,
        write_id TEXT, late INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS effect_exits(
        id TEXT PRIMARY KEY, binding_id TEXT,
        uid TEXT, replica TEXT, container_gen INTEGER,
        at INTEGER, reason TEXT, runtime TEXT, verification TEXT,
        memory_image TEXT, core_disposition TEXT)""",
    """CREATE TABLE IF NOT EXISTS effect_isolations(
        id TEXT PRIMARY KEY, binding_id TEXT, at INTEGER,
        storage_receipt TEXT, memory_receipt TEXT,
        cache_receipts TEXT, writes_blocked INTEGER NOT NULL DEFAULT 0,
        verification TEXT)""",
    """CREATE TABLE IF NOT EXISTS effect_rotations(
        id TEXT PRIMARY KEY, case_id TEXT, secret TEXT,
        old_gen INTEGER, new_gen INTEGER, kms_key TEXT, at INTEGER,
        receipt_digest TEXT, verification TEXT)""",
    """CREATE TABLE IF NOT EXISTS effect_windows(
        id TEXT PRIMARY KEY, case_id TEXT, uid TEXT,
        opened_at INTEGER, deadline_seq INTEGER, deadline_at INTEGER,
        status TEXT NOT NULL DEFAULT 'open', closed_at INTEGER)""",
    """CREATE TABLE IF NOT EXISTS effect_writes(
        id TEXT PRIMARY KEY, case_id TEXT, window_id TEXT, binding_id TEXT,
        uid TEXT, seq INTEGER, at INTEGER, record_digest TEXT,
        status TEXT NOT NULL DEFAULT 'confirmed', disposition TEXT)""",
    """CREATE TABLE IF NOT EXISTS effect_rewrites(
        id TEXT PRIMARY KEY, write_id TEXT, case_id TEXT,
        new_gen INTEGER, new_digest TEXT, at INTEGER,
        record_digest TEXT, status TEXT NOT NULL DEFAULT 'rewritten',
        read_probe_id TEXT)""",
    """CREATE TABLE IF NOT EXISTS effect_proofs(
        id TEXT PRIMARY KEY, case_id TEXT, secret TEXT, gen INTEGER,
        mode TEXT, at INTEGER, scope TEXT, evidence_digest TEXT,
        status TEXT NOT NULL DEFAULT 'valid', supersedes TEXT)""",
    """CREATE TABLE IF NOT EXISTS effect_notices(
        id TEXT PRIMARY KEY, case_id TEXT, proof_id TEXT,
        kind TEXT NOT NULL, at INTEGER, detail TEXT)""",
    """CREATE TABLE IF NOT EXISTS effect_corrections(
        id TEXT PRIMARY KEY, case_id TEXT, at INTEGER,
        target_kind TEXT, target_id TEXT, field TEXT,
        old_value TEXT, new_value TEXT, reason TEXT)""",
    """CREATE TABLE IF NOT EXISTS effect_consumption(
        proof_id TEXT, consumer TEXT, ref_id TEXT, at INTEGER, detail TEXT,
        PRIMARY KEY(consumer, ref_id))""",
]
EFFECT_SCHEMA = ";\n".join(EFFECT_TABLES)
EFFECT_TABLE_NAMES = [
    "effect_issuers", "effect_cases", "effect_commands", "effect_bindings",
    "effect_probes", "effect_exits", "effect_isolations", "effect_rotations",
    "effect_windows", "effect_writes", "effect_rewrites", "effect_proofs",
    "effect_notices", "effect_corrections", "effect_consumption",
]


def ensure_schema(db):
    """Create effect tables on any connection (idempotent)."""
    for stmt in EFFECT_TABLES:
        db.execute(stmt)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _canonical_hash(value):
    return "sha256:" + hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _notice(db, nid, case_id, kind, at, detail=None, proof_id=None):
    """Append an incident notice once; notices are never updated or deleted."""
    if nid and one(db, "SELECT 1 FROM effect_notices WHERE id=?", (nid,)):
        return nid
    db.execute(
        "INSERT INTO effect_notices(id,case_id,proof_id,kind,at,detail) VALUES(?,?,?,?,?,?)",
        (nid, case_id, proof_id, kind, at, _json(detail or {})),
    )
    return nid


def list_notices(db, case_id=None):
    if case_id:
        return rows(db, "SELECT * FROM effect_notices WHERE case_id=? ORDER BY rowid", (case_id,))
    return rows(db, "SELECT * FROM effect_notices ORDER BY rowid")


def _verify_issuer(db, kind, issuer_id, credential):
    """Independently authenticate an authority signal.

    Returns the issuer row when the out-of-band registered credential matches,
    otherwise ``None``.
    """
    if not issuer_id or credential is None:
        return None
    issuer = one(db, "SELECT * FROM effect_issuers WHERE id=?", (issuer_id,))
    if not issuer or issuer["kind"] != kind:
        return None
    expected = issuer["credential"] or ""
    given = credential or ""
    if len(expected) != len(given):
        return None
    import hmac
    return issuer if hmac.compare_digest(expected, given) else None


def _normalize_surfaces(raw):
    """Normalize the bound usable surface descriptors."""
    if raw is None:
        raw = ["process_memory"]
    out = []
    for item in raw:
        if isinstance(item, str):
            if item in ("process_memory", "memory"):
                out.append({"kind": "process_memory", "ref": "process_memory"})
            elif item.startswith("cache:"):
                out.append({"kind": "cache", "ref": item})
            else:
                out.append({"kind": "mount", "ref": item})
            continue
        kind = item.get("kind")
        if kind not in ("process_memory", "mount", "cache"):
            raise ValueError("invalid_surface_kind")
        ref = item.get("ref") or (
            "process_memory" if kind == "process_memory" else None
        )
        if not ref:
            raise ValueError("surface_ref_required")
        desc = {"kind": kind, "ref": ref}
        if item.get("delay_until") is not None:
            desc["delay_until"] = item["delay_until"]
        out.append(desc)
    if not any(s["kind"] == "process_memory" for s in out):
        out.insert(0, {"kind": "process_memory", "ref": "process_memory"})
    return out


def _resolve_binding(db, case_id, r):
    """Resolve a binding by explicit id or exact (uid,replica,container_gen)."""
    if r.get("binding"):
        return one(db, "SELECT * FROM effect_bindings WHERE id=? AND case_id=?",
                   (r["binding"], case_id))
    uid = r.get("uid")
    replica = r.get("replica") or uid
    gen = r.get("container_gen")
    if uid is None:
        return None
    if gen is not None:
        return one(
            db,
            "SELECT * FROM effect_bindings WHERE case_id=? AND uid=? AND replica=? AND container_gen=?",
            (case_id, uid, replica, gen),
        )
    candidates = rows(
        db,
        "SELECT * FROM effect_bindings WHERE case_id=? AND uid=? AND replica=? ORDER BY container_gen",
        (case_id, uid, replica),
    )
    if len(candidates) == 1:
        return candidates[0]
    return None


def classify_proof(db, proof_id, secret=None, gen=None):
    """Return ``(proof, error_code)`` for a shared effect proof reference.

    Error codes distinguish unknown/forged references, challenged/corrected/
    superseded proofs and lineage scope mismatches.
    """
    ensure_schema(db)
    proof = one(db, "SELECT * FROM effect_proofs WHERE id=?", (proof_id,))
    if not proof:
        return None, "invalid_effect_proof"
    if proof["status"] != "valid":
        return proof, "effect_proof_" + proof["status"]
    if secret is not None and proof["secret"] != secret:
        return proof, "effect_proof_scope_mismatch"
    if gen is not None and proof["gen"] != gen:
        return proof, "effect_proof_scope_mismatch"
    return proof, None


def valid_proof(db, proof_id, secret=None, gen=None, uid=None, container_gen=None):
    """Strict validity check used by delivery clearance and material retirement."""
    proof, err = classify_proof(db, proof_id, secret, gen)
    if err:
        return None
    if uid is not None:
        scope = json.loads(proof["scope"] or "{}")
        for b in scope.get("bindings", []):
            if b.get("uid") != uid:
                continue
            if container_gen is None or b.get("container_gen") == container_gen:
                return proof
        return None
    return proof


def consume_proof(db, proof_id, consumer, ref_id, at=None, detail=None):
    """Record that delivery/material consumed the shared proof (idempotent)."""
    db.execute(
        "INSERT OR IGNORE INTO effect_consumption(proof_id,consumer,ref_id,at,detail) VALUES(?,?,?,?,?)",
        (proof_id, consumer, ref_id, at, _json(detail or {})),
    )


# ---------------------------------------------------------------------------
# Completion evaluation: the single effective-revocation gate
# ---------------------------------------------------------------------------

def _binding_report(db, case, b, mode=None):
    probes = rows(db, "SELECT * FROM effect_probes WHERE binding_id=? ORDER BY seq,rowid", (b["id"],))
    exits = rows(db, "SELECT * FROM effect_exits WHERE binding_id=? ORDER BY rowid", (b["id"],))
    isolations = rows(db, "SELECT * FROM effect_isolations WHERE binding_id=? ORDER BY rowid", (b["id"],))
    writes = rows(db, "SELECT * FROM effect_writes WHERE binding_id=? ORDER BY seq", (b["id"],))

    high = b["last_use_seq"] or 0
    for p in probes:
        if p["outcome"] == "old_accepted" and (p["seq"] or 0) > high:
            high = p["seq"]
    for w in writes:
        if (w["seq"] or 0) > high:
            high = w["seq"]

    dead = [p for p in probes if p["outcome"] in DEAD_OUTCOMES and (p["seq"] or 0) > high]
    latest_dead_at = max([p["at"] for p in dead if p["at"] is not None], default=None)
    isolated = bool(isolations) and all(i["storage_receipt"] and i["memory_receipt"] for i in isolations)
    iso = isolations[-1] if isolations else None

    orphan_cleared = False
    if b["orphan_id"]:
        o = one(db, "SELECT status FROM orphans WHERE id=?", (b["orphan_id"],))
        orphan_cleared = bool(o and o["status"] == "cleared")

    blockers = []
    bid = b["id"]

    # Partition boundary: evidence only counts once the replica is reachable.
    partition_ok = True
    if b["reachability"] == "partitioned" and b["contacted_at"] is None:
        partition_ok = False
        blockers.append("partition_unverified:" + bid)
    elif b["contacted_at"] is not None:
        decisive_at = latest_dead_at
        iso_at = max([i["at"] for i in isolations if i["at"] is not None], default=None)
        decisive_at = max([x for x in (decisive_at, iso_at) if x is not None], default=None)
        if decisive_at is None or decisive_at < b["contacted_at"]:
            partition_ok = False
            blockers.append("partition_boundary_missing:" + bid)

    if b["reachability"] == "orphan":
        if not (isolated or orphan_cleared):
            blockers.append("orphan_copy_remains:" + bid)
    else:
        if mode == "quiesce":
            # Downtime path: the exact bound generation must be stopped and
            # its storage/memory images isolated.
            if not exits:
                blockers.append("verified_exit_missing:" + bid)
            if not isolations or not all(i["storage_receipt"] and i["memory_receipt"] for i in isolations):
                blockers.append("isolation_evidence_missing:" + bid)
            # A crash can leave a memory/core image behind; that residue needs
            # explicit isolation or a runtime attestation that no core exists.
            for e in exits:
                if e["reason"] == "crashed" and not e["memory_image"] \
                        and e["core_disposition"] != "none_attested" \
                        and not any(i["memory_receipt"] for i in isolations):
                    blockers.append("memory_image_required:" + bid)
                    break
        # Both paths must measure a post-high-water rejection/unavailability.
        if high > 0 and not dead:
            blockers.append("old_value_still_usable:" + bid)
        elif not dead:
            blockers.append("old_value_rejection_missing:" + bid)

    # Surface-by-surface clearance of the bound usable scope.
    cache_covered = {}
    for i in isolations:
        try:
            covered = json.loads(i["cache_receipts"] or "{}")
        except ValueError:
            covered = {}
        if isinstance(covered, dict):
            cache_covered.update(covered)
        elif isinstance(covered, list):
            for ref in covered:
                cache_covered[ref] = i["id"]

    surfaces = json.loads(b["surfaces"] or "[]")
    for s in surfaces:
        kind, ref = s["kind"], s["ref"]
        cleared = False
        if kind == "process_memory":
            cleared = bool(exits) or bool(iso and iso["memory_receipt"])
        elif kind == "mount":
            cleared = bool(iso and iso["storage_receipt"])
        elif kind == "cache":
            cleared = ref in cache_covered
        for p in dead:
            if p["surface"] == "*":
                if kind == "cache" and s.get("delay_until") is not None and p["at"] is not None \
                        and p["at"] < s["delay_until"] and not (ref in cache_covered):
                    continue
                cleared = True
            elif p["surface"] == kind and (not p["ref"] or p["ref"] == ref):
                if kind == "cache" and s.get("delay_until") is not None and p["at"] is not None \
                        and p["at"] < s["delay_until"] and not (ref in cache_covered):
                    continue
                cleared = True
        if not cleared:
            blockers.append("surface_uncleared:%s:%s" % (bid, ref))

    return {
        "binding": bid,
        "uid": b["uid"],
        "replica": b["replica"],
        "container_gen": b["container_gen"],
        "reachability": b["reachability"],
        "status": b["status"],
        "high_water_seq": high,
        "dead_probe_seq": max([p["seq"] or 0 for p in dead], default=None),
        "decisive_at": latest_dead_at or (iso["at"] if iso else None),
        "isolated": isolated or orphan_cleared,
        "partition_ok": partition_ok,
        "blockers": blockers,
    }


def is_effectively_revoked(db, case_id, mode=None):
    """Convenience predicate used by callers that only need the gate result."""
    return bool(evaluate(db, case_id, mode)["ready"])


def issue_effect_proof(db, proof_id, case_id, mode=None, at=None, **extra):
    """Functional wrapper around the shared proof-issuance command."""
    req = dict(extra)
    req.update({"op": "complete", "id": proof_id, "case": case_id})
    if mode is not None:
        req["mode"] = mode
    if at is not None:
        req["at"] = at
    return run(db, req)


def evaluate(db, case_id, mode=None):
    """Compute the effective-revocation report; never mutates state."""
    ensure_schema(db)
    case = one(db, "SELECT * FROM effect_cases WHERE id=?", (case_id,))
    if not case:
        return {"decision": "effect_status", "case": case_id,
                "ready": False, "blockers": ["case_unknown"], "bindings": []}

    blockers = []

    # 1. Control plane must really show the grant revoked.
    if case["grant_id"]:
        grant = one(db, "SELECT status FROM grants WHERE id=?", (case["grant_id"],))
        rev = one(db, "SELECT 1 FROM revocations WHERE grant_id=?", (case["grant_id"],))
        if not rev and (not grant or grant["status"] != "revoked"):
            blockers.append("control_revocation_missing")
    else:
        blockers.append("grant_binding_missing")

    # 2. At least one independently verified revocation command.
    commands = rows(db, "SELECT * FROM effect_commands WHERE case_id=? AND verification='verified'", (case_id,))
    if not commands:
        blockers.append("verified_revocation_command_missing")

    # 3. Every bound copy must be dead/contained.
    effective_mode = mode or case["path"]
    bindings = rows(db, "SELECT * FROM effect_bindings WHERE case_id=? ORDER BY rowid", (case_id,))
    if not bindings:
        blockers.append("usage_scope_binding_missing")
    reports = [_binding_report(db, case, b, effective_mode) for b in bindings]
    for rep in reports:
        blockers.extend(rep["blockers"])

    # 4. Confirmed business writes must have the mode-specific disposition.
    writes = rows(db, "SELECT * FROM effect_writes WHERE case_id=? ORDER BY seq,rowid", (case_id,))
    for w in writes:
        if effective_mode == "dual_read":
            if w["status"] == "read_verified":
                continue
            if w["status"] == "rewritten":
                blockers.append("new_value_read_unverified:" + w["id"])
            else:
                blockers.append("confirmed_write_not_rewritten:" + w["id"])
        elif effective_mode == "quiesce":
            if w["status"] != "quarantined":
                blockers.append("confirmed_write_not_contained:" + w["id"])

    # 5. Mode-specific evidence.
    rotations = rows(db, "SELECT * FROM effect_rotations WHERE case_id=? AND verification='verified'", (case_id,))
    windows = rows(db, "SELECT * FROM effect_windows WHERE case_id=? ORDER BY rowid", (case_id,))
    if effective_mode == "dual_read":
        if not rotations:
            blockers.append("verified_rotation_receipt_missing")
        if not windows:
            blockers.append("dual_read_window_missing")
        elif any(w["status"] != "closed" for w in windows):
            blockers.append("dual_read_window_open")
    elif effective_mode == "quiesce":
        blocked_iso = one(db,
                          "SELECT 1 FROM effect_isolations i JOIN effect_bindings b ON b.id=i.binding_id "
                          "WHERE b.case_id=? AND i.writes_blocked=1 LIMIT 1", (case_id,))
        if not blocked_iso:
            blockers.append("downtime_write_block_missing")
    else:
        blockers.append("remediation_path_required")

    # Stable, de-duplicated ordering.
    seen = set()
    ordered = []
    for code in blockers:
        if code not in seen:
            seen.add(code)
            ordered.append(code)

    return {
        "decision": "effect_status",
        "case": case_id,
        "mode": effective_mode,
        "ready": not ordered,
        "blockers": ordered,
        "bindings": reports,
        "commands": [c["id"] for c in commands],
        "rotations": [r["id"] for r in rotations],
        "windows": [w["id"] for w in windows],
    }


# ---------------------------------------------------------------------------
# Command dispatch
# ---------------------------------------------------------------------------

def run(db, request):
    ensure_schema(db)
    # Tolerate the natural field-name variants callers may use.  This only
    # normalizes the in-call copy; the original event payload stays untouched.
    r = dict(request)
    if r.get("case") is None and r.get("case_id") is not None:
        r["case"] = r["case_id"]
    if r.get("binding") is None and r.get("binding_id") is not None:
        r["binding"] = r["binding_id"]
    if r.get("container_gen") is None:
        for key in ("container_generation", "generation", "epoch"):
            if r.get(key) is not None:
                r["container_gen"] = r[key]
                break
    if r.get("seq") is None and r.get("sequence") is not None:
        r["seq"] = r["sequence"]
    if r.get("mode") is None and request.get("op") not in ("path", "choose_path"):
        path_value = r.get("path")
        if path_value in ("quiesce", "dual_read"):
            r["mode"] = path_value
    op = r["op"]

    # ---- trusted authorities -------------------------------------------
    if op == "issuer":
        old = one(db, "SELECT * FROM effect_issuers WHERE id=?", (r["id"],))
        if old:
            same = (old["kind"], old["credential"]) == (r["kind"], r["credential"])
            return {"decision": "reused" if same else "issuer_identity_conflict"}
        if r["kind"] not in ("console", "runtime", "prober", "kms", "security"):
            return {"decision": "invalid_issuer_kind"}
        db.execute("INSERT INTO effect_issuers VALUES(?,?,?,?)",
                   (r["id"], r["kind"], r["credential"], r.get("at")))
        return {"decision": "issuer_registered", "kind": r["kind"]}

    # ---- effect case ----------------------------------------------------
    if op in ("open", "case", "open_case"):
        cid = r["id"]
        old = one(db, "SELECT * FROM effect_cases WHERE id=?", (cid,))
        if old:
            same = (old["grant_id"], old["secret"], old["gen"], old["uid"]) == (
                r.get("grant"), r["secret"], r["gen"], r.get("uid"))
            return {"decision": "reused" if same else "case_identity_conflict"}
        db.execute(
            "INSERT INTO effect_cases(id,grant_id,revocation_id,secret,gen,uid,packet,"
            "opened_at,path,status,proof_id,last_use_seq,last_use_at,stopped_at,resumed_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cid, r.get("grant"), r.get("revocation"), r["secret"], r["gen"], r.get("uid"),
             r.get("packet"), r.get("at"), r.get("mode"), "open", None, 0, None, None, None),
        )
        return {"decision": "effect_case_opened", "case": cid}

    if op in ("path", "choose_path"):
        case = one(db, "SELECT * FROM effect_cases WHERE id=?", (r["case"],))
        if not case:
            return {"decision": "case_unknown"}
        mode = r["mode"]
        if mode not in ("quiesce", "dual_read"):
            return {"decision": "invalid_remediation_path"}
        if case["path"] and case["path"] != mode:
            return {"decision": "remediation_path_conflict", "existing": case["path"]}
        db.execute("UPDATE effect_cases SET path=? WHERE id=?", (mode, r["case"]))
        return {"decision": "remediation_path_selected", "mode": mode}

    # ---- scope binding --------------------------------------------------
    if op in ("bind", "binding", "scope", "register_scope"):
        bid = r["id"]
        old = one(db, "SELECT * FROM effect_bindings WHERE id=?", (bid,))
        surfaces = _normalize_surfaces(r.get("surfaces"))
        replica = r.get("replica") or r["uid"]
        if old:
            same = (old["case_id"], old["uid"], old["replica"], old["container_gen"]) == (
                r["case"], r["uid"], replica, r["container_gen"])
            return {"decision": "reused" if same else "binding_identity_conflict"}
        clash = one(
            db,
            "SELECT id FROM effect_bindings WHERE case_id=? AND uid=? AND replica=? AND container_gen=?",
            (r["case"], r["uid"], replica, r["container_gen"]),
        )
        if clash:
            return {"decision": "binding_generation_already_registered", "existing": clash["id"]}
        reach = r.get("reachability", "reachable")
        if reach not in ("reachable", "partitioned", "orphan"):
            return {"decision": "invalid_reachability"}
        db.execute(
            "INSERT INTO effect_bindings(id,case_id,secret,gen,uid,replica,container_gen,"
            "reachability,surfaces,last_use_seq,bound_at,status,orphan_id,partition_since,contacted_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (bid, r["case"], r.get("secret"), r.get("gen"), r["uid"],
             replica, r["container_gen"], reach, _json(surfaces),
             int(r.get("last_use_seq", 0)), r.get("at"), "bound",
             r.get("orphan_id"), r.get("partition_since"), None),
        )
        return {"decision": "usage_scope_bound", "binding": bid, "surfaces": surfaces}

    if op in ("contact", "replica_contact", "heal_partition", "heal", "replica_contacted"):
        b = _resolve_binding(db, r["case"], r)
        if not b:
            return {"decision": "binding_unknown"}
        if b["reachability"] != "partitioned":
            return {"decision": "replica_not_partitioned"}
        at = r.get("at")
        db.execute("UPDATE effect_bindings SET reachability='reachable',contacted_at=? WHERE id=?",
                   (at, b["id"]))
        _notice(db, "notice-contact-" + b["id"], r["case"], "partition_healed", at,
                {"binding": b["id"], "uid": b["uid"], "replica": b["replica"], "at": at})
        return {"decision": "partition_replica_contacted", "binding": b["id"], "contacted_at": at}

    # ---- independently verified revocation command ----------------------
    if op in ("command", "revocation_command", "console_revoke", "revoke_confirm", "console_revocation"):
        cid_cmd = r["id"]
        old = one(db, "SELECT * FROM effect_commands WHERE id=?", (cid_cmd,))
        if old:
            same = (old["case_id"], old["grant_id"], old["console"], old["at"]) == (
                r.get("case"), r.get("grant"), r.get("console"), r.get("at"))
            return {"decision": "reused" if same else "command_identity_conflict"}
        issuer = _verify_issuer(db, "console", r.get("issuer") or r.get("console_id"),
                                r.get("credential"))
        if not issuer:
            return {"decision": "revocation_command_unverified"}
        db.execute(
            "INSERT INTO effect_commands(id,case_id,grant_id,console,at,verification) VALUES(?,?,?,?,?,?)",
            (cid_cmd, r.get("case"), r.get("grant"), r.get("console") or issuer["id"],
             r.get("at"), "verified"),
        )
        if r.get("case"):
            case = one(db, "SELECT * FROM effect_cases WHERE id=?", (r["case"],))
            if case:
                consoles = rows(
                    db,
                    "SELECT DISTINCT console FROM effect_commands WHERE case_id=? AND verification='verified'",
                    (r["case"],))
                if len(consoles) >= 2:
                    _notice(db, "notice-dual-console-" + r["case"], r["case"],
                           "dual_console_revocation", r.get("at"),
                           {"consoles": sorted(c["console"] for c in consoles)})
                    return {"decision": "revocation_command_verified",
                            "dual_console_revocation": True,
                            "consoles": sorted(c["console"] for c in consoles)}
        return {"decision": "revocation_command_verified"}

    # ---- real usage probe -----------------------------------------------
    if op in ("probe", "usage_probe"):
        pid = r["id"]
        old = one(db, "SELECT * FROM effect_probes WHERE id=?", (pid,))
        if old:
            replica = r.get("replica") or r.get("uid")
            same = (
                old["case_id"] == r.get("case")
                and old["outcome"] == r.get("outcome")
                and old["seq"] == r.get("seq")
                and old["at"] == r.get("at")
                and (
                    (r.get("binding") and old["binding_id"] == r["binding"])
                    or (not r.get("binding") and old["uid"] == r.get("uid")
                        and old["container_gen"] == r.get("container_gen")
                        and old["replica"] == replica)
                )
            )
            return {"decision": "reused" if same else "probe_identity_conflict"}
        if r["outcome"] not in VALID_OUTCOMES:
            return {"decision": "invalid_probe_outcome"}
        b = _resolve_binding(db, r["case"], r)
        if not b:
            return {"decision": "probe_binding_mismatch"}
        # Optional authenticated prober channel; otherwise the probe is
        # persisted as directly observed evidence.
        verification = "recorded"
        if r.get("issuer") or r.get("observer"):
            issuer = _verify_issuer(db, "prober", r.get("issuer") or r.get("observer"),
                                    r.get("credential"))
            if not issuer:
                return {"decision": "probe_observer_unverified"}
            verification = "verified"
        surface = r.get("surface", "*" if r.get("all_surfaces") else "api")
        ref = r.get("ref")
        db.execute(
            "INSERT INTO effect_probes(id,case_id,binding_id,uid,replica,container_gen,seq,at,"
            "surface,ref,outcome,observed_by,verification,write_id,late) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
            (pid, r["case"], b["id"], b["uid"], b["replica"], b["container_gen"],
             r.get("seq"), r.get("at"), surface, ref, r["outcome"],
             r.get("observer") or r.get("issuer"), verification, r.get("write")),
        )
        if r["outcome"] == "old_accepted":
            seq = r.get("seq") or 0
            if seq > (b["last_use_seq"] or 0):
                db.execute("UPDATE effect_bindings SET last_use_seq=? WHERE id=?", (seq, b["id"]))
            case = one(db, "SELECT * FROM effect_cases WHERE id=?", (r["case"],))
            if case and seq > (case["last_use_seq"] or 0):
                db.execute("UPDATE effect_cases SET last_use_seq=?,last_use_at=? WHERE id=?",
                           (seq, r.get("at"), r["case"]))
            # A late accepted use after proof issuance challenges the proof but
            # never removes it or the original clearance conclusion.
            proof = one(db, "SELECT * FROM effect_proofs WHERE case_id=? AND status='valid'",
                        (r["case"],))
            if proof:
                scope = json.loads(proof["scope"] or "{}")
                extends = seq > (scope.get("max_use_seq") or 0)
                db.execute("UPDATE effect_proofs SET status='challenged' WHERE id=?", (proof["id"],))
                db.execute("UPDATE effect_cases SET status='challenged' WHERE id=?", (r["case"],))
                _notice(db, "notice-late-use-" + pid, r["case"], "late_old_use", r.get("at"),
                        {"probe": pid, "proof": proof["id"], "seq": seq,
                         "binding": b["id"], "extends_window": extends},
                        proof_id=proof["id"])
                return {"decision": "late_old_use_recorded", "incident": "notice-late-use-" + pid,
                        "proof": proof["id"], "extends_window": extends}
            return {"decision": "old_value_use_observed", "blocks_completion": True,
                    "binding": b["id"], "high_water_seq": max(seq, b["last_use_seq"] or 0)}

        if r["outcome"] == "new_verified" and r.get("write"):
            w = one(db, "SELECT * FROM effect_writes WHERE id=?", (r["write"],))
            rw = one(db, "SELECT * FROM effect_rewrites WHERE write_id=?", (r["write"],))
            if w and rw:
                db.execute("UPDATE effect_writes SET status='read_verified' WHERE id=?", (w["id"],))
                db.execute("UPDATE effect_rewrites SET status='read_verified',read_probe_id=? WHERE id=?",
                           (pid, rw["id"]))
                return {"decision": "new_value_read_verified", "write": w["id"]}
        return {"decision": {"old_rejected": "old_value_rejected",
                             "old_unreachable": "old_value_unreachable",
                             "new_verified": "new_value_verified"}[r["outcome"]]}

    # ---- independently verified container exit --------------------------
    if op in ("exit", "container_exit", "exit_event"):
        eid = r["id"]
        old = one(db, "SELECT * FROM effect_exits WHERE id=?", (eid,))
        if old:
            same = (
                old["at"] == r.get("at")
                and old["container_gen"] == r.get("container_gen", old["container_gen"])
                and (not r.get("binding") or old["binding_id"] == r["binding"])
                and (r.get("uid") is None or old["uid"] == r["uid"])
                and (r.get("reason") is None or old["reason"] == r["reason"])
            )
            return {"decision": "reused" if same else "exit_identity_conflict"}
        issuer = _verify_issuer(db, "runtime", r.get("runtime") or r.get("issuer"),
                                r.get("credential"))
        if not issuer:
            return {"decision": "exit_event_unverified"}
        b = _resolve_binding(db, r.get("case"), r) if r.get("case") or (r.get("uid") and r.get("container_gen") is not None) \
            else one(db, "SELECT * FROM effect_bindings WHERE id=?", (r.get("binding"),))
        if not b:
            return {"decision": "exit_binding_unknown"}
        if r.get("uid") is not None and r["uid"] != b["uid"]:
            return {"decision": "exit_binding_mismatch"}
        if r.get("container_gen") is not None and r["container_gen"] != b["container_gen"]:
            return {"decision": "exit_generation_mismatch"}
        reason = r.get("reason", "stopped")
        if reason not in ("stopped", "crashed"):
            return {"decision": "invalid_exit_reason"}
        db.execute(
            "INSERT INTO effect_exits(id,binding_id,uid,replica,container_gen,at,reason,runtime,"
            "verification,memory_image,core_disposition) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (eid, b["id"], b["uid"], b["replica"], b["container_gen"], r.get("at"), reason,
             issuer["id"], "verified", r.get("memory_image"), r.get("core_disposition")),
        )
        db.execute("UPDATE effect_bindings SET status='exited' WHERE id=?", (b["id"],))
        if reason == "crashed":
            _notice(db, "notice-crash-" + eid, b["case_id"], "container_crashed", r.get("at"),
                    {"exit": eid, "binding": b["id"], "container_gen": b["container_gen"],
                     "memory_image": bool(r.get("memory_image")),
                     "core_disposition": r.get("core_disposition")})
            return {"decision": "container_exit_verified", "crash_restart_window_preserved": True}
        return {"decision": "container_exit_verified"}

    # ---- stop + isolate evidence ----------------------------------------
    if op in ("isolate", "isolation", "quarantine"):
        iid = r["id"]
        old = one(db, "SELECT * FROM effect_isolations WHERE id=?", (iid,))
        if old:
            same = (old["binding_id"], old["at"]) == (r.get("binding"), r.get("at"))
            return {"decision": "reused" if same else "isolation_identity_conflict"}
        b = one(db, "SELECT * FROM effect_bindings WHERE id=?", (r["binding"],))
        if not b:
            return {"decision": "binding_unknown"}
        storage = r.get("storage_receipt") or r.get("isolation_receipt")
        memory = r.get("memory_receipt") or r.get("isolation_receipt")
        cache = r.get("cache_receipts")
        if cache is None:
            cache_map = {}
        elif isinstance(cache, dict):
            cache_map = cache
        else:
            cache_map = {ref: iid + ":cache:" + str(i) for i, ref in enumerate(cache)}
        writes_blocked = 1 if r.get("writes_blocked") else 0
        db.execute(
            "INSERT INTO effect_isolations(id,binding_id,at,storage_receipt,memory_receipt,"
            "cache_receipts,writes_blocked,verification) VALUES(?,?,?,?,?,?,?,?)",
            (iid, b["id"], r.get("at"), storage, memory, _json(cache_map), writes_blocked,
             r.get("verification", "recorded")),
        )
        db.execute("UPDATE effect_bindings SET status='isolated' WHERE id=?", (b["id"],))
        if writes_blocked:
            case = one(db, "SELECT * FROM effect_cases WHERE id=?", (b["case_id"],))
            if case and (not case["stopped_at"] or (r.get("at") is not None and r["at"] < case["stopped_at"])):
                db.execute("UPDATE effect_cases SET stopped_at=? WHERE id=?", (r.get("at"), b["case_id"]))
        if r.get("resumed_at") is not None:
            db.execute("UPDATE effect_cases SET resumed_at=? WHERE id=?", (r["resumed_at"], b["case_id"]))
        return {"decision": "isolation_recorded", "binding": b["id"],
                "writes_blocked": bool(writes_blocked)}

    # ---- independently verified KMS rotation receipt --------------------
    if op in ("rotation", "rotation_receipt", "verify_rotation", "key_rotation", "rotation_verify"):
        rid = r["id"]
        old = one(db, "SELECT * FROM effect_rotations WHERE id=?", (rid,))
        if old:
            same = (old["case_id"], old["secret"], old["old_gen"], old["new_gen"]) == (
                r.get("case"), r["secret"], r["old_gen"], r["new_gen"])
            return {"decision": "reused" if same else "rotation_identity_conflict"}
        issuer = _verify_issuer(db, "kms", r.get("kms") or r.get("issuer"), r.get("credential"))
        if not issuer:
            return {"decision": "rotation_receipt_unverified"}
        version = one(db, "SELECT * FROM versions WHERE secret=? AND gen=?",
                      (r["secret"], r["new_gen"]))
        if not version:
            return {"decision": "rotation_new_version_unknown"}
        if r.get("new_digest") and version["digest"] != r["new_digest"]:
            return {"decision": "rotation_digest_mismatch"}
        db.execute(
            "INSERT INTO effect_rotations(id,case_id,secret,old_gen,new_gen,kms_key,at,"
            "receipt_digest,verification) VALUES(?,?,?,?,?,?,?,?,?)",
            (rid, r.get("case"), r["secret"], r["old_gen"], r["new_gen"], issuer["id"],
             r.get("at"), r.get("receipt") or r.get("receipt_digest"), "verified"),
        )
        return {"decision": "rotation_receipt_verified"}

    # ---- bounded dual-read window ---------------------------------------
    if op in ("dual_open", "open_dual_read", "dual_read", "open_dual_read_window"):
        wid = r["id"]
        old = one(db, "SELECT * FROM effect_windows WHERE id=?", (wid,))
        if old:
            same = (old["case_id"], old["uid"]) == (r["case"], r["uid"])
            return {"decision": "reused" if same else "window_identity_conflict"}
        if r.get("deadline_seq") is None and r.get("deadline_at") is None:
            # Old and new values must never be granted side-by-side forever.
            return {"decision": "indefinite_dual_read_denied"}
        db.execute(
            "INSERT INTO effect_windows(id,case_id,uid,opened_at,deadline_seq,deadline_at,status,closed_at) "
            "VALUES(?,?,?,?,?,?, 'open', NULL)",
            (wid, r["case"], r["uid"], r.get("at"), r.get("deadline_seq"), r.get("deadline_at")),
        )
        return {"decision": "dual_read_opened", "window": wid,
                "deadline_seq": r.get("deadline_seq"), "deadline_at": r.get("deadline_at")}

    if op in ("dual_close", "close_dual_read"):
        w = one(db, "SELECT * FROM effect_windows WHERE id=?", (r["window"],))
        if not w:
            return {"decision": "window_unknown"}
        if w["status"] == "closed":
            return {"decision": "reused"}
        blockers = []
        writes = rows(db, "SELECT * FROM effect_writes WHERE case_id=? AND uid=?",
                      (w["case_id"], w["uid"]))
        for wr in writes:
            if wr["status"] != "read_verified":
                blockers.append("write_not_read_under_new:" + wr["id"])
        bindings = rows(db, "SELECT * FROM effect_bindings WHERE case_id=? AND uid=?",
                        (w["case_id"], w["uid"]))
        case_row = one(db, "SELECT * FROM effect_cases WHERE id=?", (w["case_id"],))
        for b in bindings:
            rep = _binding_report(db, case_row, b, "dual_read")
            # Per-instance measured rejection is mandatory to close dual read.
            if rep["dead_probe_seq"] is None or (rep["high_water_seq"] and rep["dead_probe_seq"] <= rep["high_water_seq"]):
                blockers.append("per_instance_old_rejection_missing:" + b["id"])
            for code in rep["blockers"]:
                if code.startswith("surface_uncleared") or code.startswith("partition"):
                    blockers.append(code)
        if blockers:
            return {"decision": "dual_read_not_safe_to_close", "blockers": sorted(set(blockers))}
        db.execute("UPDATE effect_windows SET status='closed',closed_at=? WHERE id=?",
                   (r.get("at"), w["id"]))
        if w["deadline_at"] is not None and r.get("at") is not None and r["at"] > w["deadline_at"]:
            _notice(db, "notice-deadline-" + w["id"], w["case_id"], "dual_read_deadline_exceeded",
                    r.get("at"), {"window": w["id"], "deadline_at": w["deadline_at"],
                                  "closed_at": r.get("at")})
            return {"decision": "dual_read_closed_after_deadline", "incident": "notice-deadline-" + w["id"]}
        return {"decision": "dual_read_closed"}

    # ---- confirmed business write / rewrite / containment ---------------
    if op in ("write", "business_write", "confirmed_write"):
        wid = r["id"]
        old = one(db, "SELECT * FROM effect_writes WHERE id=?", (wid,))
        if old:
            same = (old["case_id"], old["uid"], old["seq"], old["record_digest"]) == (
                r["case"], r["uid"], r["seq"], r.get("record") or r.get("record_digest"))
            return {"decision": "reused" if same else "write_identity_conflict"}
        b = _resolve_binding(db, r["case"], r)
        if r.get("container_gen") is not None or r.get("binding"):
            if not b:
                return {"decision": "write_binding_mismatch"}
        db.execute(
            "INSERT INTO effect_writes(id,case_id,window_id,binding_id,uid,seq,at,record_digest,status,disposition) "
            "VALUES(?,?,?,?,?,?,?,?, 'confirmed', NULL)",
            (wid, r["case"], r.get("window"), b["id"] if b else None, r["uid"],
             r["seq"], r.get("at"), r.get("record") or r.get("record_digest")),
        )
        if b and r["seq"] > (b["last_use_seq"] or 0):
            db.execute("UPDATE effect_bindings SET last_use_seq=? WHERE id=?", (r["seq"], b["id"]))
        case = one(db, "SELECT * FROM effect_cases WHERE id=?", (r["case"],))
        if case and r["seq"] > (case["last_use_seq"] or 0):
            db.execute("UPDATE effect_cases SET last_use_seq=?,last_use_at=? WHERE id=?",
                       (r["seq"], r.get("at"), r["case"]))
        return {"decision": "confirmed_write_recorded", "write": wid, "high_water_seq": r["seq"]}

    if op in ("rewrite", "rewrite_write"):
        rwid = r["id"]
        old = one(db, "SELECT * FROM effect_rewrites WHERE id=?", (rwid,))
        if old:
            same = (old["write_id"], old["new_gen"], old["new_digest"]) == (
                r["write"], r["new_gen"], r.get("new_digest"))
            return {"decision": "reused" if same else "rewrite_identity_conflict"}
        w = one(db, "SELECT * FROM effect_writes WHERE id=?", (r["write"],))
        if not w:
            return {"decision": "write_unknown"}
        db.execute(
            "INSERT INTO effect_rewrites(id,write_id,case_id,new_gen,new_digest,at,record_digest,status,read_probe_id) "
            "VALUES(?,?,?,?,?,?,?, 'rewritten', NULL)",
            (rwid, w["id"], w["case_id"], r["new_gen"], r.get("new_digest"), r.get("at"),
             r.get("record") or w["record_digest"]),
        )
        db.execute("UPDATE effect_writes SET status='rewritten' WHERE id=?", (w["id"],))
        return {"decision": "write_rewritten_under_new_value", "write": w["id"], "rewrite": rwid}

    if op in ("verify_read", "read_verify"):
        # Convenience: persist a new_verified probe and link it to the write.
        probe_req = {
            "op": "probe", "id": r["id"], "case": r["case"], "binding": r.get("binding"),
            "uid": r.get("uid"), "replica": r.get("replica"),
            "container_gen": r.get("container_gen"), "seq": r.get("seq"), "at": r.get("at"),
            "surface": r.get("surface", "api"), "outcome": "new_verified", "write": r["write"],
            "issuer": r.get("issuer"), "observer": r.get("observer"), "credential": r.get("credential"),
        }
        return run(db, probe_req)

    if op in ("contain_write", "quarantine_write"):
        w = one(db, "SELECT * FROM effect_writes WHERE id=?", (r["write"],))
        if not w:
            return {"decision": "write_unknown"}
        if w["status"] == "quarantined":
            return {"decision": "reused"}
        db.execute("UPDATE effect_writes SET status='quarantined',disposition=? WHERE id=?",
                   (r.get("receipt") or r.get("isolation_receipt") or "quarantined", w["id"]))
        return {"decision": "confirmed_write_quarantined_in_image", "write": w["id"]}

    # ---- incident correction (append-only) ------------------------------
    if op in ("correct", "correction"):
        cid = r["id"]
        old = one(db, "SELECT * FROM effect_corrections WHERE id=?", (cid,))
        if old:
            return {"decision": "reused" if (old["target_id"], old["field"]) ==
                    (r.get("target"), r.get("field")) else "correction_identity_conflict"}
        target_kind = r.get("target_kind", "conclusion")
        target_id = r.get("target")
        old_value = None
        new_value = r.get("new_value")
        if target_kind == "reachability":
            b = one(db, "SELECT * FROM effect_bindings WHERE id=?", (target_id,))
            if not b:
                return {"decision": "binding_unknown"}
            old_value = b["reachability"]
            new_reach = r.get("reachability") or (new_value if isinstance(new_value, str) else None)
            if new_reach not in ("reachable", "partitioned", "orphan"):
                return {"decision": "invalid_reachability"}
            db.execute("UPDATE effect_bindings SET reachability=? WHERE id=?",
                       (new_reach, b["id"]))
            new_value = new_reach
        elif target_kind in ("proof", "conclusion"):
            p = one(db, "SELECT * FROM effect_proofs WHERE id=?", (target_id,))
            if p and p["status"] in ("valid", "challenged"):
                db.execute("UPDATE effect_proofs SET status='corrected' WHERE id=?", (p["id"],))
                db.execute("UPDATE effect_cases SET status='corrected' WHERE id=?", (p["case_id"],))
            old_value = p["status"] if p else None
            new_value = "corrected"
        db.execute(
            "INSERT INTO effect_corrections(id,case_id,at,target_kind,target_id,field,old_value,"
            "new_value,reason) VALUES(?,?,?,?,?,?,?,?,?)",
            (cid, r["case"], r.get("at"), target_kind, target_id, r.get("field"),
             _json(old_value) if not isinstance(old_value, str) else old_value,
             _json(new_value) if not isinstance(new_value, str) else new_value, r.get("reason")),
        )
        _notice(db, "notice-correction-" + cid, r["case"], "incident_correction", r.get("at"),
                {"correction": cid, "target_kind": target_kind, "target": target_id,
                 "reason": r.get("reason")})
        return {"decision": "incident_correction_recorded", "correction": cid,
                "original_conclusion_retained": True}

    # ---- queries ---------------------------------------------------------
    if op in ("status", "evaluate", "case_status", "completion_status", "proof_status"):
        return evaluate(db, r["case"])
    if op == "notices":
        return {"decision": "notices", "notices": list_notices(db, r.get("case"))}
    if op == "proof":
        p = one(db, "SELECT * FROM effect_proofs WHERE id=?", (r["id"],))
        return {"decision": "proof_loaded", "proof": p} if p else {"decision": "proof_unknown"}

    # ---- issue the shared effective-revocation proof --------------------
    if op in ("complete", "prove", "issue_proof", "declare_complete", "effect_proof", "certify", "verify_revocation", "completion"):
        pid = r["id"]
        existing_proof = one(db, "SELECT * FROM effect_proofs WHERE id=?", (pid,))
        if existing_proof:
            same = (existing_proof["case_id"], existing_proof["mode"]) == (r["case"], r.get("mode") or existing_proof["mode"])
            return {"decision": "reused" if same else "proof_identity_conflict"}
        case = one(db, "SELECT * FROM effect_cases WHERE id=?", (r["case"],))
        if not case:
            return {"decision": "case_unknown"}
        mode = r.get("mode") or case["path"]
        if case["path"] and r.get("mode") and r["mode"] != case["path"]:
            return {"decision": "remediation_path_conflict", "existing": case["path"]}
        report = evaluate(db, r["case"], mode)
        if report["blockers"]:
            return {"decision": "revocation_not_effective",
                    "case": r["case"], "mode": mode, "blockers": report["blockers"],
                    "bindings": report["bindings"]}
        if case["status"] == "effective" and not r.get("supersedes"):
            return {"decision": "case_already_effective", "proof": case["proof_id"]}
        supersedes = r.get("supersedes")
        if supersedes:
            oldp = one(db, "SELECT * FROM effect_proofs WHERE id=?", (supersedes,))
            if not oldp or oldp["case_id"] != r["case"]:
                return {"decision": "superseded_proof_unknown"}
            db.execute("UPDATE effect_proofs SET status='superseded' WHERE id=?", (supersedes,))
        db.execute("UPDATE effect_cases SET path=?,status='effective' WHERE id=?",
                   (mode, r["case"]))

        bindings = rows(db, "SELECT * FROM effect_bindings WHERE case_id=? ORDER BY rowid", (r["case"],))
        scope_bindings = []
        for rep in report["bindings"]:
            scope_bindings.append({
                "id": rep["binding"], "uid": rep["uid"], "replica": rep["replica"],
                "container_gen": rep["container_gen"], "reachability": rep["reachability"],
                "high_water_seq": rep["high_water_seq"], "dead_probe_seq": rep["dead_probe_seq"],
                "decisive_at": rep["decisive_at"],
            })
        scope = {
            "case": r["case"], "grant": case["grant_id"], "secret": case["secret"],
            "gen": case["gen"], "mode": mode,
            "uids": sorted({b["uid"] for b in bindings}),
            "max_use_seq": case["last_use_seq"],
            "bindings": scope_bindings,
            "commands": report["commands"], "rotations": report["rotations"],
            "windows": report["windows"],
            "downtime": {"stopped_at": case["stopped_at"], "resumed_at": case["resumed_at"]},
        }
        evidence_ids = {
            "commands": report["commands"],
            "probes": [p["id"] for p in rows(db, "SELECT id FROM effect_probes WHERE case_id=? ORDER BY id", (r["case"],))],
            "exits": [e["id"] for e in rows(db, "SELECT e.id FROM effect_exits e JOIN effect_bindings b ON b.id=e.binding_id WHERE b.case_id=? ORDER BY e.id", (r["case"],))],
            "isolations": [i["id"] for i in rows(db, "SELECT i.id FROM effect_isolations i JOIN effect_bindings b ON b.id=i.binding_id WHERE b.case_id=? ORDER BY i.id", (r["case"],))],
            "rotations": report["rotations"],
            "writes": [w["id"] for w in rows(db, "SELECT id FROM effect_writes WHERE case_id=? ORDER BY id", (r["case"],))],
            "rewrites": [w["id"] for w in rows(db, "SELECT id FROM effect_rewrites WHERE case_id=? ORDER BY id", (r["case"],))],
        }
        digest = _canonical_hash(evidence_ids)
        db.execute(
            "INSERT INTO effect_proofs(id,case_id,secret,gen,mode,at,scope,evidence_digest,status,supersedes) "
            "VALUES(?,?,?,?,?,?,?,?,'valid',?)",
            (pid, r["case"], case["secret"], case["gen"], mode, r.get("at"),
             _json(scope), digest, supersedes),
        )
        db.execute("UPDATE effect_cases SET proof_id=? WHERE id=?", (pid, r["case"]))
        _notice(db, "notice-proof-" + pid, r["case"], "effective_revocation_proof_issued",
                r.get("at"), {"proof": pid, "mode": mode, "scope": scope}, proof_id=pid)
        return {"decision": "revocation_effect_complete", "proof": pid, "mode": mode,
                "scope": scope, "evidence_digest": digest}

    raise ValueError(op)


# Descriptive functional aliases for the shared proof authority.
evaluate_revocation = evaluate
revocation_report = evaluate
get_valid_proof = valid_proof
verify_proof = classify_proof
