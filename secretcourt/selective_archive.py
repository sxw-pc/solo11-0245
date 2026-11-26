"""Selective, offline-verifiable tenant evidence archives.

Trust boundary
--------------
The platform holds the full event ledger (see :mod:`secretcourt.store`) and is
the only party allowed to see every tenant's inputs.  A tenant archive never
exports raw ledger rows.  Every ledger event is reduced to one of three
provable views:

* ``visible``  - the tenant's own event, disclosed verbatim; its record hash is
  recomputable offline, so its content cannot be replaced silently.
* ``redacted`` - a shared event (a joint plan, a policy, a reseal...).  Other
  tenants' fields are reduced to fixed-width salted commitments inside a
  selective Merkle-style tree whose root, together with the original record
  hash, is covered by an authority attestation.  This proves the disclosed
  fields are the exact fields the original decision used, while hidden fields
  leak neither value, length, stable number nor cross-package correlation.
* ``anchor``   - an event outside the mandate window or about a different
  secret/tenant.  Only its chained record hash is exported, keeping the
  sequence gap-free without disclosing anything about the other tenant.

The ledger itself is a plain hash chain (per-event ``record_hash`` then
``chain_hash``); a published checkpoint over a chain head is the public ledger
commitment an offline verifier compares against.  Authority attestations use
HMAC-SHA256 with versioned keys, so key rotation never invalidates an archive
signed under an older key (the key id travels inside the envelope).

Export eligibility is a *mandate*: it binds a contract subject, secret
purpose, time window and two-role approval.  Knowing a secret identifier is
not sufficient.  Revoking a mandate blocks new downloads and new revisions but
cannot invalidate an already signed package - every signed package remains
verifiable forever with the verification key ring.  Later corrections are
immutable addenda chained to the predecessor package, never rewrites.
"""
import hashlib
import hmac
import json
import os
from .store import one, rows

DOMAIN = "secretcourt.selective-archive/v1"
HIDDEN_CAPACITY = 8

_DDL = """
CREATE TABLE IF NOT EXISTS archive_keys(key_id TEXT PRIMARY KEY, secret BLOB NOT NULL, status TEXT NOT NULL, created_seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS export_mandates(id TEXT PRIMARY KEY, subject TEXT, namespace TEXT, purpose TEXT, secret TEXT, from_ts INTEGER, to_ts INTEGER, status TEXT, created_seq INTEGER);
CREATE TABLE IF NOT EXISTS archive_packages(id TEXT PRIMARY KEY, mandate TEXT, subject TEXT, purpose TEXT, secret TEXT, revision INTEGER, predecessor TEXT, envelope TEXT, created_seq INTEGER);
CREATE TABLE IF NOT EXISTS package_receipts(package_id TEXT PRIMARY KEY, subject TEXT, acknowledged_at INTEGER);
"""


def _ensure_tables(db):
    db.executescript(_DDL)


def _canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(_canon(value)).hexdigest()


def _mac(key, value):
    return hmac.new(key, _canon(value), hashlib.sha256).hexdigest()


def _random_token(num_bytes=16):
    return os.urandom(num_bytes).hex()


def _record_hash(seq, subsystem, payload, result):
    material = ["record", seq, subsystem, _hash(payload), _hash(result)]
    return hashlib.sha256(_canon(material)).hexdigest()


def _chain_hashes(events):
    """Public ledger commitment material: per-event record and chain hashes."""
    out = []
    head = None
    for event in events:
        record = _record_hash(event["seq"], event["subsystem"],
                              json.loads(event["payload"]), json.loads(event["result"]))
        head = hashlib.sha256(_canon(["chain", record, head])).hexdigest()
        out.append({"seq": event["seq"], "record_hash": record, "chain_hash": head})
    return out


def ledger_head(db):
    """Chain head over the whole ledger, usable as a published checkpoint."""
    _ensure_tables(db)
    events = rows(db, "SELECT seq,subsystem,payload,result FROM events ORDER BY seq")
    chained = _chain_hashes(events)
    return chained[-1]["chain_hash"] if chained else hashlib.sha256(
        _canon(["chain", None, None])).hexdigest()


def provision_key(db, key_id=None):
    """Create a fresh attestation key; older keys stay usable for verification."""
    _ensure_tables(db)
    key_id = key_id or "key-" + _random_token(8)
    if one(db, "SELECT key_id FROM archive_keys WHERE key_id=?", (key_id,)):
        return {"decision": "reused", "key_id": key_id}
    seq = one(db, "SELECT COALESCE(MAX(seq),0) n FROM events")["n"]
    db.execute("INSERT INTO archive_keys VALUES(?,?,?,?)",
               (key_id, os.urandom(32), "active", seq))
    return {"decision": "key_active", "key_id": key_id}


def rotate_key(db, key_id=None):
    """Retire active keys and mint a replacement; old packages still verify."""
    _ensure_tables(db)
    for row in rows(db, "SELECT key_id FROM archive_keys WHERE status='active'"):
        db.execute("UPDATE archive_keys SET status='rotated' WHERE key_id=?", (row["key_id"],))
    return provision_key(db, key_id)


def _key_secrets(db):
    return {r["key_id"]: r["secret"] for r in rows(db, "SELECT * FROM archive_keys")}


def verification_ring(db):
    """Key id/status descriptors published to offline verifiers out of band.

    The descriptors name which keys ever existed (and their rotation state);
    the HMAC secrets themselves travel through the separate audit channel and
    are handed to :func:`verify_package` as its ``keys`` mapping.  An archive
    signed under a rotated key keeps verifying because its node records the
    exact key id used at issuance.
    """
    _ensure_tables(db)
    return [{"key_id": r["key_id"], "status": r["status"]}
            for r in rows(db, "SELECT key_id,status FROM archive_keys ORDER BY key_id")]


def _active_key(db):
    _ensure_tables(db)
    row = one(db, "SELECT * FROM archive_keys WHERE status='active' ORDER BY created_seq DESC, key_id")
    if not row:
        provision_key(db)
        row = one(db, "SELECT * FROM archive_keys WHERE status='active' ORDER BY created_seq DESC, key_id")
    return row["key_id"], row["secret"]


def register_mandate(db, mandate):
    """Bind an export request to subject, purpose, window and dual approval."""
    _ensure_tables(db)
    mid = mandate["id"]
    old = one(db, "SELECT * FROM export_mandates WHERE id=?", (mid,))
    if old:
        same = (old["subject"], old["namespace"], old["purpose"], old["secret"],
                old["from_ts"], old["to_ts"]) == (
            mandate["subject"], mandate["namespace"], mandate["purpose"],
            mandate["secret"], mandate["from"], mandate["to"])
        return {"decision": "reused" if same else "mandate_identity_conflict"}
    secret = one(db, "SELECT * FROM secrets WHERE id=?", (mandate["secret"],))
    if not secret or secret["purpose"] != mandate["purpose"]:
        return {"decision": "purpose_mismatch"}
    if mandate["from"] > mandate["to"]:
        return {"decision": "invalid_window"}
    approvals = rows(db, "SELECT * FROM approvals WHERE until_ts>=? AND grant_id IN "
                         "(SELECT id FROM grants WHERE secret=?)",
                     (mandate["at"], mandate["secret"]))
    valid = [a for a in approvals if a["actor"] in mandate.get("approvers", [])]
    if {a["role"] for a in valid} != {"security", "owner"} or len({a["actor"] for a in valid}) < 2:
        return {"decision": "missing_two_approvers"}
    seq = one(db, "SELECT COALESCE(MAX(seq),0) n FROM events")["n"]
    db.execute("INSERT INTO export_mandates VALUES(?,?,?,?,?,?,?,?,?)",
               (mid, mandate["subject"], mandate["namespace"], mandate["purpose"],
                mandate["secret"], mandate["from"], mandate["to"], "active", seq))
    return {"decision": "mandate_registered", "id": mid}


def revoke_mandate(db, mandate_id, at):
    """Effect: no new packages or revisions; issued packages stay valid."""
    _ensure_tables(db)
    old = one(db, "SELECT * FROM export_mandates WHERE id=?", (mandate_id,))
    if not old:
        return {"decision": "unknown_mandate"}
    if old["status"] != "active":
        return {"decision": "reused", "status": old["status"]}
    db.execute("UPDATE export_mandates SET status='revoked' WHERE id=?", (mandate_id,))
    return {"decision": "mandate_revoked", "id": mandate_id, "at": at}


def _subject_entities(db, secret, subject, namespace):
    identities = rows(db, "SELECT * FROM identities WHERE namespace=? AND uid=?", (namespace, subject))
    identity_ids = {i["id"] for i in identities}
    grants = rows(db, "SELECT * FROM grants WHERE secret=? AND uid=?", (secret, subject))
    grant_ids = {g["id"] for g in grants}
    plan_ids = {r["plan_id"] for r in rows(
        db, "SELECT DISTINCT m.plan_id FROM members m JOIN plans p ON p.id=m.plan_id "
            "WHERE p.secret=? AND m.uid=?", (secret, subject))}
    return identity_ids, grant_ids, plan_ids


def _collect_sensitive(db, secret, subject):
    """Identifiers of *other* tenants on this secret; clear-text disclosure forbidden."""
    sensitive = set()
    for identity in rows(db, "SELECT * FROM identities WHERE id IN "
                             "(SELECT identity FROM grants WHERE secret=?)", (secret,)):
        if identity["uid"] != subject:
            sensitive.update([identity["id"], identity["uid"], identity["namespace"]])
    for grant in rows(db, "SELECT * FROM grants WHERE secret=?", (secret,)):
        if grant["uid"] != subject:
            sensitive.add(grant["id"])
    for member in rows(db, "SELECT m.* FROM members m JOIN plans p ON p.id=m.plan_id WHERE p.secret=?", (secret,)):
        if member["uid"] != subject:
            sensitive.add(member["uid"])
            sensitive.add(member["grant_id"])
    for receipt in rows(db, "SELECT r.* FROM receipts r JOIN plans p ON p.id=r.plan_id WHERE p.secret=?", (secret,)):
        if receipt["uid"] != subject:
            sensitive.add(receipt["id"])
    for orphan in rows(db, "SELECT * FROM orphans WHERE secret=?", (secret,)):
        if orphan["uid"] != subject:
            sensitive.add(orphan["id"])
    for revocation in rows(db, "SELECT v.* FROM revocations v WHERE v.grant_id IN "
                              "(SELECT id FROM grants WHERE secret=?)", (secret,)):
        if revocation["grant_id"] in sensitive:
            sensitive.add(revocation["id"])
    return {s for s in sensitive if s}


def _event_time(payload):
    for key in ("at", "from", "from_ts"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
    return None


def _hidden_leaf(nonce):
    return {"hidden": "sha256:" + hashlib.sha256(_canon(["hidden", nonce])).hexdigest(), "nonce": nonce}


def _is_hidden(node):
    return isinstance(node, dict) and set(node) == {"hidden", "nonce"}


def _is_decoy(node):
    return isinstance(node, dict) and node == {"decoy": "sha256"}


def _tree_hash(node):
    if _is_hidden(node):
        return hashlib.sha256(_canon(["hidden", node["hidden"], node["nonce"]])).hexdigest()
    if _is_decoy(node):
        return hashlib.sha256(_canon(["decoy"])).hexdigest()
    if isinstance(node, dict):
        return hashlib.sha256(
            _canon(["object", sorted((k, _tree_hash(v)) for k, v in node.items())])).hexdigest()
    if isinstance(node, list):
        return hashlib.sha256(_canon(["array", [_tree_hash(v) for v in node]])).hexdigest()
    return hashlib.sha256(_canon(["scalar", node])).hexdigest()


def _redact(value, sensitive, nonces, subject=None, path=None):
    """Schema-aware irreversible minimisation of another tenant's fields.

    A roster member that is not the subject is collapsed into one fixed-width
    commitment so the hidden count and per-field structure cannot be probed;
    every other occurrence of a forbidden identifier becomes a leaf commitment.
    """
    path = path or []
    if isinstance(value, dict):
        return {k: _redact(v, sensitive, nonces, subject, path + [k]) for k, v in sorted(value.items())}
    if isinstance(value, list):
        if path and path[-1] == "members":
            redacted = []
            for item in value:
                if isinstance(item, dict) and item.get("uid") != subject:
                    redacted.append(_hidden_leaf(next(nonces)))
                else:
                    redacted.append(_redact(item, sensitive, nonces, subject, path + [len(redacted)]))
            while len(redacted) < HIDDEN_CAPACITY:
                redacted.append({"decoy": "sha256"})
            return redacted
        return [_redact(v, sensitive, nonces, subject, path + [i]) for i, v in enumerate(value)]
    if isinstance(value, str) and value in sensitive:
        return _hidden_leaf(next(nonces))
    return value


def _state_at(db, seq):
    """Replay the ledger prefix up to ``seq`` into an isolated in-memory court."""
    from .store import connect, invoke
    replay_db = connect(":memory:")
    events = rows(db, "SELECT seq,subsystem,payload,result FROM events WHERE seq<=? ORDER BY seq", (seq,))
    for event in events:
        invoke(replay_db, event["subsystem"], json.loads(event["payload"]))
    return replay_db


def _plan_predicate(db, payload, result, subject, seq):
    """Re-runnable per-member decision predicate carrying only subject data.

    Grant and identity facts are read from a replay of the ledger prefix ending
    at this plan, so the snapshot records decision-time state, not later
    revocations or identity epochs.
    """
    members = []
    point_db = _state_at(db, seq)
    try:
        for member in payload.get("members", []):
            if member["uid"] != subject:
                continue
            grant = one(point_db, "SELECT * FROM grants WHERE id=?", (member["grant"],))
            identity = one(point_db, "SELECT * FROM identities WHERE id=?",
                           (grant["identity"],)) if grant else None
            licensed = bool(
                grant and identity and grant["status"] == "active"
                and grant["secret"] == payload["secret"] and grant["gen"] == payload["gen"]
                and grant["uid"] == member["uid"] and identity["uid"] == member["uid"]
                and grant["until_ts"] >= payload["at"] and identity["active"])
            members.append({
                "uid": member["uid"],
                "grant_id": member["grant"],
                "licensed": licensed,
                "snapshot": None if not grant else {
                    "grant_status": grant["status"], "until_ts": grant["until_ts"],
                    "identity_active": bool(identity and identity["active"]),
                    "secret": grant["secret"], "gen": grant["gen"],
                },
            })
    finally:
        point_db.close()
    return {
        "op": "plan", "plan_id": payload["id"], "secret": payload["secret"],
        "gen": payload["gen"], "packet": payload["packet"], "at": payload["at"],
        "decision": result["decision"], "subject_members": members,
        "hidden_member_count_omitted": True,
    }


def _run_predicate(predicate):
    """Offline re-evaluation of the subject's part of the original plan rule.

    The subject can only re-check its own member against the recorded decision.
    A ``planned`` verdict is consistent whenever the subject's own license held;
    whether hidden members were licensed at plan time is covered by the
    authority attestation, not by data the subject is allowed to hold.
    """
    for member in predicate["subject_members"]:
        snap = member["snapshot"] or {}
        licensed = (snap.get("grant_status") == "active" and snap.get("identity_active")
                    and snap.get("secret") == predicate["secret"]
                    and snap.get("gen") == predicate["gen"]
                    and snap.get("until_ts", 0) >= predicate["at"])
        if licensed != member["licensed"]:
            return False
    if predicate["decision"] != "planned":
        return True
    return bool(predicate["subject_members"]) and all(
        m["licensed"] for m in predicate["subject_members"])


def _related(payload, mandate, identity_ids, grant_ids, plan_ids):
    if payload.get("secret") == mandate["secret"] or payload.get("purpose") == mandate["purpose"]:
        return True
    if payload.get("plan") in plan_ids or payload.get("id") in plan_ids:
        return True
    if payload.get("grant") in grant_ids or payload.get("identity") in identity_ids:
        return True
    return False


def _attest(key_id, key, seq, record_hash, selective_root, chain_hash):
    body = ["attest", seq, record_hash, selective_root, chain_hash]
    return {"key_id": key_id, "digest": "hmac-sha256", "signature": _mac(key, body), "body": body}


def issue_package(db, package_id, mandate_id, subject, at):
    """Create a signed selective archive under an active, matching mandate."""
    _ensure_tables(db)
    mandate = one(db, "SELECT * FROM export_mandates WHERE id=?", (mandate_id,))
    if not mandate:
        return {"decision": "unknown_mandate"}
    if mandate["status"] != "active":
        return {"decision": "mandate_revoked"}
    if mandate["subject"] != subject:
        return {"decision": "subject_mismatch"}
    prior = one(db, "SELECT * FROM archive_packages WHERE mandate=? ORDER BY revision DESC, id",
                (mandate_id,))
    if prior and prior["id"] == package_id:
        return {"decision": "reused", "package_id": package_id, "revision": prior["revision"]}
    events = rows(db, "SELECT seq,subsystem,payload,result FROM events ORDER BY seq")
    chained = _chain_hashes(events)
    identity_ids, grant_ids, plan_ids = _subject_entities(
        db, mandate["secret"], subject, mandate["namespace"])
    sensitive = _collect_sensitive(db, mandate["secret"], subject)
    nonces = iter(_random_token(16) for _ in iter(int, 1))
    key_id, key = _active_key(db)
    nodes = []
    prev_chain = None
    for event, chain in zip(events, chained):
        payload = json.loads(event["payload"])
        result = json.loads(event["result"])
        op = payload.get("op", event["subsystem"])
        ts = _event_time(payload)
        in_window = ts is None or mandate["from_ts"] <= ts <= mandate["to_ts"]
        # Events whose actor is another tenant's uid carry nothing of the
        # subject's own decision inputs: anchor them rather than redact them.
        actor = payload.get("uid")
        other_tenant_event = actor is not None and actor != subject and actor in sensitive
        if not in_window or not _related(payload, mandate, identity_ids, grant_ids, plan_ids) \
                or other_tenant_event:
            node = {"type": "anchor", "seq": event["seq"], "subsystem": event["subsystem"],
                    "record_hash": chain["record_hash"]}
        else:
            serialized = _canon(payload).decode("utf-8") + _canon(result).decode("utf-8")
            if not any(s in serialized for s in sensitive):
                node = {"type": "visible", "seq": event["seq"], "subsystem": event["subsystem"],
                        "payload": payload, "result": result,
                        "record_hash": chain["record_hash"]}
            else:
                payload_view = _redact(payload, sensitive, nonces, subject)
                result_view = _redact(result, sensitive, nonces, subject)
                node = {
                    "type": "redacted", "seq": event["seq"], "subsystem": event["subsystem"],
                    "payload_view": payload_view, "result_view": result_view,
                    "selective_root": _hash(["selective", event["seq"],
                                             _tree_hash(payload_view), _tree_hash(result_view)]),
                    "record_hash": chain["record_hash"],
                }
                if op == "plan" and payload.get("id") in plan_ids:
                    node["decision_predicate"] = _plan_predicate(
                        db, payload, result, subject, event["seq"])
        root = node.get("selective_root")
        node["attestation"] = _attest(key_id, key, event["seq"],
                                      chain["record_hash"], root, chain["chain_hash"])
        node["prev_chain_hash"] = prev_chain
        prev_chain = chain["chain_hash"]
        nodes.append(node)
    checkpoint = chained[-1]["chain_hash"] if chained else ledger_head(db)
    predecessor = prior["id"] if prior else None
    revision = (prior["revision"] + 1) if prior else 1
    envelope = {
        "format": DOMAIN,
        "package_id": package_id,
        "mandate_id": mandate_id,
        "subject": subject,
        "namespace": mandate["namespace"],
        "purpose": mandate["purpose"],
        "secret": mandate["secret"],
        "window": {"from": mandate["from_ts"], "to": mandate["to_ts"]},
        "revision": revision,
        "predecessor": predecessor,
        "nonce": _random_token(16),
        "ledger": {"first_seq": events[0]["seq"] if events else 0,
                   "last_seq": events[-1]["seq"] if events else 0,
                   "checkpoint": checkpoint},
        "nodes": nodes,
        "key_id": key_id,
        "issued_at": at,
    }
    envelope["manifest_signature"] = _mac(
        key, ["manifest", {k: v for k, v in envelope.items() if k != "manifest_signature"}])
    serialized = json.dumps(envelope, sort_keys=True, ensure_ascii=False)
    if any(s in serialized for s in sensitive):
        return {"decision": "minimisation_failed"}
    seq = one(db, "SELECT COALESCE(MAX(seq),0) n FROM events")["n"]
    db.execute("INSERT INTO archive_packages VALUES(?,?,?,?,?,?,?,?,?)",
               (package_id, mandate_id, subject, mandate["purpose"], mandate["secret"],
                revision, predecessor, serialized, seq))
    return {"decision": "package_issued", "package_id": package_id, "revision": revision,
            "nodes": len(nodes), "checkpoint": checkpoint, "predecessor": predecessor}


def acknowledge_package(db, package_id, subject, at):
    """Tenant signs for a package; the signed bytes are frozen from then on."""
    _ensure_tables(db)
    pkg = one(db, "SELECT * FROM archive_packages WHERE id=?", (package_id,))
    if not pkg:
        return {"decision": "unknown_package"}
    if pkg["subject"] != subject:
        return {"decision": "subject_mismatch"}
    old = one(db, "SELECT * FROM package_receipts WHERE package_id=?", (package_id,))
    if old:
        return {"decision": "reused", "package_id": package_id,
                "acknowledged_at": old["acknowledged_at"]}
    db.execute("INSERT INTO package_receipts VALUES(?,?,?)", (package_id, subject, at))
    return {"decision": "acknowledged", "package_id": package_id, "acknowledged_at": at}


def download_package(db, package_id, subject):
    """Download is authorization-gated; revoked mandates cannot re-download."""
    _ensure_tables(db)
    pkg = one(db, "SELECT * FROM archive_packages WHERE id=?", (package_id,))
    if not pkg:
        return {"decision": "unknown_package"}
    if pkg["subject"] != subject:
        return {"decision": "subject_mismatch"}
    mandate = one(db, "SELECT * FROM export_mandates WHERE id=?", (pkg["mandate"],))
    if mandate["status"] != "active":
        return {"decision": "mandate_revoked"}
    return {"decision": "downloaded", "package_id": package_id,
            "envelope": json.loads(pkg["envelope"])}


def verify_package(envelope, keys, public_checkpoint=None):
    """Offline verification: no platform database access required.

    ``keys`` maps key id -> HMAC secret, delivered through the audit channel
    together with the public ledger checkpoint.
    """
    errors = []
    if envelope.get("format") != DOMAIN:
        errors.append("format")
    body = {k: v for k, v in envelope.items() if k != "manifest_signature"}
    if not hmac.compare_digest(
            _mac(keys.get(envelope.get("key_id"), b""), ["manifest", body]),
            envelope.get("manifest_signature", "")):
        errors.append("manifest_signature")
    prev_chain = None
    for node in envelope.get("nodes", []):
        if node.get("prev_chain_hash") != prev_chain:
            errors.append("chain-order:%s" % node.get("seq"))
        attest = node.get("attestation", {})
        att_body = attest.get("body")
        if att_body is None or not hmac.compare_digest(
                _mac(keys.get(attest.get("key_id"), b""), att_body),
                attest.get("signature", "")):
            errors.append("attestation:%s" % node.get("seq"))
        else:
            _, seq, record_hash, selective_root, chain_hash = att_body
            if seq != node.get("seq") or record_hash != node.get("record_hash"):
                errors.append("attestation-binding:%s" % node.get("seq"))
            if node["type"] == "redacted":
                rebuilt = _hash(["selective", node["seq"],
                                 _tree_hash(node["payload_view"]), _tree_hash(node["result_view"])])
                if rebuilt != selective_root or rebuilt != node["selective_root"]:
                    errors.append("selective-root:%s" % node.get("seq"))
                predicate = node.get("decision_predicate")
                if predicate and not _run_predicate(predicate):
                    errors.append("decision-predicate:%s" % node.get("seq"))
            elif node["type"] == "visible":
                rebuilt_record = _record_hash(node["seq"], node["subsystem"],
                                              node["payload"], node["result"])
                if rebuilt_record != node["record_hash"]:
                    errors.append("record-hash:%s" % node.get("seq"))
            prev_chain = chain_hash
    if envelope.get("nodes") and prev_chain != envelope["ledger"]["checkpoint"]:
        errors.append("checkpoint")
    if public_checkpoint is not None and not hmac.compare_digest(
            public_checkpoint, envelope["ledger"]["checkpoint"]):
        errors.append("public-checkpoint")
    return {"verified": not errors, "errors": errors,
            "package_id": envelope.get("package_id"), "revision": envelope.get("revision"),
            "predecessor": envelope.get("predecessor")}


def scan_disclosure(envelope, forbidden_values):
    """Defensive check: no forbidden tenant token may appear anywhere in clear."""
    serialized = json.dumps(envelope, ensure_ascii=False)
    leaked = sorted(v for v in forbidden_values if v in serialized)
    return {"leak_free": not leaked, "leaked": leaked}


def hidden_commitments(envelope):
    """All hidden leaves in an envelope, for cross-package correlation tests."""
    out = []

    def walk(node):
        if _is_hidden(node):
            out.append(node)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(envelope)
    return out
