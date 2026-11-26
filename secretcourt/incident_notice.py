"""Customer incident notification as a delivery process independent of key revocation.

A grant row proves that a workload was licensed to read a field; it does not prove
that the field was read, and the licensee is not necessarily the contractual notice
recipient.  This module keeps the breach notification chain separate from the
material/grant/delivery lifecycle:

* recipients are resolved from contracts and contact authorisations valid at the
  time of the incident, never from grant counts;
* every notice binds an immutable recipient snapshot, so a same-day contact change
  can never redirect an already issued notice to an unauthorised person;
* sending an interface call is not delivery: a channel receipt (delivered /
  acknowledged / bounced / unattended) is required, and failures must be
  escalated by a registered security authority;
* corrections are append-only: the original notice, recipients and delivery facts
  are preserved when later evidence changes the incident scope;
* notification clocks are separate from freeze/reseal clocks.  Activating a new
  key generation never cancels a pending notice.
"""
import json

from .store import one, rows

TERMINAL_RECEIPTS = ("delivered", "acknowledged")
FAILED_RECEIPTS = ("bounced", "unattended")

# One statement per table so the catalog check below can stay order-independent.
_TABLES = {
    "notice_contracts":
        "CREATE TABLE IF NOT EXISTS notice_contracts(case_id TEXT, tenant TEXT, "
        "initial_hours INTEGER, detailed_hours INTEGER, PRIMARY KEY(case_id, tenant))",
    "notice_authorities":
        "CREATE TABLE IF NOT EXISTS notice_authorities(case_id TEXT, tenant TEXT, "
        "actor TEXT, role TEXT, PRIMARY KEY(case_id, tenant, actor))",
    "notice_contacts":
        "CREATE TABLE IF NOT EXISTS notice_contacts(id TEXT PRIMARY KEY, case_id TEXT, "
        "tenant TEXT, channel TEXT, address TEXT, valid_from INTEGER, valid_to INTEGER, status TEXT)",
    "notice_workloads":
        "CREATE TABLE IF NOT EXISTS notice_workloads(case_id TEXT, tenant TEXT, "
        "identity TEXT, uid TEXT, PRIMARY KEY(case_id, uid))",
    "notice_cases":
        "CREATE TABLE IF NOT EXISTS notice_cases(id TEXT PRIMARY KEY, secret TEXT, "
        "gen INTEGER, window_from INTEGER, window_to INTEGER, discovery_ts INTEGER, "
        "discovery_basis TEXT, conservative_discovery INTEGER)",
    "notice_evidence":
        "CREATE TABLE IF NOT EXISTS notice_evidence(id TEXT PRIMARY KEY, case_id TEXT, "
        "kind TEXT, uid TEXT, tenant TEXT, fields TEXT, at_ts INTEGER, basis TEXT, "
        "attribution_id TEXT, status TEXT)",
    "notice_roster":
        "CREATE TABLE IF NOT EXISTS notice_roster(case_id TEXT, tenant TEXT, "
        "classification TEXT, reason TEXT, confidence TEXT, initial_due INTEGER, "
        "detailed_due INTEGER, PRIMARY KEY(case_id, tenant))",
    "notices":
        "CREATE TABLE IF NOT EXISTS notices(id TEXT PRIMARY KEY, case_id TEXT, tenant TEXT, "
        "seq INTEGER, kind TEXT, supersedes TEXT, purpose TEXT, confirmed_fields TEXT, "
        "possible_fields TEXT, confidence TEXT, assertion TEXT, recipients TEXT, "
        "contact_ids TEXT, basis TEXT, issued_at INTEGER, status TEXT)",
    "notice_dispatches":
        "CREATE TABLE IF NOT EXISTS notice_dispatches(id TEXT PRIMARY KEY, notice_id TEXT, "
        "attempt_no INTEGER, channel TEXT, recipient_contact TEXT, address TEXT, "
        "dispatched_at INTEGER, status TEXT)",
    "notice_receipts":
        "CREATE TABLE IF NOT EXISTS notice_receipts(id TEXT PRIMARY KEY, dispatch_id TEXT, "
        "kind TEXT, at_ts INTEGER, reference TEXT, detail TEXT)",
    "notice_escalations":
        "CREATE TABLE IF NOT EXISTS notice_escalations(id TEXT PRIMARY KEY, notice_id TEXT, "
        "tenant TEXT, reason TEXT, authority_actor TEXT, contact_id TEXT, "
        "escalated_at INTEGER, outcome TEXT)",
    "notice_outcomes":
        "CREATE TABLE IF NOT EXISTS notice_outcomes(case_id TEXT, tenant TEXT, "
        "initial_notice_id TEXT, latest_notice_id TEXT, final_status TEXT, initial_due INTEGER, "
        "initial_delivered_at INTEGER, initial_on_time INTEGER, detailed_due INTEGER, "
        "detailed_delivered_at INTEGER, detailed_on_time INTEGER, conservative_initial_due INTEGER, "
        "late_responsibility TEXT, PRIMARY KEY(case_id, tenant))",
}


def ensure_schema(db):
    # Lazily create tables in autocommit (invoked before the tx() block).  Checking
    # the catalog keeps this idempotent without storing state on the connection,
    # which sqlite3.Connection does not accept.
    existing = {row["name"] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    for name, statement in _TABLES.items():
        if name not in existing:
            db.execute(statement)


def _jload(value, default):
    return json.loads(value) if value else default


def _case(db, case_id):
    return one(db, "SELECT * FROM notice_cases WHERE id=?", (case_id,))


def _tenant_for_uid(db, case_id, uid):
    row = one(db, "SELECT tenant FROM notice_workloads WHERE case_id=? AND uid=?",
              (case_id, uid))
    return row["tenant"] if row else None


def _active_contact(db, contact_id, case_id, tenant, at):
    return one(
        db,
        "SELECT * FROM notice_contacts WHERE id=? AND case_id=? AND tenant=? "
        "AND status='active' AND valid_from<=? AND (valid_to IS NULL OR valid_to>?)",
        (contact_id, case_id, tenant, at, at))


def _deadlines(db, case_id, tenant, discovery_ts):
    contract = one(
        db,
        "SELECT * FROM notice_contracts WHERE case_id=? AND tenant=?",
        (case_id, tenant))
    if not contract or discovery_ts is None:
        return None, None
    return (discovery_ts + contract["initial_hours"] * 60,
            discovery_ts + contract["detailed_hours"] * 60)


def run(db, r):
    ensure_schema(db)
    op = r["op"]
    if op == "contract":
        return _contract(db, r)
    if op == "authority":
        return _authority(db, r)
    if op == "contact":
        return _contact(db, r)
    if op == "workload":
        return _workload(db, r)
    if op == "open_case":
        return _open_case(db, r)
    if op == "evidence":
        return _evidence(db, r)
    if op == "discover":
        return _discover(db, r)
    if op == "build_roster":
        return _build_roster(db, r)
    if op == "issue_notice":
        return _issue_notice(db, r)
    if op == "dispatch":
        return _dispatch(db, r)
    if op == "receipt":
        return _receipt(db, r)
    if op == "escalate":
        return _escalate(db, r)
    if op == "finalize":
        return _finalize(db, r)
    raise ValueError(op)


def _contract(db, r):
    if r["initial_hours"] <= 0 or r["detailed_hours"] < r["initial_hours"]:
        return {"decision": "invalid_contract_terms"}
    old = one(db, "SELECT * FROM notice_contracts WHERE case_id=? AND tenant=?",
              (r["case"], r["tenant"]))
    if old:
        same = (old["initial_hours"], old["detailed_hours"]) == (
            r["initial_hours"], r["detailed_hours"])
        return {"decision": "reused"} if same else {"decision": "contract_identity_conflict"}
    db.execute("INSERT INTO notice_contracts VALUES(?,?,?,?)",
               (r["case"], r["tenant"], r["initial_hours"], r["detailed_hours"]))
    return {"decision": "registered"}


def _authority(db, r):
    if r["role"] != "security":
        return {"decision": "invalid_authority_role"}
    old = one(
        db,
        "SELECT 1 FROM notice_authorities WHERE case_id=? AND tenant=? AND actor=?",
        (r["case"], r["tenant"], r["actor"]))
    if old:
        return {"decision": "reused"}
    db.execute("INSERT INTO notice_authorities VALUES(?,?,?,?)",
               (r["case"], r["tenant"], r["actor"], r["role"]))
    return {"decision": "registered", "actor": r["actor"]}


def _contact(db, r):
    """Register a contact, or replace one while preserving the old authorisation."""
    old = one(db, "SELECT * FROM notice_contacts WHERE id=?", (r["id"],))
    if old:
        expected_status = "superseded" if r["change"] else "active"
        same = (old["case_id"], old["tenant"], old["channel"], old["address"],
                old["valid_from"], old["valid_to"], old["status"]) == (
            r["case"], r["tenant"], r["channel"], r["address"],
            r["from"], r.get("to"), expected_status)
        return {"decision": "reused"} if same else {"decision": "contact_identity_conflict"}
    if r["change"]:
        # A replacement closes the prior authorisation; the old row is retained as
        # evidence of who was authorised when the incident happened.
        updated = db.execute(
            "UPDATE notice_contacts SET status='superseded', valid_to=? "
            "WHERE case_id=? AND tenant=? AND status='active'",
            (r["from"], r["case"], r["tenant"])).rowcount
        if not updated:
            return {"decision": "no_active_contact_to_replace"}
    db.execute(
        "INSERT INTO notice_contacts VALUES(?,?,?,?,?,?,?,?)",
        (r["id"], r["case"], r["tenant"], r["channel"], r["address"], r["from"],
         r.get("to"), "active"))
    return {"decision": "contact_changed" if r["change"] else "registered"}


def _workload(db, r):
    old = one(db, "SELECT * FROM notice_workloads WHERE case_id=? AND uid=?",
              (r["case"], r["uid"]))
    if old:
        same = (old["tenant"], old["identity"]) == (r["tenant"], r["identity"])
        return {"decision": "reused"} if same else {"decision": "workload_identity_conflict"}
    db.execute("INSERT INTO notice_workloads VALUES(?,?,?,?)",
               (r["case"], r["tenant"], r["identity"], r["uid"]))
    return {"decision": "registered", "tenant": r["tenant"]}


def _open_case(db, r):
    old = _case(db, r["id"])
    if old:
        same = (old["secret"], old["gen"], old["window_from"], old["window_to"]) == (
            r["secret"], r["gen"], r["from"], r["to"])
        return {"decision": "reused"} if same else {"decision": "case_identity_conflict"}
    exposure = one(
        db,
        "SELECT * FROM exposures WHERE id=? AND secret=? AND gen=? AND from_ts=? AND to_ts=?",
        (r["exposure"], r["secret"], r["gen"], r["from"], r["to"]))
    if not exposure or r["from"] > r["to"]:
        return {"decision": "missing_exposure"}
    db.execute("INSERT INTO notice_cases(id,secret,gen,window_from,window_to,"
               "discovery_ts,discovery_basis,conservative_discovery) "
               "VALUES(?,?,?,?,?,NULL,NULL,?)",
               (r["id"], r["secret"], r["gen"], r["from"], r["to"], r["from"]))
    return {"decision": "opened", "exposure": r["exposure"]}


def _evidence(db, r):
    old = one(db, "SELECT * FROM notice_evidence WHERE id=?", (r["id"],))
    if old:
        same = (old["case_id"], old["kind"], old["uid"], old["tenant"],
                old["at_ts"], old["basis"], old["attribution_id"]) == (
            r["case"], r["kind"], r["uid"], r.get("tenant"), r["at"],
            r.get("basis"), r.get("attribution"))
        return {"decision": "reused"} if same else {"decision": "evidence_identity_conflict"}
    case = _case(db, r["case"])
    if not case:
        return {"decision": "unknown_case"}
    kind = r["kind"]
    if kind == "access":
        # Attributable workload access; the tenant is resolved from the registered
        # workload rather than trusted from the evidence payload.
        tenant = _tenant_for_uid(db, r["case"], r["uid"])
        if not tenant:
            return {"decision": "unattributed_uid"}
        fields = sorted(set(r.get("fields", [])))
        if not fields:
            return {"decision": "evidence_without_fields"}
        db.execute("INSERT INTO notice_evidence VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (r["id"], r["case"], kind, r["uid"], tenant, json.dumps(fields),
                    r["at"], r.get("basis"), None, "attributed"))
        return {"decision": "recorded", "tenant": tenant, "in_window":
                case["window_from"] <= r["at"] <= case["window_to"]}
    if kind == "stale_receipt":
        # A channel receipt arriving after the exposure window cannot prove that the
        # old UID read anything inside the window.  Keep it, but flag it as stale.
        if r["at"] <= case["window_to"]:
            return {"decision": "receipt_not_stale"}
        tenant = _tenant_for_uid(db, r["case"], r["uid"])
        db.execute("INSERT INTO notice_evidence VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (r["id"], r["case"], kind, r["uid"], tenant, "[]", r["at"],
                    r.get("basis"), None, "stale"))
        return {"decision": "recorded", "tenant": tenant, "counts_as_access": False}
    if kind == "anonymous":
        # An unattributable cache hit.  Candidate UIDs are recorded as an
        # unresolved set; the hit must not be silently assigned to any tenant.
        candidates = r.get("candidate_uids", [])
        if not candidates:
            return {"decision": "anonymous_without_candidates"}
        known = {uid: _tenant_for_uid(db, r["case"], uid) for uid in candidates}
        db.execute("INSERT INTO notice_evidence VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (r["id"], r["case"], kind, None, None, "[]", r["at"],
                    json.dumps(candidates, sort_keys=True), None, "open"))
        return {"decision": "recorded", "status": "open",
                "candidate_tenants": sorted({t for t in known.values() if t})}
    if kind == "attribution":
        # Later forensics resolving an anonymous hit or a stale UID.
        target = _tenant_for_uid(db, r["case"], r["uid"])
        if not target:
            return {"decision": "unattributed_uid"}
        source = one(db, "SELECT * FROM notice_evidence WHERE id=?",
                     (r["attribution"],))
        if not source or source["case_id"] != r["case"] or source["status"] not in (
                "open", "stale"):
            return {"decision": "attribution_source_not_open"}
        fields = sorted(set(r.get("fields", [])))
        db.execute(
            "UPDATE notice_evidence SET status='resolved', attribution_id=? WHERE id=?",
            (r["id"], r["attribution"]))
        db.execute("INSERT INTO notice_evidence VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (r["id"], r["case"], "access", r["uid"], target,
                    json.dumps(fields), r["at"], r.get("basis"),
                    r["attribution"], "attributed"))
        return {"decision": "recorded", "tenant": target, "resolves": r["attribution"]}
    return {"decision": "unknown_evidence_kind"}


def _discover(db, r):
    """Declare the defensible first-discovery point.

    The clock starts at the first *attributable* access evidence.  An anonymous
    hit cannot anchor discovery because it cannot be assigned to a tenant, but the
    exposure window start is retained as a conservative clock for late-reporting
    accountability.
    """
    case = _case(db, r["case"])
    if not case:
        return {"decision": "unknown_case"}
    if case["discovery_ts"] is not None:
        same = (case["discovery_ts"], case["discovery_basis"]) == (
            r["at"], r["basis"])
        return {"decision": "reused"} if same else {"decision": "discovery_identity_conflict"}
    basis = one(db, "SELECT * FROM notice_evidence WHERE id=? AND case_id=?",
                (r["basis"], r["case"]))
    if not basis or basis["kind"] != "access" or basis["status"] != "attributed":
        return {"decision": "anonymous_hit_cannot_anchor_discovery"}
    if not (case["window_from"] <= basis["at_ts"] <= case["window_to"]):
        return {"decision": "basis_outside_window"}
    db.execute(
        "UPDATE notice_cases SET discovery_ts=?, discovery_basis=? WHERE id=?",
        (r["at"], r["basis"], r["case"]))
    deadlines = {}
    for contract in rows(
            db, "SELECT tenant FROM notice_contracts WHERE case_id=?", (r["case"],)):
        initial, detailed = _deadlines(db, r["case"], contract["tenant"], r["at"])
        deadlines[contract["tenant"]] = {"initial_due": initial, "detailed_due": detailed}
    return {"decision": "discovered", "discovery_ts": r["at"],
            "conservative_discovery": case["conservative_discovery"],
            "deadlines": deadlines}


def _grants_for_tenant(db, case, tenant):
    return rows(
        db,
        "SELECT g.* FROM grants g JOIN notice_workloads w ON w.identity=g.identity "
        "AND w.case_id=? WHERE w.tenant=? AND g.secret=? AND g.gen=?",
        (case["id"], tenant, case["secret"], case["gen"]))


def _build_roster(db, r):
    case = _case(db, r["case"])
    if not case:
        return {"decision": "unknown_case"}
    tenants = [row["tenant"] for row in rows(
        db, "SELECT DISTINCT tenant FROM notice_workloads WHERE case_id=? ORDER BY tenant",
        (r["case"],))]
    roster = []
    for tenant in tenants:
        grants = _grants_for_tenant(db, case, tenant)
        access = rows(
            db,
            "SELECT * FROM notice_evidence WHERE case_id=? AND kind='access' "
            "AND tenant=? AND status='attributed' AND at_ts BETWEEN ? AND ?",
            (case["id"], tenant, case["window_from"], case["window_to"]))
        stale = rows(
            db, "SELECT * FROM notice_evidence WHERE case_id=? AND kind='stale_receipt' AND tenant=?",
            (case["id"], tenant))
        open_anon = rows(
            db, "SELECT * FROM notice_evidence WHERE case_id=? AND kind='anonymous' AND status='open'",
            (case["id"],))
        candidate = False
        for hit in open_anon:
            for uid in _jload(hit["basis"], []):
                if _tenant_for_uid(db, case["id"], uid) == tenant:
                    candidate = True
        if access:
            classification, reason, confidence = (
                "attributed", "in_window_access", "confirmed")
        elif stale or candidate:
            classification, reason, confidence = (
                "conditional",
                "stale_receipt" if stale else "anonymous_candidate",
                "possible")
        elif grants:
            classification, reason, confidence = (
                "permission_only", "license_without_access_evidence", "none")
        else:
            classification, reason, confidence = (
                "not_affected", "no_license_no_evidence", "none")
        initial, detailed = _deadlines(
            db, case["id"], tenant,
            case["discovery_ts"] if case["discovery_ts"] is not None
            else case["conservative_discovery"])
        roster.append({"tenant": tenant, "classification": classification,
                       "reason": reason, "confidence": confidence,
                       "initial_due": initial, "detailed_due": detailed})
    db.execute("DELETE FROM notice_roster WHERE case_id=?", (r["case"],))
    db.executemany(
        "INSERT INTO notice_roster VALUES(?,?,?,?,?,?,?)",
        [(r["case"], x["tenant"], x["classification"], x["reason"],
          x["confidence"], x["initial_due"], x["detailed_due"]) for x in roster])
    return {"decision": "roster_built",
            "roster": roster,
            "notified": sorted(x["tenant"] for x in roster
                               if x["classification"] in ("attributed", "conditional")),
            "excluded": sorted(x["tenant"] for x in roster
                               if x["classification"] in ("permission_only", "not_affected"))}


def _notice_content(db, case, tenant, kind, attribution_id):
    secret = one(db, "SELECT * FROM secrets WHERE id=?", (case["secret"],))
    grants = _grants_for_tenant(db, case, tenant)
    licensed_fields = sorted({
        f for g in grants for f in _jload(g["fields"], [])})
    access_fields = sorted({
        f for row in rows(
            db,
            "SELECT fields FROM notice_evidence WHERE case_id=? AND kind='access' "
            "AND tenant=? AND status='attributed' AND at_ts BETWEEN ? AND ?",
            (case["id"], tenant, case["window_from"], case["window_to"]))
        for f in _jload(row["fields"], [])})
    if kind == "correction" and attribution_id:
        attribution = one(db, "SELECT * FROM notice_evidence WHERE id=?",
                          (attribution_id,))
        if not attribution or attribution["kind"] != "access":
            return None, {"decision": "unknown_attribution"}
        if attribution["tenant"] == tenant:
            confirmed = sorted(set(_jload(attribution["fields"], [])))
            possible = sorted(set(licensed_fields) - set(confirmed))
            return {
                "confirmed_fields": confirmed, "possible_fields": possible,
                "confidence": "confirmed", "assertion": "access_confirmed",
            }, None
        # The attribution landed on another tenant: this tenant is narrowed out.
        return {
            "confirmed_fields": [], "possible_fields": [],
            "confidence": "cleared", "assertion": "no_access_asserted",
        }, None
    entry = one(db, "SELECT * FROM notice_roster WHERE case_id=? AND tenant=?",
                (case["id"], tenant))
    if not entry:
        return None, {"decision": "tenant_not_on_roster"}
    if entry["classification"] == "attributed":
        return {
            "confirmed_fields": access_fields,
            "possible_fields": sorted(set(licensed_fields) - set(access_fields)),
            "confidence": "confirmed", "assertion": "access_confirmed",
        }, None
    if entry["classification"] == "conditional":
        # Minimum necessary content: only fields this tenant itself could have
        # reached.  Another tenant's fields are never named here.
        return {
            "confirmed_fields": [], "possible_fields": licensed_fields,
            "confidence": "possible", "assertion": "access_possible",
        }, None
    return None, {"decision": "notice_basis_refused",
                  "classification": entry["classification"]}


def _issue_notice(db, r):
    case = _case(db, r["case"])
    if not case:
        return {"decision": "unknown_case"}
    if r["kind"] not in ("initial", "conditional", "correction"):
        return {"decision": "unknown_notice_kind"}
    old = one(db, "SELECT * FROM notices WHERE id=?", (r["id"],))
    if old:
        same = (old["case_id"], old["tenant"], old["kind"], old["supersedes"],
                old["basis"], old["issued_at"]) == (
            r["case"], r["tenant"], r["kind"], r.get("supersedes"),
            r.get("basis"), r["at"])
        return {"decision": "reused"} if same else {"decision": "notice_identity_conflict"}
    prior = rows(
        db, "SELECT * FROM notices WHERE case_id=? AND tenant=? ORDER BY seq",
        (r["case"], r["tenant"]))
    if r["kind"] == "correction":
        if not r.get("supersedes") or not any(
                n["id"] == r["supersedes"] for n in prior):
            return {"decision": "correction_without_original"}
    elif prior:
        return {"decision": "original_notice_must_be_corrected_by_append"}
    content, error = _notice_content(db, case, r["tenant"], r["kind"],
                                     r.get("basis"))
    if error:
        return error
    if r["kind"] in ("initial",) and content["assertion"] != "access_confirmed":
        # A permission holder with no access evidence must never be told its data
        # "leaked", and an unconfirmed tenant cannot receive a confirmed notice.
        return {"decision": "overclaim_refused", "assertion": content["assertion"]}
    if r.get("assert_leak") and content["assertion"] != "access_confirmed":
        return {"decision": "overclaim_refused", "assertion": content["assertion"]}
    contacts = [
        _active_contact(db, cid, r["case"], r["tenant"], r["at"])
        for cid in r["contact_ids"]]
    if any(c is None for c in contacts) or not contacts:
        return {"decision": "recipient_not_authorized_at_incident_time"}
    recipients = [{"contact_id": c["id"], "channel": c["channel"],
                   "address": c["address"]} for c in contacts]
    secret = one(db, "SELECT purpose FROM secrets WHERE id=?", (case["secret"],))
    seq = (max((n["seq"] for n in prior), default=0) + 1) if prior else 1
    db.execute(
        "INSERT INTO notices VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (r["id"], r["case"], r["tenant"], seq, r["kind"], r.get("supersedes"),
         secret["purpose"] if secret else None,
         json.dumps(content["confirmed_fields"]),
         json.dumps(content["possible_fields"]), content["confidence"],
         content["assertion"], json.dumps(recipients, sort_keys=True),
         json.dumps(r["contact_ids"], sort_keys=True), r.get("basis"),
         r["at"], "pending"))
    return {"decision": "issued", "id": r["id"], "tenant": r["tenant"],
            "seq": seq, "kind": r["kind"],
            "purpose": secret["purpose"] if secret else None,
            **content, "recipients": recipients}


def _dispatch(db, r):
    notice = one(db, "SELECT * FROM notices WHERE id=?", (r["notice"],))
    if not notice:
        return {"decision": "unknown_notice"}
    old = one(db, "SELECT * FROM notice_dispatches WHERE id=?", (r["id"],))
    if old:
        same = (old["notice_id"], old["channel"], old["recipient_contact"],
                old["address"], old["dispatched_at"]) == (
            r["notice"], r["channel"], r["contact"], r["address"], r["at"])
        return {"decision": "reused"} if same else {"decision": "dispatch_identity_conflict"}
    snapshot = {c["contact_id"]: c for c in _jload(notice["recipients"], [])}
    # A recipient is either (a) in the immutable snapshot bound at issuance, or
    # (b) added by a registered security authority through an escalation.  An
    # unauthorised new contact can never be injected into the original notice.
    escalation = one(
        db,
        "SELECT * FROM notice_escalations WHERE notice_id=? AND contact_id=? "
        "AND outcome='escalated'",
        (r["notice"], r["contact"]))
    if r["contact"] in snapshot:
        contact = snapshot[r["contact"]]
        authorized = True
    elif escalation:
        current = _active_contact(
            db, r["contact"], notice["case_id"], notice["tenant"], r["at"])
        contact = current
        authorized = current is not None
    else:
        authorized = False
        contact = None
    if not authorized:
        return {"decision": "recipient_not_authorized_for_this_notice"}
    if r["channel"] != contact["channel"] or r["address"] != contact["address"]:
        return {"decision": "dispatch_address_conflict"}
    attempt = one(
        db, "SELECT COALESCE(MAX(attempt_no),0)+1 n FROM notice_dispatches WHERE notice_id=?",
        (r["notice"],))["n"]
    db.execute("INSERT INTO notice_dispatches VALUES(?,?,?,?,?,?,?,?)",
               (r["id"], r["notice"], attempt, r["channel"], r["contact"],
                r["address"], r["at"], "attempted"))
    return {"decision": "attempted", "attempt": attempt,
            "via_escalation": escalation is not None,
            "notice_status": "pending_delivery_evidence"}


def _receipt(db, r):
    if r["kind"] not in TERMINAL_RECEIPTS + FAILED_RECEIPTS:
        return {"decision": "invalid_receipt_kind"}
    old = one(db, "SELECT * FROM notice_receipts WHERE id=?", (r["id"],))
    if old:
        same = (old["dispatch_id"], old["kind"], old["at_ts"], old["reference"]) == (
            r["dispatch"], r["kind"], r["at"], r.get("reference"))
        return {"decision": "reused"} if same else {"decision": "receipt_identity_conflict"}
    dispatch = one(db, "SELECT * FROM notice_dispatches WHERE id=?",
                   (r["dispatch"],))
    if not dispatch:
        return {"decision": "unknown_dispatch"}
    db.execute("INSERT INTO notice_receipts VALUES(?,?,?,?,?,?)",
               (r["id"], r["dispatch"], r["kind"], r["at"],
                r.get("reference"), r.get("detail")))
    if r["kind"] in TERMINAL_RECEIPTS:
        dispatch_status = "acknowledged" if r["kind"] == "acknowledged" else "delivered"
        db.execute("UPDATE notice_dispatches SET status=? WHERE id=?",
                   (dispatch_status, r["dispatch"]))
        db.execute("UPDATE notices SET status=? WHERE id=?",
                   (dispatch_status, dispatch["notice_id"]))
        return {"decision": r["kind"], "delivered": True}
    db.execute("UPDATE notice_dispatches SET status=? WHERE id=?",
               (r["kind"], r["dispatch"]))
    db.execute("UPDATE notices SET status='failed' WHERE id=?",
               (dispatch["notice_id"],))
    # Failure is recorded, not treated as delivery; escalation is now mandatory.
    return {"decision": r["kind"], "delivered": False,
            "requires_escalation": True}


def _escalate(db, r):
    notice = one(db, "SELECT * FROM notices WHERE id=?", (r["notice"],))
    if not notice:
        return {"decision": "unknown_notice"}
    old = one(db, "SELECT * FROM notice_escalations WHERE id=?", (r["id"],))
    if old:
        same = (old["notice_id"], old["reason"], old["authority_actor"],
                old["contact_id"], old["outcome"]) == (
            r["notice"], r["reason"], r["actor"], r.get("contact"), r["outcome"])
        return {"decision": "reused"} if same else {"decision": "escalation_identity_conflict"}
    failed = one(
        db,
        "SELECT 1 FROM notice_receipts rc JOIN notice_dispatches d ON d.id=rc.dispatch_id "
        "WHERE d.notice_id=? AND rc.kind IN ('bounced','unattended')",
        (r["notice"],))
    if not failed:
        return {"decision": "escalation_without_failure_evidence"}
    authority = one(
        db,
        "SELECT 1 FROM notice_authorities WHERE case_id=? AND tenant=? AND actor=? AND role='security'",
        (notice["case_id"], notice["tenant"], r["actor"]))
    if not authority:
        return {"decision": "unauthorized_escalation"}
    if r["outcome"] not in ("escalated", "undeliverable"):
        return {"decision": "invalid_escalation_outcome"}
    if r["outcome"] == "escalated":
        contact = _active_contact(
            db, r["contact"], notice["case_id"], notice["tenant"], r["at"])
        if not contact:
            return {"decision": "recipient_not_authorized_at_incident_time"}
        contact_id = r["contact"]
    else:
        # Every authorised channel exhausted: retain the non-delivery as evidence.
        contact_id = None
    db.execute("INSERT INTO notice_escalations VALUES(?,?,?,?,?,?,?,?)",
               (r["id"], r["notice"], notice["tenant"], r["reason"], r["actor"],
                contact_id, r["at"], r["outcome"]))
    return {"decision": r["outcome"], "contact_id": contact_id}


def _first_delivery(db, notice_id):
    row = one(
        db,
        "SELECT MIN(rc.at_ts) at FROM notice_receipts rc "
        "JOIN notice_dispatches d ON d.id=rc.dispatch_id "
        "WHERE d.notice_id=? AND rc.kind IN ('delivered','acknowledged')",
        (notice_id,))
    return row["at"] if row and row["at"] is not None else None


def _finalize(db, r):
    case = _case(db, r["case"])
    if not case:
        return {"decision": "unknown_case"}
    old = one(db, "SELECT * FROM notice_outcomes WHERE case_id=? AND tenant=?",
              (r["case"], r["tenant"]))
    if old:
        return {"decision": "reused", "final_status": old["final_status"]}
    notices = rows(
        db, "SELECT * FROM notices WHERE case_id=? AND tenant=? ORDER BY seq",
        (r["case"], r["tenant"]))
    if not notices:
        return {"decision": "no_notice_to_finalize"}
    initial = notices[0]
    latest = notices[-1]
    initial_at = _first_delivery(db, initial["id"])
    detailed_at = _first_delivery(db, latest["id"])
    undeliverable = one(
        db,
        "SELECT 1 FROM notice_escalations WHERE notice_id=? AND outcome='undeliverable'",
        (latest["id"],))
    if undeliverable:
        final_status = "undeliverable"
    elif detailed_at is None:
        return {"decision": "delivery_unproven"}
    else:
        final_status = latest["status"]
    entry = one(db, "SELECT * FROM notice_roster WHERE case_id=? AND tenant=?",
                (r["case"], r["tenant"]))
    initial_due = entry["initial_due"] if entry else None
    detailed_due = entry["detailed_due"] if entry else None
    conservative_due = (case["window_from"] + 4 * 60)
    initial_on_time = initial_at is not None and initial_due is not None and initial_at <= initial_due
    detailed_on_time = detailed_at is not None and detailed_due is not None and detailed_at <= detailed_due
    conservative_on_time = initial_at is not None and initial_at <= conservative_due
    responsibility = []
    if initial_at is None:
        responsibility.append("initial_never_delivered")
    elif not initial_on_time:
        responsibility.append("initial_late_vs_contract_clock")
    if not conservative_on_time:
        responsibility.append("initial_late_vs_conservative_window_clock")
    if detailed_at is None and detailed_due is not None and r["at"] > detailed_due:
        responsibility.append("detailed_overdue")
    elif detailed_at is not None and not detailed_on_time:
        responsibility.append("detailed_late")
    db.execute(
        "INSERT INTO notice_outcomes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (r["case"], r["tenant"], initial["id"], latest["id"], final_status,
         initial_due, initial_at, int(initial_on_time), detailed_due,
         detailed_at, int(detailed_on_time), conservative_due,
         json.dumps(responsibility)))
    return {"decision": "finalized", "tenant": r["tenant"],
            "final_status": final_status,
            "initial_delivered_at": initial_at,
            "detailed_delivered_at": detailed_at,
            "initial_on_time": bool(initial_on_time),
            "detailed_on_time": bool(detailed_on_time),
            "late_responsibility": responsibility}
