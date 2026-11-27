"""Verifiable e-waste material fate ledger.

`secretcourt.recycle_ticket` turns a self-reported ``hardware_order`` mass into
a recovery certificate without a weighbridge, a handler receipt, identity
checks or mass conservation.  A vendor signature on that certificate only
authenticates the self-report; it cannot make 930 g of metal plus 90 g of
residue come out of two machines whose preserved inbound readings are
840-860 g.

This module certifies material fate only from original, re-checkable evidence:

* each physical piece has its own appearance/internal fingerprint; an
  identical paper label is not an identity;
* both scale readings and both calibration certificates are kept -- the
  favourable reading is never selected and the input mass is an envelope;
* seals, seal exceptions and named custody handovers are records;
* a re-stuck seal / co-loaded third-party goods can only be waived by the
  owning customer, informed of both facts, and a batch needs an independent
  third-party witness plus 100 % identification-grade inspection;
* statistical sampling cannot exclude foreign metal -- only census-grade
  disposition of every piece can;
* batteries and circuit boards go to separately permitted chains, and every
  metal/residue gram rests on a calibrated weighing and a handler receipt;
* outputs plus reasonable loss must close against the *same* mass boundary.

After a furnace charge, single-unit identity is unrecoverable.  Mixed owners
then receive a pro-rata allocation over their provable input envelopes,
labelled an allocation rather than a measured per-customer recovery rate, and
any mass the proven inputs cannot explain stays unattributed.

All decisions are plain JSON-ish dicts and all state lives in SQLite, matching
the rest of ``secretcourt``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from .store import one, rows

# Furnace/processing loss allowance: oxidation, moisture, dust, slag carry.
# Explicit policy, never silently expanded to rescue an overrun.
DEFAULT_LOSS_FRACTION = 0.08

INPUT_STAGES = ("outbound", "intake", "witness_input")

# Methods that can actually exclude foreign material from a boundary.  Both
# must cover 100 % of pieces and give every piece an identity disposition.
EXCLUSION_METHODS = ("census_open", "full_imaging_targeted_open")

OWNER_ROLES = ("customer_owner", "customer_agent")

CATEGORIES = (
    "metal",
    "circuit_board",
    "battery",
    "battery_residue",
    "hazardous_residue",
    "residue",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mr_items(
  id TEXT PRIMARY KEY, customer TEXT NOT NULL, label_serial TEXT,
  claimed_grams REAL, appearance_json TEXT, internal_json TEXT,
  fingerprint TEXT, battery_claim TEXT);
CREATE TABLE IF NOT EXISTS mr_calibrations(
  cert_id TEXT PRIMARY KEY, scale_id TEXT NOT NULL,
  starts TEXT, ends TEXT, uncertainty_g REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS mr_weighings(
  id TEXT PRIMARY KEY, subject_kind TEXT, subject_id TEXT, stage TEXT,
  grams REAL, raw_reading REAL, scale_id TEXT, calib_id TEXT, at TEXT,
  weigher TEXT, witness TEXT, receipt_ref TEXT);
CREATE TABLE IF NOT EXISTS mr_seals(
  id TEXT PRIMARY KEY, box_id TEXT, seal_number TEXT, state TEXT,
  at TEXT, custodian TEXT, evidence_json TEXT);
CREATE TABLE IF NOT EXISTS mr_handovers(
  id TEXT PRIMARY KEY, box_id TEXT, at TEXT, from_party TEXT,
  to_party TEXT, seal_id TEXT, witness TEXT);
CREATE TABLE IF NOT EXISTS mr_transport(
  id TEXT PRIMARY KEY, box_id TEXT, at TEXT, carrier TEXT,
  vehicle_ref TEXT, co_loaded TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS mr_boundaries(
  id TEXT PRIMARY KEY, kind TEXT, box_id TEXT, charged_at TEXT);
CREATE TABLE IF NOT EXISTS mr_boundary_items(
  boundary_id TEXT, item_id TEXT, owner TEXT, status TEXT,
  PRIMARY KEY(boundary_id,item_id));
CREATE TABLE IF NOT EXISTS mr_inspections(
  id TEXT PRIMARY KEY, boundary_id TEXT, at TEXT, method TEXT,
  coverage REAL, pieces_total INTEGER, pieces_checked INTEGER,
  foreign_found INTEGER, witness TEXT, detail_json TEXT);
CREATE TABLE IF NOT EXISTS mr_segregations(
  id TEXT PRIMARY KEY, boundary_id TEXT, item_id TEXT, at TEXT,
  witness TEXT, weighing_id TEXT, to_owner TEXT,
  destination_id TEXT, receipt_ref TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS mr_authorizations(
  id TEXT PRIMARY KEY, boundary_id TEXT, customer TEXT, actor TEXT,
  role TEXT, at TEXT, scope_json TEXT, ack_seal INTEGER, ack_co INTEGER,
  witness TEXT);
CREATE TABLE IF NOT EXISTS mr_owner_scopes(
  boundary_id TEXT, owner TEXT, scope_kind TEXT, scope_id TEXT,
  PRIMARY KEY(boundary_id,owner,scope_id));
CREATE TABLE IF NOT EXISTS mr_destinations(
  id TEXT PRIMARY KEY, category TEXT, facility TEXT,
  permit_id TEXT, chain TEXT);
CREATE TABLE IF NOT EXISTS mr_outputs(
  id TEXT PRIMARY KEY, boundary_id TEXT, item_id TEXT, category TEXT,
  grams REAL, evidence_class TEXT, weighing_id TEXT,
  destination_id TEXT, receipt_ref TEXT, report_ref TEXT);
CREATE TABLE IF NOT EXISTS mr_certs(
  id TEXT PRIMARY KEY, kind TEXT, customer TEXT, boundary_id TEXT,
  body_json TEXT, signer TEXT, signature TEXT, issued_at TEXT);
"""


def ensure(db):
    db.executescript(_SCHEMA)


# ---------------------------------------------------------------------------
# deterministic digests / signatures
# ---------------------------------------------------------------------------

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def seal_body(body, signer="material-recovery-certifier"):
    """Sign a certificate body.

    This is a domain-separated digest, not a PKI claim.  It proves the sealed
    bytes have not been edited; it says nothing about whether the grams are
    physically possible.
    """
    h = hashlib.sha256(("secretcourt.material_recovery/v1/" + canonical(body)).encode("utf-8"))
    return {"signer": signer, "alg": "domain-sha256", "digest": h.hexdigest()}


def verify_seal(body, seal):
    expected = seal_body(body, seal.get("signer", "material-recovery-certifier"))
    return hmac.compare_digest(expected["digest"], seal.get("digest", ""))


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _loads(text, default=None):
    if not text:
        return default
    return json.loads(text)


def has_blocker(blockers, code):
    """True if code equals, or is a ``code:detail`` blocker."""
    return any(b == code or b.startswith(code + ":") for b in blockers)


# ---------------------------------------------------------------------------
# evidence records
# ---------------------------------------------------------------------------

def record_calibration(db, cert_id, scale_id, starts, ends, uncertainty_g=0.0):
    ensure(db)
    old = one(db, "SELECT cert_id FROM mr_calibrations WHERE cert_id=?", (cert_id,))
    if old:
        return {"decision": "reused", "cert_id": cert_id}
    db.execute(
        "INSERT INTO mr_calibrations VALUES(?,?,?,?,?)",
        (cert_id, scale_id, starts, ends, uncertainty_g),
    )
    return {"decision": "recorded", "cert_id": cert_id, "scale_id": scale_id}


def _calibration_state(db, scale_id, calib_id, at):
    day = (at or "")[:10]
    cert = None
    if calib_id:
        cert = one(db, "SELECT * FROM mr_calibrations WHERE cert_id=?", (calib_id,))
        if not cert:
            return "missing", None
    elif scale_id and day:
        cert = one(
            db,
            "SELECT * FROM mr_calibrations WHERE scale_id=? AND starts<=? AND ends>=? "
            "ORDER BY ends DESC LIMIT 1",
            (scale_id, day, day),
        )
        if not cert:
            return "missing", None
    if not cert:
        return "missing", None
    if day and not (cert["starts"] <= day <= cert["ends"]):
        return "lapsed", cert
    return "valid", cert


def record_weighing(db, weighing_id, subject_kind, subject_id, stage, grams,
                    scale_id, at, calib_id=None, raw_reading=None,
                    weigher=None, witness=None, receipt_ref=None):
    ensure(db)
    old = one(db, "SELECT id FROM mr_weighings WHERE id=?", (weighing_id,))
    if old:
        return {"decision": "reused", "weighing_id": weighing_id}
    if grams is None or grams < 0:
        return {"decision": "unavailable", "reason": "negative_or_missing_grams"}
    state, cert = _calibration_state(db, scale_id, calib_id, at)
    db.execute(
        "INSERT INTO mr_weighings VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (weighing_id, subject_kind, subject_id, stage, float(grams),
         float(grams if raw_reading is None else raw_reading), scale_id,
         cert["cert_id"] if cert else calib_id, at, weigher, witness, receipt_ref),
    )
    return {"decision": "recorded", "weighing_id": weighing_id,
            "calibration": state, "calib_id": cert["cert_id"] if cert else calib_id}


def register_item(db, item_id, customer, label_serial, appearance, internal,
                  claimed_grams=None, battery_claim="removed"):
    ensure(db)
    old = one(db, "SELECT id FROM mr_items WHERE id=?", (item_id,))
    if old:
        return {"decision": "reused", "item_id": item_id}
    appearance_json = appearance if isinstance(appearance, str) else canonical(appearance)
    internal_json = internal if isinstance(internal, str) else canonical(internal)
    fingerprint = digest({"appearance": _loads(appearance_json, appearance_json),
                         "internal": _loads(internal_json, internal_json)})
    db.execute(
        "INSERT INTO mr_items VALUES(?,?,?,?,?,?,?,?)",
        (item_id, customer, label_serial, claimed_grams, appearance_json,
         internal_json, fingerprint, battery_claim),
    )
    return {"decision": "registered", "item_id": item_id, "fingerprint": fingerprint}


def record_seal(db, seal_event_id, box_id, state, at, seal_number=None,
                custodian=None, evidence=None):
    ensure(db)
    old = one(db, "SELECT id FROM mr_seals WHERE id=?", (seal_event_id,))
    if old:
        return {"decision": "reused", "seal_event_id": seal_event_id}
    db.execute(
        "INSERT INTO mr_seals VALUES(?,?,?,?,?,?,?)",
        (seal_event_id, box_id, seal_number, state, at, custodian,
         None if evidence is None else canonical(evidence)),
    )
    return {"decision": "recorded", "seal_event_id": seal_event_id, "state": state}


def record_handoff(db, handoff_id, box_id, at, from_party, to_party,
                   seal_id=None, witness=None):
    ensure(db)
    old = one(db, "SELECT id FROM mr_handovers WHERE id=?", (handoff_id,))
    if old:
        return {"decision": "reused", "handoff_id": handoff_id}
    db.execute(
        "INSERT INTO mr_handovers VALUES(?,?,?,?,?,?,?)",
        (handoff_id, box_id, at, from_party, to_party, seal_id, witness),
    )
    return {"decision": "recorded", "handoff_id": handoff_id}


def record_transport(db, transport_id, box_id, at, carrier=None,
                     vehicle_ref=None, co_loaded=None, note=None):
    ensure(db)
    old = one(db, "SELECT id FROM mr_transport WHERE id=?", (transport_id,))
    if old:
        return {"decision": "reused", "transport_id": transport_id}
    db.execute(
        "INSERT INTO mr_transport VALUES(?,?,?,?,?,?,?)",
        (transport_id, box_id, at, carrier, vehicle_ref, co_loaded, note),
    )
    return {"decision": "recorded", "transport_id": transport_id}


def create_boundary(db, boundary_id, kind, item_ids, box_id=None, charged_at=None):
    ensure(db)
    old = one(db, "SELECT id FROM mr_boundaries WHERE id=?", (boundary_id,))
    if old:
        return {"decision": "reused", "boundary_id": boundary_id}
    db.execute("INSERT INTO mr_boundaries VALUES(?,?,?,?)",
               (boundary_id, kind, box_id, charged_at))
    for item_id in item_ids:
        item = one(db, "SELECT customer FROM mr_items WHERE id=?", (item_id,))
        if not item:
            raise ValueError("unknown item " + item_id)
        db.execute("INSERT INTO mr_boundary_items VALUES(?,?,?,?)",
                   (boundary_id, item_id, item["customer"], "in_scope"))
    return {"decision": "created", "boundary_id": boundary_id, "members": list(item_ids)}


def mark_furnace_charge(db, boundary_id, charged_at):
    ensure(db)
    if not one(db, "SELECT id FROM mr_boundaries WHERE id=?", (boundary_id,)):
        return {"decision": "missing_boundary"}
    db.execute("UPDATE mr_boundaries SET charged_at=? WHERE id=?", (charged_at, boundary_id))
    return {"decision": "charged", "boundary_id": boundary_id, "charged_at": charged_at}


def record_inspection(db, inspection_id, boundary_id, method, at, witness=None,
                      coverage=1.0, pieces_total=None, pieces_checked=None,
                      foreign_found=0, detail=None):
    ensure(db)
    old = one(db, "SELECT id FROM mr_inspections WHERE id=?", (inspection_id,))
    if old:
        return {"decision": "reused", "inspection_id": inspection_id}
    if pieces_checked is None:
        pieces_checked = pieces_total
    exclusion_grade = (
        method in EXCLUSION_METHODS
        and coverage is not None and coverage >= 1.0
        and pieces_total is not None and pieces_checked is not None
        and pieces_checked >= pieces_total
        and bool(witness)
    )
    bound_95 = None
    if method == "statistical" and not foreign_found and pieces_checked:
        # Rule of three: 95% upper bound on contamination rate after zero finds.
        bound_95 = round(3.0 / pieces_checked, 4)
    db.execute(
        "INSERT INTO mr_inspections VALUES(?,?,?,?,?,?,?,?,?,?)",
        (inspection_id, boundary_id, at, method, coverage, pieces_total,
         pieces_checked, foreign_found, witness,
         None if detail is None else canonical(detail)),
    )
    return {"decision": "recorded", "inspection_id": inspection_id,
            "exclusion_grade": exclusion_grade,
            "contamination_upper_bound_95": bound_95}


def segregate_member(db, segregation_id, boundary_id, item_id, at, witness=None,
                     weighing_id=None, to_owner=None, destination_id=None,
                     receipt_ref=None, note=None):
    ensure(db)
    old = one(db, "SELECT id FROM mr_segregations WHERE id=?", (segregation_id,))
    if old:
        return {"decision": "reused", "segregation_id": segregation_id}
    db.execute(
        "INSERT INTO mr_segregations VALUES(?,?,?,?,?,?,?,?,?,?)",
        (segregation_id, boundary_id, item_id, at, witness, weighing_id,
         to_owner, destination_id, receipt_ref, note),
    )
    db.execute(
        "UPDATE mr_boundary_items SET status='segregated' "
        "WHERE boundary_id=? AND item_id=?",
        (boundary_id, item_id),
    )
    return {"decision": "segregated", "boundary_id": boundary_id, "item_id": item_id}


def authorize_batch(db, authorization_id, boundary_id, customer, actor, role,
                    ack_seal_exception=False, ack_co_mingle=False,
                    scope_item_ids=None, witness=None, at=None):
    """Authorize merging identifiable pieces into an anonymous batch.

    Only the owning customer (or recorded agent) may surrender unit identity.
    The processor or warehouse may not authorize it for the customer.  When a
    seal exception or co-loaded third-party goods are part of the record, the
    customer must acknowledge those specific facts.  Authorization never
    covers another owner's pieces: each owner must authorize their own scope.
    """
    ensure(db)
    old = one(db, "SELECT id FROM mr_authorizations WHERE id=?", (authorization_id,))
    if old:
        return {"decision": "reused", "authorization_id": authorization_id}
    boundary = one(db, "SELECT * FROM mr_boundaries WHERE id=?", (boundary_id,))
    if not boundary:
        return {"decision": "missing_boundary"}

    blockers = []
    if not actor or role not in OWNER_ROLES:
        blockers.append("only_customer_can_authorize_merge")

    if scope_item_ids is None:
        members = rows(
            db,
            "SELECT item_id, owner FROM mr_boundary_items "
            "WHERE boundary_id=? AND status='in_scope'",
            (boundary_id,),
        )
        scope_item_ids = [m["item_id"] for m in members]
        for m in members:
            if m["owner"] != customer:
                blockers.append("cross_owner_authorization_required:" + m["item_id"])
    else:
        for item_id in scope_item_ids:
            item = one(db, "SELECT customer FROM mr_items WHERE id=?", (item_id,))
            if not item:
                blockers.append("scope_item_missing:" + item_id)
            elif item["customer"] != customer:
                blockers.append("cross_owner_authorization_required:" + item_id)

    seal_exception = False
    co_mingle = False
    if boundary["box_id"]:
        bad_seal = one(
            db,
            "SELECT id FROM mr_seals WHERE box_id=? AND state IN ('re_stuck','broken','tampered') LIMIT 1",
            (boundary["box_id"],),
        )
        seal_exception = bool(bad_seal)
        transport = one(db, "SELECT id FROM mr_transport WHERE box_id=? LIMIT 1",
                        (boundary["box_id"],))
        co_mingle = bool(transport)
    other_owner_in_scope = one(
        db,
        "SELECT item_id FROM mr_boundary_items WHERE boundary_id=? "
        "AND status='in_scope' AND owner<>? LIMIT 1",
        (boundary_id, customer),
    )
    if other_owner_in_scope:
        co_mingle = True

    if seal_exception and not ack_seal_exception:
        blockers.append("seal_exception_ack_required")
    if co_mingle and not ack_co_mingle:
        blockers.append("co_mingle_ack_required")

    if blockers:
        return {"decision": "refused_authorization",
                "authorization_id": authorization_id, "blockers": blockers}

    db.execute(
        "INSERT INTO mr_authorizations VALUES(?,?,?,?,?,?,?,?,?,?)",
        (authorization_id, boundary_id, customer, actor, role, at or _now(),
         canonical(list(scope_item_ids)), 1 if ack_seal_exception else 0,
         1 if ack_co_mingle else 0, witness),
    )
    return {"decision": "authorized", "authorization_id": authorization_id,
            "scope_item_ids": list(scope_item_ids)}


def add_owner_scope(db, boundary_id, owner, scope_kind, scope_id):
    """Attach an owner's provable input scope to a commingled furnace event."""
    ensure(db)
    db.execute(
        "INSERT OR IGNORE INTO mr_owner_scopes VALUES(?,?,?,?)",
        (boundary_id, owner, scope_kind, scope_id),
    )
    return {"decision": "scoped", "boundary_id": boundary_id, "owner": owner}


def register_destination(db, destination_id, category, facility, permit_id, chain=None):
    ensure(db)
    old = one(db, "SELECT id FROM mr_destinations WHERE id=?", (destination_id,))
    if old:
        return {"decision": "reused", "destination_id": destination_id}
    if category not in CATEGORIES:
        return {"decision": "unavailable", "reason": "unknown_category"}
    if not facility or not permit_id:
        return {"decision": "unavailable", "reason": "qualified_permit_required"}
    db.execute("INSERT INTO mr_destinations VALUES(?,?,?,?,?)",
               (destination_id, category, facility, permit_id, chain))
    return {"decision": "recorded", "destination_id": destination_id}


def record_output(db, output_id, boundary_id, category, grams,
                  destination_id=None, receipt_ref=None, weighing_id=None,
                  item_id=None, claimed=False, report_ref=None):
    ensure(db)
    old = one(db, "SELECT id FROM mr_outputs WHERE id=?", (output_id,))
    if old:
        return {"decision": "reused", "output_id": output_id}
    if category not in CATEGORIES:
        return {"decision": "unavailable", "reason": "unknown_category"}
    if grams is None or grams < 0:
        return {"decision": "unavailable", "reason": "negative_or_missing_grams"}

    evidence_class = "claimed" if claimed else "weighed"
    if not claimed:
        dest = one(db, "SELECT * FROM mr_destinations WHERE id=?", (destination_id,))
        weighing = one(db, "SELECT id FROM mr_weighings WHERE id=?", (weighing_id,))
        if not dest or dest["category"] != category or not dest["permit_id"]:
            return {"decision": "unavailable", "reason": "qualified_destination_required"}
        if not weighing:
            return {"decision": "unavailable", "reason": "output_weighing_required"}
        if not receipt_ref:
            return {"decision": "unavailable", "reason": "handler_receipt_required"}

    db.execute(
        "INSERT INTO mr_outputs VALUES(?,?,?,?,?,?,?,?,?,?)",
        (output_id, boundary_id, item_id, category, float(grams), evidence_class,
         weighing_id, destination_id, receipt_ref, report_ref),
    )
    return {"decision": "recorded", "output_id": output_id,
            "evidence_class": evidence_class}


# ---------------------------------------------------------------------------
# mass balance -- never chooses the favourable scale
# ---------------------------------------------------------------------------

def input_envelope(db, subject_kind, subject_id):
    """Return (low, high, readings) from *all* preserved input weighings."""
    ws = rows(
        db,
        "SELECT * FROM mr_weighings WHERE subject_kind=? AND subject_id=? "
        "AND stage IN ('outbound','intake','witness_input') ORDER BY at, id",
        (subject_kind, subject_id),
    )
    if not ws:
        return None, None, []
    lows, highs = [], []
    for w in ws:
        _, cert = _calibration_state(db, w["scale_id"], w["calib_id"], w["at"])
        uncertainty = cert["uncertainty_g"] if cert else 0.0
        raw = w["raw_reading"] if w["raw_reading"] is not None else w["grams"]
        lows.append(raw - uncertainty)
        highs.append(raw + uncertainty)
    return min(lows), max(highs), ws


def _closure(low, high, accounted, loss_fraction):
    if low is None or high is None:
        return {"input_low_g": None, "input_high_g": None, "closed": False,
                "unclosed_excess_g": None, "unexplained_loss_g": None}
    allowable = round(loss_fraction * high, 6)
    overrun = round(max(0.0, accounted - high), 6)
    gap = round(max(0.0, low - accounted - allowable), 6)
    return {
        "input_low_g": low,
        "input_high_g": high,
        "accounted_g": round(accounted, 6),
        "allowable_loss_g": allowable,
        "implied_loss_interval_g": [round(low - accounted, 6),
                                    round(high - accounted, 6)],
        "unclosed_excess_g": overrun,
        "unexplained_loss_g": gap,
        "unclosed_g": round(overrun + gap, 6),
        "closed": overrun == 0 and gap == 0,
    }


def mass_balance(db, boundary_id=None, item_id=None,
                 loss_fraction=DEFAULT_LOSS_FRACTION):
    """Close outputs against one physical boundary.

    Item scope uses the item's own inbound/outbound weighings and item-tagged
    outputs.  Boundary scope uses boundary weighings and every output recorded
    against that boundary.  Claimed (unweighed) outputs still enter the
    arithmetic so a physical contradiction cannot hide behind missing paper;
    evidence-quality blockers are handled by the evaluators.
    """
    ensure(db)
    if item_id is not None:
        low, high, ws = input_envelope(db, "item", item_id)
        outs = rows(db, "SELECT * FROM mr_outputs WHERE item_id=? ORDER BY id", (item_id,))
        scope = {"scope": "item", "item_id": item_id}
    else:
        low, high, ws = input_envelope(db, "boundary", boundary_id)
        outs = rows(db, "SELECT * FROM mr_outputs WHERE boundary_id=? ORDER BY id",
                    (boundary_id,))
        scope = {"scope": "boundary", "boundary_id": boundary_id}

    categories = {}
    weighed_total = 0.0
    claimed_total = 0.0
    for o in outs:
        categories[o["category"]] = round(categories.get(o["category"], 0.0) + o["grams"], 6)
        if o["evidence_class"] == "weighed":
            weighed_total += o["grams"]
        else:
            claimed_total += o["grams"]
    accounted = round(weighed_total + claimed_total, 6)

    result = dict(scope)
    result.update({
        "input_reading_ids": [w["id"] for w in ws],
        "input_readings_g": [w["raw_reading"] for w in ws],
        "output_categories_g": categories,
        "weighed_accounted_g": round(weighed_total, 6),
        "claimed_accounted_g": round(claimed_total, 6),
        "metal_g": categories.get("metal", 0.0),
        "metal_excess_vs_input_high_g": (
            None if high is None else round(max(0.0, categories.get("metal", 0.0) - high), 6)
        ),
    })
    result.update(_closure(low, high, accounted, loss_fraction))
    return result


# ---------------------------------------------------------------------------
# evidence-quality checks
# ---------------------------------------------------------------------------

def _weighing_blockers(db, weighing_id, code_prefix, require_witness=False):
    blockers = []
    w = one(db, "SELECT * FROM mr_weighings WHERE id=?", (weighing_id,))
    if not w:
        return [code_prefix + ":weighing_missing"]
    state, _ = _calibration_state(db, w["scale_id"], w["calib_id"], w["at"])
    if state != "valid":
        blockers.append(code_prefix + ":calibration_" + state + ":" + weighing_id)
    if not w["weigher"]:
        blockers.append(code_prefix + ":weigher_missing:" + weighing_id)
    if require_witness and not w["witness"]:
        blockers.append(code_prefix + ":witness_missing:" + weighing_id)
    return blockers


def _output_blockers(db, outputs, require_witness=False):
    blockers = []
    if not outputs:
        return ["no_processing_outputs", "final_disposition_missing"]
    for o in outputs:
        oid = o["id"]
        if o["evidence_class"] != "weighed" or not o["weighing_id"]:
            blockers.append("output_not_weighed:" + oid)
            continue
        blockers += _weighing_blockers(db, o["weighing_id"], "output_scale",
                                       require_witness=require_witness)
        dest = one(db, "SELECT * FROM mr_destinations WHERE id=?",
                   (o["destination_id"],)) if o["destination_id"] else None
        if not dest or dest["category"] != o["category"] or not dest["permit_id"]:
            blockers.append("qualified_destination_missing:" + oid)
        if not o["receipt_ref"]:
            blockers.append("handler_receipt_missing:" + oid)
        elif require_witness:
            # witnessed output totals are carried by the output weighing
            pass
    return blockers


def _input_blockers(db, subject_kind, subject_id, require_witnessed_total=False):
    _, _, ws = input_envelope(db, subject_kind, subject_id)
    blockers = []
    if not ws:
        return ["input_weighing_missing"]
    stages = {w["stage"] for w in ws}
    if "outbound" not in stages:
        blockers.append("outbound_weighing_missing")
    if "intake" not in stages:
        blockers.append("intake_weighing_missing")
    for w in ws:
        blockers += _weighing_blockers(db, w["id"], "input_scale")
    if require_witnessed_total and not any(w["witness"] for w in ws):
        blockers.append("third_party_input_witness_missing")
    return blockers


def _exclusion_inspection(db, boundary_id):
    rows_ = rows(db, "SELECT * FROM mr_inspections WHERE boundary_id=? ORDER BY at,id",
                 (boundary_id,))
    for insp in rows_:
        if (insp["method"] in EXCLUSION_METHODS and (insp["coverage"] or 0) >= 1.0
                and insp["pieces_total"] is not None
                and (insp["pieces_checked"] or 0) >= insp["pieces_total"]
                and insp["witness"]):
            return insp
    return None


def _custody_blockers(db, boundary):
    bid = boundary["id"]
    box_id = boundary["box_id"]
    blockers = []
    if not box_id:
        return ["seal_records_missing", "handover_records_missing"]
    seals = rows(db, "SELECT * FROM mr_seals WHERE box_id=? ORDER BY at,id", (box_id,))
    handovers = rows(db, "SELECT * FROM mr_handovers WHERE box_id=? ORDER BY at,id", (box_id,))
    if not seals:
        blockers.append("seal_records_missing")
    if not handovers:
        blockers.append("handover_records_missing")
    bad = [s for s in seals if s["state"] in ("re_stuck", "broken", "tampered")]
    if bad and not _exclusion_inspection(db, bid):
        blockers.append("seal_exception_not_witness_opened:" + bad[-1]["id"])
    return blockers


def _segregation_blockers(db, boundary_id):
    blockers = []
    members = rows(db, "SELECT * FROM mr_boundary_items WHERE boundary_id=?", (boundary_id,))
    for m in members:
        if m["status"] != "segregated":
            continue
        seg = one(db, "SELECT * FROM mr_segregations WHERE boundary_id=? AND item_id=?",
                  (boundary_id, m["item_id"]))
        if not seg:
            blockers.append("segregation_record_missing:" + m["item_id"])
            continue
        if not seg["witness"]:
            blockers.append("segregation_witness_missing:" + m["item_id"])
        if not seg["weighing_id"]:
            blockers.append("segregation_weighing_missing:" + m["item_id"])
        if not seg["to_owner"] and not seg["destination_id"]:
            blockers.append("segregation_destination_missing:" + m["item_id"])
        if seg["destination_id"] and not seg["receipt_ref"]:
            blockers.append("segregation_receipt_missing:" + m["item_id"])
    return blockers


def _boundary_for_item(db, item_id):
    m = one(db, "SELECT boundary_id FROM mr_boundary_items WHERE item_id=? LIMIT 1", (item_id,))
    return one(db, "SELECT * FROM mr_boundaries WHERE id=?", (m["boundary_id"],)) if m else None


# ---------------------------------------------------------------------------
# evaluators
# ---------------------------------------------------------------------------

def evaluate_unit(db, item_id, loss_fraction=DEFAULT_LOSS_FRACTION):
    ensure(db)
    item = one(db, "SELECT * FROM mr_items WHERE id=?", (item_id,))
    if not item:
        return {"decision": "missing_item", "eligible": False, "blockers": ["item_missing"]}

    blockers = []
    findings = []
    internal = _loads(item["internal_json"], {}) or {}

    if not item["appearance_json"] or not item["internal_json"] or not item["fingerprint"]:
        blockers.append("repeatable_appearance_internal_features_missing")

    peers = rows(db, "SELECT * FROM mr_items WHERE label_serial=?", (item["label_serial"],))
    same_fp = [p["id"] for p in peers
               if p["id"] != item_id and p["fingerprint"] == item["fingerprint"]]
    if same_fp:
        blockers.append("identity_not_independent:" + ",".join(same_fp))
    if len(peers) >= 2:
        findings.append("paper_label_shared_by_%d_pieces" % len(peers))

    battery_present = bool(internal.get("battery_present"))
    if item["battery_claim"] == "removed" and battery_present:
        findings.append("warehouse_battery_removal_claim_contradicted_by_xray")

    boundary = _boundary_for_item(db, item_id)
    if boundary:
        blockers += _custody_blockers(db, boundary)
        if boundary["charged_at"]:
            blockers.append("post_furnace_identity_unrecoverable")
    else:
        blockers += ["seal_records_missing", "handover_records_missing"]

    blockers += _input_blockers(db, "item", item_id)

    outs = rows(db, "SELECT * FROM mr_outputs WHERE item_id=? ORDER BY id", (item_id,))
    blockers += _output_blockers(db, outs, require_witness=False)
    if not any(o["category"] == "metal" for o in outs):
        blockers.append("metal_recovery_weighing_missing")
    if not any(o["category"] == "circuit_board" for o in outs):
        blockers.append("circuit_board_qualified_chain_missing")
    if battery_present and not any(o["category"] == "battery" for o in outs):
        blockers.append("hidden_battery_not_separated")

    bal = mass_balance(db, item_id=item_id, loss_fraction=loss_fraction)
    if bal["input_reading_ids"] and bal["closed"] is False and bal["unclosed_excess_g"]:
        blockers.append("mass_overrun")
    if bal["input_reading_ids"] and bal["closed"] is False and bal["unexplained_loss_g"]:
        blockers.append("mass_gap")

    return {"decision": "certifiable" if not blockers else "blocked",
            "eligible": not blockers, "item_id": item_id,
            "blockers": blockers, "findings": findings, "mass_balance": bal,
            "fingerprint": item["fingerprint"]}


def evaluate_batch(db, boundary_id, customer=None,
                    loss_fraction=DEFAULT_LOSS_FRACTION):
    ensure(db)
    boundary = one(db, "SELECT * FROM mr_boundaries WHERE id=?", (boundary_id,))
    if not boundary:
        return {"decision": "missing_boundary", "eligible": False,
                "blockers": ["boundary_missing"]}

    blockers = []
    auth = one(
        db,
        "SELECT * FROM mr_authorizations WHERE boundary_id=? "
        "ORDER BY rowid DESC LIMIT 1",
        (boundary_id,),
    )
    if not auth:
        blockers.append("batch_authorization_missing")
    elif customer and auth["customer"] != customer:
        blockers.append("batch_authorization_customer_mismatch")

    members = rows(db, "SELECT * FROM mr_boundary_items WHERE boundary_id=?", (boundary_id,))
    in_scope = [m for m in members if m["status"] == "in_scope"]
    if customer:
        for m in in_scope:
            if m["owner"] != customer:
                blockers.append("cross_owner_material_in_scope:" + m["item_id"])

    insp = _exclusion_inspection(db, boundary_id)
    if not insp:
        blockers.append("foreign_material_not_excluded_by_census")

    blockers += _segregation_blockers(db, boundary_id)
    blockers += _custody_blockers(db, boundary)
    blockers += _input_blockers(db, "boundary", boundary_id, require_witnessed_total=True)

    if boundary["charged_at"]:
        if not auth or not auth["at"] or auth["at"] > boundary["charged_at"]:
            blockers.append("authorization_after_charge")
        if not insp or not insp["at"] or insp["at"] > boundary["charged_at"]:
            blockers.append("identity_controls_after_charge")

    outs = rows(db, "SELECT * FROM mr_outputs WHERE boundary_id=? ORDER BY id", (boundary_id,))
    blockers += _output_blockers(db, outs, require_witness=True)
    if not any(o["category"] == "metal" for o in outs):
        blockers.append("metal_recovery_weighing_missing")
    if not any(o["category"] == "circuit_board" for o in outs):
        blockers.append("circuit_board_qualified_chain_missing")
    member_battery = False
    for m in in_scope:
        item = one(db, "SELECT internal_json FROM mr_items WHERE id=?", (m["item_id"],))
        if item and _loads(item["internal_json"], {}).get("battery_present"):
            member_battery = True
    if member_battery and not any(o["category"] == "battery" for o in outs):
        blockers.append("hidden_battery_not_separated")

    bal = mass_balance(db, boundary_id=boundary_id, loss_fraction=loss_fraction)
    if bal["input_reading_ids"] and bal["unclosed_excess_g"]:
        blockers.append("mass_overrun")
    if bal["input_reading_ids"] and bal["unexplained_loss_g"]:
        blockers.append("mass_gap")

    return {"decision": "certifiable" if not blockers else "blocked",
            "eligible": not blockers, "boundary_id": boundary_id,
            "blockers": blockers, "mass_balance": bal,
            "authorization_id": auth["id"] if auth else None,
            "exclusion_inspection_id": insp["id"] if insp else None}


# ---------------------------------------------------------------------------
# certificates
# ---------------------------------------------------------------------------

def get_certificate(db, certificate_id):
    ensure(db)
    row = one(db, "SELECT * FROM mr_certs WHERE id=?", (certificate_id,))
    if not row:
        return None
    body = _loads(row["body_json"], {})
    return {"certificate_id": row["id"], "kind": row["kind"],
            "customer": row["customer"], "boundary_id": row["boundary_id"],
            "issued_at": row["issued_at"], "signer": row["signer"],
            "signature": row["signature"], "body": body}


def verify_certificate(db, certificate_id):
    cert = get_certificate(db, certificate_id)
    if not cert:
        return False
    return verify_seal(cert["body"], {"signer": cert["signer"],
                                     "digest": cert["signature"]})


def _issue(db, certificate_id, kind, customer, boundary_id, body, signer, issued_at):
    issued_at = issued_at or _now()
    body = dict(body)
    body.setdefault("standard", "secretcourt.material_recovery/v1")
    body["certificate_id"] = certificate_id
    body["kind"] = kind
    body["issued_at"] = issued_at
    sealed = seal_body(body, signer)
    db.execute("INSERT INTO mr_certs VALUES(?,?,?,?,?,?,?,?)",
               (certificate_id, kind, customer, boundary_id, canonical(body),
                signer, sealed["digest"], issued_at))
    return {"decision": "signed", "certificate_id": certificate_id,
            "kind": kind, "signature": sealed, "certificate": body}


def certify_unit(db, certificate_id, item_id, signer="material-recovery-certifier",
                 issued_at=None, loss_fraction=DEFAULT_LOSS_FRACTION):
    ensure(db)
    old = one(db, "SELECT id FROM mr_certs WHERE id=?", (certificate_id,))
    if old:
        return {"decision": "reused", "certificate_id": certificate_id}
    ev = evaluate_unit(db, item_id, loss_fraction=loss_fraction)
    if not ev["eligible"]:
        return {"decision": "refused_certificate", "certificate_id": certificate_id,
                "blockers": ev["blockers"], "mass_balance": ev["mass_balance"]}

    item = one(db, "SELECT * FROM mr_items WHERE id=?", (item_id,))
    boundary = _boundary_for_item(db, item_id)
    outs = rows(db, "SELECT * FROM mr_outputs WHERE item_id=? ORDER BY category,id", (item_id,))
    streams = []
    for o in outs:
        dest = one(db, "SELECT id,facility,permit_id,chain,category FROM mr_destinations WHERE id=?",
                   (o["destination_id"],))
        streams.append({"output_id": o["id"], "category": o["category"],
                        "grams": o["grams"], "receipt_ref": o["receipt_ref"],
                        "weighing_id": o["weighing_id"], "destination": dest})
    body = {
        "granularity": "per_item_material_destination",
        "customer": item["customer"],
        "item_id": item_id,
        "label_serial": item["label_serial"],
        "identity": {
            "fingerprint": item["fingerprint"],
            "appearance": _loads(item["appearance_json"]),
            "internal": _loads(item["internal_json"]),
        },
        "findings": ev["findings"],
        "mass_balance": ev["mass_balance"],
        "streams": streams,
        "custody_boundary": boundary["id"] if boundary else None,
    }
    return _issue(db, certificate_id, "unit_itemized", item["customer"],
                  boundary["id"] if boundary else None, body, signer, issued_at)


def certify_batch(db, certificate_id, boundary_id, customer,
                  signer="material-recovery-certifier", issued_at=None,
                  loss_fraction=DEFAULT_LOSS_FRACTION):
    ensure(db)
    old = one(db, "SELECT id FROM mr_certs WHERE id=?", (certificate_id,))
    if old:
        return {"decision": "reused", "certificate_id": certificate_id}
    ev = evaluate_batch(db, boundary_id, customer=customer, loss_fraction=loss_fraction)
    if not ev["eligible"]:
        return {"decision": "refused_certificate", "certificate_id": certificate_id,
                "blockers": ev["blockers"], "mass_balance": ev["mass_balance"]}

    boundary = one(db, "SELECT * FROM mr_boundaries WHERE id=?", (boundary_id,))
    auth = one(db, "SELECT * FROM mr_authorizations WHERE id=?",
               (ev["authorization_id"],))
    outs = rows(db, "SELECT * FROM mr_outputs WHERE boundary_id=? ORDER BY category,id",
                (boundary_id,))
    streams = []
    for o in outs:
        dest = one(db, "SELECT id,facility,permit_id,chain,category FROM mr_destinations WHERE id=?",
                   (o["destination_id"],))
        streams.append({"output_id": o["id"], "category": o["category"],
                        "grams": o["grams"], "receipt_ref": o["receipt_ref"],
                        "weighing_id": o["weighing_id"], "destination": dest})
    body = {
        "granularity": "traceable_batch_totals_only",
        "per_unit_recovery_supported": False,
        "customer": customer,
        "boundary_id": boundary_id,
        "authorization": {
            "id": auth["id"], "actor": auth["actor"], "role": auth["role"],
            "at": auth["at"], "scope": _loads(auth["scope_json"]),
            "ack_seal_exception": bool(auth["ack_seal"]),
            "ack_co_mingle": bool(auth["ack_co"]),
        },
        "third_party_witness": ev["exclusion_inspection_id"] and one(
            db, "SELECT witness FROM mr_inspections WHERE id=?",
            (ev["exclusion_inspection_id"],))["witness"],
        "mass_balance": ev["mass_balance"],
        "streams": streams,
        "notice": ("Batch certificate gives witnessed input/output totals only; "
                   "no per-unit recovery ratio is asserted."),
    }
    return _issue(db, certificate_id, "batch_total", customer, boundary_id,
                  body, signer, issued_at)


# ---------------------------------------------------------------------------
# post-furnace commingling -- provable scope for every owner
# ---------------------------------------------------------------------------

def commingled_accounting(db, boundary_id, loss_fraction=DEFAULT_LOSS_FRACTION):
    ensure(db)
    boundary = one(db, "SELECT * FROM mr_boundaries WHERE id=?", (boundary_id,))
    if not boundary:
        return {"decision": "missing_boundary"}

    scopes = rows(db, "SELECT * FROM mr_owner_scopes WHERE boundary_id=? ORDER BY owner",
                  (boundary_id,))
    outs = rows(db, "SELECT * FROM mr_outputs WHERE boundary_id=? ORDER BY id", (boundary_id,))
    categories = {}
    accounted = 0.0
    for o in outs:
        categories[o["category"]] = round(categories.get(o["category"], 0.0) + o["grams"], 6)
        accounted += o["grams"]
    accounted = round(accounted, 6)

    owner_statements = []
    joint_low = joint_high = 0.0
    complete = bool(scopes)
    for s in scopes:
        low, high, ws = input_envelope(db, s["scope_kind"], s["scope_id"])
        stmt = {
            "owner": s["owner"],
            "scope_kind": s["scope_kind"],
            "scope_id": s["scope_id"],
            "provable_input_low_g": low,
            "provable_input_high_g": high,
            "input_reading_ids": [w["id"] for w in ws],
            "excess_of_total_outputs_over_owner_high_g": (
                None if high is None else round(max(0.0, accounted - high), 6)
            ),
        }
        if low is None:
            complete = False
            stmt["provable"] = False
        else:
            stmt["provable"] = True
            stmt["allocation_basis_g"] = round((low + high) / 2.0, 6)
            joint_low += low
            joint_high += high
        owner_statements.append(stmt)

    blockers = []
    if not scopes:
        blockers.append("no_owner_input_scopes")
    for s in owner_statements:
        if not s["provable"]:
            blockers.append("provable_input_incomplete:" + s["owner"])

    balance = None
    allocations = None
    unattributed_excess = None
    if complete:
        # The joint envelope is the sum of each owner's provable scope
        # envelopes (owner/boundary/item weighings), not boundary-kind rows.
        balance = _closure(joint_low, joint_high, accounted, loss_fraction)
        balance.update({"output_categories_g": categories, "accounted_g": accounted})
        unattributed_excess = balance["unclosed_excess_g"]
        if balance["closed"]:
            basis_total = sum(s["allocation_basis_g"] for s in owner_statements)
            allocations = []
            for s in owner_statements:
                share = s["allocation_basis_g"] / basis_total if basis_total else 0.0
                allocated_categories = {
                    cat: round(g * share, 6) for cat, g in categories.items()
                }
                allocated_total = round(sum(allocated_categories.values()), 6)
                allocations.append({
                    "owner": s["owner"],
                    "share": round(share, 6),
                    "allocated_outputs_g": allocated_categories,
                    "allocated_output_total_g": allocated_total,
                    "allocated_loss_g": round(s["allocation_basis_g"] - allocated_total, 6),
                    "basis": "provable_input_envelope_midpoint",
                    "measured_per_owner_recovery": False,
                })
        elif balance["unclosed_excess_g"]:
            blockers.append("mass_overrun")
        elif balance["unexplained_loss_g"]:
            blockers.append("mass_gap")

    return {
        "decision": "attributable" if allocations else "unattributable",
        "boundary_id": boundary_id,
        "furnace_charged": bool(boundary["charged_at"]),
        "identity_recoverable": False,
        "accounted_outputs_g": accounted,
        "output_categories_g": categories,
        "joint_input_low_g": joint_low if complete else None,
        "joint_input_high_g": joint_high if complete else None,
        "unattributed_excess_g": unattributed_excess,
        "mass_balance": balance,
        "owner_statements": owner_statements,
        "allocations": allocations,
        "blockers": blockers,
    }


def certify_commingled(db, certificate_id, boundary_id,
                       signer="material-recovery-certifier", issued_at=None,
                       loss_fraction=DEFAULT_LOSS_FRACTION):
    """Sign a joint pro-rata allocation statement for mixed owners."""
    ensure(db)
    old = one(db, "SELECT id FROM mr_certs WHERE id=?", (certificate_id,))
    if old:
        return {"decision": "reused", "certificate_id": certificate_id}

    accounting = commingled_accounting(db, boundary_id, loss_fraction=loss_fraction)
    if accounting["decision"] == "missing_boundary":
        return accounting
    blockers = list(accounting["blockers"])

    scopes = rows(db, "SELECT DISTINCT owner FROM mr_owner_scopes WHERE boundary_id=?",
                  (boundary_id,))
    if len(scopes) < 2:
        blockers.append("joint_batch_requires_two_owners")
    for s in scopes:
        auth = one(db, "SELECT id FROM mr_authorizations WHERE boundary_id=? AND customer=?",
                   (boundary_id, s["owner"]))
        if not auth:
            blockers.append("owner_authorization_missing:" + s["owner"])

    outs = rows(db, "SELECT * FROM mr_outputs WHERE boundary_id=? ORDER BY id", (boundary_id,))
    blockers += _output_blockers(db, outs, require_witness=True)
    if not any(o["category"] == "metal" for o in outs):
        blockers.append("metal_recovery_weighing_missing")

    if not accounting["allocations"]:
        blockers.append("no_closed_allocation_basis")

    if blockers:
        return {"decision": "refused_certificate", "certificate_id": certificate_id,
                "blockers": blockers, "accounting": accounting}

    owners = ",".join(sorted(s["owner"] for s in scopes))
    body = {
        "granularity": "joint_commingled_pro_rata_allocation",
        "per_unit_recovery_supported": False,
        "customer": owners,
        "boundary_id": boundary_id,
        "identity_after_furnace": "destroyed_single_unit_identity",
        "mass_balance": accounting["mass_balance"],
        "owner_statements": accounting["owner_statements"],
        "allocations": accounting["allocations"],
        "notice": ("Metal streams were physically commingled by the furnace. Each "
                   "owner receives a transparent pro-rata allocation over their "
                   "provable input envelope, not a measured recovery rate. Mass the "
                   "proven inputs cannot explain remains unattributed."),
    }
    return _issue(db, certificate_id, "commingled_allocation", owners,
                  boundary_id, body, signer, issued_at)
