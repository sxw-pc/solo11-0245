"""Causal loss adjustment, emergency advance, and recourse ledger.

Money is always a positive integer in the smallest currency unit.  Signed
adjustments are evidence snapshots: later logs or refunds create corrections
and ledger obligations, never mutate the signed adjustment.
"""
from __future__ import annotations

import json

from .store import one, rows, tx

PARTIES = ("customer", "platform", "insurer", "supplier")
RESPONSE_KINDS = {
    "credential_rotation",
    "key_rotation",
    "connection_credential_rotation",
    "cache_cleanup",
    "cleanup",
    "emergency_cleanup",
    "outsourcing",
    "outsourced_response",
    "emergency_team",
}
EXCLUDED_NECESSITY = {"unnecessary", "discretionary", "rejected"}
ADMITTED_NECESSITY = {
    "necessary",
    "required",
    "reasonable",
    "reasonable_necessary",
    "reasonable_and_necessary",
    "reasonable_preventive",
    "reasonable_preventive_replacement",
    "mitigation",
}


def _dumps(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def init(db):
    """Create the loss-recovery tables without touching earlier evidence."""
    statements = [
        """CREATE TABLE IF NOT EXISTS lr_claims(
            id TEXT PRIMARY KEY,
            exposure_id TEXT NOT NULL,
            customer_id TEXT NOT NULL,
            at INTEGER NOT NULL,
            notice_at INTEGER,
            notice_deadline INTEGER,
            review_deadline INTEGER,
            insurer_notice_days INTEGER NOT NULL DEFAULT 2,
            retention INTEGER NOT NULL DEFAULT 0,
            third_party_confirmed INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            request_json TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS lr_payment_originals(
            id TEXT PRIMARY KEY,
            invoice_id TEXT NOT NULL UNIQUE,
            proof_ref TEXT NOT NULL,
            amount INTEGER NOT NULL,
            paid_at INTEGER,
            payer TEXT,
            payee TEXT,
            request_json TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS lr_items(
            id TEXT PRIMARY KEY,
            claim_id TEXT NOT NULL,
            customer_id TEXT NOT NULL,
            invoice_id TEXT NOT NULL,
            payment_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            amount INTEGER NOT NULL,
            secret TEXT NOT NULL,
            gen INTEGER NOT NULL,
            location TEXT NOT NULL,
            delivery_receipt TEXT,
            loss_start INTEGER,
            loss_end INTEGER,
            necessity TEXT NOT NULL,
            causation TEXT,
            causation_evidence TEXT,
            allocation_json TEXT NOT NULL,
            admitted_amount INTEGER NOT NULL,
            held_amount INTEGER NOT NULL,
            excluded_amount INTEGER NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            request_json TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS lr_documents(
            id TEXT PRIMARY KEY,
            claim_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            signed_at INTEGER NOT NULL,
            signed_by TEXT,
            totals_json TEXT NOT NULL,
            notice_json TEXT NOT NULL,
            request_json TEXT NOT NULL,
            result_json TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS lr_ledger(
            id TEXT PRIMARY KEY,
            claim_id TEXT NOT NULL,
            document_id TEXT,
            correction_id TEXT,
            invoice_id TEXT,
            kind TEXT NOT NULL,
            from_party TEXT NOT NULL,
            to_party TEXT NOT NULL,
            amount INTEGER NOT NULL,
            status TEXT NOT NULL,
            pass_through INTEGER NOT NULL DEFAULT 0,
            counts_as_compensation INTEGER NOT NULL DEFAULT 1,
            instrument_ref TEXT,
            at INTEGER,
            cleared_at INTEGER,
            reason TEXT,
            request_json TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS lr_evidence(
            id TEXT PRIMARY KEY,
            claim_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            attribution TEXT NOT NULL,
            source TEXT,
            at INTEGER,
            resolution TEXT,
            resolved_at INTEGER,
            request_json TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS lr_corrections(
            id TEXT PRIMARY KEY,
            claim_id TEXT NOT NULL,
            document_id TEXT,
            kind TEXT NOT NULL,
            evidence_id TEXT,
            at INTEGER NOT NULL,
            title TEXT,
            amounts_json TEXT NOT NULL,
            routing_json TEXT NOT NULL,
            request_json TEXT NOT NULL,
            result_json TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS lr_recovery_claims(
            id TEXT PRIMARY KEY,
            claim_id TEXT NOT NULL,
            invoice_id TEXT NOT NULL,
            claimant_party TEXT NOT NULL,
            source_party TEXT NOT NULL,
            amount INTEGER NOT NULL,
            basis TEXT,
            at INTEGER,
            status TEXT NOT NULL,
            request_json TEXT NOT NULL,
            UNIQUE(invoice_id, claimant_party, source_party, basis)
        )""",
    ]
    for statement in statements:
        db.execute(statement)


def _missing_fields(payload, fields):
    return [name for name in fields if payload.get(name) in (None, "")]


def _interval_overlap(a_start, a_end, b_start, b_end):
    if None in (a_start, a_end, b_start, b_end):
        return 0
    return max(0, min(a_end, b_end) - max(a_start, b_start))


def allocate_detail(payload):
    """Allocate one claimed detail by causation, time, and necessity.

    Returns integer buckets satisfying amount = admitted + held + excluded.
    Downtime needs causal evidence; known pre-existing fault intervals are
    stripped proportionally.  Preventive response costs are admitted without
    proof that the exposed secret was read by a third party.
    """
    amount = payload.get("amount")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return {"decision": "invalid_amount"}

    necessity = payload.get("necessity")
    kind = payload.get("kind", "")
    if necessity in EXCLUDED_NECESSITY:
        return {
            "admitted_amount": 0,
            "held_amount": 0,
            "excluded_amount": amount,
            "status": "excluded",
            "reason": "not_reasonable_or_necessary",
        }

    start, end = payload.get("start", payload.get("loss_start")), payload.get("end", payload.get("loss_end"))
    fault_start = payload.get("fault_start")
    fault_end = payload.get("fault_end")
    causation = payload.get("causation", "")
    evidence = payload.get("causation_evidence")

    if kind == "downtime" or kind == "outage":
        if start is None or end is None or end < start:
            return {"decision": "invalid_loss_period"}
        total_duration = max(1, end - start)
        fault_duration = _interval_overlap(fault_start, fault_end, start, end)
        if causation == "preexisting_configuration_failure" and fault_duration == 0:
            fault_duration = total_duration

        if not evidence and causation != "preexisting_configuration_failure":
            return {
                "admitted_amount": 0,
                "held_amount": amount,
                "excluded_amount": 0,
                "status": "held",
                "reason": "downtime_causation_unproven",
                "fault_duration": fault_duration,
                "total_duration": total_duration,
            }

        excluded_amount = amount * fault_duration // total_duration
        remaining = amount - excluded_amount

        caused_start = payload.get("caused_start")
        caused_end = payload.get("caused_end")
        if caused_start is not None and caused_end is not None:
            proven_duration = _interval_overlap(caused_start, caused_end, start, end)
            proven_amount = amount * proven_duration // total_duration
            admitted_amount = max(0, proven_amount - excluded_amount)
            held_amount = remaining - admitted_amount
            reason = "apportioned_to_proven_causal_interval"
        else:
            admitted_amount = remaining
            held_amount = 0
            reason = "preexisting_fault_period_stripped" if excluded_amount else "exposure_caused_interval"

        return {
            "admitted_amount": admitted_amount,
            "held_amount": held_amount,
            "excluded_amount": excluded_amount,
            "status": "apportioned",
            "reason": reason,
            "fault_duration": fault_duration,
            "total_duration": total_duration,
        }

    if necessity == "review" or payload.get("requires_review"):
        return {
            "admitted_amount": 0,
            "held_amount": amount,
            "excluded_amount": 0,
            "status": "held",
            "reason": payload.get("review_reason", "necessity_or_fee_under_review"),
        }

    if necessity not in ADMITTED_NECESSITY:
        return {
            "admitted_amount": 0,
            "held_amount": 0,
            "excluded_amount": amount,
            "status": "excluded",
            "reason": "unrecognized_necessity_judgment",
        }

    reasonable_amount = payload.get("reasonable_amount")
    if isinstance(reasonable_amount, int) and 0 <= reasonable_amount < amount:
        return {
            "admitted_amount": reasonable_amount,
            "held_amount": amount - reasonable_amount,
            "excluded_amount": 0,
            "status": "partially_held",
            "reason": "amount_above_reasonable_benchmark",
        }

    return {
        "admitted_amount": amount,
        "held_amount": 0,
        "excluded_amount": 0,
        "status": "admitted",
        "reason": "reasonable_necessary_response",
        "external_read_required": False,
    }


def choose_outsourcing_fee(notice_at, *, timely_deadline, timely_fee, late_fee):
    """Select the contract fee supported by the actual notice time.

    Timely notice lets the customer use the panel rate.  If notice is late,
    the same-day unmanaged team is the reasonable available option.
    """
    if notice_at is None:
        return {"decision": "notice_time_required"}
    if notice_at <= timely_deadline:
        return {
            "decision": "fee_selected",
            "fee_code": "timely_panel_response",
            "amount": timely_fee,
            "notice_late": False,
        }
    return {
        "decision": "fee_selected",
        "fee_code": "late_notice_same_day_team",
        "amount": late_fee,
        "notice_late": True,
    }


def _open_claim(db, cmd):
    old = one(db, "SELECT * FROM lr_claims WHERE id=?", (cmd.get("id"),))
    if old:
        if old["request_json"] == _dumps(cmd):
            return {"decision": "reused", "claim": old["id"]}
        return {"decision": "claim_identity_conflict"}

    missing = _missing_fields(cmd, ["id", "exposure", "customer", "at"])
    if missing:
        return {"decision": "invalid_claim", "missing": missing}
    exposure = one(db, "SELECT * FROM exposures WHERE id=?", (cmd["exposure"],))
    if not exposure:
        return {"decision": "missing_exposure"}
    retention = cmd.get("retention", 0)
    if not isinstance(retention, int) or retention < 0:
        return {"decision": "invalid_retention"}

    db.execute(
        """INSERT INTO lr_claims(id, exposure_id, customer_id, at, notice_at,
           notice_deadline, review_deadline, insurer_notice_days, retention,
           third_party_confirmed, status, request_json)
           VALUES(?,?,?,?,?,?,?,?,?,0,'open',?)""",
        (
            cmd["id"], cmd["exposure"], cmd["customer"], cmd["at"],
            cmd.get("notice_at"), cmd.get("notice_deadline"), cmd.get("review_deadline"),
            cmd.get("insurer_notice_days", 2), retention, _dumps(cmd),
        ),
    )
    return {"decision": "claim_opened", "claim": cmd["id"], "exposure": cmd["exposure"]}


def _register_payment_original(db, cmd):
    old = one(db, "SELECT * FROM lr_payment_originals WHERE id=?", (cmd.get("id"),))
    if old:
        if old["request_json"] == _dumps(cmd):
            return {"decision": "reused", "payment": old["id"]}
        return {"decision": "payment_identity_conflict"}

    missing = _missing_fields(cmd, ["id", "invoice", "proof_ref", "amount"])
    if missing:
        return {"decision": "invalid_payment_original", "missing": missing}
    amount = cmd["amount"]
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return {"decision": "invalid_amount"}

    invoice = one(db, "SELECT id FROM lr_payment_originals WHERE invoice_id=?", (cmd["invoice"],))
    if invoice:
        return {"decision": "duplicate_invoice_original", "invoice": cmd["invoice"]}

    db.execute(
        """INSERT INTO lr_payment_originals(id, invoice_id, proof_ref, amount,
           paid_at, payer, payee, request_json) VALUES(?,?,?,?,?,?,?,?)""",
        (cmd["id"], cmd["invoice"], cmd["proof_ref"], amount, cmd.get("paid_at"),
         cmd.get("payer"), cmd.get("payee"), _dumps(cmd)),
    )
    return {"decision": "payment_original_registered", "payment": cmd["id"], "invoice": cmd["invoice"]}


def _verify_delivery(db, cmd, exposure):
    receipt_id = cmd.get("delivery_receipt")
    location = cmd.get("location")
    if receipt_id:
        receipt = one(
            db,
            """SELECT r.id, r.kind, r.uid, p.secret, p.gen
               FROM receipts r JOIN plans p ON p.id=r.plan_id
               WHERE r.id=?""",
            (receipt_id,),
        )
        if (not receipt or receipt["kind"] != "delivered" or receipt["uid"] != location
                or receipt["secret"] != cmd["secret"] or receipt["gen"] != cmd["gen"]):
            return "usage_evidence_mismatch", None
        return None, receipt_id

    found = one(
        db,
        """SELECT r.id FROM receipts r JOIN plans p ON p.id=r.plan_id
           WHERE p.secret=? AND p.gen=? AND r.uid=? AND r.kind='delivered'
           LIMIT 1""",
        (cmd["secret"], cmd["gen"], location),
    )
    return (None, found["id"]) if found else (None, None)


def _add_item(db, cmd):
    old = one(db, "SELECT * FROM lr_items WHERE id=?", (cmd.get("id"),))
    if old:
        if old["request_json"] == _dumps(cmd):
            return {"decision": "reused", "item": old["id"]}
        return {"decision": "item_identity_conflict"}

    claim = one(db, "SELECT * FROM lr_claims WHERE id=?", (cmd.get("claim"),))
    if not claim:
        return {"decision": "missing_claim"}

    missing = _missing_fields(
        cmd,
        ["id", "claim", "customer", "invoice", "payment", "kind", "amount",
         "secret", "gen", "location", "necessity"],
    )
    if missing:
        return {"decision": "invalid_loss_detail", "missing": missing}

    if one(db, "SELECT id FROM lr_documents WHERE claim_id=?", (claim["id"],)):
        return {"decision": "signed_adjustment_frozen_use_correction"}

    payment = one(db, "SELECT * FROM lr_payment_originals WHERE id=?", (cmd["payment"],))
    if not payment or payment["invoice_id"] != cmd["invoice"]:
        return {"decision": "payment_original_missing_or_invoice_mismatch"}

    exposure = one(db, "SELECT * FROM exposures WHERE id=?", (claim["exposure_id"],))
    if not exposure:
        return {"decision": "missing_exposure"}
    if cmd["secret"] != exposure["secret"] or cmd["gen"] != exposure["gen"]:
        return {"decision": "detail_not_bound_to_affected_generation"}

    amount = cmd["amount"]
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return {"decision": "invalid_amount"}
    start = cmd.get("start", cmd.get("loss_start"))
    end = cmd.get("end", cmd.get("loss_end"))
    if start is None or end is None or not isinstance(start, int) or not isinstance(end, int) or end < start:
        return {"decision": "invalid_loss_period"}

    bound_claim = one(db, "SELECT claim_id FROM lr_items WHERE invoice_id=? LIMIT 1", (cmd["invoice"],))
    if bound_claim and bound_claim["claim_id"] != claim["id"]:
        return {"decision": "invoice_claim_conflict", "invoice": cmd["invoice"]}

    used = one(db, "SELECT COALESCE(SUM(amount),0) n FROM lr_items WHERE payment_id=?", (cmd["payment"],))["n"]
    if used + cmd["amount"] > payment["amount"]:
        return {"decision": "invoice_lines_exceed_payment_original"}

    mismatch, bound_receipt = _verify_delivery(db, cmd, exposure)
    if mismatch:
        return {"decision": mismatch}

    allocation = allocate_detail(cmd)
    if "decision" in allocation:
        return allocation

    db.execute(
        """INSERT INTO lr_items(id, claim_id, customer_id, invoice_id, payment_id,
           kind, amount, secret, gen, location, delivery_receipt, loss_start, loss_end,
           necessity, causation, causation_evidence, allocation_json,
           admitted_amount, held_amount, excluded_amount, status, reason, request_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            cmd["id"], claim["id"], cmd["customer"], cmd["invoice"], cmd["payment"],
            cmd["kind"], cmd["amount"], cmd["secret"], cmd["gen"], cmd["location"],
            cmd.get("delivery_receipt") or bound_receipt, cmd.get("start", cmd.get("loss_start")),
            cmd.get("end", cmd.get("loss_end")), cmd["necessity"], cmd.get("causation"),
            cmd.get("causation_evidence"), _dumps(allocation),
            allocation["admitted_amount"], allocation["held_amount"],
            allocation["excluded_amount"], allocation["status"], allocation.get("reason"),
            _dumps(cmd),
        ),
    )
    return {
        "decision": "loss_detail_recorded",
        "item": cmd["id"],
        **{k: allocation[k] for k in ("admitted_amount", "held_amount", "excluded_amount", "status", "reason")},
    }


def _totals(db, claim_id):
    row = one(
        db,
        """SELECT COALESCE(SUM(amount),0) claimed_total,
                  COALESCE(SUM(admitted_amount),0) admitted_total,
                  COALESCE(SUM(held_amount),0) item_held_total,
                  COALESCE(SUM(excluded_amount),0) excluded_total
           FROM lr_items WHERE claim_id=?""",
        (claim_id,),
    )
    return dict(row)


def _sign_document(db, cmd):
    doc_id = cmd.get("id")
    old = one(db, "SELECT * FROM lr_documents WHERE id=?", (doc_id,))
    if old:
        if old["request_json"] == _dumps(cmd):
            return json.loads(old["result_json"])
        return {"decision": "document_identity_conflict"}

    claim = one(db, "SELECT * FROM lr_claims WHERE id=?", (cmd.get("claim"),))
    if not claim:
        return {"decision": "missing_claim"}
    if cmd.get("kind") not in ("advance_deed", "partial_settlement"):
        return {"decision": "unknown_document_kind"}
    if one(db, "SELECT id FROM lr_documents WHERE claim_id=?", (claim["id"],)):
        return {"decision": "election_already_signed"}
    if not rows(db, "SELECT id FROM lr_items WHERE claim_id=?", (claim["id"],)):
        return {"decision": "no_loss_details"}

    totals = _totals(db, claim["id"])
    admitted = totals["admitted_total"]
    item_held = totals["item_held_total"]
    requested_hold = cmd.get("hold_amount", 0 if cmd["kind"] == "advance_deed" else item_held)
    advance_amount = cmd.get("advance_amount", admitted)

    if not isinstance(requested_hold, int) or requested_hold < 0 or requested_hold > admitted:
        return {"decision": "invalid_hold_amount"}
    if not isinstance(advance_amount, int) or advance_amount < 0 or advance_amount > admitted:
        return {"decision": "invalid_advance_amount"}

    if cmd["kind"] == "advance_deed":
        immediate = advance_amount
        elective_hold = 0
        notice = {
            "document": "advance_and_subrogation_deed",
            "obligor": "platform",
            "due_at": cmd["at"] + claim["insurer_notice_days"],
            "to": ["insurer", "supplier"],
            "payment_direction": "platform_for_advance_account",
            "subrogation": True,
            "customer_cash": "immediate_settled_advance",
        }
    else:
        immediate = admitted - requested_hold
        elective_hold = requested_hold
        notice = {
            "document": "confirmed_payment_and_dispute_preservation",
            "obligor": "platform_and_customer_joint_for_hold",
            "due_at": claim["review_deadline"],
            "to": ["insurer"],
            "payment_direction": "claimant_or_time_limited_hold",
            "subrogation": False,
            "confirmed_part_final": True,
            "customer_cash": "confirmed_part_now_remainder_on_review",
        }

    totals.update({
        "elective_hold_total": elective_hold,
        "immediate_total": immediate,
        "preserved_total": item_held + elective_hold,
        "retention": claim["retention"],
        "potential_insurance_cover": max(0, admitted + item_held - claim["retention"]),
    })
    result = {
        "decision": "signed",
        "document": doc_id,
        "kind": cmd["kind"],
        "totals": totals,
        "notice": notice,
        "review_deadline": claim["review_deadline"],
    }
    db.execute(
        """INSERT INTO lr_documents(id, claim_id, kind, signed_at, signed_by,
           totals_json, notice_json, request_json, result_json)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (doc_id, claim["id"], cmd["kind"], cmd["at"], cmd.get("signed_by", "customer"),
         _dumps(totals), _dumps(notice), _dumps(cmd), _dumps(result)),
    )
    db.execute("UPDATE lr_claims SET status=? WHERE id=?", ("signed", claim["id"]))
    return result


def _customer_compensation(db, invoice_id, exclude_id=None):
    sql = """SELECT COALESCE(SUM(amount),0) n FROM lr_ledger
             WHERE invoice_id=? AND to_party='customer'
               AND status!='bounced' AND pass_through=0
               AND counts_as_compensation=1"""
    args = [invoice_id]
    if exclude_id:
        sql += " AND id!=?"
        args.append(exclude_id)
    return one(db, sql, tuple(args))["n"]


def _invoice_cap(db, invoice_id):
    row = one(
        db,
        "SELECT COALESCE(SUM(admitted_amount + held_amount),0) n FROM lr_items WHERE invoice_id=?",
        (invoice_id,),
    )
    return row["n"] if row else 0


def _insert_transfer(db, cmd, *, status="settled"):
    if cmd.get("from_party") not in PARTIES or cmd.get("to_party") not in PARTIES:
        return {"decision": "unknown_party"}
    amount = cmd.get("amount")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return {"decision": "invalid_amount"}

    old = one(db, "SELECT * FROM lr_ledger WHERE id=?", (cmd.get("id"),))
    if old:
        if old["request_json"] == _dumps(cmd):
            return {"decision": "reused", "transfer": old["id"], "status": old["status"]}
        return {"decision": "transfer_identity_conflict"}

    claim = one(db, "SELECT * FROM lr_claims WHERE id=?", (cmd.get("claim"),))
    if not claim:
        return {"decision": "missing_claim"}

    invoice_id = cmd.get("invoice")
    pass_through = 1 if cmd.get("pass_through") else 0
    counts = 0 if pass_through else cmd.get("counts_as_compensation", 1)
    if invoice_id and cmd["to_party"] == "customer" and counts:
        already = _customer_compensation(db, invoice_id)
        cap = _invoice_cap(db, invoice_id)
        if already + amount > cap:
            return {
                "decision": "invoice_double_recovery",
                "invoice": invoice_id,
                "already_committed": already,
                "requested": amount,
                "cap": cap,
            }

    db.execute(
        """INSERT INTO lr_ledger(id, claim_id, document_id, correction_id, invoice_id,
           kind, from_party, to_party, amount, status, pass_through,
           counts_as_compensation, instrument_ref, at, cleared_at, reason, request_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            cmd["id"], claim["id"], cmd.get("document"), cmd.get("correction"), invoice_id,
            cmd.get("kind", "transfer"), cmd["from_party"], cmd["to_party"], amount,
            cmd.get("status", status), pass_through, counts, cmd.get("instrument_ref"),
            cmd.get("at"), cmd.get("cleared_at", cmd.get("at") if status == "settled" else None),
            cmd.get("reason"), _dumps(cmd),
        ),
    )
    return {"decision": "transfer_recorded", "transfer": cmd["id"], "status": cmd.get("status", status)}


def _issue_payment(db, cmd):
    doc = one(db, "SELECT * FROM lr_documents WHERE id=?", (cmd.get("document"),))
    if not doc:
        return {"decision": "missing_signed_document"}
    totals = json.loads(doc["totals_json"])
    amount = cmd.get("amount")
    if not isinstance(amount, int) or amount <= 0:
        return {"decision": "invalid_amount"}

    if doc["kind"] == "advance_deed":
        cap = totals["immediate_total"]
        kind = "advance"
    else:
        cap = totals["immediate_total"]
        kind = "settlement"
    paid = one(
        db,
        """SELECT COALESCE(SUM(amount),0) n FROM lr_ledger
           WHERE document_id=? AND id!=?
             AND from_party='platform' AND to_party='customer'
             AND status!='bounced'""",
        (doc["id"], cmd.get("id", "")),
    )["n"]
    if paid + amount > cap:
        return {"decision": "payment_exceeds_signed_due_amount", "remaining": cap - paid}

    transfer_cmd = {
        **cmd,
        "op": "record_transfer",
        "claim": doc["claim_id"],
        "from_party": "platform",
        "to_party": "customer",
        "kind": cmd.get("kind", kind),
        "status": "issued",
    }
    return _insert_transfer(db, transfer_cmd, status="issued")


def _payment_event(db, cmd, new_status):
    payment = one(db, "SELECT * FROM lr_ledger WHERE id=?", (cmd.get("id"),))
    if not payment:
        return {"decision": "unknown_payment"}
    if payment["status"] == new_status:
        return {"decision": "reused", "payment": payment["id"], "status": new_status}
    if payment["status"] == "bounced" and new_status != "issued":
        return {"decision": "bounced_instrument_must_be_reissued"}
    db.execute(
        "UPDATE lr_ledger SET status=?, reason=COALESCE(?,reason), cleared_at=? WHERE id=?",
        (new_status, cmd.get("reason"), cmd.get("at") if new_status == "settled" else None, payment["id"]),
    )
    return {"decision": "cleared" if new_status == "settled" else new_status, "payment": payment["id"]}


def _record_evidence(db, cmd):
    old = one(db, "SELECT * FROM lr_evidence WHERE id=?", (cmd.get("id"),))
    if old:
        if old["request_json"] == _dumps(cmd):
            return {"decision": "reused", "evidence": old["id"]}
        return {"decision": "evidence_identity_conflict"}
    claim = one(db, "SELECT id FROM lr_claims WHERE id=?", (cmd.get("claim"),))
    if not claim:
        return {"decision": "missing_claim"}
    db.execute(
        """INSERT INTO lr_evidence(id, claim_id, kind, attribution, source, at,
           resolution, resolved_at, request_json) VALUES(?,?,?,?,?, ?,?,?,?)""",
        (cmd["id"], cmd["claim"], cmd.get("kind", "unseal_log"),
         cmd.get("attribution", "undetermined"), cmd.get("source", "supplier"),
         cmd.get("at"), None, None, _dumps(cmd)),
    )
    return {"decision": "evidence_recorded", "evidence": cmd["id"]}


def _supplier_split(loss_amount, insurance_cover, supplier_liable):
    supplier_liable = max(0, min(supplier_liable, loss_amount))
    if loss_amount == 0 or supplier_liable == 0:
        return {"supplier_to_insurer": 0, "supplier_to_platform": 0}
    to_insurer = supplier_liable * insurance_cover // loss_amount
    return {
        "supplier_to_insurer": to_insurer,
        "supplier_to_platform": supplier_liable - to_insurer,
    }


def _resolve_log(db, cmd):
    evidence = one(db, "SELECT * FROM lr_evidence WHERE id=?", (cmd.get("id"),))
    if not evidence:
        return {"decision": "missing_unseal_log"}
    attribution = cmd.get("attribution")
    if attribution not in ("legitimate_retry", "unregistered_external"):
        return {"decision": "unknown_log_attribution"}

    if evidence["resolution"]:
        if evidence["resolution"] == attribution:
            prior = one(db, "SELECT * FROM lr_corrections WHERE evidence_id=?", (evidence["id"],))
            return json.loads(prior["result_json"]) if prior else {"decision": "reused"}
        return {"decision": "late_log_already_resolved"}

    claim = one(db, "SELECT * FROM lr_claims WHERE id=?", (evidence["claim_id"],))
    doc = one(db, "SELECT * FROM lr_documents WHERE claim_id=? ORDER BY signed_at LIMIT 1", (claim["id"],))
    if not doc:
        return {"decision": "no_signed_adjustment_to_correct"}

    correction_id = cmd.get("correction_id", f"correction-{evidence['id']}")
    old_correction = one(db, "SELECT * FROM lr_corrections WHERE id=?", (correction_id,))
    if old_correction:
        return json.loads(old_correction["result_json"])

    totals = json.loads(doc["totals_json"])
    loss_amount = totals["admitted_total"] + totals["item_held_total"]
    external = attribution == "unregistered_external"
    retention = claim["retention"]
    insurance_cover = max(0, loss_amount - retention) if external else 0
    platform_retention = min(retention, loss_amount) if external else 0
    supplier_liable = cmd.get("supplier_liable", 0)
    split = _supplier_split(loss_amount, insurance_cover, supplier_liable)

    if doc["kind"] == "advance_deed":
        routing = {
            "customer_additional_due": 0,
            "insurer_to_platform": insurance_cover,
            "platform_to_customer": 0,
            "supplier_to_platform": supplier_liable,
            "platform_to_insurer_subrogation": split["supplier_to_insurer"],
            "platform_retains_from_supplier": split["supplier_to_platform"],
        }
    else:
        preserved = totals["preserved_total"]
        immediate = totals["immediate_total"]
        insurer_to_customer = min(preserved, insurance_cover) if external else 0
        if external:
            insurer_to_platform = max(0, insurance_cover - insurer_to_customer)
            platform_release = max(0, preserved - insurer_to_customer)
        else:
            insurer_to_customer = 0
            insurer_to_platform = 0
            platform_release = preserved
        routing = {
            "customer_additional_due": preserved,
            "insurer_to_customer": insurer_to_customer,
            "insurer_to_platform": insurer_to_platform,
            "platform_to_customer_hold_release": platform_release,
            "supplier_to_platform": supplier_liable,
            "platform_to_insurer_subrogation": split["supplier_to_insurer"],
            "platform_retains_from_supplier": split["supplier_to_platform"],
            "already_paid_confirmed": immediate,
        }

    amounts = {
        "loss_amount": loss_amount,
        "third_party_disclosure_confirmed": external,
        "insurance_cover": insurance_cover,
        "platform_retention": platform_retention,
        "uninsured_platform_service_amount": 0 if external else loss_amount,
        "supplier_liable": supplier_liable,
        "supplier_allocation": split,
        "insurer_net_burden_before_actual_flows": insurance_cover - split["supplier_to_insurer"],
        "platform_net_burden_before_actual_flows": (
            (loss_amount - insurance_cover) - split["supplier_to_platform"]
        ),
        "supplier_net_burden_before_actual_flows": supplier_liable,
    }
    result = {
        "decision": "correction_recorded",
        "correction": correction_id,
        "original_document": doc["id"],
        "attribution": attribution,
        "amounts": amounts,
        "routing": routing,
        "signed_adjustment_unchanged": True,
    }

    db.execute(
        "UPDATE lr_evidence SET resolution=?, resolved_at=? WHERE id=?",
        (attribution, cmd.get("at"), evidence["id"]),
    )
    if external:
        db.execute("UPDATE lr_claims SET third_party_confirmed=1 WHERE id=?", (claim["id"],))
    db.execute(
        """INSERT INTO lr_corrections(id, claim_id, document_id, kind, evidence_id,
           at, title, amounts_json, routing_json, request_json, result_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            correction_id, claim["id"], doc["id"], "late_unseal_log", evidence["id"],
            cmd.get("at", 0), "Late unseal attribution correction",
            _dumps(amounts), _dumps(routing), _dumps(cmd), _dumps(result),
        ),
    )
    return result


def _record_refund(db, cmd):
    claim = one(db, "SELECT * FROM lr_claims WHERE id=?", (cmd.get("claim"),))
    if not claim:
        return {"decision": "missing_claim"}
    doc = one(db, "SELECT * FROM lr_documents WHERE claim_id=? ORDER BY signed_at LIMIT 1", (claim["id"],))
    correction_id = cmd.get("correction_id", cmd.get("id"))
    old = one(db, "SELECT * FROM lr_corrections WHERE id=?", (correction_id,))
    if old:
        return json.loads(old["result_json"])
    amount = cmd.get("amount")
    if not isinstance(amount, int) or amount <= 0:
        return {"decision": "invalid_amount"}

    amounts = {"refunded_loss": amount, "recoverable_duplicate": amount}
    routing = {
        "refund_from": cmd.get("from_party", "outsourcer"),
        "refund_to": "customer",
        "customer_to_platform_clawback": amount,
    }
    result = {
        "decision": "refund_correction_recorded",
        "correction": correction_id,
        "original_document": doc["id"] if doc else None,
        "amounts": amounts,
        "routing": routing,
        "signed_adjustment_unchanged": True,
    }
    db.execute(
        """INSERT INTO lr_corrections(id, claim_id, document_id, kind, evidence_id,
           at, title, amounts_json, routing_json, request_json, result_json)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            correction_id, claim["id"], doc["id"] if doc else None, "late_refund",
            cmd.get("refund_evidence"), cmd.get("at", 0), "Late refund correction",
            _dumps(amounts), _dumps(routing), _dumps(cmd), _dumps(result),
        ),
    )
    return result


def file_recovery(db, cmd):
    """Persist a recovery demand while blocking duplicate customer invoices."""
    old = one(db, "SELECT * FROM lr_recovery_claims WHERE id=?", (cmd.get("id"),))
    if old:
        if old["request_json"] == _dumps(cmd):
            return {"decision": "reused", "recovery_claim": old["id"]}
        return {"decision": "recovery_claim_identity_conflict"}

    missing = _missing_fields(cmd, ["id", "claim", "invoice", "claimant", "source", "amount"])
    if missing:
        return {"decision": "invalid_recovery_claim", "missing": missing}
    amount = cmd["amount"]
    if not isinstance(amount, int) or amount <= 0:
        return {"decision": "invalid_amount"}

    if cmd["claimant"] == "customer":
        cap = _invoice_cap(db, cmd["invoice"])
        already_paid_or_committed = _customer_compensation(db, cmd["invoice"])
        row = one(
            db,
            """SELECT COALESCE(SUM(amount),0) n FROM lr_recovery_claims
               WHERE invoice_id=? AND claimant_party='customer' AND status!='rejected'""",
            (cmd["invoice"],),
        )
        if already_paid_or_committed + row["n"] + amount > cap:
            return {
                "decision": "invoice_triple_recovery_barred",
                "cap": cap,
                "already_compensated": already_paid_or_committed,
                "claimed": row["n"] + amount,
            }

    db.execute(
        """INSERT INTO lr_recovery_claims(id, claim_id, invoice_id, claimant_party,
           source_party, amount, basis, at, status, request_json)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (cmd["id"], cmd["claim"], cmd["invoice"], cmd["claimant"], cmd["source"], amount,
         cmd.get("basis"), cmd.get("at"), cmd.get("status", "filed"), _dumps(cmd)),
    )
    return {"decision": "recovery_filed", "recovery_claim": cmd["id"]}


def statement(db, claim_id):
    """Return line items, documents, corrections, cash, and party burdens."""
    init(db)
    claim = one(db, "SELECT * FROM lr_claims WHERE id=?", (claim_id,))
    if not claim:
        return {"decision": "missing_claim"}

    items = rows(db, "SELECT * FROM lr_items WHERE claim_id=? ORDER BY id", (claim_id,))
    documents = rows(db, "SELECT * FROM lr_documents WHERE claim_id=? ORDER BY signed_at,id", (claim_id,))
    corrections = rows(db, "SELECT * FROM lr_corrections WHERE claim_id=? ORDER BY at,id", (claim_id,))
    ledger = rows(db, "SELECT * FROM lr_ledger WHERE claim_id=? ORDER BY at,id", (claim_id,))
    recovery_claims = rows(db, "SELECT * FROM lr_recovery_claims WHERE claim_id=? ORDER BY id", (claim_id,))

    for item in items:
        item["allocation"] = json.loads(item.pop("allocation_json"))
    for doc in documents:
        doc["totals"] = json.loads(doc.pop("totals_json"))
        doc["notice"] = json.loads(doc.pop("notice_json"))
    for correction in corrections:
        correction["amounts"] = json.loads(correction.pop("amounts_json"))
        correction["routing"] = json.loads(correction.pop("routing_json"))

    settled = [e for e in ledger if e["status"] == "settled"]
    customer_in = sum(e["amount"] for e in settled if e["to_party"] == "customer")
    customer_out = sum(e["amount"] for e in settled if e["from_party"] == "customer")
    party_burden = {}
    for party in PARTIES:
        paid = sum(e["amount"] for e in settled if e["from_party"] == party)
        received = sum(e["amount"] for e in settled if e["to_party"] == party)
        party_burden[party] = {
            "paid": paid,
            "recovered": received,
            "net_burden": paid - received,
        }

    bounced = [e for e in ledger if e["status"] == "bounced"]
    issued = [e for e in ledger if e["status"] == "issued"]
    totals = _totals(db, claim_id)

    by_kind = {}
    for entry in ledger:
        bucket = by_kind.setdefault(entry["kind"], {"issued": 0, "settled": 0, "bounced": 0})
        if entry["status"] in bucket:
            bucket[entry["status"]] += entry["amount"]

    def settled_sum(**filters):
        return sum(
            e["amount"] for e in settled
            if all(e.get(key) == value for key, value in filters.items())
        )

    platform_retention_recognized = sum(c["amounts"].get("platform_retention", 0) for c in corrections)
    uninsured_service_recognized = sum(
        c["amounts"].get("uninsured_platform_service_amount", 0) for c in corrections
    )
    subledger = {
        "by_kind": by_kind,
        "customer_advances_settled": settled_sum(kind="advance", to_party="customer"),
        "confirmed_settlements_settled": settled_sum(kind="settlement", to_party="customer"),
        "hold_releases_settled": settled_sum(kind="hold_release", to_party="customer"),
        "insurance_indemnities_settled": settled_sum(kind="insurance_indemnity"),
        "supplier_recoveries_settled": settled_sum(kind="supplier_recovery"),
        "platform_retention_recognized": platform_retention_recognized,
        "platform_uninsured_service_recognized": uninsured_service_recognized,
    }
    return {
        "decision": "statement",
        "claim": dict(claim),
        "totals": totals,
        "items": items,
        "documents": documents,
        "corrections": corrections,
        "ledger": ledger,
        "recovery_claims": recovery_claims,
        "subledger": subledger,
        "cash": {
            "customer_settled_inflows": customer_in,
            "customer_settled_outflows": customer_out,
            "customer_actual_net_receipt": customer_in - customer_out,
            "issued_pending": sum(e["amount"] for e in issued),
            "bounced_amount": sum(e["amount"] for e in bounced),
        },
        "party_burden": party_burden,
    }


def run(db, cmd):
    init(db)
    op = cmd.get("op")
    with tx(db):
        if op == "open_claim":
            return _open_claim(db, cmd)
        if op == "register_payment_original":
            return _register_payment_original(db, cmd)
        if op == "add_item":
            return _add_item(db, cmd)
        if op == "sign_document":
            return _sign_document(db, cmd)
        if op == "issue_payment":
            return _issue_payment(db, cmd)
        if op == "clear_payment":
            return _payment_event(db, cmd, "settled")
        if op == "bounce_payment":
            return _payment_event(db, cmd, "bounced")
        if op == "record_transfer":
            return _insert_transfer(db, cmd)
        if op == "record_unseal_log":
            return _record_evidence(db, cmd)
        if op == "resolve_unseal_log":
            return _resolve_log(db, cmd)
        if op == "record_refund":
            return _record_refund(db, cmd)
        if op == "file_recovery":
            return file_recovery(db, cmd)
        if op == "statement":
            return statement(db, cmd["claim"])
        raise ValueError(op)


# Small direct wrappers for callers that prefer functions over command dicts.
def open_claim(db, **cmd):
    cmd["op"] = "open_claim"
    return run(db, cmd)


def add_item(db, **cmd):
    cmd["op"] = "add_item"
    return run(db, cmd)


def sign_document(db, **cmd):
    cmd["op"] = "sign_document"
    return run(db, cmd)


def issue_payment(db, **cmd):
    cmd["op"] = "issue_payment"
    return run(db, cmd)


def clear_payment(db, payment_id, at=None):
    return run(db, {"op": "clear_payment", "id": payment_id, "at": at})


def bounce_payment(db, payment_id, reason, at=None):
    return run(db, {"op": "bounce_payment", "id": payment_id, "reason": reason, "at": at})


def record_transfer(db, **cmd):
    cmd["op"] = "record_transfer"
    return run(db, cmd)


def resolve_unseal_log(db, **cmd):
    cmd["op"] = "resolve_unseal_log"
    return run(db, cmd)
