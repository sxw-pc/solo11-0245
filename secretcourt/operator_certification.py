"""Natural-person operator certification and duty scheduling boundaries.

The important boundary in this module is not a certificate number or the count
of distinct login names.  Every qualification is attached to a natural person;
accounts, badges and signers are only independently evidenced bindings to that
person.  Scheduling and grant approval then reason about those people.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import grant
from .store import SCHEMA as COURT_SCHEMA, one, rows

# Assessment identity states.
SELF_COMPLETED = "self_completed"
PROXY_UNRESOLVED = "proxy_unresolved"
PROXY_CONFIRMED = "proxy_confirmed"
IDENTITY_STATES = {SELF_COMPLETED, PROXY_UNRESOLVED, PROXY_CONFIRMED}
IDENTITY_STATUS_ALIASES = {
    "本人完成": SELF_COMPLETED,
    "替考未排除": PROXY_UNRESOLVED,
    "未排除替考": PROXY_UNRESOLVED,
    "已认定替考": PROXY_CONFIRMED,
    "确认替考": PROXY_CONFIRMED,
}
IDENTITY_STATUS_LABELS = {
    SELF_COMPLETED: "本人完成",
    PROXY_UNRESOLVED: "替考未排除",
    PROXY_CONFIRMED: "已认定替考",
}

# Certificate classes.  A limited certificate must never be serialized as a
# full certificate or used outside its named equipment/operation/site scope.
FULL = "full"
LIMITED_SUPERVISED = "limited_supervised"

PERSON_ACTIVE = "active"
PERSON_SUSPENDED = "suspended"
PERSON_DEPARTED = "departed"

SERVICE_ACTOR = "service"
HUMAN_ACTOR = "human"

DEFAULT_FAR_FUTURE = 10**12

SCHEMA = """
CREATE TABLE IF NOT EXISTS opcert_persons(
    id TEXT PRIMARY KEY,
    name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    status_changed_at INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS opcert_subjects(
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    person_id TEXT,
    account_class TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    label TEXT,
    bound_at INTEGER NOT NULL DEFAULT 0,
    evidence_id TEXT
);

CREATE TABLE IF NOT EXISTS opcert_binding_evidence(
    id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    person_id TEXT,
    source_kind TEXT,
    reference TEXT,
    independent INTEGER NOT NULL DEFAULT 1,
    verified_by TEXT,
    verified_at INTEGER NOT NULL DEFAULT 0,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS opcert_organizations(
    id TEXT PRIMARY KEY,
    name TEXT,
    kind TEXT NOT NULL DEFAULT 'training',
    accreditation TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    valid_from INTEGER NOT NULL DEFAULT 0,
    valid_until INTEGER NOT NULL DEFAULT 1000000000000,
    status_changed_at INTEGER,
    revocation_reason TEXT,
    created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS opcert_examiners(
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    valid_from INTEGER NOT NULL DEFAULT 0,
    valid_until INTEGER NOT NULL DEFAULT 1000000000000,
    status_changed_at INTEGER,
    revocation_reason TEXT,
    created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS opcert_assessments(
    id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL,
    skill TEXT NOT NULL,
    equipment_class TEXT NOT NULL DEFAULT '*',
    provider_id TEXT,
    examiner_id TEXT,
    taken_at INTEGER NOT NULL DEFAULT 0,
    result TEXT NOT NULL DEFAULT 'passed',
    identity_status TEXT NOT NULL,
    actual_person_id TEXT,
    status TEXT NOT NULL DEFAULT 'recorded',
    note TEXT,
    created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS opcert_assessment_evidence(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    reference TEXT,
    independent INTEGER NOT NULL DEFAULT 1,
    proves_person_id TEXT,
    verified_by TEXT,
    captured_at INTEGER NOT NULL DEFAULT 0,
    added_at INTEGER NOT NULL DEFAULT 0,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS opcert_site_signings(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    at INTEGER NOT NULL DEFAULT 0,
    factor_ids TEXT NOT NULL DEFAULT '[]',
    bound_person_ids TEXT NOT NULL DEFAULT '[]',
    asserted_person_id TEXT,
    identity_status TEXT NOT NULL,
    evidence_id TEXT,
    note TEXT
);

CREATE TABLE IF NOT EXISTS opcert_certificates(
    id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL,
    skill TEXT NOT NULL,
    equipment_class TEXT NOT NULL DEFAULT '*',
    role TEXT,
    certificate_kind TEXT NOT NULL DEFAULT 'full',
    status TEXT NOT NULL DEFAULT 'active',
    issued_at INTEGER NOT NULL DEFAULT 0,
    valid_from INTEGER NOT NULL DEFAULT 0,
    valid_until INTEGER NOT NULL,
    organization_id TEXT,
    examiner_id TEXT,
    assessment_id TEXT,
    review_id TEXT,
    scope_json TEXT NOT NULL DEFAULT '{}',
    supervision_required INTEGER NOT NULL DEFAULT 0,
    basis TEXT,
    status_changed_at INTEGER NOT NULL DEFAULT 0,
    status_reason TEXT,
    created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS opcert_reviews(
    id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    organization_id TEXT,
    reviewer_name TEXT,
    at INTEGER NOT NULL DEFAULT 0,
    conclusion TEXT,
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    certificate_id TEXT
);

CREATE TABLE IF NOT EXISTS opcert_certified_approvals(
    approval_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    certificate_id TEXT,
    role TEXT NOT NULL,
    at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS opcert_service_proxies(
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    role TEXT NOT NULL,
    responsible_person_id TEXT,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'recorded'
);

CREATE TABLE IF NOT EXISTS opcert_shifts(
    id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER NOT NULL,
    equipment_class TEXT,
    min_operators INTEGER NOT NULL DEFAULT 1,
    min_witnesses INTEGER NOT NULL DEFAULT 0,
    required_roles_json TEXT,
    provider_id TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    note TEXT
);

CREATE TABLE IF NOT EXISTS opcert_unavailability(
    id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'rest',
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS opcert_assignments(
    id TEXT PRIMARY KEY,
    shift_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    account_id TEXT,
    certificate_id TEXT,
    site_id TEXT NOT NULL,
    start_ts INTEGER NOT NULL,
    end_ts INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    operation TEXT,
    supervised_by_person_id TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    cancel_reason TEXT,
    status_changed_at INTEGER NOT NULL DEFAULT 0
);
"""


def init(db) -> None:
    """Create court and certification tables.  Safe to call repeatedly."""
    if getattr(db, "row_factory", None) is None:
        db.row_factory = sqlite3.Row
    existing = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='opcert_persons'"
    ).fetchone()
    if existing:
        return
    db.executescript(COURT_SCHEMA)
    db.executescript(SCHEMA)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _load_json(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def _scope(cert) -> dict:
    return _load_json(cert["scope_json"], {}) if cert is not None else {}


def _normalize_identity_status(status: str | None) -> str | None:
    if status is None:
        return None
    return IDENTITY_STATUS_ALIASES.get(status, status)


def _idempotent(old, same_fields: tuple[Any, ...], new_fields: tuple[Any, ...],
                reused: str = "reused", conflict: str = "identity_conflict") -> dict:
    if old is None:
        return {}
    return {"decision": reused if same_fields == new_fields else conflict}


# ---------------------------------------------------------------------------
# Natural persons and independently evidenced factor/account bindings
# ---------------------------------------------------------------------------

def register_person(db, person_id: str, name: str | None = None, at: int = 0,
                    status: str = PERSON_ACTIVE, reason: str | None = None) -> dict:
    init(db)
    if status not in {PERSON_ACTIVE, PERSON_SUSPENDED, PERSON_DEPARTED}:
        return {"decision": "invalid_person_status"}
    old = one(db, "SELECT * FROM opcert_persons WHERE id=?", (person_id,))
    if old:
        same = (old["name"], old["status"], old["reason"]) == (name, status, reason)
        return {"decision": "reused" if same else "person_identity_conflict"}
    db.execute(
        "INSERT INTO opcert_persons(id,name,status,status_changed_at,reason,created_at)"
        " VALUES(?,?,?,?,?,?)",
        (person_id, name, status, at, reason, at),
    )
    return {"decision": "registered", "person_id": person_id, "status": status}


def set_person_status(db, person_id: str, status: str, at: int = 0,
                      reason: str | None = None) -> dict:
    init(db)
    if status not in {PERSON_ACTIVE, PERSON_SUSPENDED, PERSON_DEPARTED}:
        return {"decision": "invalid_person_status"}
    person = one(db, "SELECT id FROM opcert_persons WHERE id=?", (person_id,))
    if not person:
        return {"decision": "unknown_person"}
    db.execute(
        "UPDATE opcert_persons SET status=?,status_changed_at=?,reason=? WHERE id=?",
        (status, at, reason, person_id),
    )
    return {"decision": "person_status_updated", "person_id": person_id, "status": status}


def _evidence_parts(evidence: dict | None, evidence_id: str | None,
                    evidence_ref: str | None, source_kind: str | None,
                    verified_by: str | None, independent: bool,
                    at: int) -> tuple[str, str, str, str, bool, str, int]:
    if isinstance(evidence, dict):
        evidence_id = evidence.get("id") or evidence_id
        evidence_ref = evidence.get("reference") or evidence.get("ref") or evidence_ref
        source_kind = evidence.get("source_kind") or evidence.get("kind") or source_kind
        verified_by = evidence.get("verified_by") or verified_by
        independent = evidence.get("independent", independent)
        at = evidence.get("at", evidence.get("verified_at", at))
    return (
        evidence_id or "",
        evidence_ref or "",
        source_kind or "",
        verified_by or "",
        bool(independent),
        at,
        evidence if isinstance(evidence, dict) else {},
    )


def bind_subject(db, subject_id: str, kind: str, person_id: str | None = None, *,
                 account_class: str | None = None,
                 status: str = "active", label: str | None = None, at: int = 0,
                 evidence: dict | None = None, evidence_id: str | None = None,
                 evidence_ref: str | None = None, source_kind: str | None = None,
                 verified_by: str | None = None, independent: bool = True) -> dict:
    """Bind an account/badge/signer to a natural person using independent evidence."""
    init(db)
    if kind not in {"account", "badge", "signer", "mfa", "device"}:
        return {"decision": "unknown_subject_kind"}
    if kind == "account" and account_class not in {HUMAN_ACTOR, SERVICE_ACTOR}:
        return {"decision": "account_class_required"}
    if person_id is not None:
        person = one(db, "SELECT id FROM opcert_persons WHERE id=?", (person_id,))
        if not person:
            return {"decision": "unknown_person"}

    old = one(db, "SELECT * FROM opcert_subjects WHERE id=?", (subject_id,))
    if old:
        same = (old["kind"], old["person_id"], old["account_class"], old["status"]) == (
            kind, person_id, account_class, status)
        return {"decision": "reused" if same else "binding_identity_conflict"}

    ev_id, ref, source, verifier, is_independent, ev_at, raw = _evidence_parts(
        evidence, evidence_id, evidence_ref, source_kind, verified_by, independent, at)

    # Human bindings cannot be created from self-assertion or from the mere
    # simultaneous presence of two factors belonging to different people.
    if person_id is not None:
        if not ev_id or not ref or not verifier:
            return {"decision": "independent_binding_evidence_required"}
        if not is_independent or source in {"self_declared", "actor_assertion", "self_report"}:
            return {"decision": "independent_binding_evidence_required"}
        if verifier == person_id:
            return {"decision": "independent_verifier_required"}

    db.execute(
        "INSERT INTO opcert_subjects(id,kind,person_id,account_class,status,label,bound_at,evidence_id)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (subject_id, kind, person_id, account_class, status, label, at, ev_id or None),
    )
    if ev_id:
        db.execute(
            "INSERT OR REPLACE INTO opcert_binding_evidence"
            "(id,subject_id,person_id,source_kind,reference,independent,verified_by,verified_at,payload)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (ev_id, subject_id, person_id, source, ref, 1 if is_independent else 0,
             verifier, ev_at, _json(raw)),
        )
    return {
        "decision": "bound",
        "subject_id": subject_id,
        "kind": kind,
        "person_id": person_id,
        "account_class": account_class,
    }


def bind_account(db, account_id: str, person_id: str | None, *, at: int = 0,
                 service: bool = False, **evidence_kwargs) -> dict:
    return bind_subject(
        db, account_id, "account", None if service else person_id,
        account_class=SERVICE_ACTOR if service else HUMAN_ACTOR,
        at=at, **evidence_kwargs,
    )


def bind_factor(db, factor_id: str, kind: str, person_id: str, *, at: int = 0,
                **evidence_kwargs) -> dict:
    if kind not in {"badge", "signer", "mfa", "device"}:
        kind = "device"
    return bind_subject(db, factor_id, kind, person_id, at=at, **evidence_kwargs)


def resolve_actor(db, actor: str) -> dict:
    """Resolve a grant actor to a natural person, rejecting service accounts."""
    init(db)
    subject = one(db, "SELECT * FROM opcert_subjects WHERE id=? AND kind='account'", (actor,))
    if not subject:
        return {"allowed": False, "decision": "unbound_account", "account_id": actor}
    if subject["status"] != "active":
        return {"allowed": False, "decision": "account_disabled", "account_id": actor}
    if subject["account_class"] == SERVICE_ACTOR or not subject["person_id"]:
        return {
            "allowed": False,
            "decision": "service_account_not_natural_person",
            "account_id": actor,
        }
    person = one(db, "SELECT * FROM opcert_persons WHERE id=?", (subject["person_id"],))
    if not person:
        return {"allowed": False, "decision": "unknown_person", "account_id": actor}
    if person["status"] == PERSON_DEPARTED:
        return {"allowed": False, "decision": "person_departed", "person_id": person["id"]}
    if person["status"] == PERSON_SUSPENDED:
        return {"allowed": False, "decision": "person_suspended", "person_id": person["id"]}
    return {
        "allowed": True,
        "decision": "allowed",
        "account_id": actor,
        "person_id": person["id"],
        "person": person,
        "subject": subject,
    }


# ---------------------------------------------------------------------------
# Training organizations, examiners, assessments and identity evidence
# ---------------------------------------------------------------------------

def register_organization(db, organization_id: str, name: str = "", *,
                          kind: str = "training", accreditation: str = "active",
                          status: str = "active", valid_from: int = 0,
                          valid_until: int = DEFAULT_FAR_FUTURE, at: int = 0) -> dict:
    init(db)
    old = one(db, "SELECT * FROM opcert_organizations WHERE id=?", (organization_id,))
    if old:
        return {"decision": "reused"}
    db.execute(
        "INSERT INTO opcert_organizations(id,name,kind,accreditation,status,valid_from,valid_until,"
        "status_changed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (organization_id, name, kind, accreditation, status, valid_from, valid_until, at, at),
    )
    return {"decision": "organization_registered", "organization_id": organization_id, "kind": kind}


def revoke_organization(db, organization_id: str, at: int, reason: str, *,
                        invalidate_certificates: bool = False) -> dict:
    init(db)
    org = one(db, "SELECT id FROM opcert_organizations WHERE id=?", (organization_id,))
    if not org:
        return {"decision": "unknown_organization"}
    db.execute(
        "UPDATE opcert_organizations SET status='revoked',status_changed_at=?,revocation_reason=? WHERE id=?",
        (at, reason, organization_id),
    )
    if invalidate_certificates:
        certs = rows(
            db,
            "SELECT id FROM opcert_certificates WHERE organization_id=? "
            "AND status IN ('active','held','suspended')",
            (organization_id,),
        )
    else:
        certs = rows(
            db,
            "SELECT id FROM opcert_certificates WHERE organization_id=? AND status='active'",
            (organization_id,),
        )
    new_status = "revoked" if invalidate_certificates else "held"
    reason_code = ("organization_qualification_revoked" if invalidate_certificates
                   else "organization_revocation_evidence_review")
    for cert in certs:
        db.execute(
            "UPDATE opcert_certificates SET status=?,status_changed_at=?,status_reason=? WHERE id=?",
            (new_status, at, reason_code, cert["id"]),
        )
    return {
        "decision": "organization_revoked",
        "organization_id": organization_id,
        "certificate_action": new_status,
        "affected_certificates": [c["id"] for c in certs],
        "whole_batch_invalidated": invalidate_certificates,
    }


def authorize_examiner(db, examiner_id: str, organization_id: str, name: str = "", *,
                       status: str = "active", valid_from: int = 0,
                       valid_until: int = DEFAULT_FAR_FUTURE, at: int = 0) -> dict:
    init(db)
    if not one(db, "SELECT id FROM opcert_organizations WHERE id=?", (organization_id,)):
        return {"decision": "unknown_organization"}
    old = one(db, "SELECT id FROM opcert_examiners WHERE id=?", (examiner_id,))
    if old:
        return {"decision": "reused"}
    db.execute(
        "INSERT INTO opcert_examiners(id,organization_id,name,status,valid_from,valid_until,"
        "status_changed_at,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (examiner_id, organization_id, name, status, valid_from, valid_until, at, at),
    )
    return {"decision": "examiner_authorized", "examiner_id": examiner_id}


def revoke_examiner(db, examiner_id: str, at: int, reason: str, *,
                    hold_dependent_certificates: bool = True) -> dict:
    init(db)
    examiner = one(db, "SELECT id FROM opcert_examiners WHERE id=?", (examiner_id,))
    if not examiner:
        return {"decision": "unknown_examiner"}
    db.execute(
        "UPDATE opcert_examiners SET status='revoked',status_changed_at=?,revocation_reason=? WHERE id=?",
        (at, reason, examiner_id),
    )
    held: list[str] = []
    if hold_dependent_certificates:
        certs = rows(
            db,
            "SELECT id FROM opcert_certificates WHERE examiner_id=? AND status='active'",
            (examiner_id,),
        )
        for cert in certs:
            db.execute(
                "UPDATE opcert_certificates SET status='held',status_changed_at=?,"
                "status_reason='examiner_revoked_identity_review' WHERE id=?",
                (at, cert["id"]),
            )
            held.append(cert["id"])
    return {
        "decision": "examiner_revoked",
        "examiner_id": examiner_id,
        "held_certificates": held,
        "whole_batch_invalidated": False,
    }


def _organization_check(db, org_id: str | None, at: int) -> str | None:
    if not org_id:
        return "training_organization_required"
    org = one(db, "SELECT * FROM opcert_organizations WHERE id=?", (org_id,))
    if not org:
        return "unknown_organization"
    if org["status"] == "revoked" and org["status_changed_at"] is not None and at >= org["status_changed_at"]:
        return "training_organization_revoked"
    if org["status"] not in {"active"}:
        return "training_organization_unavailable"
    if at < org["valid_from"] or at > org["valid_until"]:
        return "training_organization_qualification_expired"
    return None


def _examiner_check(db, examiner_id: str | None, at: int) -> str | None:
    if not examiner_id:
        return "examiner_required"
    examiner = one(db, "SELECT * FROM opcert_examiners WHERE id=?", (examiner_id,))
    if not examiner:
        return "unknown_examiner"
    if examiner["status"] == "revoked" and examiner["status_changed_at"] is not None and at >= examiner["status_changed_at"]:
        return "examiner_revoked"
    if examiner["status"] != "active":
        return "examiner_unavailable"
    if at < examiner["valid_from"] or at > examiner["valid_until"]:
        return "examiner_authorization_expired"
    return None


def record_assessment(db, assessment_id: str, person_id: str, skill: str, *,
                      equipment_class: str = "*", provider_id: str | None = None,
                      examiner_id: str | None = None, taken_at: int = 0,
                      result: str = "passed",
                      identity_status: str = PROXY_UNRESOLVED,
                      actual_person_id: str | None = None,
                      note: str | None = None) -> dict:
    init(db)
    identity_status = _normalize_identity_status(identity_status)
    if identity_status not in IDENTITY_STATES:
        return {"decision": "invalid_identity_status"}
    if not one(db, "SELECT id FROM opcert_persons WHERE id=?", (person_id,)):
        return {"decision": "unknown_person"}
    if identity_status == PROXY_CONFIRMED:
        if not actual_person_id or actual_person_id == person_id:
            return {"decision": "confirmed_proxy_requires_actual_person"}
        if not one(db, "SELECT id FROM opcert_persons WHERE id=?", (actual_person_id,)):
            return {"decision": "unknown_actual_person"}

    org_error = _organization_check(db, provider_id, taken_at)
    if org_error:
        return {"decision": org_error}
    examiner_error = _examiner_check(db, examiner_id, taken_at)
    if examiner_error:
        return {"decision": examiner_error}

    old = one(db, "SELECT * FROM opcert_assessments WHERE id=?", (assessment_id,))
    if old:
        same = (old["person_id"], old["skill"], old["equipment_class"], old["result"]) == (
            person_id, skill, equipment_class, result)
        return {"decision": "reused" if same else "assessment_identity_conflict"}

    db.execute(
        "INSERT INTO opcert_assessments(id,person_id,skill,equipment_class,provider_id,examiner_id,"
        "taken_at,result,identity_status,actual_person_id,note,created_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (assessment_id, person_id, skill, equipment_class, provider_id, examiner_id, taken_at,
         result, identity_status, actual_person_id, note, taken_at),
    )
    return {
        "decision": "assessment_recorded",
        "assessment_id": assessment_id,
        "person_id": person_id,
        "identity_status": identity_status,
        "identity_status_label": IDENTITY_STATUS_LABELS[identity_status],
        "result": result,
    }


def record_site_signing(db, signing_id: str, assessment_id: str, at: int = 0, *,
                        factor_ids: list[str] | tuple[str, ...] = (),
                        identity_status: str | None = None,
                        actual_person_id: str | None = None,
                        asserted_person_id: str | None = None,
                        evidence_id: str | None = None,
                        note: str | None = None) -> dict:
    init(db)
    identity_status = _normalize_identity_status(identity_status)
    assessment = one(db, "SELECT * FROM opcert_assessments WHERE id=?", (assessment_id,))
    if not assessment:
        return {"decision": "unknown_assessment"}
    if not factor_ids:
        return {"decision": "signing_factors_required"}

    placeholders = ",".join("?" for _ in factor_ids)
    factors = rows(
        db,
        f"SELECT id,person_id,status,kind FROM opcert_subjects WHERE id IN ({placeholders})",
        tuple(factor_ids),
    )
    found = {f["id"] for f in factors}
    missing = [fid for fid in factor_ids if fid not in found]
    if missing:
        return {"decision": "unknown_signing_factor", "missing": missing}

    person_ids = sorted({f["person_id"] for f in factors if f["person_id"] and f["status"] == "active"})
    if not person_ids:
        inferred = PROXY_UNRESOLVED
    elif len(person_ids) == 1:
        inferred = SELF_COMPLETED
    else:
        # An A badge plus a B signer is not two signatures combining into one
        # qualified student; it is an unresolved identity conflict.
        inferred = PROXY_UNRESOLVED

    final_status = identity_status or inferred
    if final_status not in IDENTITY_STATES:
        return {"decision": "invalid_identity_status"}
    if final_status == SELF_COMPLETED and len(person_ids) > 1:
        return {
            "decision": "conflicting_factor_identity",
            "bound_person_ids": person_ids,
            "identity_status": PROXY_UNRESOLVED,
        }
    if final_status == PROXY_CONFIRMED:
        if not actual_person_id:
            return {"decision": "confirmed_proxy_requires_actual_person"}
        if actual_person_id not in person_ids:
            return {"decision": "actual_person_not_supported_by_signing_factors"}

    db.execute(
        "INSERT INTO opcert_site_signings(id,assessment_id,at,factor_ids,bound_person_ids,"
        "asserted_person_id,identity_status,evidence_id,note)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (signing_id, assessment_id, at, _json(sorted(factor_ids)), _json(person_ids),
         asserted_person_id or assessment["person_id"], final_status, evidence_id, note),
    )
    db.execute(
        "UPDATE opcert_assessments SET identity_status=?,actual_person_id=? WHERE id=?",
        (final_status, actual_person_id if final_status == PROXY_CONFIRMED else None, assessment_id),
    )
    return {
        "decision": "site_signing_recorded",
        "signing_id": signing_id,
        "identity_status": final_status,
        "identity_status_label": IDENTITY_STATUS_LABELS[final_status],
        "bound_person_ids": person_ids,
    }


def add_assessment_evidence(db, evidence_id: str, assessment_id: str, kind: str, *,
                           reference: str | None = None, at: int = 0,
                           proves_person_id: str | None = None,
                           independent: bool = True,
                           verified_by: str | None = None,
                           captured_at: int | None = None,
                           payload: dict | None = None) -> dict:
    init(db)
    if not one(db, "SELECT id FROM opcert_assessments WHERE id=?", (assessment_id,)):
        return {"decision": "unknown_assessment"}
    old = one(db, "SELECT id FROM opcert_assessment_evidence WHERE id=?", (evidence_id,))
    if old:
        return {"decision": "reused"}
    db.execute(
        "INSERT INTO opcert_assessment_evidence(id,assessment_id,kind,reference,independent,"
        "proves_person_id,verified_by,captured_at,added_at,payload) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (evidence_id, assessment_id, kind, reference, 1 if independent else 0,
         proves_person_id, verified_by, captured_at if captured_at is not None else at, at,
         _json(payload or {})),
    )
    return {"decision": "evidence_recorded", "evidence_id": evidence_id, "kind": kind}


def flag_proxy_unresolved(db, assessment_id: str, *, evidence_id: str, at: int,
                          reference: str = "identity dispute",
                          hold_certificates: bool = True) -> dict:
    init(db)
    assessment = one(db, "SELECT id FROM opcert_assessments WHERE id=?", (assessment_id,))
    if not assessment:
        return {"decision": "unknown_assessment"}
    add_assessment_evidence(
        db, evidence_id, assessment_id, "ambiguous_identity_video",
        reference=reference, at=at, independent=True)
    db.execute(
        "UPDATE opcert_assessments SET identity_status=?,actual_person_id=NULL WHERE id=?",
        (PROXY_UNRESOLVED, assessment_id),
    )
    held: list[str] = []
    if hold_certificates:
        certs = rows(
            db,
            "SELECT id FROM opcert_certificates WHERE assessment_id=? AND status='active'",
            (assessment_id,),
        )
        for cert in certs:
            db.execute(
                "UPDATE opcert_certificates SET status='held',status_changed_at=?,"
                "status_reason='proxy_identity_unresolved' WHERE id=?",
                (at, cert["id"]),
            )
            held.append(cert["id"])
    return {"decision": "proxy_marked_unresolved", "assessment_id": assessment_id, "held_certificates": held}


def confirm_proxy(db, assessment_id: str, actual_person_id: str, *, evidence_id: str,
                  at: int, reference: str = "forensic video identification",
                  verified_by: str = "independent-forensics") -> dict:
    init(db)
    assessment = one(db, "SELECT * FROM opcert_assessments WHERE id=?", (assessment_id,))
    if not assessment:
        return {"decision": "unknown_assessment"}
    if not one(db, "SELECT id FROM opcert_persons WHERE id=?", (actual_person_id,)):
        return {"decision": "unknown_actual_person"}
    if actual_person_id == assessment["person_id"]:
        return {"decision": "not_a_proxy_confirmation"}
    add_assessment_evidence(
        db, evidence_id, assessment_id, "confirmed_proxy_video",
        reference=reference, at=at, proves_person_id=actual_person_id,
        verified_by=verified_by, independent=True)
    db.execute(
        "UPDATE opcert_assessments SET identity_status=?,actual_person_id=? WHERE id=?",
        (PROXY_CONFIRMED, actual_person_id, assessment_id),
    )
    return {
        "decision": "proxy_confirmed",
        "assessment_id": assessment_id,
        "claimed_person_id": assessment["person_id"],
        "actual_person_id": actual_person_id,
    }


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

def issue_certificate(db, certificate_id: str, person_id: str, *, skill: str,
                      valid_from: int, valid_until: int,
                      role: str | None = None, equipment_class: str = "*",
                      assessment_id: str | None = None,
                      organization_id: str | None = None,
                      examiner_id: str | None = None,
                      issued_at: int | None = None,
                      scope: dict | None = None,
                      certificate_kind: str = FULL,
                      supervision_required: bool = False,
                      basis: str = "practical_assessment",
                      can_supervise: bool = False) -> dict:
    init(db)
    if certificate_kind not in {FULL, LIMITED_SUPERVISED}:
        return {"decision": "invalid_certificate_kind"}
    if valid_until <= valid_from:
        return {"decision": "invalid_validity_period"}
    person = one(db, "SELECT id,status FROM opcert_persons WHERE id=?", (person_id,))
    if not person:
        return {"decision": "unknown_person"}

    assessment = None
    if assessment_id:
        assessment = one(db, "SELECT * FROM opcert_assessments WHERE id=?", (assessment_id,))
        if not assessment:
            return {"decision": "unknown_assessment"}
        if assessment["person_id"] != person_id:
            return {"decision": "assessment_person_mismatch"}
        if assessment["result"] != "passed":
            return {"decision": "assessment_not_passed"}
        if certificate_kind == FULL and assessment["identity_status"] != SELF_COMPLETED:
            return {"decision": f"identity_{assessment['identity_status']}"}
        if assessment["skill"] != skill:
            return {"decision": "assessment_skill_mismatch"}
        if equipment_class != "*" and assessment["equipment_class"] not in {"*", equipment_class}:
            return {"decision": "assessment_equipment_mismatch"}
        if organization_id is not None and assessment["provider_id"] and organization_id != assessment["provider_id"]:
            return {"decision": "certificate_training_body_mismatch"}
        if examiner_id is not None and assessment["examiner_id"] and examiner_id != assessment["examiner_id"]:
            return {"decision": "certificate_examiner_mismatch"}
        organization_id = organization_id or assessment["provider_id"]
        examiner_id = examiner_id or assessment["examiner_id"]

    issue_at = issued_at if issued_at is not None else valid_from
    if certificate_kind == FULL and not assessment_id:
        return {"decision": "full_certificate_requires_assessment"}
    org_error = _organization_check(db, organization_id, assessment["taken_at"] if assessment else issue_at)
    if org_error:
        return {"decision": org_error}
    org_error = _organization_check(db, organization_id, issue_at)
    if org_error:
        return {"decision": org_error}
    if certificate_kind == FULL or examiner_id:
        examiner_error = _examiner_check(db, examiner_id, assessment["taken_at"] if assessment else issue_at)
        if examiner_error:
            return {"decision": examiner_error}
        examiner_error = _examiner_check(db, examiner_id, issue_at)
        if examiner_error:
            return {"decision": examiner_error}

    old = one(db, "SELECT * FROM opcert_certificates WHERE id=?", (certificate_id,))
    if old:
        same = (old["person_id"], old["skill"], old["role"], old["valid_until"]) == (
            person_id, skill, role, valid_until)
        return {"decision": "reused" if same else "certificate_identity_conflict"}

    final_scope = dict(scope or {})
    if can_supervise:
        final_scope["can_supervise"] = True
    db.execute(
        "INSERT INTO opcert_certificates(id,person_id,skill,equipment_class,role,certificate_kind,status,"
        "issued_at,valid_from,valid_until,organization_id,examiner_id,assessment_id,review_id,scope_json,"
        "supervision_required,basis,status_changed_at,status_reason,created_at) VALUES("
        "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (certificate_id, person_id, skill, equipment_class, role, certificate_kind, "active",
         issue_at, valid_from, valid_until, organization_id, examiner_id, assessment_id, None,
         _json(final_scope), 1 if supervision_required else 0, basis, issue_at, None, issue_at),
    )
    return {
        "decision": "certificate_issued",
        "certificate_id": certificate_id,
        "person_id": person_id,
        "certificate_kind": certificate_kind,
        "role": role,
        "skill": skill,
        "equipment_class": equipment_class,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "scope": final_scope,
        "supervision_required": supervision_required,
    }


def grant_independent_review_qualification(
        db, certificate_id: str, review_id: str, assessment_id: str, person_id: str, *,
        review_organization_id: str, at: int, valid_until: int,
        operations: list[str] | tuple[str, ...],
        equipment_classes: list[str] | tuple[str, ...] | None = None,
        site_ids: list[str] | tuple[str, ...] | None = None,
        equipment_class: str | None = None,
        skill: str = "equipment-operation",
        reviewer_name: str = "independent examiner",
        conclusion: str = "personal operation proven by records and signer custody chain") -> dict:
    """Elevate an unresolved record only into a narrow, supervised, timed cert."""
    init(db)
    assessment = one(db, "SELECT * FROM opcert_assessments WHERE id=?", (assessment_id,))
    if not assessment:
        return {"decision": "unknown_assessment"}
    if not one(db, "SELECT id FROM opcert_persons WHERE id=?", (person_id,)):
        return {"decision": "unknown_person"}
    org = one(db, "SELECT * FROM opcert_organizations WHERE id=?", (review_organization_id,))
    if not org:
        return {"decision": "unknown_review_organization"}
    if org["kind"] not in {"independent_assessor", "review_board", "independent_reviewer"}:
        return {"decision": "reviewer_not_independent"}
    if assessment["provider_id"] and review_organization_id == assessment["provider_id"]:
        return {"decision": "reviewer_not_independent"}
    org_error = _organization_check(db, review_organization_id, at)
    if org_error:
        return {"decision": org_error}
    if valid_until <= at:
        return {"decision": "temporary_certificate_must_expire"}
    if not operations:
        return {"decision": "narrow_operation_scope_required"}

    evidence = rows(
        db,
        "SELECT * FROM opcert_assessment_evidence WHERE assessment_id=? AND independent=1",
        (assessment_id,),
    )
    kinds = {e["kind"] for e in evidence}
    if "operation_record" not in kinds:
        return {"decision": "operation_record_evidence_required"}
    if "signer_custody_chain" not in kinds:
        return {"decision": "signer_custody_chain_required"}
    proving = {e["kind"]: e["proves_person_id"] for e in evidence if e["proves_person_id"] == person_id}
    if "operation_record" not in proving or "signer_custody_chain" not in proving:
        return {"decision": "evidence_does_not_prove_named_person_operation"}

    equipment = list(equipment_classes or [])
    if equipment_class and equipment_class not in equipment:
        equipment.append(equipment_class)
    if not equipment:
        equipment = [assessment["equipment_class"]] if assessment["equipment_class"] else []
    if not equipment or equipment == ["*"]:
        return {"decision": "specific_equipment_class_required"}

    scope = {
        "operations": sorted(set(operations)),
        "equipment_classes": sorted(set(equipment)),
        "site_ids": sorted(set(site_ids or [])),
        "review_only": True,
        "can_supervise": False,
    }
    cert_result = issue_certificate(
        db, certificate_id, person_id, skill=skill, role="operator",
        equipment_class=equipment[0], valid_from=at, valid_until=valid_until,
        organization_id=review_organization_id, assessment_id=None, issued_at=at,
        scope=scope, certificate_kind=LIMITED_SUPERVISED, supervision_required=True,
        basis="independent_on_site_record_and_custody_review")
    if cert_result["decision"] != "certificate_issued":
        return cert_result

    db.execute(
        "INSERT INTO opcert_reviews(id,assessment_id,person_id,organization_id,reviewer_name,at,"
        "conclusion,evidence_ids_json,certificate_id) VALUES(?,?,?,?,?,?,?,?,?)",
        (review_id, assessment_id, person_id, review_organization_id, reviewer_name, at,
         conclusion, _json([e["id"] for e in evidence]), certificate_id),
    )
    db.execute("UPDATE opcert_certificates SET review_id=? WHERE id=?", (review_id, certificate_id))
    cert_result["review_id"] = review_id
    return cert_result


# Convenient long name matching the action.
independent_review = grant_independent_review_qualification


def certificate_allows(db, certificate_id: str, *, at: int, through: int | None = None,
                       role: str | None = None, skill: str | None = None,
                       equipment_class: str | None = None, operation: str | None = None,
                       site_id: str | None = None, assignment_role: str | None = None,
                       require_full: bool = False) -> dict:
    init(db)
    cert = one(db, "SELECT * FROM opcert_certificates WHERE id=?", (certificate_id,))
    if not cert:
        return {"allowed": False, "decision": "certificate_missing"}
    person = one(db, "SELECT * FROM opcert_persons WHERE id=?", (cert["person_id"],))
    if not person:
        return {"allowed": False, "decision": "unknown_person"}
    if person["status"] == PERSON_DEPARTED:
        return {"allowed": False, "decision": "person_departed", "person_id": person["id"]}
    if person["status"] == PERSON_SUSPENDED:
        return {"allowed": False, "decision": "person_suspended", "person_id": person["id"]}

    status = cert["status"]
    if status != "active":
        return {
            "allowed": False,
            "decision": f"certificate_{status}",
            "person_id": cert["person_id"],
            "status_reason": cert["status_reason"],
        }
    if at < cert["valid_from"]:
        return {"allowed": False, "decision": "certificate_not_yet_valid", "person_id": cert["person_id"]}
    if at > cert["valid_until"]:
        return {"allowed": False, "decision": "certificate_expired", "person_id": cert["person_id"]}
    if through is not None and through > cert["valid_until"]:
        return {"allowed": False, "decision": "certificate_expires_before_interval_end",
                "person_id": cert["person_id"]}
    if role is not None and cert["role"] != role:
        return {"allowed": False, "decision": "certificate_role_mismatch", "person_id": cert["person_id"]}
    if skill is not None and cert["skill"] != skill:
        return {"allowed": False, "decision": "certificate_skill_mismatch", "person_id": cert["person_id"]}

    scope = _scope(cert)
    allowed_equipment = set(scope.get("equipment_classes") or [])
    if cert["equipment_class"] and cert["equipment_class"] != "*":
        allowed_equipment.add(cert["equipment_class"])
    if equipment_class is not None and allowed_equipment and equipment_class not in allowed_equipment:
        return {"allowed": False, "decision": "equipment_scope_denied", "person_id": cert["person_id"]}

    operations = scope.get("operations")
    if operation is not None and operations and operation not in operations:
        return {"allowed": False, "decision": "operation_not_in_narrow_scope",
                "person_id": cert["person_id"]}
    if (cert["certificate_kind"] == LIMITED_SUPERVISED and assignment_role == "operator"
            and operations and operation is None):
        return {"allowed": False, "decision": "narrow_operation_name_required",
                "person_id": cert["person_id"]}
    sites = scope.get("site_ids")
    if site_id is not None and sites and site_id not in sites:
        return {"allowed": False, "decision": "site_scope_denied", "person_id": cert["person_id"]}

    if assignment_role == "supervisor":
        if cert["certificate_kind"] != FULL or not scope.get("can_supervise"):
            return {"allowed": False, "decision": "supervisor_qualification_required",
                    "person_id": cert["person_id"]}
    if assignment_role == "witness" and cert["certificate_kind"] != FULL:
        return {"allowed": False, "decision": "full_witness_qualification_required",
                "person_id": cert["person_id"]}
    if require_full and cert["certificate_kind"] != FULL:
        return {"allowed": False, "decision": "full_certificate_required", "person_id": cert["person_id"]}

    return {
        "allowed": True,
        "decision": "allowed",
        "person_id": cert["person_id"],
        "certificate_kind": cert["certificate_kind"],
        "supervision_required": bool(cert["supervision_required"]),
        "scope": scope,
    }


def usable_certificate(db, certificate_id: str, at: int, **kwargs) -> dict:
    return certificate_allows(db, certificate_id, at=at, **kwargs)


def set_certificate_status(db, certificate_id: str, status: str, at: int,
                           reason: str | None = None) -> dict:
    init(db)
    if status not in {"active", "suspended", "revoked", "held"}:
        return {"decision": "invalid_certificate_status"}
    cert = one(db, "SELECT id FROM opcert_certificates WHERE id=?", (certificate_id,))
    if not cert:
        return {"decision": "certificate_missing"}
    db.execute(
        "UPDATE opcert_certificates SET status=?,status_changed_at=?,status_reason=? WHERE id=?",
        (status, at, reason, certificate_id),
    )
    return {"decision": "certificate_status_updated", "certificate_id": certificate_id, "status": status}


def suspend_certificate(db, certificate_id: str, at: int, reason: str) -> dict:
    return set_certificate_status(db, certificate_id, "suspended", at, reason)


def revoke_certificate(db, certificate_id: str, at: int, reason: str) -> dict:
    return set_certificate_status(db, certificate_id, "revoked", at, reason)


def record_service_proxy(db, proxy_id: str, service_account: str, role: str,
                         start_ts: int, end_ts: int, *,
                         responsible_person_id: str | None = None,
                         reason: str | None = None) -> dict:
    """Record a bounded service-account role proxy.

    This is operational provenance only.  It deliberately does not turn the
    service account into a natural-person approver.
    """
    init(db)
    if end_ts <= start_ts:
        return {"decision": "invalid_proxy_interval"}
    subject = one(
        db,
        "SELECT * FROM opcert_subjects WHERE id=? AND kind='account'",
        (service_account,),
    )
    if not subject or subject["account_class"] != SERVICE_ACTOR:
        return {"decision": "service_account_required"}
    if role not in {"security", "owner", "operator"}:
        return {"decision": "invalid_proxy_role"}
    if responsible_person_id and not one(
            db, "SELECT id FROM opcert_persons WHERE id=?", (responsible_person_id,)):
        return {"decision": "unknown_responsible_person"}
    old = one(db, "SELECT id FROM opcert_service_proxies WHERE id=?", (proxy_id,))
    if old:
        return {"decision": "reused"}
    db.execute(
        "INSERT INTO opcert_service_proxies(id,account_id,role,responsible_person_id,"
        "start_ts,end_ts,reason,status) VALUES(?,?,?,?,?,?,?,'recorded')",
        (proxy_id, service_account, role, responsible_person_id, start_ts, end_ts, reason),
    )
    return {
        "decision": "service_proxy_recorded",
        "proxy_id": proxy_id,
        "service_account": service_account,
        "role": role,
        "counts_as_natural_person": False,
    }


# ---------------------------------------------------------------------------
# Certified grant approvals
# ---------------------------------------------------------------------------

def certify_approval(db, account_id: str, certificate_id: str | None, approval: dict) -> dict:
    init(db)
    actor = approval.get("actor")
    if actor != account_id:
        return {"decision": "approval_actor_account_mismatch"}
    resolved = resolve_actor(db, account_id)
    if not resolved["allowed"]:
        return resolved

    role = approval.get("role")
    if role not in {"security", "owner"}:
        return {"decision": "invalid_approval_role"}
    if not certificate_id:
        return {"decision": "certificate_required"}
    allowed = certificate_allows(
        db, certificate_id, at=approval["at"], through=approval.get("until"),
        role=role, skill="grant-approval", require_full=True)
    if not allowed["allowed"]:
        return allowed
    cert = one(db, "SELECT person_id FROM opcert_certificates WHERE id=?", (certificate_id,))
    if cert["person_id"] != resolved["person_id"]:
        return {"decision": "certificate_person_mismatch"}

    grant_id = approval.get("grant")
    # Check raw approvals too, so an alias inserted through the legacy grant
    # endpoint cannot create a false two-person panel.
    existing = rows(db, "SELECT id,actor,role FROM approvals WHERE grant_id=?", (grant_id,))
    for old in existing:
        old_resolved = resolve_actor(db, old["actor"])
        old_person = old_resolved.get("person_id") if old_resolved["allowed"] else None
        if old_person == resolved["person_id"] and old["role"] != role:
            return {
                "decision": "same_natural_person_conflict",
                "person_id": resolved["person_id"],
                "conflicting_approval": old["id"],
                "existing_role": old["role"],
                "requested_role": role,
            }

    result = grant.run(db, approval)
    if result.get("decision") in {"approved", "reused"}:
        db.execute(
            "INSERT OR REPLACE INTO opcert_certified_approvals"
            "(approval_id,grant_id,account_id,person_id,certificate_id,role,at)"
            " VALUES(?,?,?,?,?,?,?)",
            (approval["id"], grant_id, account_id, resolved["person_id"],
             certificate_id, role, approval["at"]),
        )
        result = dict(result)
        result["person_id"] = resolved["person_id"]
    return result


def verify_approval_panel(db, grant_id: str, at: int,
                          approver_accounts: list[str] | tuple[str, ...] | None = None) -> dict:
    init(db)
    approvals = rows(
        db,
        "SELECT * FROM approvals WHERE grant_id=? AND until_ts>=? ORDER BY id",
        (grant_id, at),
    )
    if approver_accounts is not None:
        allow = set(approver_accounts)
        approvals = [a for a in approvals if a["actor"] in allow]

    people_by_role: dict[str, set[str]] = {"security": set(), "owner": set()}
    account_people: dict[str, str] = {}
    errors: list[dict] = []
    certified: list[dict] = []

    for approval in approvals:
        resolved = resolve_actor(db, approval["actor"])
        if not resolved["allowed"]:
            errors.append({"approval_id": approval["id"], "decision": resolved["decision"]})
            continue
        person_id = resolved["person_id"]
        account_people[approval["actor"]] = person_id
        role = approval["role"]
        if role not in people_by_role:
            errors.append({"approval_id": approval["id"], "decision": "invalid_approval_role"})
            continue

        link = one(
            db,
            "SELECT * FROM opcert_certified_approvals WHERE approval_id=?",
            (approval["id"],),
        )
        cert_id = link["certificate_id"] if link and link["certificate_id"] else None
        approval_at = link["at"] if link and link["at"] is not None else at
        if cert_id:
            check = certificate_allows(
                db, cert_id, at=approval_at, role=role,
                skill="grant-approval", require_full=True)
        else:
            candidates = rows(
                db,
                "SELECT id FROM opcert_certificates WHERE person_id=? AND role=? AND skill='grant-approval'"
                " AND status='active' AND valid_from<=? AND valid_until>=? AND certificate_kind='full'",
                (person_id, role, approval_at, approval_at),
            )
            check = {"allowed": bool(candidates), "decision": "allowed" if candidates else "no_role_certificate"}
            cert_id = candidates[0]["id"] if candidates else None
        if not check.get("allowed"):
            errors.append({"approval_id": approval["id"], "decision": check["decision"]})
            continue

        # One natural person may not occupy both control roles on this grant,
        # even when using different accounts.
        other_role = "owner" if role == "security" else "security"
        if person_id in people_by_role[other_role]:
            errors.append({
                "approval_id": approval["id"],
                "decision": "same_natural_person_conflict",
                "person_id": person_id,
                "roles": [other_role, role],
            })
            continue
        people_by_role[role].add(person_id)
        certified.append({
            "approval_id": approval["id"],
            "account_id": approval["actor"],
            "person_id": person_id,
            "role": role,
            "certificate_id": cert_id,
        })

    if errors:
        decisions = {e["decision"] for e in errors}
        if "service_account_not_natural_person" in decisions:
            primary = "service_account_not_natural_person"
        elif "same_natural_person_conflict" in decisions:
            primary = "same_natural_person_conflict"
        else:
            primary = "uncertified_approval_panel"
        return {"allowed": False, "decision": primary, "errors": errors,
                "approvals": certified}
    if set(people_by_role) != {"security", "owner"} or not people_by_role["security"] or not people_by_role["owner"]:
        return {"allowed": False, "decision": "missing_two_qualified_natural_persons",
                "roles": {k: sorted(v) for k, v in people_by_role.items()}}
    if len(people_by_role["security"] | people_by_role["owner"]) < 2:
        return {"allowed": False, "decision": "same_natural_person_conflict"}
    return {
        "allowed": True,
        "decision": "qualified_panel",
        "people_by_role": {k: sorted(v) for k, v in people_by_role.items()},
        "person_ids": sorted(people_by_role["security"] | people_by_role["owner"]),
        "approvals": certified,
    }


def certified_issue(db, request: dict) -> dict:
    """Issue a grant only after replacing grant.py's actor-name check with people."""
    init(db)
    panel = verify_approval_panel(
        db, request["id"], request.get("at", 0), request.get("approvers", []))
    if not panel["allowed"]:
        return panel
    result = grant.run(db, request)
    if result.get("decision") == "granted":
        result = dict(result)
        result["qualified_person_ids"] = panel["person_ids"]
    return result


# Common shorter aliases.
approve = certify_approval
issue = certified_issue
qualify = issue_certificate


# ---------------------------------------------------------------------------
# Shifts, rest and double-booking boundaries
# ---------------------------------------------------------------------------

def create_shift(db, shift_id: str, site_id: str, start_ts: int, end_ts: int, *,
                 equipment_class: str | None = None, min_operators: int = 1,
                 min_witnesses: int = 0,
                 required_roles: dict | None = None,
                 provider_id: str | None = None, note: str | None = None) -> dict:
    init(db)
    if end_ts <= start_ts:
        return {"decision": "invalid_shift_interval"}
    if min_operators < 0 or min_witnesses < 0:
        return {"decision": "invalid_coverage_requirement"}
    old = one(db, "SELECT id FROM opcert_shifts WHERE id=?", (shift_id,))
    if old:
        return {"decision": "reused"}
    roles = required_roles if required_roles is not None else {"operator": min_operators}
    db.execute(
        "INSERT INTO opcert_shifts(id,site_id,start_ts,end_ts,equipment_class,min_operators,"
        "min_witnesses,required_roles_json,provider_id,status,note) VALUES(?,?,?,?,?,?,?,?,?,'draft',?)",
        (shift_id, site_id, start_ts, end_ts, equipment_class, min_operators, min_witnesses,
         _json(roles), provider_id, note),
    )
    return {"decision": "shift_created", "shift_id": shift_id, "site_id": site_id,
            "provider_id": provider_id}


def add_unavailability(db, block_id: str, person_id: str, start_ts: int, end_ts: int, *,
                       kind: str = "rest", reason: str | None = None) -> dict:
    init(db)
    if end_ts <= start_ts:
        return {"decision": "invalid_unavailability_interval"}
    if not one(db, "SELECT id FROM opcert_persons WHERE id=?", (person_id,)):
        return {"decision": "unknown_person"}
    old = one(db, "SELECT id FROM opcert_unavailability WHERE id=?", (block_id,))
    if old:
        return {"decision": "reused"}
    db.execute(
        "INSERT INTO opcert_unavailability(id,person_id,start_ts,end_ts,kind,reason,status)"
        " VALUES(?,?,?,?,?,?,'active')",
        (block_id, person_id, start_ts, end_ts, kind, reason),
    )
    return {"decision": "unavailability_recorded", "block_id": block_id, "kind": kind}


# Semantic alias.
add_rest = add_unavailability


def _overlapping_assignment(db, person_id: str, start_ts: int, end_ts: int,
                            exclude_id: str | None = None) -> dict | None:
    sql = (
        "SELECT a.*, s.site_id AS shift_site FROM opcert_assignments a "
        "LEFT JOIN opcert_shifts s ON s.id=a.shift_id "
        "WHERE a.person_id=? AND a.status='active' AND a.start_ts < ? AND a.end_ts > ?"
    )
    args: list[Any] = [person_id, end_ts, start_ts]
    if exclude_id:
        sql += " AND a.id != ?"
        args.append(exclude_id)
    sql += " ORDER BY a.start_ts LIMIT 1"
    return one(db, sql, tuple(args))


def assign_shift(db, assignment_id: str, shift_id: str, person_id: str | None = None,
                 certificate_id: str | None = None, role: str = "operator", *,
                 account_id: str | None = None, operation: str | None = None,
                 start_ts: int | None = None, end_ts: int | None = None,
                 supervised_by: str | None = None, at: int = 0) -> dict:
    init(db)
    shift = one(db, "SELECT * FROM opcert_shifts WHERE id=?", (shift_id,))
    if not shift:
        return {"decision": "unknown_shift"}
    old_assignment = one(db, "SELECT * FROM opcert_assignments WHERE id=?", (assignment_id,))
    if old_assignment:
        if old_assignment["status"] != "active":
            return {"decision": "assignment_id_not_reusable", "status": old_assignment["status"]}
        return {"decision": "reused"}

    if account_id:
        resolved = resolve_actor(db, account_id)
        if not resolved["allowed"]:
            return resolved
        account_person = resolved["person_id"]
        if person_id and person_id != account_person:
            return {"decision": "person_account_mismatch"}
        person_id = account_person
    if not person_id:
        return {"decision": "person_or_account_required"}
    if not one(db, "SELECT id FROM opcert_persons WHERE id=?", (person_id,)):
        return {"decision": "unknown_person"}

    start = shift["start_ts"] if start_ts is None else start_ts
    end = shift["end_ts"] if end_ts is None else end_ts
    if end <= start or start < shift["start_ts"] or end > shift["end_ts"]:
        return {"decision": "assignment_outside_shift"}

    blocked = one(
        db,
        "SELECT * FROM opcert_unavailability WHERE person_id=? AND status='active'"
        " AND start_ts < ? AND end_ts > ? ORDER BY start_ts LIMIT 1",
        (person_id, end, start),
    )
    if blocked:
        return {
            "decision": "rest_conflict" if blocked["kind"] == "rest" else "person_unavailable",
            "person_id": person_id,
            "unavailability_id": blocked["id"],
            "interval": [blocked["start_ts"], blocked["end_ts"]],
        }

    clash = _overlapping_assignment(db, person_id, start, end)
    if clash:
        return {
            "decision": "double_booked",
            "person_id": person_id,
            "conflicting_assignment": clash["id"],
            "conflicting_shift": clash["shift_id"],
            "conflicting_site": clash["site_id"],
            "interval": [clash["start_ts"], clash["end_ts"]],
        }

    if not certificate_id:
        return {"decision": "certificate_required"}
    cert_row = one(db, "SELECT person_id FROM opcert_certificates WHERE id=?", (certificate_id,))
    if not cert_row:
        return {"decision": "certificate_missing"}
    if cert_row["person_id"] != person_id:
        return {"decision": "certificate_person_mismatch"}

    allowed = certificate_allows(
        db, certificate_id, at=start, through=end,
        skill="equipment-operation", equipment_class=shift["equipment_class"],
        operation=operation, site_id=shift["site_id"], assignment_role=role)
    if not allowed["allowed"]:
        return allowed

    if allowed.get("supervision_required"):
        if not supervised_by or supervised_by == person_id:
            return {"decision": "named_supervisor_required"}
        supervisor = one(
            db,
            "SELECT * FROM opcert_assignments WHERE shift_id=? AND person_id=? AND role='supervisor'"
            " AND status='active' AND start_ts<=? AND end_ts>=? LIMIT 1",
            (shift_id, supervised_by, start, end),
        )
        if not supervisor:
            return {
                "decision": "supervisor_not_on_shift",
                "supervisor_person_id": supervised_by,
            }

    db.execute(
        "INSERT INTO opcert_assignments(id,shift_id,person_id,account_id,certificate_id,site_id,"
        "start_ts,end_ts,role,operation,supervised_by_person_id,status,status_changed_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,'active',?)",
        (assignment_id, shift_id, person_id, account_id, certificate_id, shift["site_id"],
         start, end, role, operation, supervised_by, at),
    )
    return {
        "decision": "assigned",
        "assignment_id": assignment_id,
        "shift_id": shift_id,
        "person_id": person_id,
        "role": role,
        "certificate_kind": allowed["certificate_kind"],
        "supervision_required": allowed["supervision_required"],
    }


def _segments(shift, assignments) -> list[tuple[int, int, list[dict]]]:
    bounds = {shift["start_ts"], shift["end_ts"]}
    for assignment in assignments:
        bounds.add(assignment["start_ts"])
        bounds.add(assignment["end_ts"])
    points = sorted(bounds)
    segments = []
    for left, right in zip(points, points[1:]):
        if left < shift["start_ts"] or right > shift["end_ts"] or right <= left:
            continue
        active = [a for a in assignments if a["start_ts"] <= left and a["end_ts"] > left]
        segments.append((left, right, active))
    return segments


def schedule_report(db, shift_id: str) -> dict:
    init(db)
    shift = one(db, "SELECT * FROM opcert_shifts WHERE id=?", (shift_id,))
    if not shift:
        return {"decision": "unknown_shift", "shift_id": shift_id, "valid": False}
    assignments = rows(
        db, "SELECT * FROM opcert_assignments WHERE shift_id=? AND status='active' ORDER BY id",
        (shift_id,))
    required_roles = _load_json(shift["required_roles_json"], {"operator": shift["min_operators"]})
    if shift["min_witnesses"]:
        required_roles["witness"] = max(required_roles.get("witness", 0), shift["min_witnesses"])

    violations: list[dict] = []
    segment_reports: list[dict] = []
    all_people: set[str] = set()

    for left, right, active in _segments(shift, assignments):
        role_people: dict[str, set[str]] = {}
        invalid: list[dict] = []
        segment_people: set[str] = set()

        person_counts: dict[str, int] = {}
        for assignment in active:
            person_counts[assignment["person_id"]] = person_counts.get(assignment["person_id"], 0) + 1
        for person_id, count in person_counts.items():
            if count > 1:
                violations.append({
                    "interval": [left, right],
                    "decision": "same_person_counted_twice",
                    "person_id": person_id,
                })

        for assignment in active:
            check = certificate_allows(
                db, assignment["certificate_id"], at=left, through=right,
                skill="equipment-operation", equipment_class=shift["equipment_class"],
                operation=assignment["operation"], site_id=shift["site_id"],
                assignment_role=assignment["role"])
            if not check.get("allowed"):
                invalid.append({
                    "assignment_id": assignment["id"],
                    "person_id": assignment["person_id"],
                    "decision": check.get("decision"),
                })
                violations.append({
                    "interval": [left, right],
                    "assignment_id": assignment["id"],
                    "person_id": assignment["person_id"],
                    "decision": check.get("decision"),
                })
                continue

            # Re-check rest and cross-shift overlaps against current state.
            blocked = one(
                db,
                "SELECT id,kind FROM opcert_unavailability WHERE person_id=? AND status='active'"
                " AND start_ts < ? AND end_ts > ? LIMIT 1",
                (assignment["person_id"], right, left),
            )
            if blocked:
                code = "rest_conflict" if blocked["kind"] == "rest" else "person_unavailable"
                invalid.append({"assignment_id": assignment["id"], "decision": code})
                violations.append({"interval": [left, right], "assignment_id": assignment["id"],
                                   "person_id": assignment["person_id"], "decision": code})
                continue

            role_people.setdefault(assignment["role"], set()).add(assignment["person_id"])
            segment_people.add(assignment["person_id"])
            all_people.add(assignment["person_id"])

            cert = one(db, "SELECT certificate_kind,supervision_required FROM opcert_certificates WHERE id=?",
                       (assignment["certificate_id"],))
            if cert and cert["supervision_required"]:
                supervisor_id = assignment["supervised_by_person_id"]
                supervisor = next((a for a in active
                                   if a["person_id"] == supervisor_id and a["role"] == "supervisor"), None)
                if not supervisor:
                    violations.append({
                        "interval": [left, right],
                        "assignment_id": assignment["id"],
                        "person_id": assignment["person_id"],
                        "decision": "supervision_absent",
                    })

        for role, required_count in required_roles.items():
            actual = len(role_people.get(role, set()))
            if actual < required_count:
                violations.append({
                    "interval": [left, right],
                    "decision": "insufficient_role_coverage",
                    "role": role,
                    "required": required_count,
                    "actual": actual,
                })

        segment_reports.append({
            "start": left,
            "end": right,
            "people": sorted(segment_people),
            "roles": {role: sorted(people) for role, people in role_people.items()},
            "invalid": invalid,
        })

    valid = not violations
    return {
        "decision": "schedule_valid" if valid else "schedule_invalid",
        "valid": valid,
        "shift_id": shift_id,
        "site_id": shift["site_id"],
        "provider_id": shift["provider_id"],
        "equipment_class": shift["equipment_class"],
        "required_roles": required_roles,
        "person_ids": sorted(all_people),
        "segments": segment_reports,
        "violations": violations,
    }


def validate_schedule(db, shift_id: str) -> dict:
    return schedule_report(db, shift_id)


def roster_report(db) -> dict:
    """Validate every shift and detect cross-site double booking."""
    init(db)
    shifts = rows(db, "SELECT id FROM opcert_shifts ORDER BY start_ts,id")
    reports = [schedule_report(db, shift["id"]) for shift in shifts]
    conflicts = rows(
        db,
        """
        SELECT a.person_id, a.id AS assignment_a, b.id AS assignment_b,
               a.shift_id AS shift_a, b.shift_id AS shift_b,
               a.site_id AS site_a, b.site_id AS site_b,
               a.start_ts AS start_a, a.end_ts AS end_a,
               b.start_ts AS start_b, b.end_ts AS end_b
        FROM opcert_assignments a
        JOIN opcert_assignments b
          ON a.person_id = b.person_id
         AND a.id < b.id
         AND a.status='active' AND b.status='active'
         AND a.start_ts < b.end_ts
         AND a.end_ts > b.start_ts
        ORDER BY a.person_id, a.start_ts
        """,
    )
    valid = all(r.get("valid") for r in reports) and not conflicts
    return {
        "decision": "roster_valid" if valid else "roster_invalid",
        "valid": valid,
        "shift_reports": reports,
        "overlapping_assignments": conflicts,
    }


def publish_shift(db, shift_id: str, at: int = 0) -> dict:
    report = schedule_report(db, shift_id)
    if not report["valid"]:
        db.execute("UPDATE opcert_shifts SET status='replanning' WHERE id=?", (shift_id,))
        return report
    db.execute("UPDATE opcert_shifts SET status='published' WHERE id=?", (shift_id,))
    report["decision"] = "schedule_published"
    return report


def cancel_assignment(db, assignment_id: str, at: int, reason: str) -> dict:
    init(db)
    assignment = one(db, "SELECT id FROM opcert_assignments WHERE id=?", (assignment_id,))
    if not assignment:
        return {"decision": "unknown_assignment"}
    db.execute(
        "UPDATE opcert_assignments SET status='canceled',cancel_reason=?,status_changed_at=? WHERE id=?",
        (reason, at, assignment_id),
    )
    return {"decision": "assignment_canceled", "assignment_id": assignment_id}


def replan_after_proxy_confirmation(db, assessment_id: str, at: int,
                                    replacements: list[dict] | tuple[dict, ...] = (),
                                    *, publish: bool = True) -> dict:
    """Revoke the wrongly attributed certificate and repair future shifts.

    Historical assignments are retained for audit.  Only assignments ending
    after ``at`` and relying on the invalidated certificate are canceled.
    Replacements pass through the same person/scope/rest/conflict checks.
    """
    init(db)
    assessment = one(db, "SELECT * FROM opcert_assessments WHERE id=?", (assessment_id,))
    if not assessment:
        return {"decision": "unknown_assessment"}
    if assessment["identity_status"] != PROXY_CONFIRMED:
        return {"decision": "proxy_not_confirmed"}

    claimed_person = assessment["person_id"]
    actual_person = assessment["actual_person_id"]
    certs = rows(
        db,
        "SELECT id FROM opcert_certificates WHERE assessment_id=? AND person_id=?",
        (assessment_id, claimed_person),
    )
    cert_ids = [c["id"] for c in certs]
    for cert_id in cert_ids:
        db.execute(
            "UPDATE opcert_certificates SET status='revoked',status_changed_at=?,"
            "status_reason='proxy_confirmed_other_person' WHERE id=?",
            (at, cert_id),
        )

    if cert_ids:
        marks = ",".join("?" for _ in cert_ids)
        future = rows(
            db,
            f"SELECT * FROM opcert_assignments WHERE status='active' AND end_ts > ? "
            f"AND certificate_id IN ({marks}) ORDER BY id",
            (at, *cert_ids),
        )
    else:
        future = []
    canceled: list[str] = []
    affected_shifts: set[str] = set()
    for assignment in future:
        db.execute(
            "UPDATE opcert_assignments SET status='canceled',cancel_reason=?,"
            "status_changed_at=? WHERE id=?",
            (f"video_confirmed_proxy:{actual_person}", at, assignment["id"]),
        )
        canceled.append(assignment["id"])
        affected_shifts.add(assignment["shift_id"])

    assignment_results: list[dict] = []
    for index, spec in enumerate(replacements, 1):
        assignment_id = spec.get("assignment_id") or spec.get("id") or f"replan-{assessment_id}-{index}"
        result = assign_shift(
            db,
            assignment_id,
            spec["shift_id"],
            spec.get("person_id"),
            spec.get("certificate_id"),
            spec.get("role", "operator"),
            account_id=spec.get("account_id"),
            operation=spec.get("operation"),
            start_ts=spec.get("start_ts"),
            end_ts=spec.get("end_ts"),
            supervised_by=spec.get("supervised_by"),
            at=at,
        )
        assignment_results.append(result)
        affected_shifts.add(spec["shift_id"])

    reports = []
    all_valid = all(r.get("decision") in {"assigned", "reused"} for r in assignment_results)
    for shift_id in sorted(affected_shifts):
        report = schedule_report(db, shift_id)
        reports.append(report)
        if not report["valid"]:
            all_valid = False
        elif publish:
            published = publish_shift(db, shift_id, at)
            reports[-1] = published

    if not all_valid:
        return {
            "decision": "replan_incomplete",
            "assessment_id": assessment_id,
            "claimed_person_id": claimed_person,
            "actual_person_id": actual_person,
            "revoked_certificates": cert_ids,
            "canceled_assignments": canceled,
            "assignment_results": assignment_results,
            "schedules": reports,
        }
    return {
        "decision": "replanned",
        "assessment_id": assessment_id,
        "claimed_person_id": claimed_person,
        "actual_person_id": actual_person,
        "revoked_certificates": cert_ids,
        "canceled_assignments": canceled,
        "assignment_results": assignment_results,
        "schedules": reports,
    }


# ---------------------------------------------------------------------------
# Small command dispatcher for callers that prefer the repository's run style.
# ---------------------------------------------------------------------------

def run(db, command: dict) -> dict:
    init(db)
    op = command.get("op")
    payload = {k: v for k, v in command.items() if k != "op"}
    dispatch = {
        "register_person": register_person,
        "set_person_status": set_person_status,
        "bind_subject": bind_subject,
        "bind_account": bind_account,
        "bind_factor": bind_factor,
        "register_organization": register_organization,
        "revoke_organization": revoke_organization,
        "authorize_examiner": authorize_examiner,
        "revoke_examiner": revoke_examiner,
        "record_assessment": record_assessment,
        "record_site_signing": record_site_signing,
        "add_assessment_evidence": add_assessment_evidence,
        "flag_proxy_unresolved": flag_proxy_unresolved,
        "confirm_proxy": confirm_proxy,
        "issue_certificate": issue_certificate,
        "independent_review": grant_independent_review_qualification,
        "certificate_allows": certificate_allows,
        "suspend_certificate": suspend_certificate,
        "revoke_certificate": revoke_certificate,
        "record_service_proxy": record_service_proxy,
        "certify_approval": certify_approval,
        "verify_approval_panel": verify_approval_panel,
        "certified_issue": certified_issue,
        "approve": certify_approval,
        "issue": certified_issue,
        "qualify": issue_certificate,
        "create_shift": create_shift,
        "add_unavailability": add_unavailability,
        "assign_shift": assign_shift,
        "schedule_report": schedule_report,
        "validate_schedule": validate_schedule,
        "roster_report": roster_report,
        "publish_shift": publish_shift,
        "cancel_assignment": cancel_assignment,
        "replan_after_proxy_confirmation": replan_after_proxy_confirmation,
    }
    if op not in dispatch:
        raise ValueError(f"unknown operator_certification op: {op}")
    return dispatch[op](db, **payload)
