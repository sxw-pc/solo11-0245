import json
import tempfile
import unittest
from pathlib import Path

from secretcourt.store import connect, invoke, one, rows
from secretcourt import incident_notice

ROOT = Path(__file__).resolve().parents[1]
NOTICE_TABLES = [
    "notice_contracts", "notice_authorities", "notice_contacts",
    "notice_workloads", "notice_cases", "notice_evidence", "notice_roster",
    "notices", "notice_dispatches", "notice_receipts",
    "notice_escalations", "notice_outcomes",
]
CASE = "incident-0200"
SECRET = "payments"
GEN = 1
WINDOW_FROM, WINDOW_TO = 120, 138          # 02:00 - 02:18
DISCOVERY = 135                             # 02:15, anchored on tenant A's access


def replay_notice_events(source_path):
    """Replay every notice event into a fresh database and compare state.

    Notice decisions read upstream material/grant rows (exposures, secrets,
    grants, identities), so those base tables are copied into the replay target
    first; the notice tables themselves are rebuilt purely from the event log.
    """
    base_tables = ["secrets", "versions", "exposures", "identities", "policies",
                   "approvals", "grants", "revocations", "plans", "members",
                   "receipts", "reseals", "orphans", "lineage_proofs"]
    source = connect(source_path)
    target = connect(":memory:")
    for table in base_tables:
        for row in source.execute("SELECT * FROM " + table).fetchall():
            cols = ",".join(row.keys())
            marks = ",".join("?" for _ in row.keys())
            target.execute(f"INSERT INTO {table}({cols}) VALUES({marks})", tuple(row))
    events = rows(source,
                  "SELECT payload,result FROM events WHERE subsystem='notice' ORDER BY seq")
    for event in events:
        actual = invoke(target, "notice", json.loads(event["payload"]))
        if actual != json.loads(event["result"]):
            source.close()
            target.close()
            return {"verified": False, "reason": "decision", "actual": actual}
    divergences = []
    for table in NOTICE_TABLES:
        before = [tuple(r) for r in source.execute("SELECT * FROM " + table + " ORDER BY rowid")]
        after = [tuple(r) for r in target.execute("SELECT * FROM " + table + " ORDER BY rowid")]
        if before != after:
            divergences.append(table)
    source.close()
    target.close()
    return {"verified": not divergences, "divergences": divergences,
            "decisions": len(events)}


class IncidentNoticeBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "notice.sqlite")
        self.db = connect(self.path)
        self._build_material_and_grants()
        self._build_contracts_contacts_and_case()

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def notice(self, payload):
        return invoke(self.db, "notice", payload)

    def _build_material_and_grants(self):
        # Material: purpose and the generation that later becomes exposed.
        invoke(self.db, "material", {"op": "secret", "id": SECRET,
                                     "purpose": "payment-signing"})
        invoke(self.db, "material", {"op": "seal", "secret": SECRET, "gen": 1,
                                     "digest": "sha256:material-one", "parent": None})
        # Identities.  Tenant C's instance is rebuilt at 02:11 (new UID, new epoch),
        # which freezes its old-UID grant.
        invoke(self.db, "grant", {"op": "identity", "id": "worker-a", "uid": "uid-a",
                                  "namespace": "checkout", "environment": "prod",
                                  "generation": 1})
        invoke(self.db, "grant", {"op": "identity", "id": "worker-b", "uid": "uid-b",
                                  "namespace": "checkout", "environment": "prod",
                                  "generation": 1})
        invoke(self.db, "grant", {"op": "identity", "id": "worker-c-old", "uid": "uid-c-old",
                                  "namespace": "checkout", "environment": "prod",
                                  "generation": 1})
        invoke(self.db, "grant", {"op": "policy", "purpose": "payment-signing",
                                  "fields": ["signing-key", "key-id"],
                                  "environments": ["prod"], "revision": 1})
        for grant_id in ("grant-a-1", "grant-b-1", "grant-c-1"):
            invoke(self.db, "grant", {"op": "approve", "id": grant_id + "-sec",
                                      "grant": grant_id, "actor": "security",
                                      "role": "security", "at": 5, "until": 900})
            invoke(self.db, "grant", {"op": "approve", "id": grant_id + "-own",
                                      "grant": grant_id, "actor": "owner",
                                      "role": "owner", "at": 5, "until": 900})
        # Grants are issued while gen 1 is still active, before the exposure.
        invoke(self.db, "grant", {"op": "issue", "id": "grant-a-1", "secret": SECRET,
                                  "gen": 1, "identity": "worker-a", "uid": "uid-a",
                                  "namespace": "checkout", "environment": "prod",
                                  "fields": ["signing-key", "key-id"], "until": 900,
                                  "at": 10, "approvers": ["security", "owner"]})
        invoke(self.db, "grant", {"op": "issue", "id": "grant-b-1", "secret": SECRET,
                                  "gen": 1, "identity": "worker-b", "uid": "uid-b",
                                  "namespace": "checkout", "environment": "prod",
                                  "fields": ["signing-key"], "until": 900,
                                  "at": 10, "approvers": ["security", "owner"]})
        invoke(self.db, "grant", {"op": "issue", "id": "grant-c-1", "secret": SECRET,
                                  "gen": 1, "identity": "worker-c-old", "uid": "uid-c-old",
                                  "namespace": "checkout", "environment": "prod",
                                  "fields": ["signing-key"], "until": 900,
                                  "at": 10, "approvers": ["security", "owner"]})
        # The exposure window 02:00-02:18 freezes the active grants.
        invoke(self.db, "material", {"op": "expose", "id": "exposure-0200",
                                     "secret": SECRET, "gen": 1,
                                     "from": WINDOW_FROM, "to": WINDOW_TO})
        self.assertEqual(one(self.db,
                             "SELECT status FROM grants WHERE id='grant-a-1'")["status"],
                         "frozen")
        # 02:11 rebuild of tenant C: new UID and a new identity epoch.
        invoke(self.db, "grant", {"op": "identity", "id": "worker-c-old",
                                  "uid": "uid-c-new", "namespace": "checkout",
                                  "environment": "prod", "generation": 2})
        self.assertEqual(one(self.db,
                             "SELECT status FROM grants WHERE id='grant-c-1'")["status"],
                         "frozen")

    def _build_contracts_contacts_and_case(self):
        for tenant in ("tenant-a", "tenant-b", "tenant-c"):
            self.assertEqual(self.notice({"op": "contract", "case": CASE, "tenant": tenant,
                                          "initial_hours": 4, "detailed_hours": 48}
                                         )["decision"], "registered")
            self.assertEqual(self.notice({"op": "authority", "case": CASE,
                                          "tenant": tenant, "actor": "soc-" + tenant[-1],
                                          "role": "security"})["decision"], "registered")
        # Incident-time authorised contacts (the only lawful recipients of originals).
        self.assertEqual(self.notice({"op": "contact", "id": "contact-a-old",
                                      "case": CASE, "tenant": "tenant-a",
                                      "channel": "email", "address": "sec-old@a.example",
                                      "from": 0, "change": False})["decision"],
                         "registered")
        self.assertEqual(self.notice({"op": "contact", "id": "contact-b",
                                      "case": CASE, "tenant": "tenant-b",
                                      "channel": "email", "address": "sec@b.example",
                                      "from": 0, "change": False})["decision"],
                         "registered")
        self.assertEqual(self.notice({"op": "contact", "id": "contact-c",
                                      "case": CASE, "tenant": "tenant-c",
                                      "channel": "email", "address": "sec@c.example",
                                      "from": 0, "change": False})["decision"],
                         "registered")
        # Workload-to-tenant mapping (distinct from the grant ledger).
        for uid, identity, tenant in (
                ("uid-a", "worker-a", "tenant-a"),
                ("uid-b", "worker-b", "tenant-b"),
                ("uid-c-old", "worker-c-old", "tenant-c"),
                ("uid-c-new", "worker-c-old", "tenant-c")):
            self.assertEqual(self.notice({"op": "workload", "case": CASE,
                                          "tenant": tenant, "identity": identity,
                                          "uid": uid})["decision"], "registered")
        self.assertEqual(self.notice({"op": "open_case", "id": CASE,
                                      "exposure": "exposure-0200", "secret": SECRET,
                                      "gen": GEN, "from": WINDOW_FROM,
                                      "to": WINDOW_TO})["decision"], "opened")

    def load_evidence_and_roster(self):
        # 02:15 attributable in-window access by tenant A.
        self.assertEqual(self.notice({"op": "evidence", "id": "ev-a-access",
                                      "case": CASE, "kind": "access", "uid": "uid-a",
                                      "fields": ["signing-key", "key-id"],
                                      "at": 135, "basis": "agent-log"})["decision"],
                         "recorded")
        # 02:24 receipt for tenant C's rebuilt-away UID, after the window: stale.
        self.assertEqual(self.notice({"op": "evidence", "id": "ev-c-stale",
                                      "case": CASE, "kind": "stale_receipt",
                                      "uid": "uid-c-old", "at": 144,
                                      "basis": "channel-receipt"})["decision"],
                         "recorded")
        # 03:00 anonymous cache hit, could be A's retry or C's old copy.
        self.assertEqual(self.notice({"op": "evidence", "id": "ev-anon",
                                      "case": CASE, "kind": "anonymous",
                                      "at": 180, "candidate_uids": ["uid-a", "uid-c-old"]
                                      })["decision"], "recorded")
        # Anonymous hits cannot anchor the discovery clock.
        self.assertEqual(self.notice({"op": "discover", "case": CASE,
                                      "at": 180, "basis": "ev-anon"})["decision"],
                         "anonymous_hit_cannot_anchor_discovery")
        discovered = self.notice({"op": "discover", "case": CASE,
                                  "at": DISCOVERY, "basis": "ev-a-access"})
        self.assertEqual(discovered["decision"], "discovered")
        # 4h initial deadline = 02:15 + 240m = 06:15 (375); 48h = 50:15 (3015).
        self.assertEqual(discovered["deadlines"]["tenant-c"]["initial_due"], 375)
        roster = self.notice({"op": "build_roster", "case": CASE})
        self.assertEqual(roster["decision"], "roster_built")
        by_tenant = {row["tenant"]: row for row in roster["roster"]}
        self.assertEqual(by_tenant["tenant-a"]["classification"], "attributed")
        self.assertEqual(by_tenant["tenant-a"]["confidence"], "confirmed")
        self.assertEqual(by_tenant["tenant-b"]["classification"], "permission_only")
        self.assertEqual(by_tenant["tenant-c"]["classification"], "conditional")
        self.assertEqual(sorted(roster["notified"]), ["tenant-a", "tenant-c"])
        self.assertEqual(roster["excluded"], ["tenant-b"])
        return by_tenant


class SixAcceptanceTrajectoriesTest(IncidentNoticeBase):
    def test_full_incident_notification_lifecycle_and_six_trajectories(self):
        self.load_evidence_and_roster()

        # --- Trajectory 2: tenant B holds a live grant but has no access or
        # delivery evidence, so it must NOT be notified, and overclaim is refused.
        self.assertEqual(self.notice({"op": "issue_notice", "id": "notice-b-x",
                                      "case": CASE, "tenant": "tenant-b",
                                      "kind": "initial", "contact_ids": ["contact-b"],
                                      "at": 200})["decision"], "notice_basis_refused")
        # Three grants exist for the exposed generation; only two tenants are
        # notified, proving grant-row counting is not the roster rule.
        grant_count = one(self.db,
                          "SELECT COUNT(*) n FROM grants WHERE secret=? AND gen=?",
                          (SECRET, GEN))["n"]
        self.assertEqual(grant_count, 3)

        # --- Trajectory 1: tenant A contact change.  The original notice binds the
        # incident-time contact and cannot be redirected to the replacement.
        issued_a = self.notice({"op": "issue_notice", "id": "notice-a-1",
                                "case": CASE, "tenant": "tenant-a", "kind": "initial",
                                "contact_ids": ["contact-a-old"], "at": 200})
        self.assertEqual(issued_a["decision"], "issued")
        self.assertEqual(issued_a["purpose"], "payment-signing")
        self.assertEqual(issued_a["confirmed_fields"], ["key-id", "signing-key"])
        self.assertEqual(issued_a["possible_fields"], [])
        self.assertEqual(issued_a["assertion"], "access_confirmed")
        self.assertNotIn("leaked", json.dumps(issued_a).lower())

        # Security contact for A changes later that day; the old authorisation is
        # preserved (superseded, never deleted or rewritten).
        self.assertEqual(self.notice({"op": "contact", "id": "contact-a-new",
                                      "case": CASE, "tenant": "tenant-a",
                                      "channel": "email",
                                      "address": "sec-new@a.example",
                                      "from": 260, "change": True})["decision"],
                         "contact_changed")
        self.assertEqual(one(self.db,
                             "SELECT status FROM notice_contacts WHERE id='contact-a-old'"
                             )["status"], "superseded")

        # First dispatch goes to the old address and bounces.
        self.assertEqual(self.notice({"op": "dispatch", "id": "dispatch-a-1",
                                      "notice": "notice-a-1", "channel": "email",
                                      "contact": "contact-a-old",
                                      "address": "sec-old@a.example",
                                      "at": 270})["decision"], "attempted")
        bounced = self.notice({"op": "receipt", "id": "rcpt-a-bounce",
                               "dispatch": "dispatch-a-1", "kind": "bounced",
                               "at": 275, "reference": "smtp-550"})
        self.assertEqual(bounced["decision"], "bounced")
        self.assertFalse(bounced["delivered"])
        self.assertTrue(bounced["requires_escalation"])
        # A bounced interface call must never look like delivery.
        self.assertEqual(one(self.db,
                             "SELECT status FROM notices WHERE id='notice-a-1'"
                             )["status"], "failed")

        # The new contact cannot be injected into the original notice.
        self.assertEqual(self.notice({"op": "dispatch", "id": "dispatch-a-hijack",
                                      "notice": "notice-a-1", "channel": "email",
                                      "contact": "contact-a-new",
                                      "address": "sec-new@a.example",
                                      "at": 280})["decision"],
                         "recipient_not_authorized_for_this_notice")
        # Escalation requires a registered security authority.
        self.assertEqual(self.notice({"op": "escalate", "id": "esc-a-bad",
                                      "notice": "notice-a-1", "reason": "bounce",
                                      "actor": "outsider", "outcome": "escalated",
                                      "contact": "contact-a-new",
                                      "at": 285})["decision"], "unauthorized_escalation")
        # --- Trajectory 5: mail bounce is upgraded to the currently authorised
        # contact by the tenant's security authority.
        self.assertEqual(self.notice({"op": "escalate", "id": "esc-a-1",
                                      "notice": "notice-a-1", "reason": "bounce",
                                      "actor": "soc-a", "outcome": "escalated",
                                      "contact": "contact-a-new",
                                      "at": 285})["decision"], "escalated")
        self.assertEqual(self.notice({"op": "dispatch", "id": "dispatch-a-2",
                                      "notice": "notice-a-1", "channel": "email",
                                      "contact": "contact-a-new",
                                      "address": "sec-new@a.example",
                                      "at": 290})["decision"], "attempted")
        ack = self.notice({"op": "receipt", "id": "rcpt-a-ack",
                           "dispatch": "dispatch-a-2", "kind": "acknowledged",
                           "at": 300, "reference": "signed-receipt-1"})
        self.assertEqual(ack["decision"], "acknowledged")
        self.assertTrue(ack["delivered"])

        # --- Trajectory 4: anonymous cache hit.  Before attribution resolves,
        # tenant C receives a content-minimised conditional notice (its own fields
        # only; A's fields are never disclosed) inside its initial-report window.
        notice_c = self.notice({"op": "issue_notice", "id": "notice-c-1",
                                "case": CASE, "tenant": "tenant-c",
                                "kind": "conditional", "contact_ids": ["contact-c"],
                                "at": 320})
        self.assertEqual(notice_c["decision"], "issued")
        self.assertEqual(notice_c["confidence"], "possible")
        self.assertEqual(notice_c["confirmed_fields"], [])
        self.assertEqual(notice_c["possible_fields"], ["signing-key"])
        self.assertEqual(notice_c["assertion"], "access_possible")
        self.assertNotIn("key-id", json.dumps(notice_c))  # A-only field withheld
        self.assertNotIn("leaked", json.dumps(notice_c).lower())
        self.assertEqual(self.notice({"op": "dispatch", "id": "dispatch-c-1",
                                      "notice": "notice-c-1", "channel": "email",
                                      "contact": "contact-c",
                                      "address": "sec@c.example",
                                      "at": 330})["decision"], "attempted")
        self.assertEqual(self.notice({"op": "receipt", "id": "rcpt-c-delivered",
                                      "dispatch": "dispatch-c-1", "kind": "delivered",
                                      "at": 340,
                                      "reference": "mta-250"})["decision"], "delivered")

        # --- Trajectory 3: stale UID receipt.  Late forensics at 04:30 attribute
        # the anonymous hit to C's old copy; the 02:24 receipt alone never counted.
        self.assertEqual(self.notice({"op": "evidence", "id": "ev-attrib-c",
                                      "case": CASE, "kind": "attribution",
                                      "uid": "uid-c-old",
                                      "fields": ["signing-key"], "at": 270,
                                      "basis": "cache-provenance",
                                      "attribution": "ev-anon"})["decision"], "recorded")
        self.assertEqual(one(self.db,
                             "SELECT status FROM notice_evidence WHERE id='ev-anon'"
                             )["status"], "resolved")

        # --- Trajectory 6: late attribution can only append a correction; the
        # original conditional notice and its delivery fact stay untouched.
        correction = self.notice({"op": "issue_notice", "id": "notice-c-2",
                                  "case": CASE, "tenant": "tenant-c",
                                  "kind": "correction", "supersedes": "notice-c-1",
                                  "basis": "ev-attrib-c", "contact_ids": ["contact-c"],
                                  "at": 400})
        self.assertEqual(correction["decision"], "issued")
        self.assertEqual(correction["seq"], 2)
        self.assertEqual(correction["confirmed_fields"], ["signing-key"])
        self.assertEqual(correction["assertion"], "access_confirmed")
        # A second original for the same tenant is refused: append-only chain.
        self.assertEqual(self.notice({"op": "issue_notice", "id": "notice-c-dup",
                                      "case": CASE, "tenant": "tenant-c",
                                      "kind": "conditional",
                                      "contact_ids": ["contact-c"],
                                      "at": 405})["decision"],
                         "original_notice_must_be_corrected_by_append")
        # A correction without an original is refused.
        self.assertEqual(self.notice({"op": "issue_notice", "id": "notice-b-corr",
                                      "case": CASE, "tenant": "tenant-b",
                                      "kind": "correction", "supersedes": "ghost",
                                      "basis": "ev-attrib-c",
                                      "contact_ids": ["contact-b"],
                                      "at": 405})["decision"],
                         "correction_without_original")
        self.assertEqual(self.notice({"op": "dispatch", "id": "dispatch-c-2",
                                      "notice": "notice-c-2", "channel": "email",
                                      "contact": "contact-c",
                                      "address": "sec@c.example",
                                      "at": 410})["decision"], "attempted")
        self.assertEqual(self.notice({"op": "receipt", "id": "rcpt-c-ack",
                                      "dispatch": "dispatch-c-2",
                                      "kind": "acknowledged", "at": 420,
                                      "reference": "signed-receipt-c-2"
                                      })["decision"], "acknowledged")

        # Finalisation records actual delivery evidence and contractual timeliness.
        final_a = self.notice({"op": "finalize", "case": CASE, "tenant": "tenant-a",
                               "at": 430})
        self.assertEqual(final_a["decision"], "finalized")
        self.assertEqual(final_a["final_status"], "acknowledged")
        self.assertEqual(final_a["initial_delivered_at"], 300)
        self.assertTrue(final_a["initial_on_time"])
        self.assertEqual(final_a["late_responsibility"], [])
        final_c = self.notice({"op": "finalize", "case": CASE, "tenant": "tenant-c",
                               "at": 430})
        self.assertEqual(final_c["decision"], "finalized")
        self.assertTrue(final_c["initial_on_time"])
        self.assertTrue(final_c["detailed_on_time"])
        self.assertEqual(final_c["late_responsibility"], [])

        # Finalise is idempotent and never overwrites the stored outcome.
        reused = self.notice({"op": "finalize", "case": CASE, "tenant": "tenant-c",
                              "at": 999})
        self.assertEqual(reused["decision"], "reused")

        # --- Replay: original and correction notices do not overwrite each other.
        original_before = one(self.db,
                              "SELECT recipients,status,issued_at FROM notices WHERE id='notice-c-1'")
        correction_before = one(self.db,
                                "SELECT recipients,status,issued_at FROM notices WHERE id='notice-c-2'")
        result = replay_notice_events(self.path)
        self.assertTrue(result["verified"], result)
        self.db.rollback()
        self.assertEqual(one(self.db,
                             "SELECT recipients,status,issued_at FROM notices WHERE id='notice-c-1'"),
                         original_before)
        self.assertEqual(one(self.db,
                             "SELECT recipients,status,issued_at FROM notices WHERE id='notice-c-2'"),
                         correction_before)
        # The two rows remain distinct and ordered as an append chain.
        chain = rows(self.db,
                     "SELECT id,seq,supersedes,kind FROM notices WHERE case_id=? AND tenant='tenant-c' ORDER BY seq",
                     (CASE,))
        self.assertEqual([(n["id"], n["seq"], n["supersedes"], n["kind"]) for n in chain],
                         [("notice-c-1", 1, None, "conditional"),
                          ("notice-c-2", 2, "notice-c-1", "correction")])

    def test_unattended_mailbox_must_escalate_and_undeliverable_is_evidence(self):
        self.load_evidence_and_roster()
        self.notice({"op": "issue_notice", "id": "notice-a-1", "case": CASE,
                     "tenant": "tenant-a", "kind": "initial",
                     "contact_ids": ["contact-a-old"], "at": 200})
        self.notice({"op": "dispatch", "id": "dispatch-a-1", "notice": "notice-a-1",
                     "channel": "email", "contact": "contact-a-old",
                     "address": "sec-old@a.example", "at": 210})
        # Escalation cannot be invented before any failure record exists.
        self.assertEqual(self.notice({"op": "escalate", "id": "esc-a-premature",
                                      "notice": "notice-a-1", "reason": "test",
                                      "actor": "soc-a", "outcome": "escalated",
                                      "contact": "contact-a-old",
                                      "at": 215})["decision"],
                         "escalation_without_failure_evidence")
        # Unattended mailbox is a failure, not a successful delivery.
        self.assertEqual(self.notice({"op": "receipt", "id": "rcpt-a-unatt",
                                      "dispatch": "dispatch-a-1",
                                      "kind": "unattended", "at": 230,
                                      "detail": "no-ack-within-sla"})["decision"],
                         "unattended")
        # Every authorised channel exhausted: non-deliverability is persisted.
        self.assertEqual(self.notice({"op": "escalate", "id": "esc-a-1",
                                      "notice": "notice-a-1",
                                      "reason": "unattended", "actor": "soc-a",
                                      "outcome": "undeliverable",
                                      "at": 250})["decision"], "undeliverable")
        # Finalisation keeps the undeliverable fact instead of inventing delivery.
        final = self.notice({"op": "finalize", "case": CASE, "tenant": "tenant-a",
                             "at": 260})
        self.assertEqual(final["decision"], "finalized")
        self.assertEqual(final["final_status"], "undeliverable")
        self.assertIsNone(final["initial_delivered_at"])
        self.assertIn("initial_never_delivered", final["late_responsibility"])

    def test_late_delivery_is_recorded_with_late_reporting_responsibility(self):
        self.load_evidence_and_roster()
        self.notice({"op": "issue_notice", "id": "notice-a-1", "case": CASE,
                     "tenant": "tenant-a", "kind": "initial",
                     "contact_ids": ["contact-a-old"], "at": 200})
        self.notice({"op": "dispatch", "id": "dispatch-a-1", "notice": "notice-a-1",
                     "channel": "email", "contact": "contact-a-old",
                     "address": "sec-old@a.example", "at": 380})
        # Delivered after the 06:15 contractual initial deadline (375) and after
        # the conservative 06:00 window-based clock (360).
        self.notice({"op": "receipt", "id": "rcpt-a-late",
                     "dispatch": "dispatch-a-1", "kind": "delivered",
                     "at": 390, "reference": "mta-250"})
        final = self.notice({"op": "finalize", "case": CASE,
                             "tenant": "tenant-a", "at": 400})
        self.assertEqual(final["decision"], "finalized")
        self.assertFalse(final["initial_on_time"])
        self.assertIn("initial_late_vs_contract_clock",
                      final["late_responsibility"])
        self.assertIn("initial_late_vs_conservative_window_clock",
                      final["late_responsibility"])

    def test_attribution_to_another_tenant_narrows_scope_by_append(self):
        self.load_evidence_and_roster()
        self.notice({"op": "issue_notice", "id": "notice-c-1", "case": CASE,
                     "tenant": "tenant-c", "kind": "conditional",
                     "contact_ids": ["contact-c"], "at": 320})
        self.notice({"op": "dispatch", "id": "dispatch-c-1", "notice": "notice-c-1",
                     "channel": "email", "contact": "contact-c",
                     "address": "sec@c.example", "at": 330})
        self.notice({"op": "receipt", "id": "rcpt-c-1", "dispatch": "dispatch-c-1",
                     "kind": "delivered", "at": 340, "reference": "mta-250"})
        # Forensics show the anonymous hit was A's retry; C is narrowed out.
        self.assertEqual(self.notice({"op": "evidence", "id": "ev-attrib-a",
                                      "case": CASE, "kind": "attribution",
                                      "uid": "uid-a", "fields": ["signing-key"],
                                      "at": 270, "basis": "cache-provenance",
                                      "attribution": "ev-anon"})["decision"],
                         "recorded")
        correction = self.notice({"op": "issue_notice", "id": "notice-c-2",
                                  "case": CASE, "tenant": "tenant-c",
                                  "kind": "correction", "supersedes": "notice-c-1",
                                  "basis": "ev-attrib-a",
                                  "contact_ids": ["contact-c"], "at": 400})
        self.assertEqual(correction["decision"], "issued")
        self.assertEqual(correction["confidence"], "cleared")
        self.assertEqual(correction["confirmed_fields"], [])
        self.assertEqual(correction["possible_fields"], [])
        # The original conditional notice and its delivery fact remain on record.
        original = one(self.db, "SELECT kind,status FROM notices WHERE id='notice-c-1'")
        self.assertEqual(original["kind"], "conditional")
        self.assertEqual(original["status"], "delivered")

    def test_notice_clocks_survive_revocation_and_new_key_activation(self):
        self.load_evidence_and_roster()
        self.notice({"op": "issue_notice", "id": "notice-a-1", "case": CASE,
                     "tenant": "tenant-a", "kind": "initial",
                     "contact_ids": ["contact-a-old"], "at": 200})
        self.notice({"op": "dispatch", "id": "dispatch-a-1", "notice": "notice-a-1",
                     "channel": "email", "contact": "contact-a-old",
                     "address": "sec-old@a.example", "at": 210})
        # Meanwhile the key is rotated: revoke the old grant and activate gen 2.
        self.assertEqual(invoke(self.db, "grant",
                                {"op": "revoke", "id": "revoke-a",
                                 "grant": "grant-a-1", "at": 220})["decision"],
                         "revoked")
        invoke(self.db, "material", {"op": "seal", "secret": SECRET, "gen": 2,
                                     "digest": "sha256:material-two", "parent": 1})
        self.db.execute("UPDATE versions SET status='active' WHERE secret=? AND gen=2",
                        (SECRET,))
        # The pending notice is neither cancelled nor rewritten by key lifecycle.
        pending = one(self.db,
                      "SELECT id,status,recipients FROM notices WHERE id='notice-a-1'")
        self.assertEqual(pending["status"], "pending")
        self.assertIn("contact-a-old", pending["recipients"])
        # The dispatch itself remains recorded as attempted, awaiting a receipt.
        self.assertEqual(one(self.db,
                             "SELECT status FROM notice_dispatches WHERE id='dispatch-a-1'"
                             )["status"], "attempted")
        # The late channel receipt still completes the independent delivery.
        receipt = self.notice({"op": "receipt", "id": "rcpt-a-1",
                               "dispatch": "dispatch-a-1", "kind": "delivered",
                               "at": 240, "reference": "mta-250"})
        self.assertTrue(receipt["delivered"])
        self.assertEqual(one(self.db,
                             "SELECT status FROM notices WHERE id='notice-a-1'")["status"],
                         "delivered")

    def test_dispatch_without_receipt_is_not_delivery_and_blocks_finalize(self):
        self.load_evidence_and_roster()
        self.notice({"op": "issue_notice", "id": "notice-a-1", "case": CASE,
                     "tenant": "tenant-a", "kind": "initial",
                     "contact_ids": ["contact-a-old"], "at": 200})
        self.assertEqual(self.notice({"op": "dispatch", "id": "dispatch-a-1",
                                      "notice": "notice-a-1", "channel": "email",
                                      "contact": "contact-a-old",
                                      "address": "sec-old@a.example",
                                      "at": 210})["decision"], "attempted")
        # No channel receipt: finalisation must refuse instead of claiming delivery.
        self.assertEqual(self.notice({"op": "finalize", "case": CASE,
                                      "tenant": "tenant-a",
                                      "at": 300})["decision"], "delivery_unproven")

    def test_all_notice_events_replay_deterministically_without_overwrite(self):
        self.load_evidence_and_roster()
        self.notice({"op": "issue_notice", "id": "notice-a-1", "case": CASE,
                     "tenant": "tenant-a", "kind": "initial",
                     "contact_ids": ["contact-a-old"], "at": 200})
        self.notice({"op": "dispatch", "id": "dispatch-a-1", "notice": "notice-a-1",
                     "channel": "email", "contact": "contact-a-old",
                     "address": "sec-old@a.example", "at": 210})
        self.notice({"op": "receipt", "id": "rcpt-a-1", "dispatch": "dispatch-a-1",
                     "kind": "delivered", "at": 220, "reference": "mta-250"})
        self.notice({"op": "issue_notice", "id": "notice-c-1", "case": CASE,
                     "tenant": "tenant-c", "kind": "conditional",
                     "contact_ids": ["contact-c"], "at": 320})
        self.notice({"op": "dispatch", "id": "dispatch-c-1", "notice": "notice-c-1",
                     "channel": "email", "contact": "contact-c",
                     "address": "sec@c.example", "at": 330})
        self.notice({"op": "receipt", "id": "rcpt-c-1", "dispatch": "dispatch-c-1",
                     "kind": "delivered", "at": 340, "reference": "mta-251"})
        result = replay_notice_events(self.path)
        self.assertTrue(result["verified"], result)
        self.assertGreater(result["decisions"], 10)
        # Replaying the same events again stays idempotent.
        again = replay_notice_events(self.path)
        self.assertTrue(again["verified"], again)
        self.assertEqual(again["decisions"], result["decisions"])


if __name__ == "__main__":
    unittest.main()
