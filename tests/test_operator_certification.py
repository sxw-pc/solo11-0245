"""Acceptance tests for natural-person operator certification and scheduling.

The test classes deliberately mirror the incident's acceptance checklist:
unresolved proxy exams, same-natural-person account aliases, service-account
signatures, training-body/examiner revocation, night-shift rest conflicts,
and the real people/scopes/shifts produced by timed supervised qualifications.
"""

import unittest

from secretcourt import grant
from secretcourt.operator_qualification import declare, provisional_approve
from secretcourt.operator_certification import (
    FULL,
    LIMITED_SUPERVISED,
    PROXY_CONFIRMED,
    PROXY_UNRESOLVED,
    SELF_COMPLETED,
    add_assessment_evidence,
    add_rest,
    assign_shift,
    bind_account,
    bind_factor,
    certify_approval,
    certified_issue,
    confirm_proxy,
    create_shift,
    flag_proxy_unresolved,
    independent_review,
    issue_certificate,
    publish_shift,
    record_assessment,
    record_site_signing,
    register_organization,
    register_person,
    authorize_examiner,
    certificate_allows,
    record_service_proxy,
    resolve_actor,
    suspend_certificate,
    replan_after_proxy_confirmation,
    revoke_examiner,
    revoke_organization,
    schedule_report,
    set_person_status,
)
from secretcourt.store import connect, one, rows


class CertificationCase(unittest.TestCase):
    def setUp(self):
        self.db = connect(":memory:")

    def tearDown(self):
        self.db.close()

    def person(self, pid, name=None):
        result = register_person(self.db, pid, name or pid, at=1)
        self.assertIn(result["decision"], {"registered", "reused"})
        return pid

    def human_account(self, pid, account=None, verifier="identity-board"):
        account = account or f"{pid}-account"
        result = bind_account(
            self.db, account, pid, at=2,
            evidence_id=f"evidence-{account}",
            evidence_ref=f"independent-id-{pid}",
            source_kind="government_identity_record",
            verified_by=verifier,
        )
        self.assertEqual(result["decision"], "bound", result)
        return account

    def service_account(self, account):
        result = bind_account(
            self.db, account, None, service=True, at=2,
            evidence_id=f"service-registration-{account}",
            evidence_ref="service-account-registry",
            source_kind="workload_identity_registry",
            verified_by="platform-identity",
        )
        self.assertEqual(result["decision"], "bound", result)
        return account

    def training_body(self, org_id="trainco", examiner_id="proctor",
                      kind="training"):
        self.assertEqual(register_organization(
            self.db, org_id, "Training Cooperative", kind=kind,
            valid_from=0, valid_until=500, at=1)["decision"], "organization_registered")
        self.assertEqual(authorize_examiner(
            self.db, examiner_id, org_id, "On-site Examiner",
            valid_from=0, valid_until=500, at=1)["decision"], "examiner_authorized")
        return org_id, examiner_id

    def full_cert(self, cert_id, pid, *, skill="equipment-operation",
                  role="operator", equipment="hsm-console", valid_from=10,
                  valid_until=500, can_supervise=False, org_id=None,
                  examiner_id=None, assessment_id=None, identity=SELF_COMPLETED):
        org_id = org_id or f"org-{cert_id}"
        examiner_id = examiner_id or f"examiner-{cert_id}"
        assessment_id = assessment_id or f"assessment-{cert_id}"
        register_organization(self.db, org_id, f"Org {cert_id}",
                              valid_from=0, valid_until=900, at=1)
        authorize_examiner(self.db, examiner_id, org_id,
                           valid_from=0, valid_until=900, at=1)
        recorded = record_assessment(
            self.db, assessment_id, pid, skill, equipment_class=equipment,
            provider_id=org_id, examiner_id=examiner_id, taken_at=5,
            identity_status=identity)
        self.assertEqual(recorded["decision"], "assessment_recorded", recorded)
        result = issue_certificate(
            self.db, cert_id, pid, skill=skill, role=role,
            equipment_class=equipment, assessment_id=assessment_id,
            valid_from=valid_from, valid_until=valid_until,
            can_supervise=can_supervise, issued_at=valid_from)
        self.assertEqual(result["decision"], "certificate_issued", result)
        return result

    def seed_grant_source(self):
        grant.run(self.db, {
            "op": "identity", "id": "worker-w", "uid": "uid-w",
            "namespace": "ops", "environment": "prod", "generation": 1,
        })
        grant.run(self.db, {
            "op": "policy", "purpose": "emergency-reset",
            "fields": ["reset-token"], "environments": ["prod"], "revision": 1,
        })
        self.db.execute(
            "INSERT INTO secrets(id,purpose,current_gen) VALUES('secret-w','emergency-reset',1)")
        self.db.execute(
            "INSERT INTO versions VALUES('secret-w',1,'digest-w',NULL,'active')")

    def issue_request(self, grant_id, approvers, at=20):
        return {
            "op": "issue", "id": grant_id, "secret": "secret-w", "gen": 1,
            "identity": "worker-w", "uid": "uid-w", "namespace": "ops",
            "environment": "prod", "fields": ["reset-token"], "until": 100,
            "at": at, "approvers": approvers,
        }

    def raw_approval(self, approval_id, grant_id, actor, role, at=10, until=90):
        return grant.run(self.db, {
            "op": "approve", "id": approval_id, "grant": grant_id,
            "actor": actor, "role": role, "at": at, "until": until,
        })


class ProxyIdentityTests(CertificationCase):
    def test_unresolved_proxy_and_split_factor_bindings_cannot_make_certificate(self):
        self.person("a", "Student A")
        self.person("b", "Substitute B")
        self.human_account("a", "a-account")
        self.human_account("b", "b-account")
        bind_factor(
            self.db, "badge-a", "badge", "a", at=2,
            evidence_id="ev-badge-a", evidence_ref="badge issuance ledger",
            source_kind="access_control_issuance", verified_by="security-office")
        bind_factor(
            self.db, "signer-b", "signer", "b", at=2,
            evidence_id="ev-signer-b", evidence_ref="hardware signer custody record",
            source_kind="device_custody_chain", verified_by="hardware-custodian")
        self.training_body()

        recorded = record_assessment(
            self.db, "exam-a", "a", "equipment-operation",
            equipment_class="hsm-console", provider_id="trainco",
            examiner_id="proctor", taken_at=10,
            identity_status=PROXY_UNRESOLVED)
        self.assertEqual(recorded["identity_status"], PROXY_UNRESOLVED)

        signing = record_site_signing(
            self.db, "signing-a", "exam-a", at=11,
            factor_ids=["badge-a", "signer-b"])
        self.assertEqual(signing["decision"], "site_signing_recorded")
        self.assertEqual(signing["identity_status"], PROXY_UNRESOLVED)
        self.assertEqual(signing["bound_person_ids"], ["a", "b"])

        issued = issue_certificate(
            self.db, "cert-a-bad", "a", skill="equipment-operation",
            equipment_class="hsm-console", assessment_id="exam-a",
            valid_from=20, valid_until=300)
        self.assertEqual(issued["decision"], "identity_proxy_unresolved")
        self.assertIsNone(one(self.db, "SELECT id FROM opcert_certificates WHERE id='cert-a-bad'"))

    def test_confirmed_proxy_does_not_auto_certify_actual_person(self):
        self.person("a")
        self.person("b")
        self.training_body()
        record_assessment(
            self.db, "exam-a", "a", "equipment-operation",
            provider_id="trainco", examiner_id="proctor", taken_at=10,
            identity_status=PROXY_UNRESOLVED)
        confirmed = confirm_proxy(
            self.db, "exam-a", "b", evidence_id="video-forensic", at=80)
        self.assertEqual(confirmed["decision"], "proxy_confirmed")

        attempted = issue_certificate(
            self.db, "cert-b-from-wrong-exam", "b", skill="equipment-operation",
            assessment_id="exam-a", valid_from=81, valid_until=200)
        self.assertEqual(attempted["decision"], "assessment_person_mismatch")
        self.assertIsNone(one(self.db, "SELECT id FROM opcert_certificates WHERE id='cert-b-from-wrong-exam'"))


class NaturalPersonApprovalTests(CertificationCase):
    def test_grant_accepts_two_aliases_but_certification_layer_rejects_one_person(self):
        self.seed_grant_source()
        self.person("x", "One Natural Person")
        sec_account = self.human_account("x", "x-security-alias")
        own_account = self.human_account("x", "x-owner-alias")
        self.full_cert("cert-x-sec", "x", skill="grant-approval",
                       role="security", equipment="*")
        self.full_cert("cert-x-own", "x", skill="grant-approval",
                       role="owner", equipment="*")

        # This is the legacy weakness: grant.py sees two different actor names.
        self.assertEqual(self.raw_approval(
            "raw-dup-sec", "grant-raw-dup", sec_account, "security")["decision"], "approved")
        self.assertEqual(self.raw_approval(
            "raw-dup-own", "grant-raw-dup", own_account, "owner")["decision"], "approved")
        raw_issue = grant.run(self.db, self.issue_request(
            "grant-raw-dup", [sec_account, own_account]))
        self.assertEqual(raw_issue["decision"], "granted", raw_issue)

        # The same raw aliases on another grant are stopped by natural identity.
        self.assertEqual(self.raw_approval(
            "block-dup-sec", "grant-block-dup", sec_account, "security")["decision"], "approved")
        self.assertEqual(self.raw_approval(
            "block-dup-own", "grant-block-dup", own_account, "owner")["decision"], "approved")
        blocked = certified_issue(self.db, self.issue_request(
            "grant-block-dup", [sec_account, own_account]))
        self.assertEqual(blocked["decision"], "same_natural_person_conflict")
        self.assertNotEqual(
            one(self.db, "SELECT status FROM grants WHERE id='grant-block-dup'"),
            {"status": "active"})

        # The certified approval entry point rejects the incompatible second role early.
        first = certify_approval(self.db, sec_account, "cert-x-sec", {
            "op": "approve", "id": "certified-dup-sec", "grant": "grant-early-dup",
            "actor": sec_account, "role": "security", "at": 20, "until": 90,
        })
        self.assertEqual(first["decision"], "approved", first)
        second = certify_approval(self.db, own_account, "cert-x-own", {
            "op": "approve", "id": "certified-dup-own", "grant": "grant-early-dup",
            "actor": own_account, "role": "owner", "at": 20, "until": 90,
        })
        self.assertEqual(second["decision"], "same_natural_person_conflict", second)

    def test_service_account_proxy_owner_signature_is_not_second_person(self):
        self.seed_grant_source()
        self.person("sec-person")
        sec_account = self.human_account("sec-person", "sec-human")
        self.full_cert("cert-sec", "sec-person", skill="grant-approval",
                       role="security", equipment="*")
        svc = self.service_account("svc-owner-proxy")
        proxy = record_service_proxy(
            self.db, "proxy-owner-window", svc, "owner", 5, 15,
            responsible_person_id="sec-person", reason="short automation cover")
        self.assertEqual(proxy["decision"], "service_proxy_recorded")
        self.assertFalse(proxy["counts_as_natural_person"])

        direct = certify_approval(self.db, svc, None, {
            "op": "approve", "id": "svc-approval", "grant": "grant-svc",
            "actor": svc, "role": "owner", "at": 20, "until": 90,
        })
        self.assertEqual(direct["decision"], "service_account_not_natural_person")

        self.assertEqual(self.raw_approval(
            "raw-human-sec", "grant-svc-block", sec_account, "security")["decision"], "approved")
        self.assertEqual(self.raw_approval(
            "raw-svc-owner", "grant-svc-block", svc, "owner")["decision"], "approved")
        result = certified_issue(self.db, self.issue_request(
            "grant-svc-block", [sec_account, svc]))
        self.assertEqual(result["decision"], "service_account_not_natural_person")

    def test_two_distinct_qualified_people_can_certify_and_issue(self):
        self.seed_grant_source()
        self.person("alice")
        self.person("bob")
        alice = self.human_account("alice", "alice-acc")
        bob = self.human_account("bob", "bob-acc")
        self.full_cert("cert-alice", "alice", skill="grant-approval",
                       role="security", equipment="*")
        self.full_cert("cert-bob", "bob", skill="grant-approval",
                       role="owner", equipment="*")

        first = certify_approval(self.db, alice, "cert-alice", {
            "op": "approve", "id": "ok-sec", "grant": "grant-ok",
            "actor": alice, "role": "security", "at": 20, "until": 90,
        })
        second = certify_approval(self.db, bob, "cert-bob", {
            "op": "approve", "id": "ok-own", "grant": "grant-ok",
            "actor": bob, "role": "owner", "at": 20, "until": 90,
        })
        self.assertEqual(first["decision"], "approved", first)
        self.assertEqual(second["decision"], "approved", second)

        issued = certified_issue(self.db, self.issue_request(
            "grant-ok", [alice, bob]))
        self.assertEqual(issued["decision"], "granted", issued)
        self.assertEqual(issued["qualified_person_ids"], ["alice", "bob"])


    def test_legacy_self_declared_certificate_is_not_natural_person_evidence(self):
        declare(self.db, "legacy-cert", "legacy-actor", "security")
        approval = {
            "op": "approve", "id": "legacy-approval", "grant": "legacy-grant",
            "actor": "legacy-actor", "role": "security", "at": 10, "until": 90,
        }
        self.assertEqual(provisional_approve(
            self.db, "legacy-cert", approval)["decision"], "approved")

        self.assertEqual(resolve_actor(self.db, "legacy-actor")["decision"],
                         "unbound_account")
        blocked = certify_approval(self.db, "legacy-actor", "legacy-cert", approval)
        self.assertEqual(blocked["decision"], "unbound_account")


class ProviderRevocationTests(CertificationCase):
    def test_revoked_examiner_blocks_new_exam_and_holds_only_dependent_credentials(self):
        self.person("c")
        self.person("d")
        self.person("a")
        self.training_body()
        record_assessment(
            self.db, "exam-c", "c", "equipment-operation",
            provider_id="trainco", examiner_id="proctor", taken_at=5,
            identity_status=SELF_COMPLETED)
        issue_certificate(
            self.db, "cert-c", "c", skill="equipment-operation",
            equipment_class="*", assessment_id="exam-c",
            valid_from=6, valid_until=400)
        # The disputed A record stays unresolved rather than becoming a batch verdict.
        record_assessment(
            self.db, "exam-a-dispute", "a", "equipment-operation",
            provider_id="trainco", examiner_id="proctor", taken_at=6,
            identity_status=PROXY_UNRESOLVED)
        # D has an independent credential and must remain qualified.
        self.full_cert("cert-d", "d", org_id="independent-org",
                       examiner_id="independent-examiner")

        revoked = revoke_examiner(self.db, "proctor", at=100,
                                  reason="identity supervision failure")
        self.assertEqual(revoked["decision"], "examiner_revoked")
        self.assertEqual(revoked["held_certificates"], ["cert-c"])
        self.assertFalse(revoked["whole_batch_invalidated"])

        use_c = certificate_allows(self.db, "cert-c", at=120)
        self.assertFalse(use_c["allowed"])
        self.assertEqual(use_c["decision"], "certificate_held")

        new_exam = record_assessment(
            self.db, "exam-late", "c", "equipment-operation",
            provider_id="trainco", examiner_id="proctor", taken_at=120,
            identity_status=SELF_COMPLETED)
        self.assertEqual(new_exam["decision"], "examiner_revoked")

        a_row = one(self.db, "SELECT identity_status FROM opcert_assessments WHERE id='exam-a-dispute'")
        self.assertEqual(a_row["identity_status"], PROXY_UNRESOLVED)
        use_d = certificate_allows(self.db, "cert-d", at=120, skill="equipment-operation")
        self.assertTrue(use_d["allowed"], use_d)

    def test_revoked_training_organization_holds_old_cert_and_blocks_new_issuance(self):
        self.person("c")
        self.training_body("bad-training", "bad-proctor")
        record_assessment(
            self.db, "exam-org", "c", "equipment-operation",
            provider_id="bad-training", examiner_id="bad-proctor", taken_at=5,
            identity_status=SELF_COMPLETED)
        issue_certificate(
            self.db, "cert-org", "c", skill="equipment-operation",
            assessment_id="exam-org", equipment_class="*",
            valid_from=6, valid_until=400)

        revoked = revoke_organization(self.db, "bad-training", at=100,
                                      reason="accreditation withdrawn")
        self.assertEqual(revoked["decision"], "organization_revoked")
        self.assertEqual(revoked["affected_certificates"], ["cert-org"])
        self.assertEqual(revoked["certificate_action"], "held")
        self.assertFalse(revoked["whole_batch_invalidated"])

        late_exam = record_assessment(
            self.db, "exam-after-org-revoke", "c", "equipment-operation",
            provider_id="bad-training", examiner_id="bad-proctor", taken_at=120,
            identity_status=SELF_COMPLETED)
        self.assertEqual(late_exam["decision"], "training_organization_revoked")

        # A formal batch invalidation is a separate act, not inferred from revocation.
        formal = revoke_organization(
            self.db, "bad-training", at=130, reason="formal batch invalidation",
            invalidate_certificates=True)
        self.assertEqual(formal["decision"], "organization_revoked")
        self.assertIn("cert-org", formal["affected_certificates"])
        self.assertEqual(one(
            self.db, "SELECT status FROM opcert_certificates WHERE id='cert-org'")["status"],
            "revoked")


class ScheduleBoundaryTests(CertificationCase):
    def test_overlapping_site_assignment_and_rest_block_same_natural_person(self):
        self.person("a")
        self.person("b")
        self.full_cert("cert-a", "a")
        self.full_cert("cert-b", "b")
        create_shift(self.db, "site-1-night", "plant-1", 200, 240,
                     equipment_class="hsm-console")
        create_shift(self.db, "site-2-emergency", "plant-2", 210, 230,
                     equipment_class="hsm-console", min_witnesses=1)

        assigned = assign_shift(self.db, "assign-a-1", "site-1-night",
                                "a", "cert-a", operation="reset")
        self.assertEqual(assigned["decision"], "assigned", assigned)

        clash = assign_shift(self.db, "assign-a-2", "site-2-emergency",
                             "a", "cert-a", role="witness")
        self.assertEqual(clash["decision"], "double_booked")
        self.assertEqual(clash["conflicting_assignment"], "assign-a-1")

        add_rest(self.db, "rest-b", "b", 200, 240, reason="mandatory overnight rest")
        rested = assign_shift(self.db, "assign-b", "site-1-night", "b", "cert-b")
        self.assertEqual(rested["decision"], "rest_conflict")

        published = publish_shift(self.db, "site-1-night")
        self.assertEqual(published["decision"], "schedule_published", published)
        self.assertEqual(published["person_ids"], ["a"])

    def test_suspended_or_departed_person_cannot_use_old_certificate(self):
        self.person("old")
        self.full_cert("cert-old", "old")
        create_shift(self.db, "shift-old", "site", 300, 360)
        set_person_status(self.db, "old", "suspended", at=200, reason="qualification audit")
        blocked = assign_shift(self.db, "assign-old", "shift-old", "old", "cert-old")
        self.assertEqual(blocked["decision"], "person_suspended")

        set_person_status(self.db, "old", "departed", at=250, reason="employment ended")
        departed = assign_shift(self.db, "assign-old-2", "shift-old", "old", "cert-old")
        self.assertEqual(departed["decision"], "person_departed")

    def test_suspended_certificate_cannot_be_used_for_new_shift(self):
        self.person("paused")
        self.full_cert("cert-paused", "paused")
        create_shift(self.db, "shift-paused", "site", 300, 360)
        suspended = suspend_certificate(self.db, "cert-paused", 250,
                                        "skills audit pending")
        self.assertEqual(suspended["decision"], "certificate_status_updated")
        blocked = assign_shift(self.db, "assign-paused", "shift-paused",
                               "paused", "cert-paused")
        self.assertEqual(blocked["decision"], "certificate_suspended")


class RecoveryPathTests(CertificationCase):
    def test_path_one_independent_retakes_restore_people_but_night_is_outsourced(self):
        self.person("a")
        self.person("b")
        self.training_body("ambiguous-trainco", "ambiguous-proctor")
        record_assessment(
            self.db, "old-exam-a", "a", "equipment-operation",
            equipment_class="hsm-console", provider_id="ambiguous-trainco",
            examiner_id="ambiguous-proctor", taken_at=10,
            identity_status=PROXY_UNRESOLVED)

        register_organization(self.db, "independent-board", "Independent Practical Board",
                              kind="independent_assessor", valid_until=900)
        authorize_examiner(self.db, "ind-exam-a", "independent-board", valid_until=900)
        authorize_examiner(self.db, "ind-exam-b", "independent-board", valid_until=900)
        for pid, examiner in [("a", "ind-exam-a"), ("b", "ind-exam-b")]:
            exam = f"retake-{pid}"
            self.assertEqual(record_assessment(
                self.db, exam, pid, "equipment-operation", equipment_class="hsm-console",
                provider_id="independent-board", examiner_id=examiner, taken_at=150,
                identity_status=SELF_COMPLETED)["decision"], "assessment_recorded")
            issued = issue_certificate(
                self.db, f"full-{pid}", pid, skill="equipment-operation",
                equipment_class="hsm-console", assessment_id=exam,
                valid_from=151, valid_until=600)
            self.assertEqual(issued["decision"], "certificate_issued", issued)
            self.assertEqual(issued["certificate_kind"], FULL)

        self.person("external-x")
        self.person("external-y")
        register_organization(self.db, "nightwatch", "Night Qualified Cover",
                              kind="external_duty_provider")
        self.full_cert("cert-ext-x", "external-x", org_id="ext-org-x")
        self.full_cert("cert-ext-y-sup", "external-y", org_id="ext-org-y",
                       can_supervise=True)

        create_shift(
            self.db, "outsourced-night", "night-site", 200, 280,
            equipment_class="hsm-console", provider_id="nightwatch",
            required_roles={"operator": 1, "supervisor": 1})
        self.assertEqual(assign_shift(
            self.db, "ext-sup", "outsourced-night", "external-y",
            "cert-ext-y-sup", role="supervisor")["decision"], "assigned")
        self.assertEqual(assign_shift(
            self.db, "ext-op", "outsourced-night", "external-x",
            "cert-ext-x", role="operator")["decision"], "assigned")
        night = publish_shift(self.db, "outsourced-night")
        self.assertEqual(night["decision"], "schedule_published", night)
        self.assertEqual(night["provider_id"], "nightwatch")
        self.assertEqual(night["person_ids"], ["external-x", "external-y"])
        self.assertNotIn("a", night["person_ids"])
        self.assertNotIn("b", night["person_ids"])

        create_shift(self.db, "restored-day", "day-site", 320, 400,
                     equipment_class="hsm-console",
                     required_roles={"operator": 2})
        self.assertEqual(assign_shift(
            self.db, "day-a", "restored-day", "a", "full-a")["decision"], "assigned")
        self.assertEqual(assign_shift(
            self.db, "day-b", "restored-day", "b", "full-b")["decision"], "assigned")
        day = publish_shift(self.db, "restored-day")
        self.assertEqual(day["decision"], "schedule_published", day)
        self.assertEqual(day["person_ids"], ["a", "b"])

    def test_path_two_limited_review_qualification_is_real_person_scope_and_supervision(self):
        from secretcourt.operator_certification import certificate_allows

        self.person("a")
        self.person("b")
        self.person("supervisor-s")
        self.training_body()
        record_assessment(
            self.db, "exam-a", "a", "equipment-operation",
            equipment_class="hsm-console", provider_id="trainco",
            examiner_id="proctor", taken_at=10,
            identity_status=PROXY_UNRESOLVED)
        add_assessment_evidence(
            self.db, "operation-log", "exam-a", "operation_record",
            reference="console operation log matching signer challenge",
            at=120, proves_person_id="b", verified_by="independent-examiner")
        add_assessment_evidence(
            self.db, "custody-chain", "exam-a", "signer_custody_chain",
            reference="signer-b issuance and custody transfers",
            at=120, proves_person_id="b", verified_by="hardware-custodian")
        register_organization(self.db, "review-board", "Independent Review Board",
                              kind="review_board", valid_until=900)

        granted = independent_review(
            self.db, "limited-b", "review-b", "exam-a", "b",
            review_organization_id="review-board", at=150, valid_until=260,
            operations=["reset-hsm"], equipment_class="hsm-console",
            site_ids=["night-site"])
        self.assertEqual(granted["decision"], "certificate_issued", granted)
        self.assertEqual(granted["certificate_kind"], LIMITED_SUPERVISED)
        self.assertTrue(granted["supervision_required"])
        self.assertEqual(granted["scope"]["operations"], ["reset-hsm"])
        self.assertTrue(granted["scope"]["review_only"])

        row = one(self.db, "SELECT * FROM opcert_certificates WHERE id='limited-b'")
        self.assertEqual(row["person_id"], "b")
        self.assertEqual(row["certificate_kind"], LIMITED_SUPERVISED)
        self.assertEqual(row["review_id"], "review-b")
        self.assertEqual(row["supervision_required"], 1)

        self.assertTrue(certificate_allows(
            self.db, "limited-b", at=200, equipment_class="hsm-console",
            operation="reset-hsm", site_id="night-site")["allowed"])
        unnamed_operation = certificate_allows(
            self.db, "limited-b", at=200, equipment_class="hsm-console",
            assignment_role="operator")
        self.assertEqual(unnamed_operation["decision"], "narrow_operation_name_required")
        outside_operation = certificate_allows(
            self.db, "limited-b", at=200, equipment_class="hsm-console",
            operation="export-all-keys")
        self.assertEqual(outside_operation["decision"], "operation_not_in_narrow_scope")
        approval_attempt = certificate_allows(
            self.db, "limited-b", at=200, role="owner",
            skill="grant-approval", require_full=True)
        self.assertFalse(approval_attempt["allowed"])

        # The other candidate remains unqualified and must retake the practical exam.
        create_shift(self.db, "a-attempt-shift", "night-site", 200, 260,
                     equipment_class="hsm-console")
        a_attempt = assign_shift(self.db, "a-without-cert", "a-attempt-shift", "a")
        self.assertEqual(a_attempt["decision"], "certificate_required")
        a_cert_attempt = issue_certificate(
            self.db, "cert-a-still-blocked", "a", skill="equipment-operation",
            equipment_class="hsm-console", assessment_id="exam-a",
            valid_from=150, valid_until=260)
        self.assertEqual(a_cert_attempt["decision"], "identity_proxy_unresolved")

        self.full_cert("full-s", "supervisor-s", can_supervise=True)
        create_shift(
            self.db, "limited-night", "night-site", 200, 260,
            equipment_class="hsm-console",
            required_roles={"operator": 1, "supervisor": 1})
        no_supervisor = assign_shift(
            self.db, "b-no-sup", "limited-night", "b", "limited-b",
            operation="reset-hsm")
        self.assertEqual(no_supervisor["decision"], "named_supervisor_required")
        missing_supervisor = assign_shift(
            self.db, "b-missing-sup", "limited-night", "b", "limited-b",
            operation="reset-hsm", supervised_by="supervisor-s")
        self.assertEqual(missing_supervisor["decision"], "supervisor_not_on_shift")

        self.assertEqual(assign_shift(
            self.db, "s-supervises", "limited-night", "supervisor-s",
            "full-s", role="supervisor")["decision"], "assigned")
        assigned = assign_shift(
            self.db, "b-operates", "limited-night", "b", "limited-b",
            operation="reset-hsm", supervised_by="supervisor-s")
        self.assertEqual(assigned["decision"], "assigned", assigned)
        published = publish_shift(self.db, "limited-night")
        self.assertEqual(published["decision"], "schedule_published", published)
        self.assertEqual(published["person_ids"], ["b", "supervisor-s"])
        operator_segment = published["segments"][0]["roles"]["operator"]
        self.assertEqual(operator_segment, ["b"])
        self.assertEqual(published["segments"][0]["roles"]["supervisor"], ["supervisor-s"])


class ProxyReplanTests(CertificationCase):
    def _dispatched_shift_with_a(self):
        self.person("a")
        self.person("b")
        self.person("s")
        self.person("q")
        self.training_body()
        record_assessment(
            self.db, "exam-a", "a", "equipment-operation",
            equipment_class="hsm-console", provider_id="trainco",
            examiner_id="proctor", taken_at=5, identity_status=SELF_COMPLETED)
        issued = issue_certificate(
            self.db, "cert-a", "a", skill="equipment-operation",
            equipment_class="hsm-console", assessment_id="exam-a",
            valid_from=6, valid_until=400)
        self.assertEqual(issued["decision"], "certificate_issued", issued)
        self.full_cert("cert-s", "s", can_supervise=True)
        self.full_cert("cert-q", "q")
        create_shift(
            self.db, "past-shift", "plant-1", 50, 60,
            equipment_class="hsm-console")
        self.assertEqual(assign_shift(
            self.db, "assign-a-past", "past-shift", "a", "cert-a",
            operation="reset-hsm")["decision"], "assigned")
        create_shift(
            self.db, "shift-replan", "plant-1", 200, 260,
            equipment_class="hsm-console",
            required_roles={"operator": 1, "supervisor": 1})
        self.assertEqual(assign_shift(
            self.db, "assign-s", "shift-replan", "s", "cert-s",
            role="supervisor")["decision"], "assigned")
        self.assertEqual(assign_shift(
            self.db, "assign-a", "shift-replan", "a", "cert-a",
            operation="reset-hsm")["decision"], "assigned")
        self.assertEqual(publish_shift(self.db, "shift-replan")["decision"],
                         "schedule_published")

        flagged = flag_proxy_unresolved(
            self.db, "exam-a", evidence_id="ambiguous-video", at=100)
        self.assertEqual(flagged["held_certificates"], ["cert-a"])
        invalid = schedule_report(self.db, "shift-replan")
        self.assertFalse(invalid["valid"])
        self.assertIn("certificate_held", [v["decision"] for v in invalid["violations"]])

        confirmed = confirm_proxy(
            self.db, "exam-a", "b", evidence_id="forensic-video", at=150)
        self.assertEqual(confirmed["decision"], "proxy_confirmed")

    def test_confirmed_b_replaces_a_with_external_qualified_operator(self):
        self._dispatched_shift_with_a()
        result = replan_after_proxy_confirmation(
            self.db, "exam-a", at=160,
            replacements=[{
                "assignment_id": "assign-q",
                "shift_id": "shift-replan",
                "person_id": "q",
                "certificate_id": "cert-q",
                "role": "operator",
                "operation": "reset-hsm",
            }])
        self.assertEqual(result["decision"], "replanned", result)
        self.assertEqual(result["canceled_assignments"], ["assign-a"])
        self.assertEqual(result["revoked_certificates"], ["cert-a"])

        canceled = one(self.db, "SELECT status,cancel_reason FROM opcert_assignments WHERE id='assign-a'")
        self.assertEqual(canceled["status"], "canceled")
        self.assertIn("b", canceled["cancel_reason"])
        past = one(self.db, "SELECT status FROM opcert_assignments WHERE id='assign-a-past'")
        self.assertEqual(past["status"], "active")
        active = rows(self.db,
                      "SELECT person_id FROM opcert_assignments WHERE shift_id='shift-replan' AND status='active' ORDER BY person_id")
        self.assertEqual([r["person_id"] for r in active], ["q", "s"])
        shift = schedule_report(self.db, "shift-replan")
        self.assertTrue(shift["valid"], shift["violations"])
        cert_a = one(self.db, "SELECT status,status_reason FROM opcert_certificates WHERE id='cert-a'")
        self.assertEqual(cert_a["status"], "revoked")
        self.assertEqual(cert_a["status_reason"], "proxy_confirmed_other_person")

        retry = replan_after_proxy_confirmation(
            self.db, "exam-a", at=160,
            replacements=[{
                "assignment_id": "assign-q",
                "shift_id": "shift-replan",
                "person_id": "q",
                "certificate_id": "cert-q",
                "role": "operator",
                "operation": "reset-hsm",
            }])
        self.assertEqual(retry["decision"], "replanned", retry)

    def test_confirmed_b_can_fill_only_existing_limited_supervised_scope(self):
        self._dispatched_shift_with_a()
        add_assessment_evidence(
            self.db, "op-log-b", "exam-a", "operation_record",
            proves_person_id="b", at=120)
        add_assessment_evidence(
            self.db, "custody-b", "exam-a", "signer_custody_chain",
            proves_person_id="b", at=120)
        register_organization(self.db, "review-board-2", kind="review_board",
                              valid_until=900)
        limited = independent_review(
            self.db, "cert-b-limited", "review-b-2", "exam-a", "b",
            review_organization_id="review-board-2", at=155, valid_until=260,
            operations=["reset-hsm"], equipment_class="hsm-console",
            site_ids=["plant-1"])
        self.assertEqual(limited["decision"], "certificate_issued", limited)

        # Out-of-scope replacement is rejected rather than turning B into a full operator.
        bad = replan_after_proxy_confirmation(
            self.db, "exam-a", at=160,
            replacements=[{
                "assignment_id": "assign-b-bad",
                "shift_id": "shift-replan",
                "person_id": "b",
                "certificate_id": "cert-b-limited",
                "role": "operator",
                "operation": "export-all-keys",
                "supervised_by": "s",
            }])
        self.assertEqual(bad["decision"], "replan_incomplete")
        self.assertEqual(bad["assignment_results"][0]["decision"],
                         "operation_not_in_narrow_scope")

        good = replan_after_proxy_confirmation(
            self.db, "exam-a", at=160,
            replacements=[{
                "assignment_id": "assign-b-good",
                "shift_id": "shift-replan",
                "person_id": "b",
                "certificate_id": "cert-b-limited",
                "role": "operator",
                "operation": "reset-hsm",
                "supervised_by": "s",
            }])
        self.assertEqual(good["decision"], "replanned", good)
        active = rows(self.db,
                      "SELECT person_id,certificate_id FROM opcert_assignments "
                      "WHERE shift_id='shift-replan' AND status='active' ORDER BY person_id")
        self.assertEqual([(r["person_id"], r["certificate_id"]) for r in active],
                         [("b", "cert-b-limited"), ("s", "cert-s")])
        report = schedule_report(self.db, "shift-replan")
        self.assertTrue(report["valid"], report["violations"])


if __name__ == "__main__":
    unittest.main()
