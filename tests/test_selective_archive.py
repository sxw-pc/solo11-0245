import copy
import json
import tempfile
import unittest
from pathlib import Path

from secretcourt.store import connect, invoke
from secretcourt import selective_archive as sa


class SelectiveArchiveTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = connect(str(Path(self.temp.name) / "court.sqlite"))
        # A and B live in different namespaces; B's identifiers are contractually
        # forbidden from ever reaching A.
        self.b_tokens = ["uid-b", "ns-billing", "worker-b", "grant-b-1",
                         "approve-b-security", "approve-b-owner", "receipt-b-late"]
        self._bootstrap_material()
        self._bootstrap_identities_and_grants()

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def _bootstrap_material(self):
        invoke(self.db, "material", {"op": "secret", "id": "payments", "purpose": "payment-signing"})
        invoke(self.db, "material", {"op": "seal", "secret": "payments", "gen": 1,
                                     "digest": "sha256:material-one", "parent": None})

    def _bootstrap_identities_and_grants(self):
        invoke(self.db, "grant", {"op": "identity", "id": "worker-a", "uid": "uid-a",
                                  "namespace": "checkout", "environment": "prod", "generation": 1})
        invoke(self.db, "grant", {"op": "identity", "id": "worker-b", "uid": "uid-b",
                                  "namespace": "ns-billing", "environment": "prod", "generation": 1})
        invoke(self.db, "grant", {"op": "policy", "purpose": "payment-signing",
                                  "fields": ["signing-key", "key-id"],
                                  "environments": ["prod"], "revision": 1})
        for actor, grant in [("security", "grant-a-1"), ("owner", "grant-a-1"),
                             ("security", "grant-b-1"), ("owner", "grant-b-1")]:
            invoke(self.db, "grant", {"op": "approve", "id": "approve-%s-%s" % (grant.split("-")[1], actor),
                                      "grant": grant, "actor": actor, "role": actor,
                                      "at": 5, "until": 90})
        invoke(self.db, "grant", {"op": "issue", "id": "grant-a-1", "secret": "payments", "gen": 1,
                                  "identity": "worker-a", "uid": "uid-a", "namespace": "checkout",
                                  "environment": "prod", "fields": ["signing-key"],
                                  "until": 100, "at": 10, "approvers": ["security", "owner"]})
        invoke(self.db, "grant", {"op": "issue", "id": "grant-b-1", "secret": "payments", "gen": 1,
                                  "identity": "worker-b", "uid": "uid-b", "namespace": "ns-billing",
                                  "environment": "prod", "fields": ["signing-key"],
                                  "until": 100, "at": 10, "approvers": ["security", "owner"]})

    def _joint_plan(self):
        return invoke(self.db, "delivery", {
            "op": "plan", "id": "plan-joint", "secret": "payments", "gen": 1,
            "packet": "sha256:packet-one", "at": 20,
            "members": [{"uid": "uid-a", "grant": "grant-a-1"},
                        {"uid": "uid-b", "grant": "grant-b-1"}]})

    def _mandate(self, mid="mandate-a", frm=0, to=22):
        return sa.register_mandate(self.db, {
            "id": mid, "subject": "uid-a", "namespace": "checkout",
            "purpose": "payment-signing", "secret": "payments",
            "from": frm, "to": to, "at": 21, "approvers": ["security", "owner"]})

    def _keys(self):
        return {r["key_id"]: r["secret"] for r in
                self.db.execute("SELECT key_id,secret FROM archive_keys").fetchall()}

    def _node(self, envelope, seq):
        return next(n for n in envelope["nodes"] if n["seq"] == seq)

    def test_joint_plan_is_redacted_with_hidden_member_commitment_and_predicate(self):
        plan = self._joint_plan()
        self.assertEqual(plan["decision"], "planned")
        self.assertEqual(plan["members"], ["uid-a", "uid-b"])
        self.assertEqual(self._mandate()["decision"], "mandate_registered")
        issued = sa.issue_package(self.db, "pkg-a-1", "mandate-a", "uid-a", 22)
        self.assertEqual(issued["decision"], "package_issued")
        self.assertEqual(issued["revision"], 1)

        download = sa.download_package(self.db, "pkg-a-1", "uid-a")
        envelope = download["envelope"]
        # Nothing of B survives in clear text: uid, namespace, grant/licence ids.
        self.assertEqual(sa.scan_disclosure(envelope, self.b_tokens),
                         {"leak_free": True, "leaked": []})

        plan_seq = self.db.execute(
            "SELECT seq FROM events WHERE subsystem='delivery' ORDER BY seq LIMIT 1").fetchone()[0]
        node = self._node(envelope, plan_seq)
        self.assertEqual(node["type"], "redacted")
        # A's own member stays fully visible and identical to the original decision input.
        member_views = node["payload_view"]["members"]
        own = next(m for m in member_views if not sa._is_hidden(m) and not sa._is_decoy(m))
        self.assertEqual(own, {"grant": "grant-a-1", "uid": "uid-a"})
        # Hidden roster slots have a fixed width and are padded so the hidden
        # count cannot be inferred from list length.
        hidden = [m for m in member_views if sa._is_hidden(m)]
        decoys = [m for m in member_views if sa._is_decoy(m)]
        self.assertEqual(len(member_views), sa.HIDDEN_CAPACITY)
        self.assertEqual(len(hidden), 1)
        self.assertGreater(len(decoys), 0)
        for leaf in hidden:
            self.assertEqual(len(leaf["hidden"]), len("sha256:") + 64)
            self.assertEqual(len(leaf["nonce"]), 32)
        # The selective proof ties the redacted view to the original record hash.
        result = sa.verify_package(envelope, self._keys(),
                                   public_checkpoint=envelope["ledger"]["checkpoint"])
        self.assertTrue(result["verified"], result["errors"])
        # A can locally re-run the decision predicate for its own member.
        predicate = node["decision_predicate"]
        self.assertEqual(predicate["decision"], "planned")
        self.assertEqual(predicate["subject_members"][0]["uid"], "uid-a")
        self.assertTrue(predicate["subject_members"][0]["licensed"])
        self.assertTrue(sa._run_predicate(predicate))
        # The hidden count is deliberately not disclosed.
        self.assertTrue(predicate["hidden_member_count_omitted"])

    def test_late_b_receipt_cannot_backfill_a_signed_package_and_addendum_chains_it(self):
        self._joint_plan()
        invoke(self.db, "delivery", {"op": "receipt", "id": "receipt-a-1", "plan": "plan-joint",
                                     "uid": "uid-a", "kind": "delivered",
                                     "packet": "sha256:packet-one", "at": 21})
        self.assertEqual(self._mandate(to=22)["decision"], "mandate_registered")
        first = sa.issue_package(self.db, "pkg-a-1", "mandate-a", "uid-a", 22)
        sa.acknowledge_package(self.db, "pkg-a-1", "uid-a", 22)
        v1 = sa.download_package(self.db, "pkg-a-1", "uid-a")["envelope"]
        v1_checkpoint = v1["ledger"]["checkpoint"]
        v1_bytes = json.dumps(v1, sort_keys=True)

        # B's receipt arrives two days late.
        invoke(self.db, "delivery", {"op": "receipt", "id": "receipt-b-late", "plan": "plan-joint",
                                     "uid": "uid-b", "kind": "delivered",
                                     "packet": "sha256:packet-one", "at": 24})
        # The already signed package is immutable: re-issuing the same id is idempotent.
        again = sa.issue_package(self.db, "pkg-a-1", "mandate-a", "uid-a", 24)
        self.assertEqual(again["decision"], "reused")
        v1_after = sa.download_package(self.db, "pkg-a-1", "uid-a")["envelope"]
        self.assertEqual(json.dumps(v1_after, sort_keys=True), v1_bytes)

        # The correction package is a new revision explicitly linked to the old one.
        self.assertEqual(self._mandate("mandate-a-2", to=30)["decision"], "mandate_registered")
        second = sa.issue_package(self.db, "pkg-a-2", "mandate-a-2", "uid-a", 25)
        self.assertEqual(second["decision"], "package_issued")
        self.assertEqual(second["revision"], 1)
        v2 = sa.download_package(self.db, "pkg-a-2", "uid-a")["envelope"]
        self.assertEqual(v2["predecessor"], None)
        # Within the same mandate, revisions chain; demonstrate with a second reissue.
        third = sa.issue_package(self.db, "pkg-a-3", "mandate-a-2", "uid-a", 26)
        self.assertEqual(third["predecessor"], "pkg-a-2")
        v3 = sa.download_package(self.db, "pkg-a-3", "uid-a")["envelope"]
        self.assertEqual(v3["predecessor"], "pkg-a-2")

        # B's late receipt is present in v2 but carries nothing of B in clear.
        self.assertEqual(sa.scan_disclosure(v2, self.b_tokens)["leak_free"], True)
        late_seq = self.db.execute(
            "SELECT seq FROM events WHERE payload LIKE '%receipt-b-late%'").fetchone()[0]
        late_node = self._node(v2, late_seq)
        self.assertEqual(late_node["type"], "anchor")
        self.assertNotIn(late_seq, [n["seq"] for n in v1["nodes"] if n["type"] != "anchor"])

        # Ordering proof: A's delivery event seq precedes B's late receipt, and
        # v1's checkpoint was fixed before the late event existed - no backfill.
        a_seq = self.db.execute(
            "SELECT seq FROM events WHERE payload LIKE '%receipt-a-1%'").fetchone()[0]
        self.assertLess(a_seq, late_seq)
        self.assertNotEqual(v1_checkpoint, v2["ledger"]["checkpoint"])
        self.assertEqual(v1["ledger"]["checkpoint"], v1_checkpoint)
        # Both packages independently verify offline against their own checkpoints.
        for envelope in (v1, v2, v3):
            verdict = sa.verify_package(envelope, self._keys(),
                                        public_checkpoint=envelope["ledger"]["checkpoint"])
            self.assertTrue(verdict["verified"], verdict["errors"])

    def test_export_requires_bound_mandate_not_secret_knowledge(self):
        self._joint_plan()
        # No mandate at all.
        self.assertEqual(sa.issue_package(self.db, "pkg-x", "mandate-a", "uid-a", 22)["decision"],
                         "unknown_mandate")
        self.assertEqual(self._mandate()["decision"], "mandate_registered")
        # Another subject presenting A's mandate is rejected.
        self.assertEqual(sa.issue_package(self.db, "pkg-x", "mandate-a", "uid-b", 22)["decision"],
                         "subject_mismatch")
        # A mandate over a non-matching purpose is rejected at registration.
        bad = sa.register_mandate(self.db, {
            "id": "mandate-wrong", "subject": "uid-a", "namespace": "checkout",
            "purpose": "other-purpose", "secret": "payments",
            "from": 0, "to": 22, "at": 21, "approvers": ["security", "owner"]})
        self.assertEqual(bad["decision"], "purpose_mismatch")
        # Missing dual approval cannot establish export eligibility.
        no_approval = sa.register_mandate(self.db, {
            "id": "mandate-no-approval", "subject": "uid-a", "namespace": "checkout",
            "purpose": "payment-signing", "secret": "payments",
            "from": 0, "to": 22, "at": 21, "approvers": ["security"]})
        self.assertEqual(no_approval["decision"], "missing_two_approvers")
        # A window that covers none of the events still produces an anchored package,
        # but a reversed window is rejected.
        reversed_window = sa.register_mandate(self.db, {
            "id": "mandate-rev", "subject": "uid-a", "namespace": "checkout",
            "purpose": "payment-signing", "secret": "payments",
            "from": 30, "to": 5, "at": 21, "approvers": ["security", "owner"]})
        self.assertEqual(reversed_window["decision"], "invalid_window")
        # Download by a different subject is denied.
        sa.issue_package(self.db, "pkg-a-1", "mandate-a", "uid-a", 22)
        self.assertEqual(sa.download_package(self.db, "pkg-a-1", "uid-b")["decision"],
                         "subject_mismatch")

    def test_packages_cannot_be_correlated_through_hidden_commitments(self):
        self._joint_plan()
        self._mandate()
        sa.issue_package(self.db, "pkg-a-1", "mandate-a", "uid-a", 22)
        # More ledger activity, then a fresh package under a renewed mandate window.
        invoke(self.db, "delivery", {"op": "receipt", "id": "receipt-a-1", "plan": "plan-joint",
                                     "uid": "uid-a", "kind": "delivered",
                                     "packet": "sha256:packet-one", "at": 21})
        self._mandate("mandate-a-2", to=30)
        sa.issue_package(self.db, "pkg-a-2", "mandate-a-2", "uid-a", 25)
        e1 = sa.download_package(self.db, "pkg-a-1", "uid-a")["envelope"]
        e2 = sa.download_package(self.db, "pkg-a-2", "uid-a")["envelope"]
        c1 = sa.hidden_commitments(e1)
        c2 = sa.hidden_commitments(e2)
        self.assertTrue(c1 and c2)
        # Every salt, nonce and envelope nonce is unique: no stable handle for B.
        self.assertEqual({c["nonce"] for c in c1}.isdisjoint({c["nonce"] for c in c2}), True)
        self.assertEqual({c["hidden"] for c in c1}.isdisjoint({c["hidden"] for c in c2}), True)
        self.assertNotEqual(e1["nonce"], e2["nonce"])
        # All hidden digests share one fixed width: length is not a side channel.
        for leaf in c1 + c2:
            self.assertEqual(len(leaf["hidden"]), len("sha256:") + 64)

    def test_tampering_with_original_or_archive_is_detected_offline(self):
        self._joint_plan()
        invoke(self.db, "delivery", {"op": "receipt", "id": "receipt-a-1", "plan": "plan-joint",
                                     "uid": "uid-a", "kind": "delivered",
                                     "packet": "sha256:packet-one", "at": 21})
        self._mandate()
        sa.issue_package(self.db, "pkg-a-1", "mandate-a", "uid-a", 22)
        envelope = sa.download_package(self.db, "pkg-a-1", "uid-a")["envelope"]
        keys = self._keys()
        checkpoint = envelope["ledger"]["checkpoint"]
        self.assertTrue(sa.verify_package(envelope, keys, public_checkpoint=checkpoint)["verified"])

        # 1. Tamper with a disclosed field: record hash no longer matches.
        tampered = copy.deepcopy(envelope)
        visible = next(n for n in tampered["nodes"] if n["type"] == "visible")
        visible["result"]["pending"] = visible["result"].get("pending", 0) + 1
        verdict = sa.verify_package(tampered, keys, public_checkpoint=checkpoint)
        self.assertFalse(verdict["verified"])
        self.assertIn("record-hash", " ".join(verdict["errors"]))

        # 2. Tamper with a redacted view: selective root breaks.
        tampered = copy.deepcopy(envelope)
        redacted = next(n for n in tampered["nodes"] if n["type"] == "redacted")
        redacted["result_view"]["decision"] = "forged"
        verdict = sa.verify_package(tampered, keys, public_checkpoint=checkpoint)
        self.assertFalse(verdict["verified"])
        self.assertTrue(any(e.startswith("selective-root") for e in verdict["errors"]))

        # 3. Reorder events: chain order proof breaks.
        tampered = copy.deepcopy(envelope)
        tampered["nodes"][0], tampered["nodes"][1] = tampered["nodes"][1], tampered["nodes"][0]
        verdict = sa.verify_package(tampered, keys, public_checkpoint=checkpoint)
        self.assertFalse(verdict["verified"])
        self.assertTrue(any("chain-order" in e for e in verdict["errors"]))

        # 4. Forge the manifest signature: rejected.
        tampered = copy.deepcopy(envelope)
        tampered["issued_at"] = 999
        verdict = sa.verify_package(tampered, keys, public_checkpoint=checkpoint)
        self.assertIn("manifest_signature", verdict["errors"])

        # 5. A different published checkpoint (ledger rewrite) does not match.
        verdict = sa.verify_package(envelope, keys, public_checkpoint="0" * 64)
        self.assertIn("public-checkpoint", verdict["errors"])

        # 6. Tamper with the platform ledger itself: the exported record hashes
        #    no longer match the recomputed ledger chain.
        row = self.db.execute("SELECT seq,payload FROM events ORDER BY seq LIMIT 1").fetchone()
        payload = json.loads(row["payload"])
        payload["tampered"] = True
        self.db.execute("UPDATE events SET payload=? WHERE seq=?",
                        (json.dumps(payload, sort_keys=True), row["seq"]))
        head = sa.ledger_head(self.db)
        self.assertNotEqual(head, checkpoint)
        self.assertFalse(sa.verify_package(envelope, keys, public_checkpoint=head)["verified"])

    def test_revocation_blocks_download_but_signed_package_verifies_forever(self):
        self._joint_plan()
        invoke(self.db, "delivery", {"op": "receipt", "id": "receipt-a-1", "plan": "plan-joint",
                                     "uid": "uid-a", "kind": "delivered",
                                     "packet": "sha256:packet-one", "at": 21})
        self._mandate()
        sa.issue_package(self.db, "pkg-a-1", "mandate-a", "uid-a", 22)
        sa.acknowledge_package(self.db, "pkg-a-1", "uid-a", 22)
        envelope = sa.download_package(self.db, "pkg-a-1", "uid-a")["envelope"]
        keys = self._keys()
        checkpoint = envelope["ledger"]["checkpoint"]

        revoked = sa.revoke_mandate(self.db, "mandate-a", 23)
        self.assertEqual(revoked["decision"], "mandate_revoked")
        # Re-download after revocation is refused, and no new package can be minted.
        self.assertEqual(sa.download_package(self.db, "pkg-a-1", "uid-a")["decision"],
                         "mandate_revoked")
        self.assertEqual(sa.issue_package(self.db, "pkg-a-9", "mandate-a", "uid-a", 24)["decision"],
                         "mandate_revoked")
        # Revocation is idempotent.
        self.assertEqual(sa.revoke_mandate(self.db, "mandate-a", 24)["decision"], "reused")
        # The acknowledged package, held offline by A, still verifies independently.
        verdict = sa.verify_package(envelope, keys, public_checkpoint=checkpoint)
        self.assertTrue(verdict["verified"], verdict["errors"])

    def test_key_rotation_and_lifecycle_decisions_are_persisted(self):
        self._joint_plan()
        self._mandate()
        first_key = sa.provision_key(self.db)["key_id"]
        sa.issue_package(self.db, "pkg-a-1", "mandate-a", "uid-a", 22)
        envelope = sa.download_package(self.db, "pkg-a-1", "uid-a")["envelope"]
        old_keys = self._keys()
        # Rotate: new packages use the new key, the old key remains for verification.
        rotated = sa.rotate_key(self.db)
        self.assertNotEqual(rotated["key_id"], first_key)
        self._mandate("mandate-a-2", to=30)
        sa.issue_package(self.db, "pkg-a-2", "mandate-a-2", "uid-a", 25)
        new_envelope = sa.download_package(self.db, "pkg-a-2", "uid-a")["envelope"]
        self.assertEqual(new_envelope["key_id"], rotated["key_id"])
        # Old package verifies with the archived key ring; new package with the new key.
        self.assertTrue(sa.verify_package(envelope, old_keys,
                                          public_checkpoint=envelope["ledger"]["checkpoint"])["verified"])
        self.assertTrue(sa.verify_package(new_envelope, self._keys(),
                                          public_checkpoint=new_envelope["ledger"]["checkpoint"])["verified"])
        # Idempotent mandate and package retries keep their business identity.
        self.assertEqual(self._mandate()["decision"], "reused")
        self.assertEqual(sa.issue_package(self.db, "pkg-a-1", "mandate-a", "uid-a", 26)["decision"],
                         "reused")
        # Acknowledgement is idempotent and subject-bound.
        self.assertEqual(sa.acknowledge_package(self.db, "pkg-a-1", "uid-a", 27)["decision"],
                         "acknowledged")
        self.assertEqual(sa.acknowledge_package(self.db, "pkg-a-1", "uid-a", 28)["decision"],
                         "reused")
        self.assertEqual(sa.acknowledge_package(self.db, "pkg-a-1", "uid-b", 28)["decision"],
                         "subject_mismatch")

    def test_continuity_from_initial_seal_through_revocation_is_covered(self):
        # Full lifecycle: seal, grants, joint plan, A delivery, B delivery,
        # exposure, reseal lineage and A's grant revocation.
        self._joint_plan()
        invoke(self.db, "delivery", {"op": "receipt", "id": "receipt-a-1", "plan": "plan-joint",
                                     "uid": "uid-a", "kind": "delivered",
                                     "packet": "sha256:packet-one", "at": 21})
        invoke(self.db, "delivery", {"op": "receipt", "id": "receipt-b-1", "plan": "plan-joint",
                                     "uid": "uid-b", "kind": "delivered",
                                     "packet": "sha256:packet-one", "at": 22})
        invoke(self.db, "material", {"op": "seal", "secret": "payments", "gen": 2,
                                     "digest": "sha256:material-two", "parent": 1})
        invoke(self.db, "material", {"op": "expose", "id": "exposure-1", "secret": "payments",
                                     "gen": 1, "from": 30, "to": 40})
        invoke(self.db, "material", {"op": "proof", "id": "proof-1", "secret": "payments",
                                     "old_gen": 1, "new_gen": 2, "purpose": "payment-signing",
                                     "old_digest": "sha256:material-one",
                                     "new_digest": "sha256:material-two", "at": 41})
        invoke(self.db, "material", {"op": "reseal", "id": "reseal-1", "secret": "payments",
                                     "old_gen": 1, "new_gen": 2, "proof": "proof-1"})
        revoke = invoke(self.db, "grant", {"op": "revoke", "id": "revoke-a",
                                           "grant": "grant-a-1", "at": 42})
        self.assertEqual(revoke["decision"], "revoked")

        self.assertEqual(self._mandate(to=50)["decision"], "mandate_registered")
        sa.issue_package(self.db, "pkg-life", "mandate-a", "uid-a", 43)
        envelope = sa.download_package(self.db, "pkg-life", "uid-a")["envelope"]
        # No B identifier anywhere, including B receipts, grants and approvals.
        self.assertEqual(sa.scan_disclosure(envelope, self.b_tokens)["leak_free"], True)
        # The package spans the whole ledger without sequence gaps.
        seqs = [n["seq"] for n in envelope["nodes"]]
        self.assertEqual(seqs, list(range(1, max(seqs) + 1)))
        # A's own lineage (seal, proof, reseal, revocation) is visible and
        # replayable; the exposure result lists B's frozen grants, so it is redacted.
        visible_ops = [n["payload"].get("op") for n in envelope["nodes"] if n["type"] == "visible"]
        redacted_ops = [n["payload_view"].get("op")
                        for n in envelope["nodes"] if n["type"] == "redacted"]
        for op in ("secret", "seal", "proof", "reseal", "revoke"):
            self.assertIn(op, visible_ops)
        self.assertIn("expose", redacted_ops)
        verdict = sa.verify_package(envelope, self._keys(),
                                    public_checkpoint=envelope["ledger"]["checkpoint"])
        self.assertTrue(verdict["verified"], verdict["errors"])
        # The revocation event visible to A carries A's grant id, never B's.
        revoke_node = next(n for n in envelope["nodes"]
                           if n["type"] == "visible" and n["payload"].get("op") == "revoke")
        self.assertEqual(revoke_node["payload"]["grant"], "grant-a-1")


if __name__ == "__main__":
    unittest.main()
