"""Tests for effective revocation: real unusability instead of control-plane state.

The headline scene is instance U / old packet P:

* minute 8  - P confirmed delivered;
* minute 10 - grant revoked;
* minute 11 - console accepts a bare ``cleared`` receipt;
* minute 12 - U really completes a write with the cached old value;
* minute 15 - the partitioned read replica becomes contactable.

The tests prove the bare clearance cannot retire the old version, then exercise
both sanctioned remediations (stop/isolate downtime and bounded dual read),
plus cache delay, orphans, partitioned readers, same-name rebuilds, duplicate
consoles/receipts, crash recovery, late use and append-only correction.
"""
import json
import tempfile
import unittest
from pathlib import Path

from secretcourt.store import connect, invoke, one, replay

ROOT = Path(__file__).resolve().parents[1]


class RevocationEffectTestBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "effect.sqlite"
        self.db = connect(str(self.path))

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def iv(self, subsystem, command):
        return invoke(self.db, subsystem, command)

    def fx(self, subsystem, name):
        commands = json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))
        return [self.iv(subsystem, c) for c in commands]

    def assertDecision(self, result, expected):
        self.assertEqual(result.get("decision"), expected, result)

    def assertBlocker(self, report, code):
        hits = [c for c in report["blockers"] if c == code or c.startswith(code + ":")]
        self.assertTrue(hits, "expected blocker %s in %s" % (code, report["blockers"]))

    def assertNoBlocker(self, report, code):
        hits = [c for c in report["blockers"] if c == code or c.startswith(code + ":")]
        self.assertFalse(hits, "unexpected blocker %s: %s" % (code, report["blockers"]))

    # -- shared world -----------------------------------------------------
    def seed_world(self):
        """Build U/P with delivery at 8 and revocation at 10 via events only."""
        self.assertDecision(self.iv("material", {
            "op": "secret", "id": "payments", "purpose": "payment-signing"}), "created")
        self.assertDecision(self.iv("material", {
            "op": "seal", "secret": "payments", "gen": 1,
            "digest": "sha256:P", "parent": None}), "active")
        self.assertDecision(self.iv("grant", {
            "op": "identity", "id": "worker-u", "uid": "U",
            "namespace": "checkout", "environment": "prod", "generation": 1}), "observed")
        self.assertDecision(self.iv("grant", {
            "op": "policy", "purpose": "payment-signing",
            "fields": ["signing-key"], "environments": ["prod"], "revision": 1}), "policy_active")
        self.iv("grant", {"op": "approve", "id": "ap-sec", "grant": "grant-U",
                          "actor": "sec", "role": "security", "at": 4, "until": 90})
        self.iv("grant", {"op": "approve", "id": "ap-own", "grant": "grant-U",
                          "actor": "own", "role": "owner", "at": 4, "until": 90})
        self.assertDecision(self.iv("grant", {
            "op": "issue", "id": "grant-U", "secret": "payments", "gen": 1,
            "identity": "worker-u", "uid": "U", "namespace": "checkout",
            "environment": "prod", "fields": ["signing-key"],
            "until": 100, "at": 5, "approvers": ["sec", "own"]}), "granted")
        self.assertDecision(self.iv("delivery", {
            "op": "plan", "id": "plan-P", "secret": "payments", "gen": 1,
            "packet": "P", "at": 8,
            "members": [{"uid": "U", "grant": "grant-U"}]}), "planned")
        self.assertDecision(self.iv("delivery", {
            "op": "receipt", "id": "delivered-8", "plan": "plan-P", "uid": "U",
            "kind": "delivered", "packet": "P", "at": 8}), "delivered")
        self.assertDecision(self.iv("grant", {
            "op": "revoke", "id": "rev-U", "grant": "grant-U", "at": 10}), "revoked")
        for iid, kind, cred in [("console-a", "console", "ca-secret"),
                                ("console-b", "console", "cb-secret"),
                                ("runtime-1", "runtime", "cr-secret"),
                                ("kms-1", "kms", "ck-secret"),
                                ("prober-1", "prober", "cp-secret")]:
            self.iv("revocation_effect", {"op": "issuer", "id": iid,
                                          "kind": kind, "credential": cred, "at": 1})
        return {"plan": "plan-P", "grant": "grant-U"}

    def open_case(self, cid="case-U", mode=None, **extra):
        req = {"op": "open", "id": cid, "grant": "grant-U", "revocation": "rev-U",
               "secret": "payments", "gen": 1, "uid": "U", "packet": "P", "at": 10}
        if mode:
            req["mode"] = mode
        req.update(extra)
        return self.iv("revocation_effect", req)

    def verified_command(self, cid="cmd-a", case="case-U", console="console-a",
                         cred="ca-secret", **extra):
        req = {"op": "command", "id": cid, "case": case, "grant": "grant-U",
               "console": console, "issuer": console, "credential": cred, "at": 10}
        req.update(extra)
        return self.iv("revocation_effect", req)

    def status(self, case="case-U"):
        return self.iv("revocation_effect", {"op": "status", "case": case})

    U_SURFACES = [
        {"kind": "process_memory", "ref": "process_memory"},
        {"kind": "mount", "ref": "/var/lib/u"},
        {"kind": "cache", "ref": "cache:redis", "delay_until": 14},
    ]

    def bind_u(self, bid="b-U", gen=1, surfaces=None, **extra):
        req = {"op": "bind", "id": bid, "case": "case-U", "uid": "U",
               "replica": "U", "container_gen": gen, "at": 8,
               "surfaces": self.U_SURFACES if surfaces is None else surfaces}
        req.update(extra)
        return self.iv("revocation_effect", req)

    def quiesce_u(self, bid="b-U", exit_id="exit-U", iso_id="iso-U",
                  probe_id="dead-U", seq=13, at=15, blocked=True, **iso_extra):
        self.assertDecision(self.iv("revocation_effect", {
            "op": "exit", "id": exit_id, "case": "case-U", "binding": bid,
            "runtime": "runtime-1", "credential": "cr-secret",
            "container_gen": 1, "at": at, "reason": "stopped"}), "container_exit_verified")
        iso = {"op": "isolate", "id": iso_id, "binding": bid, "at": at,
               "storage_receipt": iso_id + "-storage",
               "memory_receipt": iso_id + "-memory",
               "cache_receipts": {"cache:redis": iso_id + "-cache"},
               "writes_blocked": blocked}
        iso.update(iso_extra)
        self.assertDecision(self.iv("revocation_effect", iso), "isolation_recorded")
        self.assertDecision(self.iv("revocation_effect", {
            "op": "probe", "id": probe_id, "case": "case-U", "binding": bid,
            "seq": seq, "at": at, "outcome": "old_unreachable"}), "old_value_unreachable")

    def complete_quiesce_proof(self, pid="proof-Q", **complete_extra):
        req = {"op": "complete", "id": pid, "case": "case-U",
               "mode": "quiesce", "at": 16}
        req.update(complete_extra)
        result = self.iv("revocation_effect", req)
        self.assertDecision(result, "revocation_effect_complete")
        return result


class HeadlineNarrativeTests(RevocationEffectTestBase):
    def test_bare_cleared_at_11_cannot_hide_write_at_12(self):
        self.seed_world()

        # The existing control/delivery planes accept the bare clearance.
        weak = self.iv("delivery", {"op": "receipt", "id": "cleared-11",
                                    "plan": "plan-P", "uid": "U", "kind": "cleared",
                                    "packet": "P", "at": 11})
        self.assertDecision(weak, "cleared")
        self.assertEqual(one(self.db, "SELECT status FROM members WHERE plan_id='plan-P' AND uid='U'")["status"],
                         "cleared")

        # Effect court: command + scope binding, then the real minute-12 write.
        self.open_case()
        self.verified_command()
        self.bind_u()
        # The read replica is partitioned until minute 15 and cannot attest yet.
        self.assertDecision(self.iv("revocation_effect", {
            "op": "bind", "id": "b-R", "case": "case-U", "uid": "U",
            "replica": "read-replica", "container_gen": 1, "at": 8,
            "reachability": "partitioned", "partition_since": 11}), "usage_scope_bound")
        # Minute 12: a real completed write proves the cached old value still works.
        write = self.iv("revocation_effect", {
            "op": "write", "id": "write-12", "case": "case-U", "uid": "U",
            "container_gen": 1, "seq": 12, "at": 12, "record": "business-record-12"})
        self.assertDecision(write, "confirmed_write_recorded")

        # The bound usable scope persists UID, exact generation, every surface
        # and the latest successful-use sequence.
        bound = one(self.db, "SELECT * FROM effect_bindings WHERE id='b-U'")
        self.assertEqual((bound["uid"], bound["replica"], bound["container_gen"]), ("U", "U", 1))
        self.assertEqual(bound["last_use_seq"], 12)
        kinds = {(s["kind"], s["ref"]) for s in json.loads(bound["surfaces"])}
        self.assertIn(("process_memory", "process_memory"), kinds)
        self.assertIn(("mount", "/var/lib/u"), kinds)
        self.assertIn(("cache", "cache:redis"), kinds)

        report = self.status()
        self.assertFalse(report["ready"])
        self.assertBlocker(report, "old_value_still_usable")
        self.assertBlocker(report, "surface_uncleared")
        self.assertBlocker(report, "partition_unverified:b-R")
        self.assertBlocker(report, "remediation_path_required")

        done = self.iv("revocation_effect", {
            "op": "complete", "id": "proof-x", "case": "case-U", "mode": "quiesce"})
        self.assertDecision(done, "revocation_not_effective")
        self.assertBlocker(done, "old_value_still_usable")
        self.assertBlocker(done, "verified_exit_missing")
        self.assertBlocker(done, "isolation_evidence_missing")
        self.assertIsNone(one(self.db, "SELECT 1 FROM effect_proofs WHERE id='proof-x'"))

        # Neither material retirement nor strong delivery clearance may proceed.
        self.assertDecision(self.iv("material", {
            "op": "retire", "secret": "payments", "gen": 1}), "effect_proof_required")
        self.assertDecision(self.iv("material", {
            "op": "retire", "secret": "payments", "gen": 1, "proof": "proof-x"}),
            "invalid_effect_proof")
        blocked_clear = self.iv("delivery", {
            "op": "effect_clear", "id": "ec-x", "plan": "plan-P", "uid": "U",
            "packet": "P", "at": 16, "container_gen": 1, "proof": "proof-x"})
        self.assertDecision(blocked_clear, "invalid_effect_proof")

    def test_legacy_cleared_without_proof_still_accepted_for_backward_compat(self):
        self.seed_world()
        result = self.iv("delivery", {"op": "receipt", "id": "old-style-clear",
                                      "plan": "plan-P", "uid": "U", "kind": "cleared",
                                      "packet": "P", "at": 11})
        self.assertDecision(result, "cleared")


class QuiescePathTests(RevocationEffectTestBase):
    def test_stop_and_isolate_path_covers_partition_and_retires(self):
        self.seed_world()
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u()
        self.assertDecision(self.iv("revocation_effect", {
            "op": "bind", "id": "b-R", "case": "case-U", "uid": "R",
            "replica": "read-replica", "container_gen": 1, "at": 8,
            "reachability": "partitioned", "partition_since": 11}), "usage_scope_bound")
        self.iv("revocation_effect", {"op": "write", "id": "write-12", "case": "case-U",
                                      "uid": "U", "container_gen": 1, "seq": 12, "at": 12})

        # Before minute 15 the partition replica cannot even be verified.
        early = self.status()
        self.assertBlocker(early, "partition_unverified")

        self.assertDecision(self.iv("revocation_effect", {
            "op": "contact", "id": "contact-15", "case": "case-U", "uid": "R",
            "replica": "read-replica", "at": 15}), "partition_replica_contacted")

        # Stop U and the replica, isolate storage + memory images, block writes.
        self.quiesce_u()
        self.assertDecision(self.iv("revocation_effect", {
            "op": "exit", "id": "exit-R", "case": "case-U", "binding": "b-R",
            "runtime": "runtime-1", "credential": "cr-secret",
            "container_gen": 1, "at": 15}), "container_exit_verified")
        self.assertDecision(self.iv("revocation_effect", {
            "op": "isolate", "id": "iso-R", "binding": "b-R", "at": 15,
            "isolation_receipt": "iso-R-combined", "writes_blocked": True}), "isolation_recorded")
        self.assertDecision(self.iv("revocation_effect", {
            "op": "probe", "id": "dead-R", "case": "case-U", "binding": "b-R",
            "seq": 14, "at": 15, "outcome": "old_unreachable"}), "old_value_unreachable")

        # The minute-12 confirmed write is contained in the isolated image.
        self.assertDecision(self.iv("revocation_effect", {
            "op": "contain_write", "id": "contain-1", "write": "write-12",
            "receipt": "iso-U-storage", "at": 15}), "confirmed_write_quarantined_in_image")

        report = self.status()
        self.assertFalse(report["blockers"], report["blockers"])
        proof = self.complete_quiesce_proof(at=16)
        self.assertEqual(proof["scope"]["mode"], "quiesce")
        self.assertTrue(proof["scope"]["downtime"]["stopped_at"] == 15)
        self.assertEqual(one(self.db, "SELECT status FROM effect_writes WHERE id='write-12'")["status"],
                         "quarantined")

        # Same shared proof drives material retirement and delivery clearance.
        retired = self.iv("material", {"op": "retire", "secret": "payments",
                                       "gen": 1, "proof": "proof-Q", "at": 16})
        self.assertDecision(retired, "version_retired")
        self.assertEqual(one(self.db, "SELECT status FROM versions WHERE secret='payments' AND gen=1")["status"],
                         "retired")
        cleared = self.iv("delivery", {"op": "effect_clear", "id": "ec-U",
                                       "plan": "plan-P", "uid": "U", "packet": "P",
                                       "at": 16, "container_gen": 1, "proof": "proof-Q"})
        self.assertDecision(cleared, "effect_cleared")
        self.assertEqual(one(self.db, "SELECT proof_id FROM effect_consumption WHERE consumer='delivery.effect_clear' AND ref_id='ec-U'")["proof_id"],
                         "proof-Q")

    def test_quiesce_requires_downtime_write_block_evidence(self):
        self.seed_world()
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u()
        self.quiesce_u(blocked=False)
        # No writes_blocked isolation -> the downtime boundary is not evidenced.
        result = self.iv("revocation_effect", {"op": "complete", "id": "proof-q2",
                                                "case": "case-U", "mode": "quiesce"})
        self.assertDecision(result, "revocation_not_effective")
        self.assertIn("downtime_write_block_missing", result["blockers"])


class DualReadPathTests(RevocationEffectTestBase):
    def _dual_world_ready_to_close(self):
        self.seed_world()
        self.assertDecision(self.iv("material", {
            "op": "seal", "secret": "payments", "gen": 2,
            "digest": "sha256:new", "parent": 1}), "sealed")
        self.open_case(mode="dual_read")
        self.verified_command()
        self.bind_u()
        self.assertDecision(self.iv("revocation_effect", {
            "op": "write", "id": "write-12", "case": "case-U", "uid": "U",
            "container_gen": 1, "seq": 12, "at": 12,
            "record": "confirmed-business-write"}), "confirmed_write_recorded")

    def test_indefinite_dual_read_window_is_denied(self):
        self.seed_world()
        self.open_case(mode="dual_read")
        self.verified_command()
        self.bind_u()
        denied = self.iv("revocation_effect", {"op": "dual_open", "id": "win-bad",
                                               "case": "case-U", "uid": "U", "at": 12})
        self.assertDecision(denied, "indefinite_dual_read_denied")
        self.assertIsNone(one(self.db, "SELECT 1 FROM effect_windows WHERE id='win-bad'"))

    def test_controlled_dual_read_rewrites_write_and_measures_rejection(self):
        self._dual_world_ready_to_close()

        self.assertDecision(self.iv("revocation_effect", {
            "op": "dual_open", "id": "win", "case": "case-U", "uid": "U",
            "at": 12, "deadline_seq": 30, "deadline_at": 20}), "dual_read_opened")
        self.assertDecision(self.iv("revocation_effect", {
            "op": "rotation", "id": "rot", "case": "case-U", "secret": "payments",
            "old_gen": 1, "new_gen": 2, "new_digest": "sha256:new",
            "kms": "kms-1", "credential": "ck-secret", "at": 13,
            "receipt": "kms-rotation-1"}), "rotation_receipt_verified")
        self.assertDecision(self.iv("revocation_effect", {
            "op": "rewrite", "id": "rw-1", "write": "write-12",
            "new_gen": 2, "new_digest": "sha256:new", "at": 13}),
            "write_rewritten_under_new_value")
        # The confirmed business record is carried intact into the new key lineage.
        rw = one(self.db, "SELECT record_digest,new_digest FROM effect_rewrites WHERE id='rw-1'")
        self.assertEqual(rw["record_digest"], "confirmed-business-write")
        self.assertEqual(rw["new_digest"], "sha256:new")
        read_back = self.iv("revocation_effect", {
            "op": "verify_read", "id": "read-new", "case": "case-U", "uid": "U",
            "container_gen": 1, "seq": 13, "at": 13, "write": "write-12"})
        self.assertDecision(read_back, "new_value_read_verified")
        self.assertEqual(one(self.db, "SELECT status FROM effect_writes WHERE id='write-12'")["status"],
                         "read_verified")
        self.assertEqual(one(self.db, "SELECT status FROM effect_rewrites WHERE id='rw-1'")["status"],
                         "read_verified")

        # Cache delay: a rejection measured before delay_until does not clear cache.
        early = self.iv("revocation_effect", {
            "op": "probe", "id": "cache-early", "case": "case-U", "uid": "U",
            "container_gen": 1, "seq": 14, "at": 13, "surface": "cache",
            "ref": "cache:redis", "outcome": "old_rejected"})
        self.assertDecision(early, "old_value_rejected")
        before = self.status()
        self.assertBlocker(before, "surface_uncleared:b-U:cache:redis")

        # Per-instance measured rejection after the high-water use and cache delay.
        measured = self.iv("revocation_effect", {
            "op": "probe", "id": "reject-U", "case": "case-U", "uid": "U",
            "container_gen": 1, "seq": 15, "at": 15,
            "outcome": "old_rejected", "all_surfaces": True})
        self.assertDecision(measured, "old_value_rejected")

        closed = self.iv("revocation_effect", {"op": "dual_close", "id": "close-win",
                                               "window": "win", "at": 16})
        self.assertDecision(closed, "dual_read_closed")

        proof = self.iv("revocation_effect", {"op": "complete", "id": "proof-D",
                                              "case": "case-U", "at": 16})
        self.assertDecision(proof, "revocation_effect_complete")
        self.assertEqual(proof["mode"], "dual_read")
        # Continuous business: no downtime write block was required or recorded.
        self.assertIsNone(proof["scope"]["downtime"]["stopped_at"])
        self.assertIsNone(one(self.db, "SELECT 1 FROM effect_isolations WHERE writes_blocked=1"))

        retired = self.iv("material", {"op": "retire", "secret": "payments",
                                       "gen": 1, "proof": "proof-D"})
        self.assertDecision(retired, "version_retired")

    def test_dual_read_close_requires_per_instance_rejection(self):
        self._dual_world_ready_to_close()
        self.iv("revocation_effect", {"op": "dual_open", "id": "win", "case": "case-U",
                                      "uid": "U", "at": 12, "deadline_at": 20})
        self.iv("revocation_effect", {"op": "rotation", "id": "rot", "case": "case-U",
                                      "secret": "payments", "old_gen": 1, "new_gen": 2,
                                      "new_digest": "sha256:new", "kms": "kms-1",
                                      "credential": "ck-secret", "at": 13})
        self.iv("revocation_effect", {"op": "rewrite", "id": "rw", "write": "write-12",
                                      "new_gen": 2, "at": 13})
        self.iv("revocation_effect", {"op": "verify_read", "id": "vr", "case": "case-U",
                                      "uid": "U", "container_gen": 1, "seq": 13,
                                      "at": 13, "write": "write-12"})
        denied = self.iv("revocation_effect", {"op": "dual_close", "id": "c",
                                               "window": "win", "at": 16})
        self.assertDecision(denied, "dual_read_not_safe_to_close")
        self.assertTrue(any(x.startswith("per_instance_old_rejection_missing")
                            for x in denied["blockers"]), denied["blockers"])
        done = self.iv("revocation_effect", {"op": "complete", "id": "p",
                                            "case": "case-U"})
        self.assertDecision(done, "revocation_not_effective")
        self.assertBlocker(done, "old_value_still_usable")

    def test_cache_purge_receipt_clears_delayed_cache_without_timed_probe(self):
        self.seed_world()
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u(surfaces=[{"kind": "process_memory"},
                              {"kind": "cache", "ref": "cache:redis", "delay_until": 30}])
        self.quiesce_u(cache_receipts=["cache:redis"])
        report = self.status()
        self.assertNoBlocker(report, "surface_uncleared:b-U:cache:redis")


class GenerationAndReceiptTests(RevocationEffectTestBase):
    def test_same_name_rebuild_cannot_borrow_generation_one_clearance(self):
        self.seed_world()
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u(gen=1)
        self.quiesce_u()
        self.complete_quiesce_proof()

        # gen-1 proof authorizes the gen-1 strong clearance.
        ec1 = self.iv("delivery", {"op": "effect_clear", "id": "ec-gen1",
                                   "plan": "plan-P", "uid": "U", "packet": "P",
                                   "at": 16, "container_gen": 1, "proof": "proof-Q"})
        self.assertDecision(ec1, "effect_cleared")
        self.assertDecision(self.iv("delivery", {"op": "effect_clear", "id": "ec-gen1",
                                                 "plan": "plan-P", "uid": "U", "packet": "P",
                                                 "at": 16, "container_gen": 1,
                                                 "proof": "proof-Q"}), "reused")

        # Same UID is rebuilt as container generation 2: a new bound footprint.
        self.assertDecision(self.iv("revocation_effect", {
            "op": "bind", "id": "b-U2", "case": "case-U", "uid": "U",
            "replica": "U", "container_gen": 2, "at": 17}), "usage_scope_bound")

        # The gen-1 proof must not authorize gen-2 clearance.
        borrowed = self.iv("delivery", {"op": "effect_clear", "id": "ec-gen2-x",
                                         "plan": "plan-P", "uid": "U", "packet": "P",
                                         "at": 18, "container_gen": 2, "proof": "proof-Q"})
        self.assertDecision(borrowed, "effect_proof_generation_scope_mismatch")

        # An exit event carrying gen 2 cannot close the gen-1 binding.
        mismatch = self.iv("revocation_effect", {
            "op": "exit", "id": "exit-bad", "case": "case-U", "binding": "b-U",
            "runtime": "runtime-1", "credential": "cr-secret",
            "container_gen": 2, "at": 18})
        self.assertDecision(mismatch, "exit_generation_mismatch")

        # A new completion is blocked until gen 2 itself is contained.
        blocked = self.iv("revocation_effect", {"op": "complete", "id": "proof-Q2-x",
                                                "case": "case-U", "mode": "quiesce"})
        self.assertDecision(blocked, "revocation_not_effective")
        self.assertBlocker(blocked, "verified_exit_missing:b-U2")

        self.assertDecision(self.iv("revocation_effect", {
            "op": "exit", "id": "exit-U2", "case": "case-U", "binding": "b-U2",
            "runtime": "runtime-1", "credential": "cr-secret",
            "container_gen": 2, "at": 18, "reason": "stopped"}), "container_exit_verified")
        self.assertDecision(self.iv("revocation_effect", {
            "op": "isolate", "id": "iso-U2", "binding": "b-U2", "at": 18,
            "isolation_receipt": "iso-u2", "writes_blocked": True}), "isolation_recorded")
        self.assertDecision(self.iv("revocation_effect", {
            "op": "probe", "id": "dead-U2", "case": "case-U", "binding": "b-U2",
            "seq": 20, "at": 18, "outcome": "old_unreachable"}), "old_value_unreachable")

        proof2 = self.iv("revocation_effect", {"op": "complete", "id": "proof-Q2",
                                               "case": "case-U", "mode": "quiesce",
                                               "supersedes": "proof-Q", "at": 19})
        self.assertDecision(proof2, "revocation_effect_complete")
        ec2 = self.iv("delivery", {"op": "effect_clear", "id": "ec-gen2",
                                   "plan": "plan-P", "uid": "U", "packet": "P",
                                   "at": 19, "container_gen": 2, "proof": "proof-Q2"})
        self.assertDecision(ec2, "effect_cleared")
        proof_q = one(self.db, "SELECT scope FROM effect_proofs WHERE id='proof-Q'")
        gens = sorted(b["container_gen"] for b in json.loads(proof_q["scope"])["bindings"])
        self.assertEqual(gens, [1])

    def test_duplicate_receipt_payload_conflict_is_rejected(self):
        self.seed_world()
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u()
        self.quiesce_u()
        self.complete_quiesce_proof()
        req = {"op": "effect_clear", "id": "ec-1", "plan": "plan-P", "uid": "U",
               "packet": "P", "at": 16, "container_gen": 1, "proof": "proof-Q"}
        self.assertDecision(self.iv("delivery", req), "effect_cleared")
        changed = dict(req, at=17)
        self.assertDecision(self.iv("delivery", changed), "receipt_identity_conflict")


class ConsoleAndAuthorityTests(RevocationEffectTestBase):
    def test_dual_console_duplicate_revocation_is_verified_and_noticed(self):
        self.seed_world()
        self.open_case()
        first = self.verified_command()
        self.assertDecision(first, "revocation_command_verified")
        self.assertDecision(self.verified_command(), "reused")
        conflict = self.verified_command(console="console-b", cid="cmd-a")
        self.assertDecision(conflict, "command_identity_conflict")

        forged = self.verified_command(cid="cmd-forged", console="console-a",
                                       cred="wrong")
        self.assertDecision(forged, "revocation_command_unverified")
        self.assertIsNone(one(self.db, "SELECT 1 FROM effect_commands WHERE id='cmd-forged'"))

        second = self.verified_command(cid="cmd-b", console="console-b", cred="cb-secret")
        self.assertDecision(second, "revocation_command_verified")
        self.assertTrue(second["dual_console_revocation"])
        notice = one(self.db, "SELECT * FROM effect_notices WHERE id='notice-dual-console-case-U'")
        self.assertIsNotNone(notice)
        # Replaying the second console command stays idempotent.
        again = self.verified_command(cid="cmd-b", console="console-b", cred="cb-secret")
        self.assertDecision(again, "reused")

    def test_forged_exit_and_rotation_receipts_rejected(self):
        self.seed_world()
        self.open_case()
        self.bind_u()
        bad_exit = self.iv("revocation_effect", {
            "op": "exit", "id": "e-bad", "binding": "b-U", "runtime": "runtime-1",
            "credential": "nope", "container_gen": 1, "at": 15})
        self.assertDecision(bad_exit, "exit_event_unverified")
        self.assertIsNone(one(self.db, "SELECT 1 FROM effect_exits WHERE id='e-bad'"))

        bad_rot = self.iv("revocation_effect", {
            "op": "rotation", "id": "r-bad", "case": "case-U", "secret": "payments",
            "old_gen": 1, "new_gen": 2, "kms": "kms-1", "credential": "nope"})
        self.assertDecision(bad_rot, "rotation_receipt_unverified")

        self.iv("material", {"op": "seal", "secret": "payments", "gen": 2,
                             "digest": "sha256:new", "parent": 1})
        mismatch = self.iv("revocation_effect", {
            "op": "rotation", "id": "r-1", "case": "case-U", "secret": "payments",
            "old_gen": 1, "new_gen": 2, "new_digest": "forged-digest",
            "kms": "kms-1", "credential": "ck-secret"})
        self.assertDecision(mismatch, "rotation_digest_mismatch")


class ReplicaAndOrphanTests(RevocationEffectTestBase):
    def test_partition_evidence_before_contact_does_not_establish_boundary(self):
        self.seed_world()
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u()
        self.assertDecision(self.iv("revocation_effect", {
            "op": "bind", "id": "b-R", "case": "case-U", "uid": "R",
            "replica": "rr", "container_gen": 1,
            "reachability": "partitioned"}), "usage_scope_bound")
        # Isolation evidence timestamped during partition cannot bound completion.
        self.iv("revocation_effect", {"op": "isolate", "id": "iso-R-early",
                                      "binding": "b-R", "at": 12,
                                      "isolation_receipt": "x", "writes_blocked": True})
        self.iv("revocation_effect", {"op": "contact", "case": "case-U", "uid": "R",
                                     "replica": "rr", "at": 15})
        report = self.status()
        self.assertBlocker(report, "partition_boundary_missing")

        self.iv("revocation_effect", {"op": "isolate", "id": "iso-R-late",
                                      "binding": "b-R", "at": 15,
                                      "isolation_receipt": "y", "writes_blocked": True})
        self.iv("revocation_effect", {"op": "probe", "id": "dead-R", "case": "case-U",
                                      "uid": "R", "replica": "rr", "container_gen": 1,
                                      "seq": 5, "at": 15, "outcome": "old_unreachable"})
        report = self.status()
        self.assertNoBlocker(report, "partition")

    def test_orphan_copy_blocks_until_isolated_or_cleared_in_delivery(self):
        self.seed_world()
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u()
        self.quiesce_u()
        self.assertDecision(self.iv("revocation_effect", {
            "op": "bind", "id": "b-O", "case": "case-U", "uid": "ghost",
            "replica": "orphan-1", "container_gen": 1,
            "reachability": "orphan"}), "usage_scope_bound")
        blocked = self.iv("revocation_effect", {"op": "complete", "id": "p",
                                                "case": "case-U", "mode": "quiesce"})
        self.assertDecision(blocked, "revocation_not_effective")
        self.assertBlocker(blocked, "orphan_copy_remains:b-O")

        self.assertDecision(self.iv("revocation_effect", {
            "op": "isolate", "id": "iso-O", "binding": "b-O", "at": 15,
            "isolation_receipt": "orphan-isolated"}), "isolation_recorded")
        report = self.status()
        self.assertNoBlocker(report, "orphan_copy_remains:b-O")

    def test_orphan_bound_to_delivery_orphan_record_is_accepted(self):
        self.seed_world()
        # Existing delivery orphan ledger row, resolved through its own op.
        self.iv("delivery", {"op": "orphan", "id": "orphan-ledger",
                             "secret": "payments", "gen": 1, "uid": "ghost"})
        self.iv("delivery", {"op": "resolve_orphan", "id": "orphan-ledger",
                             "uid": "ghost", "isolation_receipt": "ledger-iso"})
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u()
        self.quiesce_u()
        self.assertDecision(self.iv("revocation_effect", {
            "op": "bind", "id": "b-O", "case": "case-U", "uid": "ghost",
            "replica": "orphan-1", "container_gen": 1, "reachability": "orphan",
            "orphan_id": "orphan-ledger"}), "usage_scope_bound")
        report = self.status()
        self.assertNoBlocker(report, "orphan_copy_remains:b-O")


class LateUseCorrectionCrashTests(RevocationEffectTestBase):
    def _issued_quiesce_proof(self, pid="proof-Q"):
        self.seed_world()
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u()
        self.quiesce_u()
        self.complete_quiesce_proof(pid=pid)

    def test_late_old_use_challenges_proof_and_keeps_incident_notice(self):
        self._issued_quiesce_proof()
        retired = self.iv("material", {"op": "retire", "secret": "payments",
                                       "gen": 1, "proof": "proof-Q"})
        self.assertDecision(retired, "version_retired")

        late = self.iv("revocation_effect", {
            "op": "probe", "id": "late-use", "case": "case-U", "uid": "U",
            "container_gen": 1, "seq": 99, "at": 20, "outcome": "old_accepted"})
        self.assertDecision(late, "late_old_use_recorded")
        self.assertTrue(late["extends_window"])
        # The real usable window is preserved at its new high-water mark.
        self.assertEqual(one(self.db, "SELECT last_use_seq FROM effect_cases WHERE id='case-U'")["last_use_seq"],
                         99)
        self.assertEqual(one(self.db, "SELECT last_use_seq FROM effect_bindings WHERE id='b-U'")["last_use_seq"],
                         99)
        self.assertEqual(one(self.db, "SELECT status FROM effect_proofs WHERE id='proof-Q'")["status"],
                         "challenged")
        notice = one(self.db, "SELECT * FROM effect_notices WHERE id='notice-late-use-late-use'")
        self.assertEqual(notice["kind"], "late_old_use")

        # Challenged proof can no longer authorize retirement/clearance.
        again = self.iv("material", {"op": "retire", "secret": "payments",
                                     "gen": 1, "proof": "proof-Q"})
        self.assertDecision(again, "effect_proof_challenged")
        clear = self.iv("delivery", {"op": "effect_clear", "id": "ec-late",
                                     "plan": "plan-P", "uid": "U", "packet": "P",
                                     "container_gen": 1, "proof": "proof-Q"})
        self.assertDecision(clear, "effect_proof_challenged")

        # Original proof and minute-11 style clearance are retained, not deleted.
        self.assertIsNotNone(one(self.db, "SELECT 1 FROM effect_proofs WHERE id='proof-Q'"))

        # Re-measure rejection after the extended high-water mark, re-prove.
        self.iv("revocation_effect", {"op": "probe", "id": "re-dead", "case": "case-U",
                                      "uid": "U", "container_gen": 1, "seq": 100,
                                      "at": 21, "outcome": "old_rejected",
                                      "all_surfaces": True})
        proof2 = self.iv("revocation_effect", {"op": "complete", "id": "proof-Q2",
                                               "case": "case-U", "mode": "quiesce",
                                               "supersedes": "proof-Q", "at": 22})
        self.assertDecision(proof2, "revocation_effect_complete")
        self.assertEqual(one(self.db, "SELECT status FROM effect_proofs WHERE id='proof-Q'")["status"],
                         "superseded")
        # Superseded proof stays unusable.
        self.assertDecision(self.iv("material", {"op": "retire", "secret": "payments",
                                                 "gen": 1, "proof": "proof-Q"}),
                            "effect_proof_superseded")

    def test_incident_correction_is_append_only(self):
        self._issued_quiesce_proof()
        corr = self.iv("revocation_effect", {
            "op": "correct", "id": "corr-1", "case": "case-U", "at": 12,
            "target_kind": "proof", "target": "proof-Q",
            "reason": "console clearance was false; minute-12 write is real"})
        self.assertDecision(corr, "incident_correction_recorded")
        self.assertEqual(one(self.db, "SELECT status FROM effect_proofs WHERE id='proof-Q'")["status"],
                         "corrected")
        # Correction is idempotent by id and conflicts on changed target.
        self.assertDecision(self.iv("revocation_effect", {
            "op": "correct", "id": "corr-1", "case": "case-U", "at": 12,
            "target_kind": "proof", "target": "proof-Q"}), "reused")
        conflict = self.iv("revocation_effect", {
            "op": "correct", "id": "corr-1", "case": "case-U", "at": 12,
            "target_kind": "proof", "target": "other"})
        self.assertDecision(conflict, "correction_identity_conflict")
        self.assertIsNotNone(one(self.db, "SELECT 1 FROM effect_corrections WHERE id='corr-1'"))
        self.assertIsNotNone(one(self.db, "SELECT 1 FROM effect_notices WHERE kind='incident_correction'"))

    def test_crash_restart_requires_memory_image_and_persists_window(self):
        self.seed_world()
        self.open_case(mode="quiesce")
        self.verified_command()
        self.bind_u()
        # gen-1 crashes: without core/memory image disposition the image of
        # process memory may survive on disk.
        self.assertDecision(self.iv("revocation_effect", {
            "op": "exit", "id": "exit-crash", "case": "case-U", "binding": "b-U",
            "runtime": "runtime-1", "credential": "cr-secret",
            "container_gen": 1, "at": 14, "reason": "crashed"}), "container_exit_verified")
        report = self.status()
        self.assertBlocker(report, "memory_image_required:b-U")
        notice = one(self.db, "SELECT 1 FROM effect_notices WHERE kind='container_crashed'")
        self.assertIsNotNone(notice)

        # Memory image isolated, then same-name gen-2 restart must prove rejection.
        self.iv("revocation_effect", {"op": "isolate", "id": "iso-crash",
                                      "binding": "b-U", "at": 15,
                                      "storage_receipt": "st", "memory_receipt": "mem-img",
                                      "cache_receipts": {"cache:redis": "cache-img"},
                                      "writes_blocked": True})
        self.iv("revocation_effect", {"op": "probe", "id": "dead1", "case": "case-U",
                                      "binding": "b-U", "seq": 13, "at": 15,
                                      "outcome": "old_unreachable"})
        self.iv("revocation_effect", {"op": "bind", "id": "b-U2", "case": "case-U",
                                      "uid": "U", "replica": "U", "container_gen": 2,
                                      "at": 16})
        blocked = self.status()
        self.assertBlocker(blocked, "old_value_rejection_missing:b-U2")
        self.iv("revocation_effect", {"op": "probe", "id": "dead2", "case": "case-U",
                                      "binding": "b-U2", "seq": 3, "at": 17,
                                      "outcome": "old_rejected", "all_surfaces": True})
        # Strict downtime containment also stops and images the restarted gen.
        self.iv("revocation_effect", {"op": "exit", "id": "exit-U2", "case": "case-U",
                                      "binding": "b-U2", "runtime": "runtime-1",
                                      "credential": "cr-secret", "container_gen": 2,
                                      "at": 18, "reason": "stopped"})
        self.iv("revocation_effect", {"op": "isolate", "id": "iso-U2", "binding": "b-U2",
                                      "at": 18, "isolation_receipt": "iso-u2",
                                      "writes_blocked": True})
        done = self.iv("revocation_effect", {"op": "complete", "id": "proof-crash",
                                             "case": "case-U", "mode": "quiesce"})
        self.assertDecision(done, "revocation_effect_complete")

        # Crash recovery: close and reopen the handle; evidence/window survive.
        self.db.close()
        self.db = connect(str(self.path))
        row = one(self.db, "SELECT status,mode FROM effect_proofs WHERE id='proof-crash'")
        self.assertEqual(row["status"], "valid")
        again = self.iv("revocation_effect", {"op": "status", "case": "case-U"})
        self.assertTrue(again["ready"])

    def test_full_effect_scenario_replays_exactly(self):
        # A broad event-only scenario including late use, correction and reproof.
        self._issued_quiesce_proof(pid="proof-R")
        self.iv("material", {"op": "retire", "secret": "payments", "gen": 1, "proof": "proof-R"})
        self.iv("delivery", {"op": "effect_clear", "id": "ec-R", "plan": "plan-P",
                             "uid": "U", "packet": "P", "at": 16,
                             "container_gen": 1, "proof": "proof-R"})
        self.iv("revocation_effect", {"op": "probe", "id": "late-R", "case": "case-U",
                                      "uid": "U", "container_gen": 1, "seq": 40,
                                      "at": 20, "outcome": "old_accepted"})
        self.iv("revocation_effect", {"op": "correct", "id": "corr-R", "case": "case-U",
                                      "at": 20, "target_kind": "proof", "target": "proof-R",
                                      "reason": "late cached use"})
        self.iv("revocation_effect", {"op": "probe", "id": "redead-R", "case": "case-U",
                                      "uid": "U", "container_gen": 1, "seq": 41,
                                      "at": 21, "outcome": "old_rejected",
                                      "all_surfaces": True})
        self.iv("revocation_effect", {"op": "complete", "id": "proof-R2", "case": "case-U",
                                      "mode": "quiesce", "supersedes": "proof-R", "at": 22})
        self.iv("revocation_effect", {"op": "notices", "case": "case-U"})
        self.iv("revocation_effect", {"op": "status", "case": "case-U"})

        self.db.close()
        result = replay(str(self.path))
        self.assertTrue(result["verified"], result["divergences"])


class CloseResealProofIntegrationTests(RevocationEffectTestBase):
    def _ready_reseal_with_proof(self):
        # Existing exposed/failure fixtures reach an old-cleared/orphan-resolved/
        # new-delivered state; stop just before the final close_reseal.
        self.fx("material", "material_normal.json")
        self.fx("grant", "grant_normal.json")
        self.fx("delivery", "delivery_normal.json")
        self.fx("material", "material_failure.json")
        self.fx("grant", "grant_failure.json")
        failure = json.loads((ROOT / "fixtures" / "delivery_failure.json").read_text("utf-8"))
        for command in failure[:-1]:
            self.iv("delivery", command)
        self.iv("grant", {"op": "revoke", "id": "rev-a1", "grant": "grant-a-1", "at": 30})
        self.iv("grant", {"op": "revoke", "id": "rev-b1", "grant": "grant-b-1", "at": 30})
        for iid, kind, cred in [("console-a", "console", "ca"), ("runtime-1", "runtime", "cr")]:
            self.iv("revocation_effect", {"op": "issuer", "id": iid, "kind": kind, "credential": cred})
        self.iv("revocation_effect", {"op": "open", "id": "case-r", "grant": "grant-a-1",
                                       "secret": "payments", "gen": 1, "mode": "quiesce", "at": 30})
        self.iv("revocation_effect", {"op": "command", "id": "cmd", "case": "case-r",
                                      "grant": "grant-a-1", "console": "console-a",
                                      "issuer": "console-a", "credential": "ca", "at": 30})
        for uid in ("uid-a", "uid-b"):
            bid = "b-" + uid
            self.iv("revocation_effect", {"op": "bind", "id": bid, "case": "case-r",
                                          "uid": uid, "replica": uid, "container_gen": 1})
            self.iv("revocation_effect", {"op": "exit", "id": "e-" + uid, "case": "case-r",
                                          "binding": bid, "runtime": "runtime-1",
                                          "credential": "cr", "container_gen": 1, "at": 33})
            self.iv("revocation_effect", {"op": "isolate", "id": "i-" + uid, "binding": bid,
                                          "at": 33, "isolation_receipt": "iso-" + uid,
                                          "writes_blocked": True})
            self.iv("revocation_effect", {"op": "probe", "id": "d-" + uid, "case": "case-r",
                                          "binding": bid, "seq": 9, "at": 33,
                                          "outcome": "old_unreachable"})
        proof = self.iv("revocation_effect", {"op": "complete", "id": "proof-r",
                                              "case": "case-r", "mode": "quiesce", "at": 34})
        self.assertDecision(proof, "revocation_effect_complete")

    def test_close_reseal_rejects_bad_proof_refs(self):
        self._ready_reseal_with_proof()
        bad = self.iv("delivery", {"op": "close_reseal", "id": "reseal-one",
                                   "effect_proof": "does-not-exist"})
        self.assertDecision(bad, "invalid_effect_proof")
        mismatch = self.iv("delivery", {"op": "close_reseal", "id": "reseal-one",
                                        "effect_proof": "proof-r"})
        # proof-r matches payments/gen1 -> passes proof gate and closes.
        self.assertDecision(mismatch, "reseal_complete")
        self.assertEqual(mismatch["effect_proof"], "proof-r")

    def test_close_reseal_without_proof_keeps_legacy_behavior(self):
        self._ready_reseal_with_proof()
        result = self.iv("delivery", {"op": "close_reseal", "id": "reseal-one"})
        self.assertDecision(result, "reseal_complete")
        self.assertNotIn("effect_proof", result)


if __name__ == "__main__":
    unittest.main()
