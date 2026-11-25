import json
import tempfile
import unittest
from pathlib import Path
import secretcourt
from secretcourt.store import connect, invoke, one, replay

ROOT = Path(__file__).resolve().parents[1]

class SecretCourtTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.sqlite"
        self.db = connect(str(self.path))

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def fixture(self, subsystem, name):
        commands = json.loads((ROOT / "fixtures" / name).read_text(encoding="utf-8"))
        return [invoke(self.db, subsystem, command) for command in commands]

    def base(self):
        self.fixture("material", "material_normal.json")
        self.fixture("grant", "grant_normal.json")
        self.fixture("delivery", "delivery_normal.json")

    def exposed(self):
        self.base()
        self.fixture("material", "material_failure.json")
        self.fixture("grant", "grant_failure.json")

    def test_material_lineage_rejects_duplicate_digest_and_stale_parent(self):
        self.fixture("material", "material_normal.json")
        self.assertEqual(invoke(self.db, "material", {"op":"seal","secret":"payments","gen":1,"digest":"forged","parent":None})["decision"], "seal_identity_conflict")
        self.assertEqual(invoke(self.db, "material", {"op":"seal","secret":"payments","gen":3,"digest":"new","parent":1})["decision"], "stale_parent")
        self.assertEqual(invoke(self.db, "material", {"op":"seal","secret":"payments","gen":2,"digest":"sha256:material-one","parent":1})["decision"], "unchanged_material")

    def test_exposure_freezes_grant_and_does_not_auto_restore(self):
        self.base()
        results = self.fixture("material", "material_failure.json")
        self.assertEqual(results[0]["decision"], "seal_identity_conflict")
        self.assertEqual(results[1]["frozen_grants"], ["grant-a-1", "grant-b-1"])
        self.assertEqual(results[2]["decision"], "closed_without_regrant")
        self.assertEqual(one(self.db, "SELECT status FROM grants WHERE id='grant-a-1'")["status"], "frozen")
        self.assertEqual(results[-1]["decision"], "reseal_open")

    def test_scope_and_two_approvers_change_grant_result(self):
        self.fixture("material", "material_normal.json")
        self.fixture("grant", "grant_normal.json")
        request = {"op":"issue","id":"bad","secret":"payments","gen":1,"identity":"worker-a","uid":"uid-a","namespace":"checkout","environment":"prod","fields":["root-password"],"until":80,"at":20,"approvers":["security","owner"]}
        self.assertEqual(invoke(self.db, "grant", request)["decision"], "scope_denied")
        request.update(fields=["signing-key"], approvers=["owner"])
        self.assertEqual(invoke(self.db, "grant", request)["decision"], "missing_two_approvers")

    def test_workload_recreation_freezes_old_grant_and_plan(self):
        self.base()
        result = invoke(self.db, "grant", {"op":"identity","id":"worker-a","uid":"new-a","namespace":"checkout","environment":"prod","generation":2})
        self.assertEqual(result["decision"], "observed")
        self.assertEqual(one(self.db, "SELECT status FROM grants WHERE id='grant-a-1'")["status"], "frozen")
        self.assertEqual(one(self.db, "SELECT status FROM plans WHERE id='plan-old'")["status"], "complete")
        self.assertEqual(invoke(self.db, "grant", {"op":"identity","id":"worker-a","uid":"uid-a","namespace":"checkout","environment":"prod","generation":1})["decision"], "stale_identity")

    def test_identity_generation_change_with_same_uid_freezes_pending_delivery(self):
        self.fixture("material", "material_normal.json")
        self.fixture("grant", "grant_normal.json")
        plan=json.loads((ROOT/"fixtures"/"delivery_normal.json").read_text(encoding="utf-8"))[0]
        self.assertEqual(invoke(self.db,"delivery",plan)["decision"],"planned")
        self.assertEqual(invoke(self.db,"grant",{"op":"identity","id":"worker-a","uid":"uid-a","namespace":"checkout","environment":"prod","generation":2})["decision"],"observed")
        self.assertEqual(one(self.db,"SELECT status FROM grants WHERE id='grant-a-1'")["status"],"frozen")
        self.assertEqual(one(self.db,"SELECT status FROM plans WHERE id='plan-old'")["status"],"frozen")
        receipt=json.loads((ROOT/"fixtures"/"delivery_normal.json").read_text(encoding="utf-8"))[1]
        self.assertEqual(invoke(self.db,"delivery",receipt)["decision"],"plan_frozen")

    def test_undelivered_member_cannot_claim_old_copy_clearance(self):
        self.fixture("material", "material_normal.json")
        self.fixture("grant", "grant_normal.json")
        plan=json.loads((ROOT/"fixtures"/"delivery_normal.json").read_text(encoding="utf-8"))[0]
        invoke(self.db,"delivery",plan)
        self.assertEqual(invoke(self.db,"delivery",{"op":"receipt","id":"false-clear","plan":"plan-old","uid":"uid-a","kind":"cleared","packet":"sha256:packet-one","at":22})["decision"],"copy_never_delivered")

    def test_revocation_freezes_unfinished_delivery(self):
        self.fixture("material", "material_normal.json")
        self.fixture("grant", "grant_normal.json")
        commands=json.loads((ROOT/"fixtures"/"delivery_normal.json").read_text(encoding="utf-8"))
        invoke(self.db,"delivery",commands[0])
        result=invoke(self.db,"grant",{"op":"revoke","id":"revoke-a","grant":"grant-a-1","at":21})
        self.assertEqual(result["affected_plans"],["plan-old"])
        self.assertEqual(invoke(self.db,"delivery",commands[1])["decision"],"plan_frozen")
        self.assertEqual(invoke(self.db,"grant",{"op":"revoke","id":"revoke-a","grant":"grant-a-1","at":21})["decision"],"reused")

    def test_fixed_roster_rejects_foreign_receipt_and_conflicting_retry(self):
        self.base()
        foreign={"op":"receipt","id":"x","plan":"plan-old","uid":"foreign","kind":"delivered","packet":"sha256:packet-one","at":22}
        self.assertEqual(invoke(self.db,"delivery",foreign)["decision"],"foreign_or_stale_receipt")
        original=json.loads((ROOT/"fixtures"/"delivery_normal.json").read_text(encoding="utf-8"))[0]
        self.assertEqual(invoke(self.db,"delivery",original)["decision"],"reused")
        original["members"]=original["members"][:1]
        self.assertEqual(invoke(self.db,"delivery",original)["decision"],"plan_identity_conflict")

    def test_reseal_requires_old_clear_new_delivery_and_orphan_resolution(self):
        self.exposed()
        results=self.fixture("delivery","delivery_failure.json")
        self.assertEqual(results[3]["decision"],"old_copies_remain")
        self.assertEqual(results[7]["decision"],"orphan_copy_remains")
        self.assertEqual(results[9]["decision"],"new_delivery_incomplete")
        self.assertEqual(results[-1]["decision"],"reseal_complete")
        self.assertEqual(one(self.db,"SELECT status FROM versions WHERE secret='payments' AND gen=1")["status"],"retired")
        self.assertEqual(one(self.db,"SELECT status FROM versions WHERE secret='payments' AND gen=2")["status"],"active")

    def test_source_license_expiry_blocks_new_delivery(self):
        self.fixture("material","material_normal.json")
        self.fixture("grant","grant_normal.json")
        plan=json.loads((ROOT/"fixtures"/"delivery_normal.json").read_text(encoding="utf-8"))[0]
        plan.update(id="late",at=101)
        self.assertEqual(invoke(self.db,"delivery",plan)["decision"],"unlicensed_member")

    def test_policy_shrink_freezes_existing_grant_and_pending_plan(self):
        self.fixture("material","material_normal.json")
        self.fixture("grant","grant_normal.json")
        plan=json.loads((ROOT/"fixtures"/"delivery_normal.json").read_text(encoding="utf-8"))[0]
        invoke(self.db,"delivery",plan)
        result=invoke(self.db,"grant",{"op":"policy","purpose":"payment-signing","fields":["key-id"],"environments":["prod"],"revision":2})
        self.assertEqual(set(result["frozen_grants"]),{"grant-a-1","grant-b-1"})
        self.assertEqual(one(self.db,"SELECT status FROM plans WHERE id='plan-old'")["status"],"frozen")
        self.assertEqual(invoke(self.db,"grant",json.loads((ROOT/"fixtures"/"grant_normal.json").read_text(encoding="utf-8"))[7])["decision"],"grant_inactive")

    def test_reseal_requires_persisted_purpose_and_digest_proof(self):
        self.base()
        steps=json.loads((ROOT/"fixtures"/"material_failure.json").read_text(encoding="utf-8"))
        for step in steps[:4]: invoke(self.db,"material",step)
        self.assertEqual(invoke(self.db,"material",steps[-1])["decision"],"missing_lineage_proof")
        forged=dict(steps[4],id="forged",purpose="another-purpose")
        self.assertEqual(invoke(self.db,"material",forged)["decision"],"invalid_lineage_proof")
        self.assertEqual(invoke(self.db,"material",steps[4])["decision"],"proof_verified")
        self.assertEqual(invoke(self.db,"material",steps[5])["decision"],"reseal_open")

    def test_approval_role_and_expiry_are_persisted_business_evidence(self):
        self.fixture("material","material_normal.json")
        self.fixture("grant","grant_normal.json")
        issue=dict(json.loads((ROOT/"fixtures"/"grant_normal.json").read_text(encoding="utf-8"))[7],id="late-approval",at=91,until=120)
        self.assertEqual(invoke(self.db,"grant",issue)["decision"],"missing_two_approvers")
        self.assertEqual(invoke(self.db,"grant",{"op":"approve","id":"bad-role","grant":"late-approval","actor":"owner","role":"security","at":91,"until":120})["decision"],"approved")
        self.assertEqual(invoke(self.db,"grant",issue)["decision"],"missing_two_approvers")

    def test_late_orphan_reopens_completed_reseal_until_isolated(self):
        self.exposed()
        self.fixture("delivery","delivery_failure.json")
        self.assertEqual(invoke(self.db,"delivery",{"op":"orphan","id":"late-copy","secret":"payments","gen":1,"uid":"late-uid"})["decision"],"closure_reopened")
        self.assertEqual(one(self.db,"SELECT status FROM reseals WHERE id='reseal-one'")["status"],"reopened")
        self.assertEqual(one(self.db,"SELECT status FROM versions WHERE secret='payments' AND gen=2")["status"],"at_risk")
        self.assertEqual(one(self.db,"SELECT status FROM grants WHERE id='grant-a-2'")["status"],"frozen")
        self.assertEqual(invoke(self.db,"delivery",{"op":"close_reseal","id":"reseal-one"})["decision"],"orphan_copy_remains")
        self.assertEqual(invoke(self.db,"delivery",{"op":"resolve_orphan","id":"late-copy","uid":"late-uid","isolation_receipt":"late-isolate"})["decision"],"cleared")
        self.assertEqual(invoke(self.db,"delivery",{"op":"close_reseal","id":"reseal-one"})["decision"],"reseal_complete")
        self.assertEqual(one(self.db,"SELECT status FROM versions WHERE secret='payments' AND gen=2")["status"],"active")

    def test_all_six_fixtures_replay_exact_business_state(self):
        self.base()
        self.fixture("material","material_failure.json")
        self.fixture("grant","grant_failure.json")
        self.fixture("delivery","delivery_failure.json")
        result=replay(str(self.path))
        self.assertTrue(result["verified"],result["divergences"])
        self.assertEqual(result["decisions"],40)

    def test_material_grant_delivery_are_separate_entry_points(self):
        self.assertTrue((ROOT/"secretcourt"/"material.py").exists())
        self.assertTrue((ROOT/"secretcourt"/"grant.py").exists())
        self.assertTrue((ROOT/"secretcourt"/"delivery.py").exists())
        self.assertEqual(Path(secretcourt.__file__).resolve().parents[1],ROOT)

print("module_file",secretcourt.__file__)
if __name__ == "__main__":
    unittest.main()
