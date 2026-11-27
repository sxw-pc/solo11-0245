"""Audit tests for verifiable e-waste material recovery.

The six groups of original evidence from the HSM case are exercised directly:

1. two machines sharing one paper serial label;
2. the unremoved, different-capacity backup battery seen on X-ray;
3. the re-stuck seal on the box;
4. the warehouse 840 g vs processor 860 g scales with different calibrations;
5. the other customer's network boards on the same truck / in the feed;
6. the 930 g metal + 90 g residue output report that cannot conserve mass.

Against those originals the tests check every *signable* certificate:
two per-unit itemized certificates, one totals-only batch certificate, and one
post-furnace joint allocation certificate for both owners -- plus the exact
unclosed mass difference that refuses the fraudulent report.
"""
import unittest

from secretcourt.store import connect, one
from secretcourt import material_recovery as mr
from secretcourt.hardware_order import draft as order_draft
from secretcourt.recycle_ticket import intake as legacy_intake
from secretcourt.recycle_ticket import certify as legacy_certify
from secretcourt.recycle_ticket import verify_vendor_signature

T_PACK = "2026-11-18T16:00"
T_HANDOVER_1 = "2026-11-19T10:00"
T_OUT = "2026-11-20T09:10"
T_IN = "2026-11-20T15:40"
T_WITNESS = "2026-11-21T10:20"
T_OUTPUT = "2026-11-22T10:00"
T_CHARGE = "2026-11-22T16:30"

CUSTOMER = "cust-hsm"
OTHER = "cust-net"
WITNESS = "thirdparty-wang"

APPEARANCE_A = {
    "chassis": "black-anodized-420g-class",
    "photo_hash": "sha256:1111aaaa",
    "asset_etch": "HSM-LAB-A",
    "scuff_pattern": "left-rail-two-marks",
    "ports": ["dual-psu", "mgmt-rj45", "hsm-slot-0"],
}
APPEARANCE_B = {
    "chassis": "black-anodized-420g-class",
    "photo_hash": "sha256:2222bbbb",
    "asset_etch": "HSM-LAB-B",
    "scuff_pattern": "top-cover-long-scratch",
    "ports": ["dual-psu", "mgmt-rj45", "hsm-slot-0"],
}
INTERNAL_A = {
    "board_rev": "HSM-3.1",
    "fru_id": "FRA-0001-77",
    "xray_signature": "xray-a-empty-battery-bay",
    "battery_present": False,
    "battery_capacity_wh": 0,
}
INTERNAL_B = {
    "board_rev": "HSM-3.1",
    "fru_id": "FRB-0002-88",
    "xray_signature": "xray-b-large-backup-cell",
    "battery_present": True,
    "battery_capacity_wh": 72,
    "factory_standard_capacity_wh": 8,
    "capacity_variant": "extended",
}
APPEARANCE_NET = {
    "board": "1U-network-blade",
    "photo_hash": "sha256:3333cccc",
    "asset_etch": "NET-OPS-9",
}
INTERNAL_NET = {"board_rev": "NET-X-5", "mac_range": "aa:bb:cc:90:*",
                "battery_present": False}


def has(blockers, code):
    return mr.has_blocker(blockers, code)


class World:
    """Seeds the original case evidence; every test gets a fresh in-memory DB."""

    def __init__(self):
        self.db = connect(":memory:")
        mr.ensure(self.db)
        self.db.execute("INSERT INTO secrets VALUES('s','p',0)")
        self._calibrations()
        self._destinations()

    def _calibrations(self):
        c = mr.record_calibration
        c(self.db, "CAL-WH", "WH-S2", "2026-05-01", "2027-04-30")
        c(self.db, "CAL-PR", "PR-S1", "2026-08-15", "2027-08-14")
        c(self.db, "CAL-WS", "WS-1", "2026-01-01", "2026-12-31")
        c(self.db, "CAL-OS", "OS-1", "2026-01-01", "2026-12-31")
        c(self.db, "CAL-CN", "CN-S9", "2026-02-01", "2027-01-31")

    def _destinations(self):
        d = mr.register_destination
        d(self.db, "d-metal", "metal", "Northern Metals Refinery", "PERMIT-M-01",
          "approved_metal_smelter")
        d(self.db, "d-pcb", "circuit_board", "GreenBoard Recovery", "PERMIT-CB-02",
          "qualified_pcb_chain")
        d(self.db, "d-batt", "battery", "Volt Battery Chain", "PERMIT-B-03",
          "licensed_battery_chain")
        d(self.db, "d-haz", "hazardous_residue", "Regional HazWaaste Cell",
          "PERMIT-H-04", "licensed_hazardous")
        d(self.db, "d-res", "residue", "City Residue Landfill", "PERMIT-R-05",
          "permitted_residue")

    def register_pieces(self):
        mr.register_item(self.db, "unit-a", CUSTOMER, "HSM-DUP-07",
                         APPEARANCE_A, INTERNAL_A, claimed_grams=420,
                         battery_claim="removed")
        mr.register_item(self.db, "unit-b", CUSTOMER, "HSM-DUP-07",
                         APPEARANCE_B, INTERNAL_B, claimed_grams=420,
                         battery_claim="removed")
        mr.register_item(self.db, "net-board-9", OTHER, "NET-X-9",
                         APPEARANCE_NET, INTERNAL_NET, claimed_grams=170,
                         battery_claim="removed")
        return self

    def make_case(self, bid="case-07", charged_at=None):
        self.register_pieces()
        mr.create_boundary(self.db, bid, "sealed_box",
                           ["unit-a", "unit-b", "net-board-9"],
                           box_id="BOX-07", charged_at=charged_at)
        mr.record_seal(self.db, "seal-apply", "BOX-07", "intact", T_PACK,
                       seal_number="SL-77", custodian="owner.chen",
                       evidence={"photo_hash": "sha256:seal-intact"})
        mr.record_seal(self.db, "seal-recheck", "BOX-07", "re_stuck", T_IN,
                       seal_number="SL-77", custodian="proc.li",
                       evidence={"photo_hash": "sha256:seal-restuck",
                                 "trace": "shell edge old plus new adhesive"})
        mr.record_handoff(self.db, "ho-1", "BOX-07", T_HANDOVER_1,
                          "owner.chen:cust-hsm", "wh.zhou:warehouse", seal_id="SL-77")
        mr.record_handoff(self.db, "ho-2", "BOX-07", "2026-11-20T08:30",
                          "wh.zhou:warehouse", "driver.sun:carrier")
        mr.record_handoff(self.db, "ho-3", "BOX-07", T_IN,
                          "driver.sun:carrier", "proc.li:processor",
                          witness="gate.guard")
        mr.record_transport(self.db, "tr-1", "BOX-07", "2026-11-20T07:00",
                            carrier="FastFreight", vehicle_ref="truck-7",
                            co_loaded="cust-net decommissioned network boards",
                            note="other customer consignment on same vehicle")
        # The two preserved original scale readings (plus witness total).
        mr.record_weighing(self.db, "w-out", "boundary", bid, "outbound", 840,
                           "WH-S2", T_OUT, calib_id="CAL-WH",
                           weigher="wh.zhou")
        mr.record_weighing(self.db, "w-in", "boundary", bid, "intake", 860,
                           "PR-S1", T_IN, calib_id="CAL-PR",
                           weigher="proc.li")
        mr.record_weighing(self.db, "w-wit", "boundary", bid, "witness_input", 850,
                           "WS-1", T_WITNESS, calib_id="CAL-WS",
                           weigher="lab.zhao", witness=WITNESS)
        return self

    def item_scales(self):
        w = mr.record_weighing
        w(self.db, "wa-out", "item", "unit-a", "outbound", 420, "WH-S2", T_OUT,
          calib_id="CAL-WH", weigher="wh.zhou")
        w(self.db, "wa-in", "item", "unit-a", "intake", 424, "WS-1", T_WITNESS,
          calib_id="CAL-WS", weigher="lab.zhao", witness=WITNESS)
        w(self.db, "wb-out", "item", "unit-b", "outbound", 420, "WH-S2", T_OUT,
          calib_id="CAL-WH", weigher="wh.zhou")
        w(self.db, "wb-in", "item", "unit-b", "intake", 426, "WS-1", T_WITNESS,
          calib_id="CAL-WS", weigher="lab.zhao", witness=WITNESS)
        return self

    def net_scales(self):
        mr.record_weighing(self.db, "wn-out", "item", "net-board-9", "outbound",
                           168, "CN-S9", T_OUT, calib_id="CAL-CN",
                           weigher="net.ops")
        mr.record_weighing(self.db, "wn-in", "item", "net-board-9", "intake",
                           172, "PR-S1", T_IN, calib_id="CAL-PR",
                           weigher="proc.li")
        return self

    def census(self, bid="case-07", inspection_id="insp-census", at=T_WITNESS,
               method="census_open", total=3, checked=3, foreign=1, coverage=1.0):
        return mr.record_inspection(
            self.db, inspection_id, bid, method, at, witness=WITNESS,
            coverage=coverage, pieces_total=total, pieces_checked=checked,
            foreign_found=foreign,
            detail={"disposition": "two HSM matched to distinct fingerprints; "
                                   "one cust-net board segregated"})

    def segregate_net(self, bid="case-07"):
        return mr.segregate_member(
            self.db, "seg-1", bid, "net-board-9", T_WITNESS, witness=WITNESS,
            weighing_id="wn-out", to_owner=OTHER,
            receipt_ref="RCP-NET-RETURN-1",
            note="returned under other customer's own chain, never fed to HSM batch")

    def auth(self, authorization_id="auth-hsm", bid="case-07", customer=CUSTOMER,
             actor="owner.chen", role="customer_owner", scope_item_ids=None,
             at=T_WITNESS, ack_seal_exception=True, ack_co_mingle=True):
        return mr.authorize_batch(
            self.db, authorization_id, bid, customer, actor, role,
            ack_seal_exception=ack_seal_exception,
            ack_co_mingle=ack_co_mingle,
            scope_item_ids=scope_item_ids, at=at, witness=WITNESS)

    def weighed_output(self, output_id, bid, category, grams, destination,
                       item_id=None, witness=WITNESS):
        weighing_id = "wo-" + output_id
        rw = mr.record_weighing(
            self.db, weighing_id, "output", output_id, "output", grams,
            "OS-1", T_OUTPUT, calib_id="CAL-OS", weigher="out.zhao",
            witness=witness)
        assert rw["decision"] == "recorded", rw
        ro = mr.record_output(
            self.db, output_id, bid, category, grams,
            destination_id=destination, receipt_ref="RCP-" + output_id.upper(),
            weighing_id=weighing_id, item_id=item_id)
        assert ro["decision"] == "recorded", ro
        return ro

    def itemized_outputs(self):
        o = self.weighed_output
        o("a-metal", "case-07", "metal", 336, "d-metal", item_id="unit-a")
        o("a-pcb", "case-07", "circuit_board", 56, "d-pcb", item_id="unit-a")
        o("a-res", "case-07", "residue", 14, "d-res", item_id="unit-a")
        o("b-batt", "case-07", "battery", 46, "d-batt", item_id="unit-b")
        o("b-metal", "case-07", "metal", 300, "d-metal", item_id="unit-b")
        o("b-pcb", "case-07", "circuit_board", 54, "d-pcb", item_id="unit-b")
        o("b-haz", "case-07", "hazardous_residue", 12, "d-haz", item_id="unit-b")
        o("b-res", "case-07", "residue", 6, "d-res", item_id="unit-b")
        return self

    def batch_outputs(self, bid="case-07"):
        o = self.weighed_output
        o("batch-metal", bid, "metal", 700, "d-metal")
        o("batch-pcb", bid, "circuit_board", 72, "d-pcb")
        o("batch-batt", bid, "battery", 46, "d-batt")
        o("batch-haz", bid, "hazardous_residue", 8, "d-haz")
        o("batch-res", bid, "residue", 10, "d-res")
        return self

    def fraud_outputs(self, bid="case-07"):
        mr.record_output(self.db, "f-metal", bid, "metal", 930, claimed=True,
                         report_ref="furnace-report-9")
        mr.record_output(self.db, "f-battres", bid, "battery_residue", 90,
                         claimed=True, report_ref="furnace-report-9")
        return self


class SixOriginalEvidenceTest(unittest.TestCase):
    """Each of the six original problem groups is independently checkable."""

    def test_1_same_paper_label_does_not_merge_two_identities(self):
        w = World().register_pieces()
        a = one(w.db, "SELECT label_serial,fingerprint FROM mr_items WHERE id='unit-a'")
        b = one(w.db, "SELECT label_serial,fingerprint FROM mr_items WHERE id='unit-b'")
        self.assertEqual(a["label_serial"], b["label_serial"], "labels really are identical")
        self.assertNotEqual(a["fingerprint"], b["fingerprint"])

        ev_a = mr.evaluate_unit(w.db, "unit-a")
        self.assertFalse(has(ev_a["blockers"], "identity_not_independent"))

        # A third record that merely copies A's features cannot be a new identity.
        mr.register_item(w.db, "unit-clone", CUSTOMER, "HSM-DUP-07",
                         APPEARANCE_A, INTERNAL_A, claimed_grams=420)
        ev_clone = mr.evaluate_unit(w.db, "unit-clone")
        self.assertTrue(has(ev_clone["blockers"], "identity_not_independent"))

    def test_2_hidden_extended_battery_blocks_until_separately_routed(self):
        w = World().make_case()
        before = mr.evaluate_unit(w.db, "unit-b")
        self.assertTrue(has(before["blockers"], "hidden_battery_not_separated"))
        self.assertIn("warehouse_battery_removal_claim_contradicted_by_xray",
                      before["findings"])

        w.weighed_output("b-batt", "case-07", "battery", 46, "d-batt",
                         item_id="unit-b")
        after = mr.evaluate_unit(w.db, "unit-b")
        self.assertFalse(has(after["blockers"], "hidden_battery_not_separated"))
        # The historical contradiction stays disclosed on the certificate.
        self.assertIn("warehouse_battery_removal_claim_contradicted_by_xray",
                      after["findings"])

    def test_3_only_owning_customer_informed_of_seal_and_coload_can_merge(self):
        w = World().make_case()

        proc = w.auth("auth-proc", actor="proc.li", role="processor")
        self.assertEqual(proc["decision"], "refused_authorization")
        self.assertTrue(has(proc["blockers"], "only_customer_can_authorize_merge"))

        wh = w.auth("auth-wh", actor="wh.zhou", role="warehouse")
        self.assertTrue(has(wh["blockers"], "only_customer_can_authorize_merge"))

        uniformed = w.auth("auth-owner-noack",
                           ack_seal_exception=False, ack_co_mingle=False,
                           scope_item_ids=["unit-a", "unit-b"])
        self.assertEqual(uniformed["decision"], "refused_authorization")
        self.assertIn("seal_exception_ack_required", uniformed["blockers"])
        self.assertIn("co_mingle_ack_required", uniformed["blockers"])

        # Customer cannot merge another customer's board into their own scope.
        cross = w.auth("auth-cross")  # default scope = every in-scope member
        self.assertTrue(has(cross["blockers"], "cross_owner_authorization_required"))

        w.segregate_net()
        ok = w.auth("auth-ok")
        self.assertEqual(ok["decision"], "authorized")
        self.assertEqual(ok["scope_item_ids"], ["unit-a", "unit-b"])

    def test_4_both_scales_and_distinct_calibrations_are_preserved_as_envelope(self):
        w = World().make_case()
        bal = mr.mass_balance(w.db, "case-07")
        self.assertEqual(bal["input_low_g"], 840)
        self.assertEqual(bal["input_high_g"], 860)
        self.assertEqual(bal["input_readings_g"], [840.0, 860.0, 850.0])

        wh_cal = one(w.db, "SELECT starts,ends FROM mr_calibrations WHERE cert_id='CAL-WH'")
        pr_cal = one(w.db, "SELECT starts,ends FROM mr_calibrations WHERE cert_id='CAL-PR'")
        self.assertNotEqual((wh_cal["starts"], wh_cal["ends"]),
                            (pr_cal["starts"], pr_cal["ends"]))

        # A lapsed calibration is flagged but the raw reading is not deleted.
        probe = World()
        mr.register_item(probe.db, "probe", CUSTOMER, "P-1", {"v": 1}, {"v": 1})
        r = mr.record_weighing(probe.db, "w-old", "item", "probe", "intake", 500,
                               "WH-S2", "2028-01-10T09:00", calib_id="CAL-WH",
                               weigher="wh.zhou")
        self.assertEqual(r["calibration"], "lapsed")
        low, high, readings = mr.input_envelope(probe.db, "item", "probe")
        self.assertEqual((low, high), (500.0, 500.0))
        ev = mr.evaluate_unit(probe.db, "probe")
        self.assertTrue(any(b.startswith("input_scale:calibration_lapsed")
                            for b in ev["blockers"]))

    def test_5_statistical_sampling_cannot_exclude_foreign_metal_but_census_can(self):
        w = World().make_case().net_scales()
        sample = w.census(inspection_id="insp-stat", method="statistical",
                          total=30, checked=3, foreign=0, coverage=0.1)
        self.assertFalse(sample["exclusion_grade"])
        # Zero finds in 3 pieces only bounds contamination at ~100% (rule of 3).
        self.assertEqual(sample["contamination_upper_bound_95"], 1.0)

        blocked = mr.evaluate_batch(w.db, "case-07", CUSTOMER)
        self.assertTrue(has(blocked["blockers"],
                            "foreign_material_not_excluded_by_census"))

        census = w.census()
        self.assertTrue(census["exclusion_grade"])
        w.segregate_net()
        again = mr.evaluate_batch(w.db, "case-07", CUSTOMER)
        self.assertFalse(has(again["blockers"],
                             "foreign_material_not_excluded_by_census"))

        # The other owner's 168-172 g never moves this customer's boundary.
        net_bal = mr.mass_balance(w.db, item_id="net-board-9")
        self.assertEqual((net_bal["input_low_g"], net_bal["input_high_g"]), (168, 172))
        case_bal = mr.mass_balance(w.db, "case-07")
        self.assertEqual((case_bal["input_low_g"], case_bal["input_high_g"]), (840, 860))

    def test_6_930_metal_plus_90_residue_has_exact_unclosed_mass_difference(self):
        w = World().make_case()
        w.census()
        w.segregate_net()
        w.auth()
        w.fraud_outputs()

        bal = mr.mass_balance(w.db, "case-07")
        self.assertEqual(bal["input_low_g"], 840)
        self.assertEqual(bal["input_high_g"], 860)
        self.assertEqual(bal["metal_g"], 930)
        self.assertEqual(bal["output_categories_g"]["battery_residue"], 90)
        self.assertEqual(bal["accounted_g"], 1020)
        # Metal alone beats the largest possible total input by 70 g.
        self.assertEqual(bal["metal_excess_vs_input_high_g"], 70)
        # Best case uses the heavier 860 g processor reading: still 160 g over.
        self.assertEqual(bal["unclosed_excess_g"], 160)
        self.assertEqual(bal["unclosed_g"], 160)
        # Against the warehouse reading the unexplained excess is 180 g.
        self.assertEqual(bal["implied_loss_interval_g"], [-180, -160])
        self.assertFalse(bal["closed"])

        result = mr.certify_batch(w.db, "cert-fraud", "case-07", CUSTOMER)
        self.assertEqual(result["decision"], "refused_certificate")
        self.assertTrue(has(result["blockers"], "mass_overrun"))
        self.assertTrue(has(result["blockers"], "output_not_weighed"))
        self.assertIsNone(mr.get_certificate(w.db, "cert-fraud"))


class SignableCertificatesTest(unittest.TestCase):
    def test_itemized_option_signs_two_independent_unit_certificates(self):
        w = World().make_case()
        w.census()
        w.item_scales()
        w.itemized_outputs()

        ra = mr.certify_unit(w.db, "cert-a", "unit-a", issued_at=T_OUTPUT)
        rb = mr.certify_unit(w.db, "cert-b", "unit-b", issued_at=T_OUTPUT)
        self.assertEqual(ra["decision"], "signed", ra)
        self.assertEqual(rb["decision"], "signed", rb)
        self.assertTrue(mr.verify_certificate(w.db, "cert-a"))
        self.assertTrue(mr.verify_certificate(w.db, "cert-b"))

        ca, cb = ra["certificate"], rb["certificate"]
        self.assertEqual(ca["kind"], "unit_itemized")
        self.assertEqual(cb["kind"], "unit_itemized")
        self.assertNotEqual(ca["identity"]["fingerprint"],
                            cb["identity"]["fingerprint"])
        self.assertTrue(ca["mass_balance"]["closed"])
        self.assertTrue(cb["mass_balance"]["closed"])
        self.assertEqual(ca["mass_balance"]["accounted_g"], 406)
        self.assertEqual(ca["mass_balance"]["implied_loss_interval_g"], [14, 18])
        self.assertEqual(cb["mass_balance"]["accounted_g"], 418)
        self.assertEqual(cb["mass_balance"]["implied_loss_interval_g"], [2, 8])

        cats_a = {s["category"]: s["grams"] for s in ca["streams"]}
        cats_b = {s["category"]: s["grams"] for s in cb["streams"]}
        self.assertEqual(cats_a["metal"], 336)
        self.assertEqual(cats_b["battery"], 46)
        # Every stream carries a handler receipt and a permitted destination.
        for cert in (ca, cb):
            for stream in cert["streams"]:
                self.assertTrue(stream["receipt_ref"])
                self.assertTrue(stream["destination"]["permit_id"])

        # Certificate ids are idempotent.
        again = mr.certify_unit(w.db, "cert-a", "unit-a")
        self.assertEqual(again["decision"], "reused")

    def test_batch_option_signs_one_total_only_certificate(self):
        w = World().make_case()
        w.census()
        w.segregate_net()
        w.auth()
        w.batch_outputs()

        result = mr.certify_batch(w.db, "cert-batch", "case-07", CUSTOMER,
                                  issued_at=T_OUTPUT)
        self.assertEqual(result["decision"], "signed", result)
        self.assertTrue(mr.verify_certificate(w.db, "cert-batch"))
        body = result["certificate"]
        self.assertEqual(body["kind"], "batch_total")
        self.assertFalse(body["per_unit_recovery_supported"])
        self.assertNotIn("unit_recovery_rates", body)
        self.assertEqual(body["mass_balance"]["accounted_g"], 836)
        self.assertEqual(body["mass_balance"]["implied_loss_interval_g"], [4, 24])
        self.assertTrue(body["mass_balance"]["closed"])
        totals = {s["category"]: s["grams"] for s in body["streams"]}
        self.assertEqual(totals["metal"], 700)  # more metal retained vs itemized 636
        self.assertEqual(body["third_party_witness"], WITNESS)
        self.assertTrue(body["authorization"]["ack_seal_exception"])
        self.assertTrue(body["authorization"]["ack_co_mingle"])

    def test_intake_signoff_alone_never_becomes_completed_certificate(self):
        w = World()
        mr.create_boundary(w.db, "dock-only", "sealed_box", [])
        mr.record_weighing(w.db, "dock-w", "boundary", "dock-only", "intake",
                           850, "PR-S1", T_IN, calib_id="CAL-PR",
                           weigher="proc.li")
        result = mr.certify_batch(w.db, "cert-dock", "dock-only", CUSTOMER)
        self.assertEqual(result["decision"], "refused_certificate")
        self.assertTrue(has(result["blockers"], "final_disposition_missing"))
        self.assertTrue(has(result["blockers"], "no_processing_outputs"))
        self.assertIsNone(mr.get_certificate(w.db, "cert-dock"))

    def test_weighed_output_requires_receipt_and_permitted_destination(self):
        w = World()
        # The write API refuses a "weighed" output without receipt/destination.
        mr.record_weighing(w.db, "wo-x", "output", "x", "output", 10, "OS-1",
                           T_OUTPUT, calib_id="CAL-OS", weigher="out.zhao")
        no_receipt = mr.record_output(w.db, "o-x", "case-07", "metal", 10,
                                      destination_id="d-metal",
                                      weighing_id="wo-x")
        self.assertEqual(no_receipt["decision"], "unavailable")
        self.assertEqual(no_receipt["reason"], "handler_receipt_required")
        bad_dest = mr.record_output(w.db, "o-y", "case-07", "metal", 10,
                                    destination_id="not-a-dest",
                                    receipt_ref="R", weighing_id="wo-x")
        self.assertEqual(bad_dest["decision"], "unavailable")

    def test_output_row_without_receipt_blocks_batch_certificate(self):
        w = World().make_case()
        w.census()
        w.segregate_net()
        w.auth()
        w.batch_outputs()
        # A zero-mass output linked to a valid weighing but with no handler
        # receipt/destination must still block signing.
        w.db.execute(
            "INSERT INTO mr_outputs VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("bad-row", "case-07", None, "residue", 0, "weighed",
             "wo-batch-metal", None, "", None))
        result = mr.certify_batch(w.db, "cert-bad-row", "case-07", CUSTOMER)
        self.assertEqual(result["decision"], "refused_certificate")
        self.assertTrue(has(result["blockers"], "qualified_destination_missing:bad-row"))
        self.assertTrue(has(result["blockers"], "handler_receipt_missing:bad-row"))
        self.assertIsNone(mr.get_certificate(w.db, "cert-bad-row"))

    def test_legacy_vendor_signature_still_certifies_420_and_cannot_match_physics(self):
        w = World()
        db = w.db
        order_draft(db, "o", "s", "hsm", 100)
        legacy_intake(db, "t", "hsm", 420)
        legacy = legacy_certify(db, "t", signer="vendor-signing-key-01")
        self.assertEqual(legacy["decision"], "certified")
        self.assertEqual(legacy["grams"], 420)

        # The vendor signature over the self-reported certificate verifies...
        self.assertTrue(verify_vendor_signature(legacy, legacy["vendor_signature"]))
        forged = dict(legacy, grams=930)
        self.assertFalse(verify_vendor_signature(forged, legacy["vendor_signature"]))

        # ...but adds no physical evidence and cannot move the mass envelope:
        # recording the same six originals and the 930/90 report still refuses.
        w.make_case()
        w.fraud_outputs()
        bal = mr.mass_balance(db, "case-07")
        self.assertEqual(bal["unclosed_excess_g"], 160)
        self.assertFalse(bal["closed"])
        self.assertIsNone(mr.get_certificate(db, "t"))

    def test_seal_detects_post_issue_tampering(self):
        body = {"grams": 836, "id": "x"}
        sealed = mr.seal_body(body)
        self.assertTrue(mr.verify_seal(body, sealed))
        tampered = dict(body, grams=930)
        self.assertFalse(mr.verify_seal(tampered, sealed))


class PostFurnaceComminglingTest(unittest.TestCase):
    def _joint_boundary(self, bid, charged_at=T_CHARGE):
        w = World().make_case().net_scales()
        mr.create_boundary(w.db, bid, "joint_furnace",
                           ["unit-a", "unit-b", "net-board-9"],
                           box_id="BOX-JOINT", charged_at=charged_at)
        mr.add_owner_scope(w.db, bid, CUSTOMER, "boundary", "case-07")
        mr.add_owner_scope(w.db, bid, OTHER, "item", "net-board-9")
        w.auth("auth-hsm-j", bid=bid, scope_item_ids=["unit-a", "unit-b"])
        mr.authorize_batch(w.db, "auth-net-j", bid, OTHER, "net.ops",
                           "customer_owner", ack_seal_exception=True,
                           ack_co_mingle=True, scope_item_ids=["net-board-9"],
                           at=T_WITNESS)
        return w

    def test_both_owners_receive_provable_scope_and_prorata_allocation(self):
        w = self._joint_boundary("joint-1")
        w.weighed_output("j-metal", "joint-1", "metal", 900, "d-metal")
        w.weighed_output("j-res", "joint-1", "residue", 60, "d-res")

        accounting = mr.commingled_accounting(w.db, "joint-1")
        self.assertEqual(accounting["decision"], "attributable")
        self.assertFalse(accounting["identity_recoverable"])
        self.assertEqual((accounting["joint_input_low_g"],
                          accounting["joint_input_high_g"]), (1008, 1032))
        self.assertTrue(accounting["mass_balance"]["closed"])

        stmts = {s["owner"]: s for s in accounting["owner_statements"]}
        self.assertEqual((stmts[CUSTOMER]["provable_input_low_g"],
                          stmts[CUSTOMER]["provable_input_high_g"]), (840, 860))
        self.assertEqual((stmts[OTHER]["provable_input_low_g"],
                          stmts[OTHER]["provable_input_high_g"]), (168, 172))

        result = mr.certify_commingled(w.db, "cert-joint", "joint-1",
                                       issued_at=T_OUTPUT)
        self.assertEqual(result["decision"], "signed", result)
        self.assertTrue(mr.verify_certificate(w.db, "cert-joint"))
        alloc = {a["owner"]: a for a in result["certificate"]["allocations"]}

        # Midpoint bases 850 : 170 = 5 : 1, so 900 metal splits 750/150 and
        # 60 residue splits 50/10. Nothing is claimed per unit.
        self.assertAlmostEqual(alloc[CUSTOMER]["share"], 5 / 6, places=5)
        self.assertEqual(alloc[CUSTOMER]["allocated_outputs_g"]["metal"], 750)
        self.assertEqual(alloc[CUSTOMER]["allocated_outputs_g"]["residue"], 50)
        self.assertEqual(alloc[CUSTOMER]["allocated_output_total_g"], 800)
        self.assertEqual(alloc[CUSTOMER]["allocated_loss_g"], 50)
        self.assertEqual(alloc[OTHER]["allocated_outputs_g"]["metal"], 150)
        self.assertEqual(alloc[OTHER]["allocated_outputs_g"]["residue"], 10)
        self.assertEqual(alloc[OTHER]["allocated_output_total_g"], 160)
        self.assertEqual(alloc[OTHER]["allocated_loss_g"], 10)
        self.assertFalse(alloc[CUSTOMER]["measured_per_owner_recovery"])
        self.assertFalse(result["certificate"]["per_unit_recovery_supported"])

    def test_post_furnace_discovery_with_unproven_foreign_input_refuses(self):
        w = World().make_case()  # no net scales: other owner mass unproven
        mr.create_boundary(w.db, "joint-r", "joint_furnace",
                           ["unit-a", "unit-b", "net-board-9"],
                           box_id="BOX-R", charged_at=T_CHARGE)
        mr.add_owner_scope(w.db, "joint-r", CUSTOMER, "boundary", "case-07")
        mr.add_owner_scope(w.db, "joint-r", OTHER, "item", "net-board-9")
        w.fraud_outputs(bid="joint-r")  # 930 + 90 claimed after the fact

        accounting = mr.commingled_accounting(w.db, "joint-r")
        self.assertEqual(accounting["decision"], "unattributable")
        stmts = {s["owner"]: s for s in accounting["owner_statements"]}
        self.assertTrue(stmts[CUSTOMER]["provable"])
        self.assertEqual((stmts[CUSTOMER]["provable_input_low_g"],
                          stmts[CUSTOMER]["provable_input_high_g"]), (840, 860))
        # Even against total reported outputs, our customer's provable scope
        # can explain at most 860 g; the 1020 g report is 160 g over it.
        self.assertEqual(
            stmts[CUSTOMER]["excess_of_total_outputs_over_owner_high_g"], 160)
        self.assertFalse(stmts[OTHER]["provable"])
        self.assertTrue(has(accounting["blockers"],
                            "provable_input_incomplete:" + OTHER))

        result = mr.certify_commingled(w.db, "cert-r", "joint-r")
        self.assertEqual(result["decision"], "refused_certificate")
        self.assertIsNone(mr.get_certificate(w.db, "cert-r"))

    def test_mass_the_proven_inputs_cannot_explain_stays_unattributed(self):
        w = self._joint_boundary("joint-x")
        w.weighed_output("x-metal", "joint-x", "metal", 1040, "d-metal")
        w.weighed_output("x-res", "joint-x", "residue", 60, "d-res")

        accounting = mr.commingled_accounting(w.db, "joint-x")
        # 1100 g weighed outputs vs 1008-1032 g proven joint input.
        self.assertEqual(accounting["accounted_outputs_g"], 1100)
        self.assertEqual(accounting["unattributed_excess_g"], 68)
        self.assertIsNone(accounting["allocations"])

        result = mr.certify_commingled(w.db, "cert-x", "joint-x")
        self.assertEqual(result["decision"], "refused_certificate")
        self.assertTrue(has(result["blockers"], "mass_overrun"))
        self.assertIsNone(mr.get_certificate(w.db, "cert-x"))


if __name__ == "__main__":
    unittest.main()
