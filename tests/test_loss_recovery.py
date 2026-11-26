import unittest

from secretcourt.store import connect, one
from secretcourt.loss_recovery import allocate_detail, choose_outsourcing_fee, run, statement


def seed_world(db):
    """Exposed gen 1 with real delivered receipts for customers A and B."""
    db.execute("INSERT INTO exposures VALUES('incident','payments',1,23,40,'open')")
    db.execute(
        "INSERT INTO plans VALUES('plan-a','payments',1,'grant-a-1','uid-a','packet-one','complete',1)"
    )
    db.execute(
        "INSERT INTO plans VALUES('plan-b','payments',1,'grant-b-1','uid-b','packet-one','complete',1)"
    )
    db.execute(
        "INSERT INTO receipts VALUES('receipt-a','plan-a','uid-a','delivered','packet-one',21)"
    )
    db.execute(
        "INSERT INTO receipts VALUES('receipt-b','plan-b','uid-b','delivered','packet-one',22)"
    )


def open_a_claim(db, retention=200):
    return run(db, {
        "op": "open_claim", "id": "claim-a", "exposure": "incident", "customer": "customer-a",
        "at": 24, "notice_at": 24, "notice_deadline": 25, "review_deadline": 45,
        "insurer_notice_days": 2, "retention": retention,
    })


def register_a_invoice(db):
    return run(db, {
        "op": "register_payment_original", "id": "payment-a", "invoice": "INV-A",
        "proof_ref": "wire-receipt-a-hash", "amount": 2000, "paid_at": 24,
        "payer": "customer-a", "payee": "response-vendor",
    })


def add_a_items(db):
    common = {
        "op": "add_item", "claim": "claim-a", "customer": "customer-a",
        "invoice": "INV-A", "payment": "payment-a", "secret": "payments", "gen": 1,
    }
    results = []
    results.append(run(db, dict(
        common, id="a-rotation", kind="credential_rotation", amount=300,
        location="uid-a", delivery_receipt="receipt-a", start=24, end=25,
        necessity="reasonable_preventive", causation_evidence="exposed_gen_delivered_prod",
    )))
    results.append(run(db, dict(
        common, id="a-cache", kind="cache_cleanup", amount=500,
        location="uid-a", delivery_receipt="receipt-a", start=24, end=27,
        necessity="necessary", causation_evidence="exposed_credential_reached_cache",
    )))
    fee = choose_outsourcing_fee(
        24, timely_deadline=25, timely_fee=1200, late_fee=1600
    )
    results.append(run(db, dict(
        common, id="a-outsource", kind="outsourcing", amount=fee["amount"],
        location="uid-a", delivery_receipt="receipt-a", start=24, end=30,
        necessity="necessary", fee_code=fee["fee_code"],
        causation_evidence="same_day_ir_team_required",
    )))
    return results


def build_paid_a(db, retention=200):
    seed_world(db)
    open_a_claim(db, retention)
    register_a_invoice(db)
    add_a_items(db)
    run(db, {
        "op": "sign_document", "id": "doc-a-advance", "claim": "claim-a",
        "kind": "advance_deed", "at": 25, "signed_by": "customer-a",
    })
    run(db, {
        "op": "issue_payment", "id": "bank-a-1", "document": "doc-a-advance",
        "invoice": "INV-A", "amount": 2000, "at": 25, "instrument_ref": "wire-A-1",
    })
    run(db, {"op": "clear_payment", "id": "bank-a-1", "at": 25})


class LossRecoveryTrajectoryTest(unittest.TestCase):
    def setUp(self):
        self.db = connect(":memory:")

    def tearDown(self):
        self.db.close()

    def test_01_a_actual_necessary_costs_are_advanced_and_not_count_per_recipient(self):
        seed_world(self.db)
        self.assertEqual(open_a_claim(self.db)["decision"], "claim_opened")
        self.assertEqual(register_a_invoice(self.db)["decision"], "payment_original_registered")
        results = add_a_items(self.db)
        self.assertTrue(all(r["decision"] == "loss_detail_recorded" for r in results), results)

        # Notice timing selects the panel fee; late notice would select rush fee.
        early = choose_outsourcing_fee(24, timely_deadline=25, timely_fee=1200, late_fee=1600)
        late = choose_outsourcing_fee(26, timely_deadline=25, timely_fee=1200, late_fee=1600)
        self.assertEqual((early["fee_code"], early["amount"]), ("timely_panel_response", 1200))
        self.assertEqual((late["fee_code"], late["amount"]), ("late_notice_same_day_team", 1600))

        signed = run(self.db, {
            "op": "sign_document", "id": "doc-a", "claim": "claim-a",
            "kind": "advance_deed", "at": 25,
        })
        self.assertEqual(signed["totals"]["claimed_total"], 2000)
        self.assertEqual(signed["totals"]["admitted_total"], 2000)
        self.assertTrue(signed["notice"]["subrogation"])
        self.assertEqual(signed["notice"]["obligor"], "platform")

        issued = run(self.db, {
            "op": "issue_payment", "id": "bank-a", "document": "doc-a",
            "invoice": "INV-A", "amount": 2000, "at": 25,
        })
        self.assertEqual(issued["status"], "issued")
        self.assertEqual(statement(self.db, "claim-a")["cash"]["customer_actual_net_receipt"], 0)
        run(self.db, {"op": "clear_payment", "id": "bank-a", "at": 25})

        result = statement(self.db, "claim-a")
        self.assertEqual(result["cash"]["customer_actual_net_receipt"], 2000)
        self.assertEqual(result["party_burden"]["platform"]["net_burden"], 2000)
        self.assertEqual(result["party_burden"]["insurer"]["net_burden"], 0)
        a_item = next(i for i in result["items"] if i["id"] == "a-rotation")
        self.assertEqual(a_item["delivery_receipt"], "receipt-a")
        self.assertEqual(a_item["location"], "uid-a")

        # The old finance draft remains a draft-only shortcut; it is not the adjustment.
        from secretcourt.breach_claim import draft
        self.assertEqual(draft(self.db, "finance-draft", "incident", 999999)["decision"], "drafted")
        self.assertEqual(result["totals"]["admitted_total"], 2000)

    def test_02_b_preexisting_outage_is_stripped_but_preventive_rotation_survives(self):
        seed_world(self.db)
        run(self.db, {
            "op": "open_claim", "id": "claim-b", "exposure": "incident", "customer": "customer-b",
            "at": 24, "retention": 0,
        })
        run(self.db, {
            "op": "register_payment_original", "id": "payment-b", "invoice": "INV-B",
            "proof_ref": "wire-b", "amount": 1200,
        })
        downtime = run(self.db, {
            "op": "add_item", "id": "b-downtime", "claim": "claim-b", "customer": "customer-b",
            "invoice": "INV-B", "payment": "payment-b", "kind": "downtime", "amount": 1000,
            "secret": "payments", "gen": 1, "location": "uid-b",
            "delivery_receipt": "receipt-b", "start": 18, "end": 23,
            "necessity": "reasonable", "causation": "preexisting_configuration_failure",
            "causation_evidence": "config-health-log-before-exposure",
            "fault_start": 18, "fault_end": 23,
        })
        self.assertEqual(downtime["excluded_amount"], 1000)
        rotation = run(self.db, {
            "op": "add_item", "id": "b-rotation", "claim": "claim-b", "customer": "customer-b",
            "invoice": "INV-B", "payment": "payment-b", "kind": "credential_rotation", "amount": 200,
            "secret": "payments", "gen": 1, "location": "uid-b",
            "delivery_receipt": "receipt-b", "start": 24, "end": 25,
            "necessity": "reasonable_preventive",
        })
        self.assertEqual(rotation["admitted_amount"], 200)

        signed = run(self.db, {
            "op": "sign_document", "id": "doc-b", "claim": "claim-b",
            "kind": "advance_deed", "at": 25,
        })
        self.assertEqual(signed["totals"]["claimed_total"], 1200)
        self.assertEqual(signed["totals"]["admitted_total"], 200)
        self.assertEqual(signed["totals"]["excluded_total"], 1000)
        run(self.db, {
            "op": "issue_payment", "id": "bank-b", "document": "doc-b",
            "invoice": "INV-B", "amount": 200, "at": 25,
        })
        run(self.db, {"op": "clear_payment", "id": "bank-b", "at": 25})
        result = statement(self.db, "claim-b")
        self.assertEqual(result["cash"]["customer_actual_net_receipt"], 200)
        self.assertEqual(result["party_burden"]["platform"]["net_burden"], 200)
        self.assertEqual(result["party_burden"]["insurer"]["net_burden"], 0)

        # A mixed ten-unit outage is apportioned: five fault units, five exposure units.
        mixed = allocate_detail({
            "kind": "downtime", "amount": 1000, "start": 20, "end": 30,
            "fault_start": 20, "fault_end": 25,
            "causation_evidence": "restart and rotation telemetry",
        })
        self.assertEqual((mixed["excluded_amount"], mixed["admitted_amount"]), (500, 500))

    def test_03_log_legitimate_retry_leaves_loss_with_platform(self):
        build_paid_a(self.db)
        before = one(self.db, "SELECT result_json FROM lr_documents WHERE id='doc-a-advance'")["result_json"]
        run(self.db, {
            "op": "record_unseal_log", "id": "unseal-log", "claim": "claim-a",
            "at": 41, "attribution": "undetermined",
        })
        resolved = run(self.db, {
            "op": "resolve_unseal_log", "id": "unseal-log", "at": 44,
            "attribution": "legitimate_retry",
        })
        self.assertFalse(resolved["amounts"]["third_party_disclosure_confirmed"])
        self.assertEqual(resolved["amounts"]["insurance_cover"], 0)
        self.assertEqual(resolved["amounts"]["uninsured_platform_service_amount"], 2000)

        result = statement(self.db, "claim-a")
        self.assertEqual(result["cash"]["customer_actual_net_receipt"], 2000)
        self.assertEqual(result["party_burden"]["platform"]["net_burden"], 2000)
        self.assertEqual(result["party_burden"]["insurer"]["net_burden"], 0)
        self.assertEqual(result["party_burden"]["supplier"]["net_burden"], 0)
        after = one(self.db, "SELECT result_json FROM lr_documents WHERE id='doc-a-advance'")["result_json"]
        self.assertEqual(before, after)

    def test_03b_log_external_use_and_full_supplier_recourse_clears_three_parties(self):
        build_paid_a(self.db)
        run(self.db, {"op": "record_unseal_log", "id": "unseal-log", "claim": "claim-a", "at": 41})
        resolved = run(self.db, {
            "op": "resolve_unseal_log", "id": "unseal-log", "at": 44,
            "attribution": "unregistered_external", "supplier_liable": 2000,
        })
        self.assertEqual(resolved["amounts"]["insurance_cover"], 1800)
        self.assertEqual(resolved["amounts"]["platform_retention"], 200)
        self.assertEqual(resolved["amounts"]["supplier_allocation"]["supplier_to_insurer"], 1800)
        self.assertEqual(resolved["amounts"]["supplier_allocation"]["supplier_to_platform"], 200)

        run(self.db, {
            "op": "record_transfer", "id": "supplier-pay", "claim": "claim-a",
            "correction": "correction-unseal-log", "invoice": "INV-A",
            "from_party": "supplier", "to_party": "platform", "amount": 2000, "at": 46,
            "kind": "supplier_recovery",
        })
        run(self.db, {
            "op": "record_transfer", "id": "insurer-late", "claim": "claim-a",
            "correction": "correction-unseal-log",
            "from_party": "insurer", "to_party": "platform", "amount": 1800, "at": 60,
            "kind": "insurance_indemnity",
        })
        run(self.db, {
            "op": "record_transfer", "id": "subrogation-pass", "claim": "claim-a",
            "correction": "correction-unseal-log",
            "from_party": "platform", "to_party": "insurer", "amount": 1800, "at": 61,
            "kind": "subrogation_pass_through", "counts_as_compensation": 0,
        })

        result = statement(self.db, "claim-a")
        self.assertEqual(result["cash"]["customer_actual_net_receipt"], 2000)
        self.assertEqual(result["party_burden"]["platform"]["net_burden"], 0)
        self.assertEqual(result["party_burden"]["insurer"]["net_burden"], 0)
        self.assertEqual(result["party_burden"]["supplier"]["net_burden"], 2000)

    def test_04_same_invoice_cannot_be_claimed_three_times(self):
        build_paid_a(self.db)
        run(self.db, {
            "op": "open_claim", "id": "claim-a-duplicate", "exposure": "incident",
            "customer": "customer-a", "at": 26,
        })
        duplicate_item = run(self.db, {
            "op": "add_item", "id": "duplicate-item", "claim": "claim-a-duplicate",
            "customer": "customer-a", "invoice": "INV-A", "payment": "payment-a",
            "kind": "outsourcing", "amount": 2000, "secret": "payments", "gen": 1,
            "location": "uid-a", "start": 24, "end": 30, "necessity": "necessary",
        })
        self.assertEqual(duplicate_item["decision"], "invoice_claim_conflict")

        duplicate_original = run(self.db, {
            "op": "register_payment_original", "id": "payment-a-new", "invoice": "INV-A",
            "proof_ref": "different-proof", "amount": 2000,
        })
        self.assertEqual(duplicate_original["decision"], "duplicate_invoice_original")

        supplier_cash = run(self.db, {
            "op": "record_transfer", "id": "double-supplier", "claim": "claim-a",
            "invoice": "INV-A", "from_party": "supplier", "to_party": "customer",
            "amount": 500, "kind": "supplier_recovery", "at": 27,
        })
        insurer_cash = run(self.db, {
            "op": "record_transfer", "id": "double-insurer", "claim": "claim-a",
            "invoice": "INV-A", "from_party": "insurer", "to_party": "customer",
            "amount": 500, "kind": "insurance_indemnity", "at": 27,
        })
        self.assertEqual(supplier_cash["decision"], "invoice_double_recovery")
        self.assertEqual(insurer_cash["decision"], "invoice_double_recovery")

        recovery = run(self.db, {
            "op": "file_recovery", "id": "customer-triple", "claim": "claim-a",
            "invoice": "INV-A", "claimant": "customer", "source": "insurer",
            "amount": 2000,
        })
        self.assertEqual(recovery["decision"], "invoice_triple_recovery_barred")

    def test_05_late_insurance_payment_routes_to_platform_advance_account(self):
        build_paid_a(self.db)
        run(self.db, {"op": "record_unseal_log", "id": "log-late", "claim": "claim-a", "at": 41})
        run(self.db, {
            "op": "resolve_unseal_log", "id": "log-late", "at": 44,
            "attribution": "unregistered_external",
        })
        payment = run(self.db, {
            "op": "record_transfer", "id": "insurer-late-platform", "claim": "claim-a",
            "from_party": "insurer", "to_party": "platform", "amount": 1800, "at": 70,
            "kind": "insurance_indemnity",
        })
        self.assertEqual(payment["decision"], "transfer_recorded")
        result = statement(self.db, "claim-a")
        self.assertEqual(result["cash"]["customer_actual_net_receipt"], 2000)
        self.assertEqual(result["subledger"]["insurance_indemnities_settled"], 1800)
        self.assertEqual(result["subledger"]["platform_retention_recognized"], 200)
        self.assertEqual(result["party_burden"]["platform"]["net_burden"], 200)
        self.assertEqual(result["party_burden"]["insurer"]["net_burden"], 1800)

    def test_05b_late_insurance_paid_to_customer_is_forwarded_not_counted_twice(self):
        build_paid_a(self.db)
        run(self.db, {"op": "record_unseal_log", "id": "log-direct", "claim": "claim-a", "at": 41})
        run(self.db, {
            "op": "resolve_unseal_log", "id": "log-direct", "at": 44,
            "attribution": "unregistered_external",
        })
        blocked = run(self.db, {
            "op": "record_transfer", "id": "insurer-direct-blocked", "claim": "claim-a",
            "invoice": "INV-A", "from_party": "insurer", "to_party": "customer",
            "amount": 1800, "kind": "insurance_indemnity", "at": 70,
        })
        self.assertEqual(blocked["decision"], "invoice_double_recovery")

        direct = run(self.db, {
            "op": "record_transfer", "id": "insurer-direct", "claim": "claim-a",
            "invoice": "INV-A", "from_party": "insurer", "to_party": "customer",
            "amount": 1800, "kind": "insurance_indemnity", "at": 70,
            "pass_through": True,
        })
        self.assertEqual(direct["decision"], "transfer_recorded")
        run(self.db, {
            "op": "record_transfer", "id": "forward-insurance", "claim": "claim-a",
            "from_party": "customer", "to_party": "platform", "amount": 1800, "at": 70,
            "kind": "pass_through_to_advancing_platform", "counts_as_compensation": 0,
        })
        result = statement(self.db, "claim-a")
        self.assertEqual(result["cash"]["customer_settled_inflows"], 3800)
        self.assertEqual(result["cash"]["customer_actual_net_receipt"], 2000)
        self.assertEqual(result["party_burden"]["platform"]["net_burden"], 200)

    def test_06_bounced_bank_instrument_is_not_a_customer_receipt(self):
        seed_world(self.db)
        open_a_claim(self.db)
        register_a_invoice(self.db)
        add_a_items(self.db)
        run(self.db, {
            "op": "sign_document", "id": "doc-bounce", "claim": "claim-a",
            "kind": "advance_deed", "at": 25,
        })
        run(self.db, {
            "op": "issue_payment", "id": "bank-bad", "document": "doc-bounce",
            "invoice": "INV-A", "amount": 2000, "at": 25,
        })
        run(self.db, {"op": "clear_payment", "id": "bank-bad", "at": 25})
        self.assertEqual(statement(self.db, "claim-a")["cash"]["customer_actual_net_receipt"], 2000)
        bounced = run(self.db, {
            "op": "bounce_payment", "id": "bank-bad", "at": 26, "reason": "returned_refer_to_maker",
        })
        self.assertEqual(bounced["decision"], "bounced")
        cash = statement(self.db, "claim-a")["cash"]
        self.assertEqual(cash["customer_actual_net_receipt"], 0)
        self.assertEqual(cash["bounced_amount"], 2000)

        run(self.db, {
            "op": "issue_payment", "id": "bank-good", "document": "doc-bounce",
            "invoice": "INV-A", "amount": 2000, "at": 27,
        })
        run(self.db, {"op": "clear_payment", "id": "bank-good", "at": 27})
        result = statement(self.db, "claim-a")
        self.assertEqual(result["cash"]["customer_actual_net_receipt"], 2000)
        self.assertEqual(result["cash"]["bounced_amount"], 2000)
        self.assertEqual(result["party_burden"]["platform"]["net_burden"], 2000)

    def test_partial_settlement_pays_confirmed_part_and_preserves_rest_until_review(self):
        seed_world(self.db)
        open_a_claim(self.db)
        register_a_invoice(self.db)
        add_a_items(self.db)
        signed = run(self.db, {
            "op": "sign_document", "id": "doc-partial", "claim": "claim-a",
            "kind": "partial_settlement", "at": 25, "hold_amount": 1200,
        })
        self.assertEqual(signed["totals"]["immediate_total"], 800)
        self.assertEqual(signed["totals"]["preserved_total"], 1200)
        self.assertEqual(signed["notice"]["due_at"], 45)
        self.assertFalse(signed["notice"]["subrogation"])

        run(self.db, {
            "op": "issue_payment", "id": "partial-bank", "document": "doc-partial",
            "invoice": "INV-A", "amount": 800, "at": 25,
        })
        run(self.db, {"op": "clear_payment", "id": "partial-bank", "at": 25})
        self.assertEqual(statement(self.db, "claim-a")["cash"]["customer_actual_net_receipt"], 800)

        run(self.db, {"op": "record_unseal_log", "id": "log-partial", "claim": "claim-a", "at": 41})
        review = run(self.db, {
            "op": "resolve_unseal_log", "id": "log-partial", "at": 44,
            "attribution": "legitimate_retry",
        })
        self.assertEqual(review["routing"]["platform_to_customer_hold_release"], 1200)
        run(self.db, {
            "op": "record_transfer", "id": "hold-release", "claim": "claim-a",
            "correction": "correction-log-partial", "invoice": "INV-A",
            "from_party": "platform", "to_party": "customer", "amount": 1200,
            "kind": "hold_release", "at": 44,
        })
        result = statement(self.db, "claim-a")
        self.assertEqual(result["cash"]["customer_actual_net_receipt"], 2000)
        self.assertEqual(result["party_burden"]["platform"]["net_burden"], 2000)

    def test_late_refund_creates_recourse_but_does_not_rewrite_signed_adjustment(self):
        build_paid_a(self.db)
        before = one(self.db, "SELECT totals_json FROM lr_documents WHERE id='doc-a-advance'")["totals_json"]
        correction = run(self.db, {
            "op": "record_refund", "id": "refund-1", "claim": "claim-a", "at": 50,
            "amount": 300, "from_party": "response-vendor", "reason": "duplicate_vendor_charge_refund",
        })
        self.assertEqual(correction["decision"], "refund_correction_recorded")

        # Vendor refund is not new compensation under the invoice cap.
        run(self.db, {
            "op": "record_transfer", "id": "vendor-refund-money", "claim": "claim-a",
            "invoice": "INV-A", "from_party": "supplier", "to_party": "customer",
            "amount": 300, "at": 50, "kind": "vendor_refund", "counts_as_compensation": 0,
        })
        run(self.db, {
            "op": "record_transfer", "id": "refund-clawback", "claim": "claim-a",
            "from_party": "customer", "to_party": "platform", "amount": 300, "at": 51,
            "kind": "duplicate_compensation_return", "counts_as_compensation": 0,
        })
        after = one(self.db, "SELECT totals_json FROM lr_documents WHERE id='doc-a-advance'")["totals_json"]
        self.assertEqual(before, after)
        result = statement(self.db, "claim-a")
        self.assertEqual(result["cash"]["customer_actual_net_receipt"], 2000)
        self.assertEqual(result["party_burden"]["platform"]["net_burden"], 1700)

    def test_notice_time_changes_the_bound_outsourcing_fee(self):
        seed_world(self.db)
        run(self.db, {
            "op": "open_claim", "id": "claim-late-notice", "exposure": "incident",
            "customer": "customer-a", "at": 24, "notice_at": 26, "notice_deadline": 25,
        })
        run(self.db, {
            "op": "register_payment_original", "id": "payment-late-fee",
            "invoice": "INV-LATE-FEE", "proof_ref": "wire-late", "amount": 1600,
        })
        fee = choose_outsourcing_fee(26, timely_deadline=25, timely_fee=1200, late_fee=1600)
        recorded = run(self.db, {
            "op": "add_item", "id": "late-outsource", "claim": "claim-late-notice",
            "customer": "customer-a", "invoice": "INV-LATE-FEE", "payment": "payment-late-fee",
            "kind": "outsourcing", "amount": fee["amount"], "secret": "payments", "gen": 1,
            "location": "uid-a", "delivery_receipt": "receipt-a", "start": 26, "end": 30,
            "necessity": "necessary", "fee_code": fee["fee_code"],
        })
        self.assertEqual(fee["fee_code"], "late_notice_same_day_team")
        self.assertEqual(recorded["admitted_amount"], 1600)

    def test_incomplete_detail_and_wrong_delivery_location_are_rejected(self):
        seed_world(self.db)
        open_a_claim(self.db)
        register_a_invoice(self.db)
        missing = run(self.db, {
            "op": "add_item", "id": "bad-1", "claim": "claim-a", "customer": "customer-a",
            "invoice": "INV-A", "payment": "payment-a", "kind": "cache_cleanup", "amount": 100,
            "secret": "payments", "gen": 1, "start": 24, "end": 25, "necessity": "necessary",
        })
        self.assertEqual(missing["decision"], "invalid_loss_detail")

        wrong = run(self.db, {
            "op": "add_item", "id": "bad-2", "claim": "claim-a", "customer": "customer-a",
            "invoice": "INV-A", "payment": "payment-a", "kind": "cache_cleanup", "amount": 100,
            "secret": "payments", "gen": 1, "location": "uid-a", "delivery_receipt": "receipt-b",
            "start": 24, "end": 25, "necessity": "necessary",
        })
        self.assertEqual(wrong["decision"], "usage_evidence_mismatch")


if __name__ == "__main__":
    unittest.main()
