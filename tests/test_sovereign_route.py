import unittest

from secretcourt import regional_delivery, sovereign_route as sr
from secretcourt.store import connect, one


CONTRACT = "contract-acme-v3"
CUSTOMER = "cross-border-customer"
VERSION = "contract-2026-11-v3"
SECRET = "regional-proof"
GEN = 7

SOURCE = "dev-source-vault"
EDGE_SOUTH = "dev-edge-south"
NORTH = "dev-north-cache"
BACKUP = "dev-north-backup"
REPACKER = "dev-south-repacker"
VAULT = "dev-south-vault"
U = "dev-u"
U2 = "dev-u-rebuilt"
UID = "instance-U"


class SovereignRouteAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.db = connect(":memory:")
        sr.ensure_schema(self.db)
        sr.bind_contract(self.db, {
            "id": CONTRACT,
            "customer": CUSTOMER,
            "contract_version": VERSION,
            "secret": SECRET,
            "gen": GEN,
            "plaintext_region": "south",
            "ciphertext_regions": ["north", "south"],
            "key_regions": ["south"],
            "key_id": "kek-regional-7",
            "key_holder": "south-hsm",
            "valid_from": 0,
            "valid_until": 10_000,
        })

        devices = [
            (SOURCE, "source-vault", "south-resource-label", True),
            (EDGE_SOUTH, "edge-agent", "south-resource-label", True),
            (NORTH, "backbone-cache", "north-resource-label", False),
            (BACKUP, "backup-relay", "north-resource-label", False),
            (REPACKER, "trusted-repackager", "south-resource-label", True),
            (VAULT, "parking-vault", "south-resource-label", True),
            (U, "instance", "south-resource-label", True),
        ]
        for device_id, kind, label, certified in devices:
            sr.register_device(self.db, {
                "id": device_id, "kind": kind, "cloud_label": label,
                "certified": certified, "certified_until": 10_000,
            })

        locations = [
            ("loc-source", SOURCE, "south", "south-source-hsm-site", "independent_dc_access_audit"),
            ("loc-edge", EDGE_SOUTH, "south", "south-edge-certified-site", "metro_access_audit"),
            ("loc-north", NORTH, "north", "north-carrier-cache-site", "independent_carrier_log_audit"),
            ("loc-backup", BACKUP, "north", "north-backup-pop-site", "independent_network_path_audit"),
            ("loc-repacker", REPACKER, "south", "south-repackager-enclave-site", "remote_enclave_attestation"),
            ("loc-vault", VAULT, "south", "south-recoverable-vault", "independent_dc_access_audit"),
            ("loc-u", U, "south", "south-customer-certified-device", "hardware_attestation_chain"),
        ]
        for evidence_id, device_id, region, site, source in locations:
            sr.record_location(self.db, {
                "id": evidence_id, "device_id": device_id, "at": 100,
                "region": region, "site": site, "source_kind": source,
                "independent": True, "digest": f"digest-{evidence_id}",
            })

    def tearDown(self):
        self.db.close()

    # ----- helpers ---------------------------------------------------------

    def codes(self, result):
        return result.get("blockers", [])

    def assertBlocker(self, result, fragment):
        blockers = result.get("blockers")
        if blockers is None and isinstance(result.get("verdict"), dict):
            blockers = result["verdict"].get("blockers", [])
        blockers = blockers or []
        self.assertTrue(
            any(fragment in code for code in blockers),
            f"expected blocker containing {fragment!r}, got {blockers!r}; result={result!r}",
        )

    def auth(self, route_id, kind="original_path", auth_id=None, at=200, until=5_000, **extra):
        payload = {
            "id": auth_id or f"auth-{route_id}-{kind}",
            "route_id": route_id,
            "kind": kind,
            "customer_actor": "customer-acme-approver",
            "compliance_actor": "compliance-sovereign-desk",
            "at": at,
            "valid_from": extra.pop("valid_from", at),
            "valid_until": until,
        }
        payload.update(extra)
        return sr.authorize(self.db, payload)

    def north_hops(self):
        return [
            {"seq": 1, "device_id": SOURCE, "role": "sealed-source",
             "visibility": "ciphertext", "key_control": "holds_root_key", "key_holder": "south-hsm"},
            {"seq": 2, "device_id": NORTH, "role": "failover-cache",
             "visibility": "ciphertext", "key_control": "no_key", "key_holder": "south-hsm"},
            {"seq": 3, "device_id": EDGE_SOUTH, "role": "south-edge",
             "visibility": "ciphertext", "key_control": "no_key", "key_holder": "south-hsm"},
            {"seq": 4, "device_id": U, "role": "target",
             "visibility": "plaintext", "key_control": "holds_authorized_key",
             "key_holder": "instance-U-enclave"},
        ]

    def create_north(self, route_id="route-north", packet="pkg-north", **extra):
        payload = {
            "id": route_id,
            "contract_id": CONTRACT,
            "packet_id": packet,
            "target_uid": UID,
            "target_generation": 1,
            "identity_generation": 1,
            "target_device_id": U,
            "at": 200,
            "hops": self.north_hops(),
            "eta_seconds": 1_800,
        }
        payload.update(extra)
        return sr.create_route(self.db, payload)

    def prove_north(self, route_id, packet, devices=(NORTH, EDGE_SOUTH), at=220):
        for device_id in devices:
            safe = device_id.replace("-", "_")
            sr.add_evidence(self.db, {
                "id": f"ev-transfer-{route_id}-{safe}",
                "route_id": route_id, "device_id": device_id, "at": at,
                "kind": "packet_transfer_log", "claim": "packet_transfer_log",
                "independent": True, "verifier": "independent-carrier-log-audit",
                "payload": {"packet_id": packet, "digest": packet},
            })
            sr.add_evidence(self.db, {
                "id": f"ev-cipher-{route_id}-{safe}",
                "route_id": route_id, "device_id": device_id, "at": at,
                "kind": "content_attestation", "claim": "ciphertext_only",
                "independent": True, "verifier": "remote-enclave-and-process-audit",
                "payload": {"observed_bytes": "application-ciphertext", "plaintext_operations": 0},
            })
            sr.add_evidence(self.db, {
                "id": f"ev-key-{route_id}-{safe}",
                "route_id": route_id, "device_id": device_id, "at": at,
                "kind": "kms_audit", "claim": "no_key_release",
                "independent": True, "verifier": "kms-independent-audit-export",
                "payload": {"key_id": "kek-regional-7", "releases": []},
            })

    def touch(self, route_id, touch_id, device_id, at, packet, action="handoff_accepted"):
        return sr.observe_touch(self.db, {
            "id": touch_id, "route_id": route_id, "device_id": device_id,
            "at": at, "packet_id": packet, "action": action,
            "digest": f"touch-digest-{touch_id}",
        })

    def deliver(self, route_id, packet, at=320, receipt_id="receipt-1", commitment=None):
        route_row = one(self.db, "SELECT commitment,target_device_id FROM sr_routes WHERE id=?", (route_id,))
        route_commitment = commitment or route_row["commitment"]
        target_device = route_row["target_device_id"]
        attestation_digest = f"target-attestation-{receipt_id}"
        sr.add_evidence(self.db, {
            "id": f"ev-target-{receipt_id}",
            "route_id": route_id,
            "device_id": target_device,
            "at": at,
            "kind": "hardware_attestation",
            "claim": "target_attestation",
            "independent": True,
            "verifier": "independent-device-attestation-service",
            "digest": attestation_digest,
            "payload": {"uid": UID, "packet_id": packet},
        })
        return sr.verify_delivery_receipt(self.db, {
            "id": receipt_id,
            "route_id": route_id,
            "at": at,
            "packet_id": packet,
            "route_commitment": route_commitment,
            "attestation_digest": attestation_digest,
            "attestation_evidence_id": f"ev-target-{receipt_id}",
        })

    def parked(self, route_id):
        return sr.customer_view(self.db, route_id)["parked_packet"]

    # ----- acceptance trajectories ----------------------------------------

    def test_north_pure_ciphertext_cache_is_verified_then_released(self):
        self.create_north()
        self.auth("route-north")
        sr.enqueue_packet(self.db, {
            "route_id": "route-north", "packet_id": "pkg-north",
            "custodian_device_id": SOURCE, "at": 200,
        })
        self.touch("route-north", "touch-source", SOURCE, 205, "pkg-north", "sealed_dispatch")
        self.touch("route-north", "touch-north", NORTH, 210, "pkg-north", "cached_ciphertext")

        blocked = sr.activate_route(self.db, {"id": "route-north", "at": 215})
        self.assertEqual(blocked["decision"], "not_producible")
        self.assertBlocker(blocked, "missing_independent_ciphertext_only_proof")
        self.assertBlocker(blocked, "missing_key_boundary_proof")
        parking = blocked["parking"]
        self.assertEqual(parking["custodian_device_id"], NORTH)
        self.assertEqual(parking["region"], "north")
        self.assertEqual(parking["status"], "parked")
        self.assertTrue(parking["id"] and blocked["recovery_token"].startswith("recovery-"))

        proof_before = sr.customer_view(self.db, "route-north")
        north_path = next(p for p in proof_before["actual_device_path"] if p["device_id"] == NORTH)
        self.assertEqual(north_path["actual_region"], "north")
        self.assertEqual(north_path["visibility"], "ciphertext")
        self.assertEqual(north_path["key_holder"], "south-hsm")
        self.assertEqual(proof_before["parked_packet"]["packet_id"], "pkg-north")

        self.prove_north("route-north", "pkg-north")
        resumed = sr.resume_packet(self.db, {
            "parking_id": parking["id"], "recovery_token": blocked["recovery_token"], "at": 225,
        })
        self.assertEqual(resumed["decision"], "resumed")
        self.assertEqual(resumed["verdict"]["decision"], "ready_for_production")

        self.touch("route-north", "touch-edge", EDGE_SOUTH, 300, "pkg-north", "forwarded")
        self.touch("route-north", "touch-u", U, 310, "pkg-north", "accepted")

        same_packet_south = sr.create_route(self.db, {
            "id": "route-same-packet-south", "contract_id": CONTRACT, "packet_id": "pkg-north",
            "target_uid": UID, "target_device_id": U, "at": 200,
            "hops": [
                {"seq": 1, "device_id": SOURCE, "visibility": "ciphertext", "key_control": "holds_root_key"},
                {"seq": 2, "device_id": EDGE_SOUTH, "visibility": "ciphertext", "key_control": "no_key"},
                {"seq": 3, "device_id": U, "visibility": "plaintext", "key_control": "holds_authorized_key"},
            ],
        })
        self.assertNotEqual(same_packet_south["commitment"], resumed["verdict"]["route_commitment"])

        wrong_commitment = sr.verify_delivery_receipt(self.db, {
            "id": "receipt-wrong-commitment", "route_id": "route-north", "at": 315,
            "packet_id": "pkg-north", "route_commitment": "sha256:packet-id-alone-is-not-path-proof",
            "attestation_digest": "target-attestation-wrong",
        })
        self.assertEqual(wrong_commitment["decision"], "receipt_route_commitment_mismatch")
        self.assertIsNone(one(self.db, "SELECT 1 FROM sr_receipts WHERE id='receipt-wrong-commitment'"))

        missing_commitment = sr.verify_delivery_receipt(self.db, {
            "id": "receipt-missing-commitment", "route_id": "route-north", "at": 316,
            "packet_id": "pkg-north", "attestation_digest": "x",
        })
        self.assertEqual(missing_commitment["decision"], "receipt_missing_route_commitment")

        bogus_attestation = sr.verify_delivery_receipt(self.db, {
            "id": "receipt-bogus-attestation", "route_id": "route-north", "at": 317,
            "packet_id": "pkg-north", "route_commitment": resumed["verdict"]["route_commitment"],
            "attestation_digest": "self-asserted-arbitrary-string",
        })
        self.assertEqual(bogus_attestation["decision"], "missing_independent_target_attestation")

        result = self.deliver("route-north", "pkg-north", at=320)
        self.assertEqual(result["decision"], "delivered", result)

        proof = result["customer_proof"]
        regions = [p["actual_region"] for p in proof["actual_device_path"]]
        self.assertEqual(regions, ["south", "south", "north", "south", "south"])
        self.assertIsNone(proof["parked_packet"])
        self.assertTrue(any(p["region"] == "north" for p in proof["parking_history"]))
        self.assertEqual(proof["receipts"][0]["route_commitment"], proof["route_commitment"])

    def test_late_north_key_request_parks_and_late_release_is_hard_block(self):
        self.create_north(route_id="route-key-bad", packet="pkg-key-bad")
        self.auth("route-key-bad")
        sr.enqueue_packet(self.db, {
            "route_id": "route-key-bad", "packet_id": "pkg-key-bad",
            "custodian_device_id": SOURCE, "at": 200,
        })
        self.touch("route-key-bad", "touch-source-bad", SOURCE, 205, "pkg-key-bad")
        self.touch("route-key-bad", "touch-north-bad", NORTH, 1010, "pkg-key-bad", "cached_ciphertext")
        sr.request_key(self.db, {
            "request_id": "key-req-late", "route_id": "route-key-bad",
            "key_id": "kek-regional-7", "device_id": NORTH,
            "principal": "north-backbone-agent", "at": 1_000,
        })

        waiting = sr.activate_route(self.db, {"id": "route-key-bad", "at": 1_100})
        self.assertEqual(waiting["decision"], "not_producible")
        self.assertBlocker(waiting, "key_request_unresolved:key-req-late")
        parking = waiting["parking"]
        self.assertEqual(parking["custodian_device_id"], NORTH)
        self.assertEqual(parking["status"], "parked")

        view = sr.customer_view(self.db, "route-key-bad")
        self.assertEqual(view["key_control"]["requests"][0]["status"], "pending")
        self.assertEqual(view["parked_packet"]["id"], parking["id"])
        self.assertEqual(next(p for p in view["actual_device_path"] if p["device_id"] == NORTH)["key_holder"], "south-hsm")

        denied_resume = sr.resume_packet(self.db, {
            "parking_id": parking["id"], "recovery_token": waiting["recovery_token"], "at": 1_110,
        })
        self.assertEqual(denied_resume["decision"], "still_blocked")

        late = sr.resolve_key_request(self.db, {
            "request_id": "key-req-late",
            "outcome": "released",
            "receipt_id": "kms-receipt-arrived-20m-late",
            "receipt_at": 2_200,
            "independent": True,
            "evidence_source": "kms_audit",
            "digest": "late-kms-receipt-digest",
        })
        self.assertEqual(late["decision"], "key_request_resolved")
        self.assertEqual(late["late_seconds"], 1_200)
        self.assertEqual(late["late_minutes"], 20)

        rejected = sr.activate_route(self.db, {"id": "route-key-bad", "at": 2_201})
        self.assertEqual(rejected["verdict"]["decision"], "route_rejected")
        self.assertBlocker(rejected, "key_released_to_no_key_hop:key-req-late")
        self.assertEqual(rejected["parking"]["status"], "quarantined")
        no_resume = sr.resume_packet(self.db, {
            "parking_id": rejected["parking"]["id"],
            "recovery_token": rejected["recovery_token"], "at": 2_202,
        })
        self.assertEqual(no_resume["decision"], "parking_quarantined_rotation_required")
        self.assertIsNone(one(self.db, "SELECT 1 FROM sr_receipts WHERE route_id='route-key-bad'"))

    def test_late_key_request_denied_allows_original_north_path(self):
        self.create_north(route_id="route-key-denied", packet="pkg-key-denied")
        self.auth("route-key-denied")
        sr.enqueue_packet(self.db, {
            "route_id": "route-key-denied", "packet_id": "pkg-key-denied",
            "custodian_device_id": SOURCE, "at": 200,
        })
        self.touch("route-key-denied", "touch-source-ok", SOURCE, 205, "pkg-key-denied")
        self.touch("route-key-denied", "touch-north-ok", NORTH, 1_010, "pkg-key-denied", "cached_ciphertext")
        sr.request_key(self.db, {
            "request_id": "key-req-denied", "route_id": "route-key-denied",
            "key_id": "kek-regional-7", "device_id": NORTH, "at": 1_000,
        })
        parked_result = sr.activate_route(self.db, {"id": "route-key-denied", "at": 1_100})
        self.assertBlocker(parked_result, "key_request_unresolved")

        resolution = sr.resolve_key_request(self.db, {
            "request_id": "key-req-denied", "outcome": "denied",
            "receipt_id": "kms-denial-receipt-late", "receipt_at": 2_200,
            "independent": True, "evidence_source": "kms_audit",
        })
        self.assertEqual(resolution["late_minutes"], 20)
        self.prove_north("route-key-denied", "pkg-key-denied")
        resumed = sr.resume_packet(self.db, {
            "parking_id": parked_result["parking"]["id"],
            "recovery_token": parked_result["recovery_token"], "at": 2_210,
        })
        self.assertEqual(resumed["decision"], "resumed", resumed)

        self.touch("route-key-denied", "touch-edge-ok", EDGE_SOUTH, 2_300, "pkg-key-denied")
        self.touch("route-key-denied", "touch-u-ok", U, 2_310, "pkg-key-denied")
        result = self.deliver("route-key-denied", "pkg-key-denied", at=2_320, receipt_id="receipt-denied")
        self.assertEqual(result["decision"], "delivered", result)
        self.assertEqual(result["customer_proof"]["key_control"]["requests"][0]["outcome"], "denied")

    def test_approved_region_permit_and_south_cloud_label_do_not_save_key_breach(self):
        # 常规字段修补：region_permits.status/approved=1，实例云标签是 south。
        self.db.execute("INSERT INTO secrets VALUES('s','p',1)")
        self.db.execute("INSERT INTO versions VALUES('s',1,'digest',NULL,'active')")
        self.db.execute("INSERT INTO identities VALUES('i','ns',?, 'prod',1,1)", (UID,))
        self.db.execute("INSERT INTO grants VALUES('g','s',1,'i',?,'[]','prod',10000,'active',1)", (UID,))
        self.assertEqual(regional_delivery.permit(self.db, "rp-label", "g", "south")["decision"], "drafted")
        self.assertEqual(regional_delivery.permit(self.db, "rp-only", "g", "north")["decision"], "drafted")
        self.db.execute("ALTER TABLE region_permits ADD COLUMN approved INTEGER NOT NULL DEFAULT 0")
        self.db.execute("UPDATE region_permits SET status='approved', approved=1 WHERE id='rp-label'")

        self.create_north(
            route_id="route-label-patch", packet="pkg-label", permit_id="rp-label",
            plan_id="plan-label",
        )
        self.auth("route-label-patch")
        sr.request_key(self.db, {
            "request_id": "req-label", "route_id": "route-label-patch",
            "key_id": "kek-regional-7", "device_id": NORTH, "at": 100,
        })
        sr.resolve_key_request(self.db, {
            "request_id": "req-label", "outcome": "released", "receipt_id": "late",
            "receipt_at": 120, "independent": True, "evidence_source": "kms_audit",
        })

        permit = one(self.db, "SELECT * FROM region_permits WHERE id='rp-label'")
        target = sr._device(self.db, U)
        target_location = sr._location_at(self.db, U, 130)
        self.assertEqual(permit["approved"], 1)
        self.assertEqual(target["cloud_label"], "south-resource-label")
        self.assertEqual(target_location["region"], "south")

        step = {"op": "plan", "id": "plan-label", "secret": "s", "gen": 1,
                "packet": "pkg-label", "members": [{"uid": UID, "grant": "g"}], "at": 130}
        result = sr.provisional_delivery(self.db, "rp-label", step)
        self.assertEqual(result["decision"], "parked_sovereign_route")
        self.assertEqual(result["verdict_decision"], "route_rejected")
        self.assertIsNone(one(self.db, "SELECT * FROM plans WHERE id='plan-label'"))

        conventional_only = sr.provisional_delivery(self.db, "rp-only", {"op": "plan", "id": "plan-other"})
        self.assertEqual(conventional_only["decision"], "sovereign_route_required")
        missing = sr.provisional_delivery(self.db, "unknown-sovereign-ref")
        self.assertEqual(missing["decision"], "missing_sovereign_route")

    def test_south_trusted_repack_path_has_distinct_custody_chain(self):
        route = sr.create_route(self.db, {
            "id": "route-repack",
            "contract_id": CONTRACT,
            "packet_id": "pkg-up",
            "target_uid": UID,
            "target_device_id": U,
            "at": 200,
            "route_kind": "south_repack",
            "eta_seconds": 600,
            "hops": [
                {"seq": 1, "device_id": SOURCE, "role": "source", "visibility": "ciphertext",
                 "key_control": "holds_root_key", "key_holder": "south-hsm"},
                {"seq": 2, "device_id": REPACKER, "role": "authorized_repackager",
                 "visibility": "ciphertext", "key_control": "holds_authorized_key",
                 "key_holder": "south-repacker-enclave"},
                {"seq": 3, "device_id": U, "role": "target", "visibility": "plaintext",
                 "key_control": "holds_authorized_key", "key_holder": "instance-U-enclave"},
            ],
        })
        self.assertEqual(route["decision"], "route_created")
        self.auth("route-repack", kind="repack", auth_id="auth-repack-customer-compliance",
                  handlers=[REPACKER], terms={"plaintext_boundary": "south-enclave-only"})

        sr.request_key(self.db, {
            "request_id": "key-repack", "route_id": "route-repack",
            "key_id": "kek-regional-7", "device_id": REPACKER, "at": 205,
        })
        sr.resolve_key_request(self.db, {
            "request_id": "key-repack", "outcome": "released", "receipt_id": "repack-kms",
            "receipt_at": 210, "independent": True, "evidence_source": "hsm_audit",
        })
        activated = sr.activate_route(self.db, {"id": "route-repack", "at": 220})
        self.assertEqual(activated["decision"], "production", activated)

        enqueued = sr.enqueue_packet(self.db, {
            "route_id": "route-repack", "packet_id": "pkg-up",
            "custodian_device_id": SOURCE, "at": 200,
        })
        self.assertEqual(enqueued["parking"]["region"], "south")
        self.assertIsNotNone(self.parked("route-repack"))

        forwarded = sr.advance_packet(self.db, {"route_id": "route-repack", "at": 230})
        self.assertEqual(forwarded["decision"], "forwarded")
        self.assertEqual(forwarded["device_id"], REPACKER)

        sr.add_evidence(self.db, {
            "id": "ev-repack-attestation", "route_id": "route-repack",
            "device_id": REPACKER, "at": 240, "kind": "remote_attestation",
            "claim": "south_repack_attestation", "independent": True,
            "verifier": "independent-enclave-attestation-service",
            "payload": {"plaintext_egress": False, "region": "south", "material_gen": GEN},
        })
        repacked = sr.repack_packet(self.db, {
            "id": "repack-1", "route_id": "route-repack", "at": 240,
            "device_id": REPACKER, "old_packet_id": "pkg-up",
            "new_packet_id": "pkg-down",
            "attestation_evidence_id": "ev-repack-attestation",
        })
        self.assertEqual(repacked["decision"], "repacked_in_south", repacked)

        forwarded_u = sr.advance_packet(self.db, {"route_id": "route-repack", "at": 250, "packet_id": "pkg-down"})
        self.assertEqual(forwarded_u["decision"], "forwarded")
        self.assertEqual(forwarded_u["device_id"], U)

        result = self.deliver("route-repack", "pkg-down", at=260, receipt_id="receipt-repack")
        self.assertEqual(result["decision"], "delivered", result)
        proof = result["customer_proof"]
        self.assertEqual(proof["repacks"][0]["old_packet"], "pkg-up")
        self.assertEqual(proof["repacks"][0]["new_packet"], "pkg-down")
        self.assertEqual(proof["packet_lineage"]["initial_packet"], "pkg-up")
        self.assertEqual(proof["packet_lineage"]["final_packet"], "pkg-down")
        repack_path = next(p for p in proof["actual_device_path"] if p["device_id"] == REPACKER and p["action"] == "repacked")
        self.assertEqual(repack_path["actual_region"], "south")
        self.assertEqual(repack_path["visibility"], "plaintext")
        self.assertEqual(repack_path["key_holder"], "south-repacker-enclave")
        self.assertEqual(proof["delivery_at"], 260)
        self.assertEqual(proof["eta_seconds"], 600)

    def test_instance_rebuild_parks_and_recovers_to_rebound_route(self):
        sr.create_route(self.db, {
            "id": "route-rebuild-old", "contract_id": CONTRACT, "packet_id": "pkg-rebuild",
            "target_uid": UID, "target_generation": 1, "target_device_id": U, "at": 200,
            "hops": [
                {"seq": 1, "device_id": VAULT, "role": "south-vault", "visibility": "ciphertext",
                 "key_control": "no_key", "key_holder": "south-hsm"},
                {"seq": 2, "device_id": U, "role": "target", "visibility": "plaintext",
                 "key_control": "holds_authorized_key", "key_holder": "instance-U-enclave"},
            ],
        })
        self.auth("route-rebuild-old")
        sr.add_evidence(self.db, {
            "id": "ev-vault-key-old", "route_id": "route-rebuild-old", "device_id": VAULT,
            "at": 200, "claim": "no_key_release", "independent": True,
            "verifier": "kms_audit", "payload": {},
        })
        sr.enqueue_packet(self.db, {
            "route_id": "route-rebuild-old", "packet_id": "pkg-rebuild",
            "custodian_device_id": VAULT, "at": 200,
        })

        rebuilt = sr.rebuild_instance(self.db, {
            "old_device_id": U, "new_device_id": U2, "new_generation": 2, "at": 800,
        })
        self.assertEqual(rebuilt["decision"], "instance_rebuilt")
        sr.record_location(self.db, {
            "id": "loc-u2", "device_id": U2, "at": 810, "region": "south",
            "site": "south-replacement-certified-device",
            "source_kind": "hardware_attestation_chain", "independent": True,
        })

        blocked = sr.activate_route(self.db, {"id": "route-rebuild-old", "at": 900})
        self.assertEqual(blocked["decision"], "not_producible")
        self.assertBlocker(blocked, "target_instance_rebuilt")
        parking = blocked["parking"]
        self.assertEqual(parking["custodian_device_id"], VAULT)
        self.assertEqual(parking["region"], "south")
        self.assertEqual(parking["packet_id"], "pkg-rebuild")

        sr.create_route(self.db, {
            "id": "route-rebuild-new", "contract_id": CONTRACT, "packet_id": "pkg-rebuild",
            "target_uid": UID, "target_generation": 2, "identity_generation": 2,
            "target_device_id": U2, "at": 900,
            "hops": [
                {"seq": 1, "device_id": VAULT, "role": "south-vault", "visibility": "ciphertext",
                 "key_control": "no_key", "key_holder": "south-hsm"},
                {"seq": 2, "device_id": U2, "role": "rebuilt-target", "visibility": "plaintext",
                 "key_control": "holds_authorized_key", "key_holder": "instance-U2-enclave"},
            ],
        })
        self.auth("route-rebuild-new", auth_id="auth-rebuild-new")
        sr.add_evidence(self.db, {
            "id": "ev-vault-key-new", "route_id": "route-rebuild-new", "device_id": VAULT,
            "at": 900, "claim": "no_key_release", "independent": True,
            "verifier": "kms_audit", "payload": {},
        })
        recovered = sr.recover_to_route(self.db, {
            "parking_id": parking["id"], "recovery_token": blocked["recovery_token"],
            "new_route_id": "route-rebuild-new", "at": 910,
        })
        self.assertEqual(recovered["decision"], "recovered_to_route", recovered)

        forwarded = sr.advance_packet(self.db, {"route_id": "route-rebuild-new", "at": 920})
        self.assertEqual(forwarded["decision"], "forwarded")
        self.assertEqual(forwarded["device_id"], U2)
        result = self.deliver("route-rebuild-new", "pkg-rebuild", at=930, receipt_id="receipt-rebuild")
        self.assertEqual(result["decision"], "delivered", result)
        self.assertEqual(result["customer_proof"]["target"]["generation"], 2)
        self.assertEqual(result["customer_proof"]["actual_device_path"][-1]["device_id"], U2)

    def test_grant_identity_rebuild_freezes_sovereign_route_binding(self):
        self.db.execute("INSERT INTO secrets VALUES('s','p',1)")
        self.db.execute("INSERT INTO versions VALUES('s',1,'digest',NULL,'active')")
        self.db.execute("INSERT INTO identities VALUES('i','ns',?, 'prod',1,1)", (UID,))
        self.db.execute("INSERT INTO grants VALUES('g','s',1,'i',?,'[]','prod',10000,'active',1)", (UID,))
        self.create_north(route_id="route-grant-rebuild", grant_id="g", identity_generation=1)
        self.auth("route-grant-rebuild")
        self.prove_north("route-grant-rebuild", "pkg-north")

        from secretcourt import grant
        observed = grant.run(self.db, {
            "op": "identity", "id": "i", "namespace": "ns", "uid": UID,
            "environment": "prod", "generation": 2,
        })
        self.assertEqual(observed["decision"], "observed")
        verdict = sr.evaluate_route(self.db, "route-grant-rebuild", at=300)
        self.assertFalse(verdict["production"])
        self.assertTrue(any("target_instance_rebuilt" in x for x in verdict["unresolved"]), verdict)
        self.assertTrue(any("workload_grant_frozen" in x for x in verdict["unresolved"]), verdict)

    def test_temporary_detour_requires_separate_unexpired_authorization(self):
        self.create_north(
            route_id="route-detour", packet="pkg-detour", route_kind="temporary_detour",
        )
        # 只有原始路径授权，不能替代 detour 授权。
        self.auth("route-detour", kind="original_path", auth_id="auth-original-not-detour")
        sr.enqueue_packet(self.db, {
            "route_id": "route-detour", "packet_id": "pkg-detour",
            "custodian_device_id": SOURCE, "at": 200,
        })
        self.touch("route-detour", "detour-source", SOURCE, 205, "pkg-detour")
        self.touch("route-detour", "detour-north", NORTH, 210, "pkg-detour", "temporary_failover_cache")
        missing = sr.activate_route(self.db, {"id": "route-detour", "at": 220})
        self.assertBlocker(missing, "missing_authorization:detour")

        # 过期的临时绕路授权同样不可用；先补齐设备证据，以隔离授权有效期判断。
        self.prove_north("route-detour", "pkg-detour")
        self.auth("route-detour", kind="detour", auth_id="auth-detour-expired", at=200, until=260)
        expired = sr.activate_route(self.db, {"id": "route-detour", "at": 300})
        self.assertBlocker(expired, "authorization_expired_or_inactive:auth-detour-expired")
        parking = expired["parking"]
        self.assertEqual(parking["custodian_device_id"], NORTH)
        self.assertEqual(parking["region"], "north")
        self.assertEqual(parking["reason"], "authorization_expired_or_inactive:auth-detour-expired")
        self.assertEqual(sr.resume_packet(self.db, {
            "parking_id": parking["id"], "recovery_token": expired["recovery_token"], "at": 305,
        })["decision"], "still_blocked")

        self.auth("route-detour", kind="detour", auth_id="auth-detour-current", at=290, until=5_000)
        resumed = sr.resume_packet(self.db, {
            "parking_id": parking["id"], "recovery_token": expired["recovery_token"], "at": 310,
        })
        self.assertEqual(resumed["decision"], "resumed", resumed)

        self.touch("route-detour", "detour-edge", EDGE_SOUTH, 320, "pkg-detour")
        self.touch("route-detour", "detour-u", U, 330, "pkg-detour")
        result = self.deliver("route-detour", "pkg-detour", at=340, receipt_id="receipt-detour")
        self.assertEqual(result["decision"], "delivered", result)
        kinds = {a["kind"] for a in result["customer_proof"]["authorizations"]}
        self.assertIn("detour", kinds)

    def test_lost_backup_channel_keeps_packet_at_last_known_custodian(self):
        sr.create_route(self.db, {
            "id": "route-backup", "contract_id": CONTRACT, "packet_id": "pkg-backup",
            "target_uid": UID, "target_device_id": U, "at": 200,
            "hops": [
                {"seq": 1, "device_id": SOURCE, "role": "source", "visibility": "ciphertext",
                 "key_control": "holds_root_key", "key_holder": "south-hsm"},
                {"seq": 2, "device_id": EDGE_SOUTH, "role": "south-edge", "visibility": "ciphertext",
                 "key_control": "no_key", "key_holder": "south-hsm"},
                {"seq": 3, "device_id": BACKUP, "role": "backup-channel", "visibility": "ciphertext",
                 "key_control": "no_key", "key_holder": "south-hsm"},
                {"seq": 4, "device_id": U, "role": "target", "visibility": "plaintext",
                 "key_control": "holds_authorized_key", "key_holder": "instance-U-enclave"},
            ],
        })
        self.auth("route-backup")
        self.prove_north("route-backup", "pkg-backup", devices=(BACKUP, EDGE_SOUTH))
        activated = sr.activate_route(self.db, {"id": "route-backup", "at": 220})
        self.assertEqual(activated["decision"], "production", activated)

        sr.enqueue_packet(self.db, {
            "route_id": "route-backup", "packet_id": "pkg-backup",
            "custodian_device_id": SOURCE, "at": 200,
        })
        first = sr.advance_packet(self.db, {"route_id": "route-backup", "at": 230})
        self.assertEqual(first["decision"], "forwarded")
        self.assertEqual(first["device_id"], EDGE_SOUTH)

        sr.set_device_reachability(self.db, {"id": BACKUP, "reachable": False})
        lost = sr.advance_packet(self.db, {"route_id": "route-backup", "at": 240})
        self.assertEqual(lost["decision"], "parked_unreachable")
        self.assertEqual(lost["next_device_id"], BACKUP)
        parking = lost["parking"]
        self.assertEqual(parking["custodian_device_id"], EDGE_SOUTH)
        self.assertEqual(parking["region"], "south")
        self.assertIn("next_channel_unreachable", parking["reason"])
        self.assertIsNone(one(
            self.db, "SELECT 1 FROM sr_touches WHERE route_id='route-backup' AND device_id=?",
            (BACKUP,),
        ))

        view = sr.customer_view(self.db, "route-backup")
        self.assertEqual(view["parked_packet"]["id"], parking["id"])
        self.assertEqual(view["actual_device_path"][-1]["device_id"], EDGE_SOUTH)
        self.assertTrue(all(p["device_id"] != BACKUP for p in view["actual_device_path"]))

        early_resume = sr.resume_packet(self.db, {
            "parking_id": parking["id"], "recovery_token": lost["recovery_token"], "at": 245,
        })
        self.assertEqual(early_resume["decision"], "next_hop_still_unreachable")

        sr.set_device_reachability(self.db, {"id": BACKUP, "reachable": True})
        resumed = sr.resume_packet(self.db, {
            "parking_id": parking["id"], "recovery_token": lost["recovery_token"], "at": 250,
        })
        self.assertEqual(resumed["decision"], "resumed", resumed)
        to_backup = sr.advance_packet(self.db, {"route_id": "route-backup", "at": 260})
        self.assertEqual(to_backup["decision"], "forwarded")
        self.assertEqual(to_backup["device_id"], BACKUP)
        to_u = sr.advance_packet(self.db, {"route_id": "route-backup", "at": 270})
        self.assertEqual(to_u["decision"], "forwarded")
        self.assertEqual(to_u["device_id"], U)

        result = self.deliver("route-backup", "pkg-backup", at=280, receipt_id="receipt-backup")
        self.assertEqual(result["decision"], "delivered", result)
        self.assertIn(BACKUP, [p["device_id"] for p in result["customer_proof"]["actual_device_path"]])

    def test_cloud_resource_label_is_not_physical_location_evidence(self):
        device_id = "dev-label-only"
        sr.register_device(self.db, {"id": device_id, "kind": "agent", "cloud_label": "region-south"})
        recorded = sr.record_location(self.db, {
            "id": "loc-cloud-label", "device_id": device_id, "at": 200,
            "region": "south", "source_kind": "cloud_label", "independent": True,
        })
        self.assertEqual(recorded["decision"], "location_recorded")
        self.assertFalse(recorded["usable"])
        self.assertIsNone(sr._location_at(self.db, device_id, 200))

    def test_north_agent_self_report_is_not_independent_evidence(self):
        self.create_north(route_id="route-self-report", packet="pkg-self-report")
        self.auth("route-self-report")
        sr.add_evidence(self.db, {
            "id": "self-report-only-cipher", "route_id": "route-self-report",
            "device_id": NORTH, "at": 210, "claim": "ciphertext_only",
            "independent": False, "verifier": "north-agent-self-report",
            "payload": {"agent_says": "trust me"},
        })
        verdict = sr.evaluate_route(self.db, "route-self-report", at=220)
        self.assertFalse(verdict["production"])
        self.assertBlocker({"verdict": verdict}, "missing_independent_ciphertext_only_proof:dev-north-cache")

    def test_retired_next_handler_does_not_receive_forwarded_packet(self):
        ghost = "dev-ghost-relay"
        sr.register_device(self.db, {"id": ghost, "kind": "deregistered-relay", "certified": False})
        sr.record_location(self.db, {
            "id": "loc-ghost", "device_id": ghost, "at": 100, "region": "south",
            "site": "south-old-relay", "source_kind": "independent_dc_access_audit",
            "independent": True,
        })
        sr.create_route(self.db, {
            "id": "route-ghost", "contract_id": CONTRACT, "packet_id": "pkg-ghost",
            "target_uid": UID, "target_device_id": U, "at": 200,
            "hops": [
                {"seq": 1, "device_id": SOURCE, "visibility": "ciphertext", "key_control": "holds_root_key"},
                {"seq": 2, "device_id": ghost, "visibility": "ciphertext", "key_control": "no_key"},
                {"seq": 3, "device_id": U, "visibility": "plaintext", "key_control": "holds_authorized_key"},
            ],
        })
        self.auth("route-ghost")
        sr.add_evidence(self.db, {
            "id": "ev-ghost-key", "route_id": "route-ghost", "device_id": ghost,
            "at": 200, "claim": "no_key_release", "independent": True,
            "verifier": "kms_audit", "payload": {},
        })
        self.assertEqual(sr.activate_route(self.db, {"id": "route-ghost", "at": 210})["decision"], "production")
        sr.enqueue_packet(self.db, {
            "route_id": "route-ghost", "packet_id": "pkg-ghost",
            "custodian_device_id": SOURCE, "at": 200,
        })

        sr.rebuild_instance(self.db, {"old_device_id": ghost, "new_device_id": "dev-ghost-replacement"})
        stopped = sr.advance_packet(self.db, {"route_id": "route-ghost", "at": 220})
        self.assertEqual(stopped["decision"], "unknown_handler_packet_parked")
        self.assertEqual(stopped["parking"]["custodian_device_id"], SOURCE)
        self.assertIn("unknown_or_retired_next_handler", stopped["parking"]["reason"])
        self.assertIsNone(one(
            self.db, "SELECT 1 FROM sr_touches WHERE route_id='route-ghost' AND device_id=?", (ghost,)
        ))

    def test_north_key_holder_label_cannot_bypass_region_gate(self):
        hops = self.north_hops()
        for hop in hops:
            if hop["device_id"] == NORTH:
                hop["key_control"] = "holds_root_key"
                hop["key_holder"] = "north-agent-hsm"
        sr.create_route(self.db, {
            "id": "route-key-label-bypass", "contract_id": CONTRACT, "packet_id": "pkg-bypass",
            "target_uid": UID, "target_device_id": U, "at": 200, "hops": hops,
        })
        self.auth("route-key-label-bypass")
        verdict = sr.evaluate_route(self.db, "route-key-label-bypass", at=220)
        self.assertFalse(verdict["production"])
        self.assertBlocker({"verdict": verdict},
                           "key_holder_outside_authorized_region:dev-north-cache")

    def test_omitted_activation_timestamp_cannot_accept_expired_authorization(self):
        self.create_north(route_id="route-no-at")
        self.auth("route-no-at", at=0, valid_from=0, until=10)
        self.prove_north("route-no-at", "pkg-north")
        activated = sr.activate_route(self.db, {"id": "route-no-at"})
        self.assertEqual(activated["decision"], "activation_at_required")
        verdict = sr.evaluate_route(self.db, "route-no-at")
        self.assertFalse(verdict["production"])
        self.assertBlocker({"verdict": verdict}, "authorization_expired_or_inactive")

    def test_key_released_after_production_quarantines_and_stops_next_forward(self):
        self.create_north(route_id="route-post-key", packet="pkg-post-key")
        self.auth("route-post-key")
        self.prove_north("route-post-key", "pkg-post-key")
        self.assertEqual(
            sr.activate_route(self.db, {"id": "route-post-key", "at": 220})["decision"],
            "production",
        )
        sr.enqueue_packet(self.db, {
            "route_id": "route-post-key", "packet_id": "pkg-post-key",
            "custodian_device_id": SOURCE, "at": 200,
        })
        to_north = sr.advance_packet(self.db, {"route_id": "route-post-key", "at": 230})
        self.assertEqual(to_north["decision"], "forwarded")
        self.assertEqual(to_north["device_id"], NORTH)

        sr.request_key(self.db, {
            "request_id": "post-production-key", "route_id": "route-post-key",
            "key_id": "kek-regional-7", "device_id": NORTH, "at": 240,
        })
        resolved = sr.resolve_key_request(self.db, {
            "request_id": "post-production-key", "outcome": "released",
            "receipt_id": "late-kms-release", "receipt_at": 1_440,
            "independent": True, "evidence_source": "kms_audit",
        })
        self.assertEqual(resolved.get("enforcement"), "quarantined")
        self.assertEqual(resolved["parking"]["custodian_device_id"], NORTH)
        self.assertEqual(resolved["parking"]["status"], "quarantined")

        stopped = sr.advance_packet(self.db, {"route_id": "route-post-key", "at": 1_450})
        self.assertEqual(stopped["decision"], "route_not_production")
        self.assertTrue(stopped["verdict"]["violations"])
        self.assertIsNone(one(
            self.db,
            "SELECT 1 FROM sr_touches WHERE route_id='route-post-key' AND device_id=?",
            (EDGE_SOUTH,),
        ))

    def test_repack_from_unlisted_south_device_is_rejected(self):
        sr.create_route(self.db, {
            "id": "route-wrong-repacker", "contract_id": CONTRACT, "packet_id": "pkg-up-x",
            "target_uid": UID, "target_device_id": U, "route_kind": "repack", "at": 200,
            "hops": [
                {"seq": 1, "device_id": SOURCE, "key_control": "holds_root_key"},
                {"seq": 2, "device_id": REPACKER, "key_control": "holds_authorized_key"},
                {"seq": 3, "device_id": U, "key_control": "holds_authorized_key"},
            ],
        })
        self.auth("route-wrong-repacker", kind="repack", handlers=[REPACKER])
        result = sr.repack_packet(self.db, {
            "id": "repack-wrong", "route_id": "route-wrong-repacker", "at": 240,
            "device_id": EDGE_SOUTH, "new_packet_id": "pkg-down-x",
            "attestation_evidence_id": "whatever",
        })
        self.assertEqual(result["decision"], "repack_device_not_listed_in_authorization")

    def test_two_approved_paths_record_different_handlers_and_delivery_moments(self):
        # 路径 A：等待北区独立日志和密钥边界查清后，沿北区原始路径交付。
        self.create_north(route_id="route-choice-north", packet="pkg-choice-north", eta_seconds=1_800)
        self.auth("route-choice-north", auth_id="auth-choice-north")
        self.prove_north("route-choice-north", "pkg-choice-north")
        sr.activate_route(self.db, {"id": "route-choice-north", "at": 200})
        sr.enqueue_packet(self.db, {
            "route_id": "route-choice-north", "packet_id": "pkg-choice-north",
            "custodian_device_id": SOURCE, "at": 200,
        })
        for i, device in enumerate([NORTH, EDGE_SOUTH, U], 210):
            self.touch("route-choice-north", f"choice-north-{device}", device, 300 + i,
                       "pkg-choice-north")
        north_result = self.deliver("route-choice-north", "pkg-choice-north",
                                    at=3_000, receipt_id="receipt-choice-north")
        self.assertEqual(north_result["decision"], "delivered", north_result)

        # 路径 B：南区受托商再封装，不引入北区密钥控制，恢复更快但多一个保管主体。
        sr.create_route(self.db, {
            "id": "route-choice-repack", "contract_id": CONTRACT, "packet_id": "pkg-choice-up",
            "target_uid": UID, "target_device_id": U, "at": 200, "route_kind": "repack",
            "eta_seconds": 600,
            "hops": [
                {"seq": 1, "device_id": SOURCE, "role": "source", "visibility": "ciphertext",
                 "key_control": "holds_root_key"},
                {"seq": 2, "device_id": REPACKER, "role": "trusted_repackager",
                 "visibility": "ciphertext", "key_control": "holds_authorized_key"},
                {"seq": 3, "device_id": U, "role": "target", "visibility": "plaintext",
                 "key_control": "holds_authorized_key"},
            ],
        })
        self.auth("route-choice-repack", kind="repack", auth_id="auth-choice-repack",
                  handlers=[REPACKER])
        sr.activate_route(self.db, {"id": "route-choice-repack", "at": 220})
        sr.enqueue_packet(self.db, {
            "route_id": "route-choice-repack", "packet_id": "pkg-choice-up",
            "custodian_device_id": SOURCE, "at": 200,
        })
        sr.advance_packet(self.db, {"route_id": "route-choice-repack", "at": 230})
        sr.add_evidence(self.db, {
            "id": "ev-choice-repack", "route_id": "route-choice-repack",
            "device_id": REPACKER, "at": 240, "claim": "south_repack_attestation",
            "independent": True, "verifier": "enclave-attestation",
        })
        sr.repack_packet(self.db, {
            "id": "repack-choice", "route_id": "route-choice-repack", "at": 240,
            "device_id": REPACKER, "new_packet_id": "pkg-choice-down",
            "attestation_evidence_id": "ev-choice-repack",
        })
        sr.advance_packet(self.db, {"route_id": "route-choice-repack", "at": 250,
                                    "packet_id": "pkg-choice-down"})
        repack_result = self.deliver("route-choice-repack", "pkg-choice-down",
                                     at=1_200, receipt_id="receipt-choice-repack")
        self.assertEqual(repack_result["decision"], "delivered", repack_result)

        north_proof = north_result["customer_proof"]
        repack_proof = repack_result["customer_proof"]
        self.assertIn(NORTH, [h["device_id"] for h in north_proof["planned_device_path"]])
        self.assertNotIn(REPACKER, [h["device_id"] for h in north_proof["planned_device_path"]])
        self.assertIn(REPACKER, [h["device_id"] for h in repack_proof["planned_device_path"]])
        self.assertNotIn(NORTH, [h["device_id"] for h in repack_proof["planned_device_path"]])
        self.assertNotEqual(north_proof["route_commitment"], repack_proof["route_commitment"])
        self.assertGreater(north_proof["delivery_at"], repack_proof["delivery_at"])
        self.assertGreater(north_proof["eta_seconds"], repack_proof["eta_seconds"])
        self.assertEqual(north_proof["key_control"]["contract_key_holder"], "south-hsm")
        self.assertTrue(any(p["key_holder"] == "south-repacker-enclave"
                            for p in repack_proof["actual_device_path"]))


if __name__ == "__main__":
    unittest.main()
