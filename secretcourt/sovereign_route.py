"""可执行的区域路由、实际设备位置与中转密钥隔离庭。

这个模块不使用云资源标签代替司法辖区证据。一条可生产路线必须同时绑定：

* 客户合同版本与有效期；
* 物料 secret/generation；
* 目标实例 UID、重建代际和物理设备；
* 每一跳的实际设备位置、可见材料和密钥控制；
* 客户与合规方对原始路径、临时绕路或南区再封装的分别授权；
* 独立的传输日志、纯密文证明和 KMS/HSM 密钥边界证据；
* 与路线承诺哈希绑定的送达回执。

证据不足时，路线不会调用旧的 ``delivery.plan``，而是把包停在已知保管设备内
的可恢复停放位。确认北区取得密钥等硬性越界则隔离，而不是继续投递。

纯密文中转至少需要四类相互独立的证据：

1. 数据中心准入、硬件证明或运营商路径审计给出的 *实际设备位置*；云标签不可用；
2. 与包摘要一致的传输/缓存日志；
3. 远程飞地、进程或流量审计给出的 ``ciphertext_only`` 证明，代理自述不算；
4. KMS/HSM/密钥代理审计给出的无密钥释放记录；若存在密钥请求，则必须有最终
   ``released``/``denied`` 回执，pending 本身即阻断生产。
"""
from __future__ import annotations

import hashlib
import json

from . import delivery
from .store import one, rows

SOUTH = "south"
NORTH = "north"

CLOUD_LABEL_SOURCES = {"cloud_label", "cloud-tag", "resource-label", "cloud_resource_tag"}
INDEPENDENT_KEY_SOURCES = {
    "kms_audit",
    "hsm_audit",
    "key_broker_audit",
    "independent_key_log",
    "independent_kms_audit",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS sr_contracts(
  id TEXT PRIMARY KEY, customer TEXT, contract_version TEXT, secret TEXT, gen INTEGER,
  plaintext_region TEXT, ciphertext_regions TEXT, key_regions TEXT, key_id TEXT,
  key_holder TEXT, valid_from INTEGER, valid_until INTEGER, commitment TEXT, payload TEXT
);
CREATE TABLE IF NOT EXISTS sr_devices(
  id TEXT PRIMARY KEY, kind TEXT, cloud_label TEXT, certified INTEGER,
  certified_class TEXT, certified_until INTEGER, reachable INTEGER, status TEXT, payload TEXT
);
CREATE TABLE IF NOT EXISTS sr_locations(
  id TEXT PRIMARY KEY, device_id TEXT, at INTEGER, region TEXT, site TEXT,
  source_kind TEXT, independent INTEGER, usable INTEGER, digest TEXT, payload TEXT
);
CREATE TABLE IF NOT EXISTS sr_evidence(
  id TEXT PRIMARY KEY, route_id TEXT, at INTEGER, device_id TEXT, kind TEXT,
  claim TEXT, independent INTEGER, verifier TEXT, digest TEXT, payload TEXT
);
CREATE TABLE IF NOT EXISTS sr_key_requests(
  request_id TEXT PRIMARY KEY, route_id TEXT, key_id TEXT, device_id TEXT,
  principal TEXT, requested_at INTEGER, status TEXT, outcome TEXT, receipt_id TEXT,
  receipt_at INTEGER, late_seconds INTEGER, evidence_source TEXT, independent INTEGER,
  digest TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS sr_authorizations(
  id TEXT PRIMARY KEY, route_id TEXT, kind TEXT, customer_actor TEXT,
  compliance_actor TEXT, issued_at INTEGER, valid_from INTEGER, valid_until INTEGER,
  path_commitment TEXT, handlers TEXT, terms TEXT, commitment TEXT, status TEXT
);
CREATE TABLE IF NOT EXISTS sr_routes(
  id TEXT PRIMARY KEY, contract_id TEXT, secret TEXT, gen INTEGER, grant_id TEXT,
  identity_generation INTEGER, target_uid TEXT, target_generation INTEGER,
  target_device_id TEXT, plan_id TEXT, permit_id TEXT, key_id TEXT, key_holder TEXT,
  initial_packet TEXT, final_packet TEXT, route_kind TEXT, status TEXT,
  commitment TEXT, created_at INTEGER, eta_seconds INTEGER, blocker TEXT, parking_id TEXT
);
CREATE TABLE IF NOT EXISTS sr_route_hops(
  route_id TEXT, seq INTEGER, device_id TEXT, role TEXT, visibility TEXT,
  key_control TEXT, key_holder TEXT, authorization_id TEXT,
  PRIMARY KEY(route_id, seq)
);
CREATE TABLE IF NOT EXISTS sr_touches(
  id TEXT PRIMARY KEY, route_id TEXT, seq INTEGER, at INTEGER, device_id TEXT,
  packet_id TEXT, action TEXT, visibility TEXT, key_holder TEXT,
  evidence_id TEXT, digest TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS sr_packets(
  packet_id TEXT PRIMARY KEY, route_id TEXT, parent_packet TEXT, gen INTEGER,
  state TEXT, current_device_id TEXT, parking_id TEXT, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS sr_parked(
  id TEXT PRIMARY KEY, route_id TEXT, packet_id TEXT, at INTEGER,
  custodian_device_id TEXT, region TEXT, site TEXT, reason TEXT, status TEXT,
  recovery_token TEXT, resumed_at INTEGER, resolution TEXT
);
CREATE TABLE IF NOT EXISTS sr_repacks(
  id TEXT PRIMARY KEY, route_id TEXT, at INTEGER, device_id TEXT, old_packet TEXT,
  new_packet TEXT, gen INTEGER, attestation_evidence_id TEXT,
  attestation_digest TEXT, commitment TEXT
);
CREATE TABLE IF NOT EXISTS sr_receipts(
  id TEXT PRIMARY KEY, route_id TEXT, at INTEGER, target_uid TEXT,
  target_generation INTEGER, target_device_id TEXT, packet_id TEXT,
  route_commitment TEXT, attestation_digest TEXT, location_evidence_id TEXT,
  verified INTEGER, result TEXT
);
"""


def ensure_schema(db):
    db.executescript(SCHEMA)


def _json(value, default):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return default
    return value if value is not None else default


def _digest(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _missing_fields(payload, fields):
    return [name for name in fields if payload.get(name) in (None, "")]


def _location_at(db, device_id, at):
    if at is None:
        return one(
            db,
            "SELECT * FROM sr_locations WHERE device_id=? AND usable=1 ORDER BY at DESC, rowid DESC LIMIT 1",
            (device_id,),
        )
    return one(
        db,
        """SELECT * FROM sr_locations
           WHERE device_id=? AND usable=1 AND at<=?
           ORDER BY at DESC, rowid DESC LIMIT 1""",
        (device_id, at),
    )


def _device(db, device_id):
    return one(db, "SELECT * FROM sr_devices WHERE id=?", (device_id,))


def _active_parking(db, route_id):
    return one(
        db,
        """SELECT * FROM sr_parked
           WHERE route_id=? AND status IN ('parked','quarantined')
           ORDER BY rowid DESC LIMIT 1""",
        (route_id,),
    )


def _parking_view(row):
    if not row:
        return None
    return {
        "id": row["id"],
        "parking_id": row["id"],
        "route_id": row["route_id"],
        "packet_id": row["packet_id"],
        "at": row["at"],
        "custodian_device_id": row["custodian_device_id"],
        "region": row["region"],
        "site": row["site"],
        "reason": row["reason"],
        "status": row["status"],
        "resumed_at": row["resumed_at"],
        "resolution": row["resolution"],
    }


def _park(db, route_id, packet_id, at, device_id, reason, status="parked", parking_id=None,
          keep_route_status=False):
    """把包停在已知设备；同一设备的旧占位会被新占位取代。"""
    ensure_schema(db)
    at = 0 if at is None else at
    active = one(
        db,
        """SELECT * FROM sr_parked
           WHERE route_id IS ? AND packet_id=? AND status IN ('parked','quarantined')
           ORDER BY rowid DESC LIMIT 1""",
        (route_id, packet_id),
    )
    if active and active["custodian_device_id"] == device_id and active["reason"] == reason:
        return dict(active)
    if active:
        db.execute(
            "UPDATE sr_parked SET status='superseded', resumed_at=?, resolution=? WHERE id=?",
            (at, "superseded_by_new_parking", active["id"]),
        )

    count = one(db, "SELECT COUNT(*) n FROM sr_parked", ())["n"]
    pid = parking_id or f"park:{route_id or 'global'}:{packet_id}:{count + 1}"
    token = "recovery-" + _digest({"id": pid, "packet": packet_id, "route": route_id})[7:31]
    device = _device(db, device_id) if device_id else None
    location = _location_at(db, device_id, at) if device_id else None
    region = location["region"] if location else "location-unverified"
    site = location["site"] if location else (device["kind"] if device else "unknown-custodian")

    db.execute(
        """INSERT INTO sr_parked(id, route_id, packet_id, at, custodian_device_id,
           region, site, reason, status, recovery_token, resumed_at, resolution)
           VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL)""",
        (pid, route_id, packet_id, at, device_id, region, site, reason, status, token),
    )
    if one(db, "SELECT 1 FROM sr_packets WHERE packet_id=?", (packet_id,)):
        db.execute(
            "UPDATE sr_packets SET state=?, current_device_id=?, parking_id=? WHERE packet_id=?",
            ("quarantined" if status == "quarantined" else "parked", device_id, pid, packet_id),
        )
    if route_id and one(db, "SELECT 1 FROM sr_routes WHERE id=?", (route_id,)):
        if status == "quarantined":
            db.execute(
                "UPDATE sr_routes SET status='blocked', blocker=?, parking_id=? WHERE id=?",
                (reason, pid, route_id),
            )
        elif keep_route_status:
            db.execute("UPDATE sr_routes SET parking_id=? WHERE id=?", (pid, route_id))
        else:
            db.execute(
                "UPDATE sr_routes SET status='parked', blocker=?, parking_id=? WHERE id=?",
                (reason, pid, route_id),
            )
    return one(db, "SELECT * FROM sr_parked WHERE id=?", (pid,))


# ---------------------------------------------------------------------------
# 基础证据登记
# ---------------------------------------------------------------------------

def bind_contract(db, c):
    ensure_schema(db)
    missing = _missing_fields(c, ["id", "customer", "contract_version", "secret", "valid_until"])
    if missing:
        return {"decision": "invalid_contract", "missing": missing}

    valid_from = c.get("valid_from", c.get("at", 0))
    valid_until = c["valid_until"]
    if valid_until <= valid_from:
        return {"decision": "invalid_contract", "reason": "valid_until_must_follow_valid_from"}

    contract = {
        "id": c["id"],
        "customer": c["customer"],
        "contract_version": str(c["contract_version"]),
        "secret": c["secret"],
        "gen": int(c.get("gen", c.get("generation", 1))),
        "plaintext_region": c.get("plaintext_region", SOUTH),
        "ciphertext_regions": sorted(set(c.get("ciphertext_regions", [SOUTH, NORTH]))),
        "key_regions": sorted(set(c.get("key_regions", [c.get("plaintext_region", SOUTH)]))),
        "key_id": c.get("key_id", f"key-{c['secret']}-{c.get('gen', c.get('generation', 1))}"),
        "key_holder": c.get("key_holder", "south-hsm"),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "terms": c.get("terms", {}),
    }
    commitment = _digest(contract)
    old = one(db, "SELECT * FROM sr_contracts WHERE id=?", (contract["id"],))
    if old:
        if old["commitment"] == commitment:
            return {"decision": "reused", "id": old["id"], "commitment": commitment}
        return {"decision": "contract_identity_conflict", "id": contract["id"]}

    db.execute(
        """INSERT INTO sr_contracts(id,customer,contract_version,secret,gen,
           plaintext_region,ciphertext_regions,key_regions,key_id,key_holder,
           valid_from,valid_until,commitment,payload)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            contract["id"], contract["customer"], contract["contract_version"],
            contract["secret"], contract["gen"], contract["plaintext_region"],
            json.dumps(contract["ciphertext_regions"]),
            json.dumps(contract["key_regions"]), contract["key_id"],
            contract["key_holder"], contract["valid_from"], contract["valid_until"],
            commitment, json.dumps(contract, sort_keys=True, ensure_ascii=False),
        ),
    )
    return {"decision": "contract_bound", "id": contract["id"], "commitment": commitment}


def register_device(db, d):
    ensure_schema(db)
    if not d.get("id") or not d.get("kind"):
        return {"decision": "invalid_device", "missing": _missing_fields(d, ["id", "kind"])}
    device_id = d["id"]
    certified = 1 if d.get("certified") else 0
    reachable = 0 if d.get("reachable") is False or d.get("reachable") == 0 else 1
    certified_until = d.get("certified_until", 10**12)
    core = (
        d["kind"], d.get("cloud_label"), certified, d.get("certified_class"),
        certified_until, d.get("status", "active"),
    )
    old = _device(db, device_id)
    if old:
        old_core = (
            old["kind"], old["cloud_label"], old["certified"], old["certified_class"],
            old["certified_until"], old["status"],
        )
        if old_core == core:
            return {"decision": "reused", "id": device_id}
        return {"decision": "device_identity_conflict", "id": device_id}

    db.execute(
        """INSERT INTO sr_devices(id,kind,cloud_label,certified,certified_class,
           certified_until,reachable,status,payload) VALUES(?,?,?,?,?,?,?,?,?)""",
        (
            device_id, d["kind"], d.get("cloud_label"), certified,
            d.get("certified_class", "sovereign-plaintext-enclave"), certified_until,
            reachable, d.get("status", "active"),
            json.dumps(d, sort_keys=True, ensure_ascii=False, default=str),
        ),
    )
    return {"decision": "device_registered", "id": device_id, "reachable": bool(reachable)}


def set_device_reachability(db, d):
    ensure_schema(db)
    device_id = d.get("device_id") or d.get("id")
    device = _device(db, device_id)
    if not device:
        return {"decision": "unknown_device", "device_id": device_id}
    reachable = 1 if d.get("reachable") else 0
    db.execute("UPDATE sr_devices SET reachable=? WHERE id=?", (reachable, device_id))
    return {"decision": "reachability_observed", "device_id": device_id, "reachable": bool(reachable)}


def rebuild_instance(db, c):
    """把实例标记为重建；不复制旧设备的物理位置证据。"""
    ensure_schema(db)
    old_id = c.get("old_device_id") or c.get("device_id") or c.get("old_device")
    new_id = c.get("new_device_id") or c.get("new_device")
    old = _device(db, old_id)
    if not old or not new_id:
        return {"decision": "unknown_device_or_new_id_required"}
    at = c.get("at", 0)
    db.execute("UPDATE sr_devices SET status='rebuilt', reachable=0 WHERE id=?", (old_id,))
    if not _device(db, new_id):
        db.execute(
            """INSERT INTO sr_devices(id,kind,cloud_label,certified,certified_class,
               certified_until,reachable,status,payload) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                new_id, "instance", old["cloud_label"], old["certified"],
                old["certified_class"], old["certified_until"], 1, "active",
                json.dumps({"rebuilt_from": old_id, "at": at}, sort_keys=True),
            ),
        )
    return {
        "decision": "instance_rebuilt",
        "old_device_id": old_id,
        "new_device_id": new_id,
        "new_generation": int(c.get("new_generation", c.get("generation", 2))),
        "physical_location_evidence_required": True,
        "cloud_label_not_reused_as_location": True,
    }


def record_location(db, e):
    ensure_schema(db)
    missing = _missing_fields(e, ["id", "device_id", "at", "region"])
    if missing:
        return {"decision": "invalid_location_evidence", "missing": missing}
    source_kind = e.get("source_kind", "unspecified")
    independent = bool(e.get("independent")) and source_kind not in CLOUD_LABEL_SOURCES
    core = {
        "device_id": e["device_id"], "at": e["at"], "region": e["region"],
        "site": e.get("site"), "source_kind": source_kind, "independent": independent,
    }
    digest = e.get("digest") or _digest(core)
    old = one(db, "SELECT * FROM sr_locations WHERE id=?", (e["id"],))
    if old:
        return {"decision": "reused" if old["digest"] == digest else "location_evidence_conflict"}

    db.execute(
        """INSERT INTO sr_locations(id,device_id,at,region,site,source_kind,
           independent,usable,digest,payload) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (
            e["id"], e["device_id"], e["at"], e["region"], e.get("site"),
            source_kind, 1 if independent else 0, 1 if independent else 0,
            digest, json.dumps(e, sort_keys=True, ensure_ascii=False, default=str),
        ),
    )
    return {"decision": "location_recorded", "id": e["id"], "usable": independent}


def add_evidence(db, e):
    ensure_schema(db)
    missing = _missing_fields(e, ["id", "route_id"])
    if missing:
        return {"decision": "invalid_evidence", "missing": missing}
    claim = e.get("claim") or e.get("kind") or "unclassified"
    core = {
        "route_id": e["route_id"], "at": e.get("at", 0), "device_id": e.get("device_id"),
        "kind": e.get("kind", "independent_log"), "claim": claim,
        "independent": bool(e.get("independent")), "verifier": e.get("verifier"),
        "payload": e.get("payload", {}),
    }
    digest = e.get("digest") or _digest(core)
    old = one(db, "SELECT * FROM sr_evidence WHERE id=?", (e["id"],))
    if old:
        return {"decision": "reused" if old["digest"] == digest else "evidence_identity_conflict"}
    db.execute(
        """INSERT INTO sr_evidence(id,route_id,at,device_id,kind,claim,independent,
           verifier,digest,payload) VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (
            e["id"], e["route_id"], e.get("at", 0), e.get("device_id"),
            e.get("kind", "independent_log"), claim,
            1 if e.get("independent") else 0, e.get("verifier"), digest,
            json.dumps(e.get("payload", {}), sort_keys=True, ensure_ascii=False, default=str),
        ),
    )
    return {"decision": "evidence_recorded", "id": e["id"], "claim": claim}


def request_key(db, e):
    ensure_schema(db)
    request_id = e.get("request_id") or e.get("id")
    if not request_id or not e.get("device_id") or e.get("at") is None:
        return {"decision": "invalid_key_request"}
    old = one(db, "SELECT * FROM sr_key_requests WHERE request_id=?", (request_id,))
    if old:
        return {"decision": "reused" if (old["device_id"], old["requested_at"], old["key_id"]) == (e["device_id"], e["at"], e.get("key_id", old["key_id"])) else "key_request_conflict"}
    db.execute(
        """INSERT INTO sr_key_requests(request_id,route_id,key_id,device_id,principal,
           requested_at,status,outcome,receipt_id,receipt_at,late_seconds,
           evidence_source,independent,digest,detail)
           VALUES(?,?,?,?,?,?,'pending',NULL,NULL,NULL,NULL,NULL,0,NULL,?)""",
        (
            request_id, e.get("route_id"), e.get("key_id"), e["device_id"],
            e.get("principal"), e["at"],
            json.dumps(e.get("detail", {}), sort_keys=True, default=str),
        ),
    )
    return {"decision": "key_requested", "request_id": request_id, "status": "pending"}


def resolve_key_request(db, e):
    ensure_schema(db)
    request_id = e.get("request_id") or e.get("id")
    req = one(db, "SELECT * FROM sr_key_requests WHERE request_id=?", (request_id,))
    if not req:
        return {"decision": "unknown_key_request", "request_id": request_id}
    if req["status"] != "pending":
        same = (
            req["outcome"] == e.get("outcome")
            and req["receipt_id"] == e.get("receipt_id")
            and req["receipt_at"] == e.get("receipt_at")
        )
        return {"decision": "reused" if same else "key_receipt_conflict"}

    source = e.get("evidence_source") or e.get("source_kind")
    independent = bool(e.get("independent"))
    if e.get("outcome") not in ("released", "denied") or not e.get("receipt_id") or e.get("receipt_at") is None:
        return {"decision": "invalid_key_receipt"}
    if not independent or source not in INDEPENDENT_KEY_SOURCES:
        return {
            "decision": "missing_independent_key_receipt",
            "request_id": request_id,
            "required_sources": sorted(INDEPENDENT_KEY_SOURCES),
        }

    late_seconds = max(0, int(e["receipt_at"]) - int(req["requested_at"]))
    digest = e.get("digest") or _digest(e)
    db.execute(
        """UPDATE sr_key_requests SET status='resolved', outcome=?, receipt_id=?,
           receipt_at=?, late_seconds=?, evidence_source=?, independent=1, digest=?
           WHERE request_id=?""",
        (e["outcome"], e["receipt_id"], e["receipt_at"], late_seconds, source, digest, request_id),
    )
    result = {
        "decision": "key_request_resolved",
        "request_id": request_id,
        "outcome": e["outcome"],
        "late_seconds": late_seconds,
        "late_minutes": round(late_seconds / 60, 2),
    }
    if req["route_id"]:
        route = one(db, "SELECT * FROM sr_routes WHERE id=?", (req["route_id"],))
        if route and route["status"] != "delivered":
            verdict = evaluate_route(
                db, req["route_id"], at=e.get("at", e["receipt_at"]), stage="production"
            )
            result["route_production_allowed"] = verdict["production"]
            if not verdict["production"]:
                stopped = _stop_for_verdict(
                    db, route, verdict, e.get("at", e["receipt_at"])
                )
                result["enforcement"] = "quarantined" if verdict["violations"] else "parked"
                result["parking"] = _parking_view(stopped)
    return result


# ---------------------------------------------------------------------------
# 路线与授权
# ---------------------------------------------------------------------------

_ROUTE_KINDS = {
    "original": "original",
    "original_path": "original",
    "north_verified": "original",
    "repack": "repack",
    "south_repack": "repack",
    "detour": "detour",
    "temporary_detour": "detour",
}


def create_route(db, r):
    ensure_schema(db)
    route_id = r.get("id") or r.get("route_id")
    contract_id = r.get("contract_id")
    contract = one(db, "SELECT * FROM sr_contracts WHERE id=?", (contract_id,)) if contract_id else None
    target_uid = r.get("target_uid") or r.get("uid")
    target_device = r.get("target_device_id") or r.get("target_device") or r.get("device_id")
    raw_hops = r.get("hops") or r.get("path") or []
    if not route_id or not contract or not target_uid or not target_device or not raw_hops:
        return {
            "decision": "invalid_route",
            "missing": _missing_fields(
                {"id": route_id, "contract_id": contract_id, "target_uid": target_uid,
                 "target_device": target_device, "hops": raw_hops},
                ["id", "contract_id", "target_uid", "target_device", "hops"],
            ),
        }

    secret = r.get("secret", contract["secret"])
    gen = int(r.get("gen", contract["gen"]))
    if secret != contract["secret"] or gen != contract["gen"]:
        return {"decision": "route_contract_material_conflict"}

    route_kind = _ROUTE_KINDS.get(r.get("route_kind", r.get("kind", "original")), "original")
    target_generation = int(r.get("target_generation", r.get("instance_generation", 1)))
    identity_generation = int(r.get("identity_generation", target_generation))
    created_at = r.get("at", 0)
    hops = []
    commitment_hops = []
    for index, h in enumerate(raw_hops, 1):
        device_id = h.get("device_id") or h.get("device") or h.get("id")
        if not device_id:
            return {"decision": "invalid_route_hop", "hop": index}
        visibility = h.get("visibility") or h.get("sees") or "ciphertext"
        key_control = h.get("key_control") or (
            "holds_authorized_key" if visibility == "plaintext" else "no_key"
        )
        hop = {
            "seq": int(h.get("seq", index)),
            "device_id": device_id,
            "role": h.get("role", "relay"),
            "visibility": visibility,
            "key_control": key_control,
            "key_holder": h.get("key_holder") or (
                "authorized-local-enclave" if key_control == "holds_authorized_key" else contract["key_holder"]
            ),
            "authorization_id": h.get("authorization_id"),
        }
        hops.append(hop)
        location = _location_at(db, device_id, created_at)
        commitment_hop = dict(hop)
        commitment_hop["actual_location_at_commitment"] = None if not location else {
            "evidence_id": location["id"],
            "at": location["at"],
            "region": location["region"],
            "site": location["site"],
            "source_kind": location["source_kind"],
            "digest": location["digest"],
        }
        commitment_hops.append(commitment_hop)
    hops.sort(key=lambda h: h["seq"])
    commitment_hops.sort(key=lambda h: h["seq"])

    route_identity = {
        "route_id": route_id,
        "contract_commitment": contract["commitment"],
        "customer": contract["customer"],
        "contract_version": contract["contract_version"],
        "secret": secret,
        "gen": gen,
        "grant_id": r.get("grant_id"),
        "identity_generation": identity_generation,
        "target": {
            "uid": target_uid,
            "generation": target_generation,
            "device_id": target_device,
        },
        "plan_id": r.get("plan_id"),
        "permit_id": r.get("permit_id"),
        "packet_id": r.get("packet_id"),
        "route_kind": route_kind,
        "eta_seconds": r.get("eta_seconds"),
        "hops": commitment_hops,
    }
    commitment = r.get("commitment") or _digest(route_identity)
    old = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,))
    if old:
        if old["commitment"] == commitment:
            return {"decision": "reused", "route_id": route_id, "commitment": commitment}
        return {"decision": "route_identity_conflict", "route_id": route_id}

    at = r.get("at", 0)
    db.execute(
        """INSERT INTO sr_routes(id,contract_id,secret,gen,grant_id,identity_generation,
           target_uid,target_generation,target_device_id,plan_id,permit_id,key_id,
           key_holder,initial_packet,final_packet,route_kind,status,commitment,
           created_at,eta_seconds,blocker,parking_id)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'draft',?,?,?,NULL,NULL)""",
        (
            route_id, contract_id, secret, gen, r.get("grant_id"), identity_generation,
            target_uid, target_generation, target_device, r.get("plan_id"), r.get("permit_id"),
            contract["key_id"], contract["key_holder"], r.get("packet_id"),
            r.get("final_packet", r.get("packet_id")), route_kind, commitment, at,
            r.get("eta_seconds"),
        ),
    )
    db.executemany(
        """INSERT INTO sr_route_hops(route_id,seq,device_id,role,visibility,
           key_control,key_holder,authorization_id) VALUES(?,?,?,?,?,?,?,?)""",
        [(route_id, h["seq"], h["device_id"], h["role"], h["visibility"],
          h["key_control"], h["key_holder"], h["authorization_id"]) for h in hops],
    )

    parking = None
    if r.get("enqueue"):
        enqueued = enqueue_packet(db, {
            "route_id": route_id,
            "packet_id": r["packet_id"],
            "custodian_device_id": r.get("origin_device_id", hops[0]["device_id"]),
            "at": at,
            "reason": "enqueued_recoverable_slot",
        })
        parking = enqueued.get("parking")
    return {
        "decision": "route_created",
        "route_id": route_id,
        "status": "draft",
        "commitment": commitment,
        "parking": _parking_view(parking) if parking else None,
    }


def authorize(db, a):
    ensure_schema(db)
    auth_id = a.get("id") or a.get("authorization_id")
    route_id = a.get("route_id")
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,)) if route_id else None
    if not auth_id or not route:
        return {"decision": "unknown_route_or_authorization"}

    customer_actor = a.get("customer_actor") or a.get("customer")
    compliance_actor = a.get("compliance_actor") or a.get("compliance")
    for approval in a.get("approvals", []):
        if approval.get("role") == "customer":
            customer_actor = customer_actor or approval.get("actor")
        if approval.get("role") == "compliance":
            compliance_actor = compliance_actor or approval.get("actor")
    if not customer_actor or not compliance_actor:
        return {"decision": "customer_and_compliance_approval_required"}

    issued_at = a.get("at", a.get("issued_at"))
    valid_from = a.get("valid_from", issued_at)
    valid_until = a.get("valid_until")
    if issued_at is None or valid_until is None or valid_until <= valid_from:
        return {"decision": "invalid_authorization_validity"}

    path_commitment = a.get("path_commitment") or route["commitment"]
    if path_commitment != route["commitment"]:
        return {"decision": "authorization_route_commitment_mismatch"}

    kind = a.get("kind", "original_path")
    auth_body = {
        "id": auth_id,
        "route_id": route_id,
        "kind": kind,
        "customer_actor": customer_actor,
        "compliance_actor": compliance_actor,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "path_commitment": path_commitment,
        "handlers": sorted(a.get("handlers", [])),
        "terms": a.get("terms", {}),
    }
    commitment = _digest(auth_body)
    old = one(db, "SELECT * FROM sr_authorizations WHERE id=?", (auth_id,))
    if old:
        return {"decision": "reused" if old["commitment"] == commitment else "authorization_identity_conflict"}

    db.execute(
        """INSERT INTO sr_authorizations(id,route_id,kind,customer_actor,compliance_actor,
           issued_at,valid_from,valid_until,path_commitment,handlers,terms,commitment,status)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            auth_id, route_id, kind, customer_actor, compliance_actor, issued_at,
            valid_from, valid_until, path_commitment,
            json.dumps(auth_body["handlers"]), json.dumps(auth_body["terms"], sort_keys=True),
            commitment, a.get("status", "approved"),
        ),
    )
    return {"decision": "authorized", "id": auth_id, "kind": kind, "commitment": commitment}


# ---------------------------------------------------------------------------
# 包入队、实际接触、停放与恢复
# ---------------------------------------------------------------------------

def enqueue_packet(db, p):
    ensure_schema(db)
    packet_id = p.get("packet_id") or p.get("id")
    route_id = p.get("route_id")
    device_id = p.get("custodian_device_id") or p.get("origin_device_id") or p.get("device_id")
    at = p.get("at", 0)
    if not packet_id or not device_id:
        return {"decision": "invalid_packet"}
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,)) if route_id else None
    if route and packet_id not in (route["initial_packet"], route["final_packet"]):
        return {"decision": "packet_route_mismatch"}

    old = one(db, "SELECT * FROM sr_packets WHERE packet_id=?", (packet_id,))
    if old:
        parking = _active_parking(db, route_id) if route_id else None
        return {"decision": "reused", "packet_id": packet_id, "parking": _parking_view(parking)}

    gen = p.get("gen", route["gen"] if route else 1)
    db.execute(
        """INSERT INTO sr_packets(packet_id,route_id,parent_packet,gen,state,
           current_device_id,parking_id,created_at) VALUES(?,?,?,?, 'queued', ?,NULL,?)""",
        (packet_id, route_id, p.get("parent_packet"), gen, device_id, at),
    )
    parked = _park(
        db, route_id, packet_id, at, device_id,
        p.get("reason", "enqueued_recoverable_slot"), status="parked",
        parking_id=p.get("parking_id"), keep_route_status=True,
    )
    touch_id = f"enqueue:{packet_id}"
    if route_id and not one(db, "SELECT 1 FROM sr_touches WHERE id=?", (touch_id,)):
        first_hop = one(
            db, "SELECT seq,visibility,key_holder FROM sr_route_hops WHERE route_id=? ORDER BY seq LIMIT 1",
            (route_id,),
        )
        db.execute(
            """INSERT INTO sr_touches(id,route_id,seq,at,device_id,packet_id,action,
               visibility,key_holder,evidence_id,digest,detail)
               VALUES(?,?,?,?,?,?, 'enqueued',?,?,NULL,?, '{}')""",
            (
                touch_id, route_id, first_hop["seq"] if first_hop else None, at,
                device_id, packet_id,
                first_hop["visibility"] if first_hop else "ciphertext",
                first_hop["key_holder"] if first_hop else "south-hsm",
                _digest({"enqueued": packet_id, "at": at}),
            ),
        )
    return {"decision": "enqueued", "packet_id": packet_id, "parking": _parking_view(parked)}


def park_packet(db, p):
    ensure_schema(db)
    route_id = p.get("route_id")
    packet_id = p.get("packet_id")
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,)) if route_id else None
    if route and not packet_id:
        packet_id = route["final_packet"] or route["initial_packet"]
    device_id = p.get("custodian_device_id") or p.get("device_id")
    if not device_id:
        packet = one(db, "SELECT * FROM sr_packets WHERE packet_id=?", (packet_id,)) if packet_id else None
        device_id = packet["current_device_id"] if packet else None
        if not device_id and route:
            first = one(db, "SELECT device_id FROM sr_route_hops WHERE route_id=? ORDER BY seq LIMIT 1", (route_id,))
            device_id = first["device_id"] if first else None
    if not packet_id or not device_id:
        return {"decision": "unknown_parking_target"}
    row = _park(
        db, route_id, packet_id, p.get("at", 0), device_id,
        p.get("reason", "manual_park"), status=p.get("status", "parked"),
        parking_id=p.get("parking_id"),
    )
    return {"decision": "parked", "parking": _parking_view(row), "recovery_token": row["recovery_token"]}


def resume_packet(db, p):
    ensure_schema(db)
    parking_id = p.get("parking_id") or p.get("id")
    token = p.get("recovery_token") or p.get("token")
    parking = one(db, "SELECT * FROM sr_parked WHERE id=?", (parking_id,))
    if not parking:
        return {"decision": "unknown_parking", "parking_id": parking_id}
    if parking["status"] in ("resumed", "released", "recovered_to_route"):
        return {"decision": "reused", "status": parking["status"]}
    if parking["status"] == "quarantined":
        return {"decision": "parking_quarantined_rotation_required", "parking": _parking_view(parking)}
    if parking["recovery_token"] != token:
        return {"decision": "invalid_recovery_token"}

    at = p.get("at", parking["at"])
    verdict = evaluate_route(db, parking["route_id"], at=at, stage="production")
    if not verdict["production"]:
        return {"decision": "still_blocked", "parking": _parking_view(parking), "verdict": verdict}

    packet = one(db, "SELECT * FROM sr_packets WHERE packet_id=?", (parking["packet_id"],))
    if packet:
        hops = rows(
            db, "SELECT * FROM sr_route_hops WHERE route_id=? ORDER BY seq",
            (parking["route_id"],),
        )
        current_index = next((i for i, h in enumerate(hops) if h["device_id"] == packet["current_device_id"]), -1)
        if 0 <= current_index < len(hops) - 1:
            next_device = _device(db, hops[current_index + 1]["device_id"])
            if not next_device or next_device["status"] != "active" or not next_device["reachable"]:
                return {
                    "decision": "next_hop_still_unreachable",
                    "next_device_id": hops[current_index + 1]["device_id"],
                    "parking": _parking_view(parking),
                }

    db.execute(
        "UPDATE sr_parked SET status='resumed', resumed_at=?, resolution='resumed_same_route' WHERE id=?",
        (at, parking_id),
    )
    db.execute(
        "UPDATE sr_packets SET state='in_transit' WHERE packet_id=?",
        (parking["packet_id"],),
    )
    db.execute("UPDATE sr_routes SET status='production' WHERE id=?", (parking["route_id"],))
    return {"decision": "resumed", "parking_id": parking_id, "route_id": parking["route_id"], "verdict": verdict}


def recover_to_route(db, p):
    """从旧路线的可恢复停放位改挂到已批准的新路线（例如实例重建后）。"""
    ensure_schema(db)
    parking_id = p.get("parking_id") or p.get("id")
    token = p.get("recovery_token") or p.get("token")
    new_route_id = p.get("new_route_id") or p.get("route_id")
    at = p.get("at")
    parking = one(db, "SELECT * FROM sr_parked WHERE id=?", (parking_id,))
    new_route = one(db, "SELECT * FROM sr_routes WHERE id=?", (new_route_id,))
    if not parking or not new_route:
        return {"decision": "unknown_parking_or_route"}
    if parking["status"] != "parked":
        return {"decision": "parking_not_recoverable", "status": parking["status"]}
    if parking["recovery_token"] != token:
        return {"decision": "invalid_recovery_token"}

    at = at if at is not None else parking["at"]
    verdict = evaluate_route(db, new_route_id, at=at, stage="production")
    if not verdict["production"]:
        return {"decision": "replacement_route_not_ready", "verdict": verdict}

    db.execute(
        "UPDATE sr_parked SET status='recovered_to_route', resumed_at=?, resolution=? WHERE id=?",
        (at, new_route_id, parking_id),
    )
    db.execute(
        "UPDATE sr_packets SET route_id=?, state='in_transit', current_device_id=? WHERE packet_id=?",
        (new_route_id, parking["custodian_device_id"], parking["packet_id"]),
    )
    db.execute("UPDATE sr_routes SET status='production' WHERE id=?", (new_route_id,))
    recovery_touch = f"recover:{parking_id}"
    if not one(db, "SELECT 1 FROM sr_touches WHERE id=?", (recovery_touch,)):
        first_hop = one(
            db, "SELECT seq,visibility,key_holder FROM sr_route_hops WHERE route_id=? ORDER BY seq LIMIT 1",
            (new_route_id,),
        )
        db.execute(
            """INSERT INTO sr_touches(id,route_id,seq,at,device_id,packet_id,action,
               visibility,key_holder,evidence_id,digest,detail)
               VALUES(?,?,?,?,?,?, 'recovered_from_parking',?,?,NULL,?, '{}')""",
            (
                recovery_touch, new_route_id, first_hop["seq"] if first_hop else None,
                at, parking["custodian_device_id"], parking["packet_id"],
                first_hop["visibility"] if first_hop else "ciphertext",
                first_hop["key_holder"] if first_hop else new_route["key_holder"],
                _digest({"recovered": parking_id, "to": new_route_id}),
            ),
        )
    return {
        "decision": "recovered_to_route",
        "parking_id": parking_id,
        "old_route_id": parking["route_id"],
        "new_route_id": new_route_id,
        "custodian_device_id": parking["custodian_device_id"],
        "verdict": verdict,
    }


def observe_touch(db, t):
    """登记来自独立设备/网络日志的实际接触；这是事后证据，不执行转发。"""
    ensure_schema(db)
    touch_id = t.get("id")
    route_id = t.get("route_id")
    device_id = t.get("device_id")
    at = t.get("at")
    packet_id = t.get("packet_id")
    if not touch_id or not route_id or not device_id or at is None or not packet_id:
        return {"decision": "invalid_touch"}
    digest = t.get("digest") or _digest({k: v for k, v in t.items() if k != "digest"})
    old = one(db, "SELECT * FROM sr_touches WHERE id=?", (touch_id,))
    if old:
        return {"decision": "reused" if old["digest"] == digest else "touch_identity_conflict"}

    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,))
    if not route:
        return {"decision": "unknown_route"}
    known_packets = {route["initial_packet"], route["final_packet"]}
    if one(db, "SELECT parent_packet FROM sr_packets WHERE packet_id=?", (packet_id,)):
        pkt = one(db, "SELECT parent_packet FROM sr_packets WHERE packet_id=?", (packet_id,))
        if pkt and pkt["parent_packet"]:
            known_packets.add(pkt["parent_packet"])
    if packet_id not in known_packets:
        return {"decision": "foreign_packet_for_route"}

    hop = one(db, "SELECT * FROM sr_route_hops WHERE route_id=? AND device_id=? ORDER BY seq LIMIT 1",
              (route_id, device_id))
    seq = t.get("seq", hop["seq"] if hop else None)
    visibility = t.get("visibility") or (hop["visibility"] if hop else None)
    key_holder = t.get("key_holder") or (hop["key_holder"] if hop else "unverified")
    digest = t.get("digest") or _digest(t)
    db.execute(
        """INSERT INTO sr_touches(id,route_id,seq,at,device_id,packet_id,action,
           visibility,key_holder,evidence_id,digest,detail)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            touch_id, route_id, seq, at, device_id, packet_id,
            t.get("action", "observed"), visibility, key_holder,
            t.get("evidence_id"), digest,
            json.dumps(t.get("detail", {}), sort_keys=True, default=str),
        ),
    )
    packet = one(db, "SELECT * FROM sr_packets WHERE packet_id=?", (packet_id,))
    if packet and (not packet["route_id"] or packet["route_id"] == route_id):
        db.execute(
            "UPDATE sr_packets SET current_device_id=? WHERE packet_id=?",
            (device_id, packet_id),
        )
    return {"decision": "touch_recorded", "touch_id": touch_id, "device_id": device_id}


def advance_packet(db, a):
    """受控转发到下一个已知且在线的处理者；失联时停在当前保管设备。"""
    ensure_schema(db)
    route_id = a.get("route_id")
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,))
    if not route:
        return {"decision": "missing_route"}
    at = a.get("at", 0)
    verdict = evaluate_route(db, route_id, at, "production")
    if not verdict["production"]:
        stopped = _stop_for_verdict(db, route, verdict, at)
        return {
            "decision": "route_not_production",
            "verdict": verdict,
            "parking": _parking_view(stopped),
            "recovery_token": stopped["recovery_token"],
        }
    if route["status"] != "production":
        return {
            "decision": "route_not_production",
            "route_status": route["status"],
            "verdict": verdict,
            "parking": _parking_view(_active_parking(db, route_id)),
        }

    packet_id = a.get("packet_id") or route["final_packet"] or route["initial_packet"]
    packet = one(db, "SELECT * FROM sr_packets WHERE packet_id=?", (packet_id,))
    if not packet:
        enqueued = enqueue_packet(db, {
            "route_id": route_id, "packet_id": packet_id,
            "custodian_device_id": a.get("current_device_id") or route["target_device_id"],
            "at": at,
        })
        return {"decision": "packet_not_enqueued", "enqueued": enqueued}

    current_device = packet["current_device_id"]
    hops = rows(db, "SELECT * FROM sr_route_hops WHERE route_id=? ORDER BY seq", (route_id,))
    current_index = next((i for i, h in enumerate(hops) if h["device_id"] == current_device), -1)
    if current_index < 0:
        return {"decision": "current_custodian_not_on_route", "current_device_id": current_device}
    if current_index + 1 >= len(hops):
        return {"decision": "no_further_hop", "current_device_id": current_device}
    nxt = hops[current_index + 1]
    next_device = _device(db, nxt["device_id"])
    if not next_device or next_device["status"] != "active":
        parking = _park(db, route_id, packet_id, at, current_device,
                        f"unknown_or_retired_next_handler:{nxt['device_id']}")
        return {"decision": "unknown_handler_packet_parked", "parking": _parking_view(parking)}
    if not next_device["reachable"]:
        parking = _park(db, route_id, packet_id, at, current_device,
                        f"next_channel_unreachable:{nxt['device_id']}")
        return {"decision": "parked_unreachable", "next_device_id": nxt["device_id"],
                "parking": _parking_view(parking), "recovery_token": parking["recovery_token"]}

    active_parking = _active_parking(db, route_id)
    if active_parking and active_parking["status"] == "parked":
        db.execute(
            "UPDATE sr_parked SET status='resumed', resumed_at=?, resolution='normal_forward' WHERE id=?",
            (at, active_parking["id"]),
        )
    touch_id = a.get("touch_id") or f"handoff:{route_id}:{nxt['seq']}:{nxt['device_id']}"
    if not one(db, "SELECT 1 FROM sr_touches WHERE id=?", (touch_id,)):
        db.execute(
            """INSERT INTO sr_touches(id,route_id,seq,at,device_id,packet_id,action,
               visibility,key_holder,evidence_id,digest,detail)
               VALUES(?,?,?,?,?,?,'handoff_accepted',?,?,NULL,?,?)""",
            (
                touch_id, route_id, nxt["seq"], at, nxt["device_id"], packet_id,
                nxt["visibility"], nxt["key_holder"],
                _digest({"handoff": touch_id, "at": at}), "{}",
            ),
        )
    db.execute(
        "UPDATE sr_packets SET current_device_id=?, state='in_transit' WHERE packet_id=?",
        (nxt["device_id"], packet_id),
    )
    return {"decision": "forwarded", "seq": nxt["seq"], "device_id": nxt["device_id"],
            "visibility": nxt["visibility"], "key_holder": nxt["key_holder"]}


def repack_packet(db, c):
    ensure_schema(db)
    repack_id = c.get("id") or c.get("repack_id")
    route_id = c.get("route_id")
    at = c.get("at")
    device_id = c.get("device_id") or c.get("repackager_device_id")
    new_packet = c.get("new_packet_id") or c.get("new_packet")
    old_packet = c.get("old_packet_id") or c.get("old_packet")
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,))
    if not repack_id or not route or at is None or not device_id or not new_packet:
        return {"decision": "invalid_repack"}
    if route["route_kind"] != "repack":
        return {"decision": "repack_not_authorized_for_route_kind"}

    old = one(db, "SELECT * FROM sr_repacks WHERE id=?", (repack_id,))
    if old:
        return {"decision": "reused" if old["new_packet"] == new_packet else "repack_identity_conflict"}

    old_packet = old_packet or route["final_packet"] or route["initial_packet"]
    auth = one(
        db,
        """SELECT * FROM sr_authorizations
           WHERE route_id=? AND kind='repack' AND status='approved'
             AND path_commitment=? AND valid_from<=? AND valid_until>=?
           ORDER BY rowid DESC LIMIT 1""",
        (route_id, route["commitment"], at, at),
    )
    if not auth:
        return {"decision": "missing_valid_repack_authorization"}
    authorized_handlers = _json(auth["handlers"], [])
    if not authorized_handlers or device_id not in authorized_handlers:
        return {
            "decision": "repack_device_not_listed_in_authorization",
            "device_id": device_id,
            "authorized_handlers": authorized_handlers,
        }

    device = _device(db, device_id)
    location = _location_at(db, device_id, at)
    if not device or not location or location["region"] != SOUTH or not device["certified"]:
        return {"decision": "repack_device_not_in_certified_south"}

    evidence_id = c.get("attestation_evidence_id")
    evidence = one(db, "SELECT * FROM sr_evidence WHERE id=?", (evidence_id,)) if evidence_id else None
    if not evidence or not evidence["independent"] or evidence["claim"] != "south_repack_attestation":
        return {"decision": "missing_independent_south_repack_attestation"}

    db.execute(
        """INSERT INTO sr_repacks(id,route_id,at,device_id,old_packet,new_packet,gen,
           attestation_evidence_id,attestation_digest,commitment)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (
            repack_id, route_id, at, device_id, old_packet, new_packet, route["gen"],
            evidence_id, c.get("attestation_digest") or evidence["digest"],
            _digest({"repack": repack_id, "route": route["commitment"], "old": old_packet, "new": new_packet}),
        ),
    )
    if not one(db, "SELECT 1 FROM sr_packets WHERE packet_id=?", (new_packet,)):
        db.execute(
            """INSERT INTO sr_packets(packet_id,route_id,parent_packet,gen,state,
               current_device_id,parking_id,created_at)
               VALUES(?,?,?,?, 'repacked', ?,NULL,?)""",
            (new_packet, route_id, old_packet, route["gen"], device_id, at),
        )
    db.execute("UPDATE sr_routes SET final_packet=? WHERE id=?", (new_packet, route_id))
    touch_id = f"repack:{repack_id}"
    if not one(db, "SELECT 1 FROM sr_touches WHERE id=?", (touch_id,)):
        db.execute(
            """INSERT INTO sr_touches(id,route_id,seq,at,device_id,packet_id,action,
               visibility,key_holder,evidence_id,digest,detail)
               VALUES(?,?, (SELECT seq FROM sr_route_hops WHERE route_id=? AND device_id=? LIMIT 1),
                      ?,?,?, 'repacked','plaintext','south-repacker-enclave',?,?,?)""",
            (touch_id, route_id, route_id, device_id, at, device_id, old_packet,
             evidence_id, evidence["digest"], json.dumps({"new_packet": new_packet}, sort_keys=True)),
        )
    return {"decision": "repacked_in_south", "old_packet": old_packet, "new_packet": new_packet,
            "custodian_device_id": device_id}


# ---------------------------------------------------------------------------
# 路线证据评估
# ---------------------------------------------------------------------------

def _has_claim(db, route_id, device_id, claim):
    return one(
        db,
        """SELECT * FROM sr_evidence
           WHERE route_id=? AND independent=1 AND claim=?
             AND (device_id=? OR device_id IS NULL)
           ORDER BY rowid DESC LIMIT 1""",
        (route_id, claim, device_id),
    )


def evaluate_route(db, route_id, at=None, stage="production"):
    ensure_schema(db)
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,))
    if not route:
        return {
            "decision": "missing_route", "production": False,
            "violations": ["missing_route"], "unresolved": [],
            "blockers": ["missing_route"], "actual_device_path": [],
            "key_control": {"requests": []}, "parked_packet": None,
        }

    # 不允许用省略 at 的方式跳过合同、认证和授权有效期判断。
    if at is None:
        at = route["created_at"] if route["created_at"] is not None else 0

    violations = []
    unresolved = []
    satisfied = []
    contract = one(db, "SELECT * FROM sr_contracts WHERE id=?", (route["contract_id"],))
    if not contract:
        violations.append("missing_contract")
        contract_regions = [SOUTH, NORTH]
        key_regions = [SOUTH]
        plain_region = SOUTH
    else:
        contract_regions = _json(contract["ciphertext_regions"], [SOUTH, NORTH])
        key_regions = _json(contract["key_regions"], [SOUTH])
        plain_region = contract["plaintext_region"]
        if at is not None and not (contract["valid_from"] <= at <= contract["valid_until"]):
            unresolved.append("contract_version_outside_validity")
        else:
            satisfied.append("contract_version_bound")

    hops = rows(db, "SELECT * FROM sr_route_hops WHERE route_id=? ORDER BY seq", (route_id,))
    if not hops:
        violations.append("route_has_no_hops")

    # 目标实例与既有 workload grant/identity 代际。
    target_device = _device(db, route["target_device_id"])
    if not target_device:
        violations.append(f"target_device_unknown:{route['target_device_id']}")
    elif target_device["status"] != "active":
        unresolved.append(f"target_instance_rebuilt:{route['target_device_id']}")
    target_location = _location_at(db, route["target_device_id"], at)
    if not target_location:
        unresolved.append(f"missing_independent_target_location:{route['target_device_id']}")
    elif target_location["region"] != plain_region:
        violations.append(f"target_outside_plaintext_region:{route['target_device_id']}")
    elif not target_device or not target_device["certified"] or (
        at is not None and target_device["certified_until"] < at
    ):
        violations.append(f"target_not_certified_plaintext_device:{route['target_device_id']}")
    else:
        satisfied.append("target_in_certified_south")

    if route["grant_id"]:
        grant = one(db, "SELECT * FROM grants WHERE id=?", (route["grant_id"],))
        if not grant:
            violations.append("missing_workload_grant")
        else:
            identity = one(db, "SELECT * FROM identities WHERE id=?", (grant["identity"],))
            if grant["status"] != "active":
                unresolved.append(f"workload_grant_{grant['status']}:{grant['id']}")
            if grant["uid"] != route["target_uid"] or grant["secret"] != route["secret"] or grant["gen"] != route["gen"]:
                violations.append("grant_route_binding_mismatch")
            if at is not None and grant["until_ts"] < at:
                violations.append("grant_expired")
            if not identity or not identity["active"]:
                unresolved.append("workload_identity_inactive")
            elif identity["uid"] != route["target_uid"] or identity["generation"] != route["identity_generation"]:
                unresolved.append(
                    f"target_instance_rebuilt:identity_generation_{identity['generation']}_route_{route['identity_generation']}"
                )
            else:
                satisfied.append("workload_identity_generation_bound")

    # 计划路径上的每台设备都必须有独立物理位置与合规可见性。
    for hop in hops:
        device = _device(db, hop["device_id"])
        if not device:
            violations.append(f"unknown_planned_device:{hop['device_id']}")
            continue
        location = _location_at(db, hop["device_id"], at)
        if not location:
            unresolved.append(f"missing_physical_location_evidence:{hop['device_id']}")
            region = None
        else:
            region = location["region"]
            if hop["visibility"] == "plaintext":
                if region != plain_region:
                    violations.append(f"plaintext_outside_boundary:{hop['device_id']}:{region}")
                elif not device["certified"] or (at is not None and device["certified_until"] < at):
                    violations.append(f"plaintext_device_not_certified:{hop['device_id']}")
            elif region not in contract_regions:
                violations.append(f"ciphertext_region_forbidden:{hop['device_id']}:{region}")
            elif region != plain_region:
                if not _has_claim(db, route_id, hop["device_id"], "ciphertext_only"):
                    unresolved.append(f"missing_independent_ciphertext_only_proof:{hop['device_id']}")

        if hop["key_control"] and hop["key_control"] != "no_key":
            if region not in key_regions:
                violations.append(f"key_holder_outside_authorized_region:{hop['device_id']}:{region}")
            elif hop["visibility"] == "plaintext" and (
                not device["certified"] or (at is not None and device["certified_until"] < at)
            ):
                violations.append(f"key_controlling_device_not_certified:{hop['device_id']}")

    # 密钥请求/KMS 回执是独立于代理自述的关键证据。
    key_requests = rows(db, "SELECT * FROM sr_key_requests WHERE route_id=? ORDER BY requested_at, rowid", (route_id,))
    hop_by_device = {h["device_id"]: h for h in hops}
    for req in key_requests:
        if req["status"] == "pending":
            unresolved.append(f"key_request_unresolved:{req['request_id']}")
            continue
        if req["outcome"] == "released":
            release_at = req["receipt_at"] or req["requested_at"]
            location = _location_at(db, req["device_id"], release_at)
            region = location["region"] if location else None
            hop = hop_by_device.get(req["device_id"])
            if region not in key_regions:
                violations.append(f"key_released_to_unauthorized_jurisdiction:{req['request_id']}:{region}")
            if not hop or hop["key_control"] == "no_key":
                violations.append(f"key_released_to_no_key_hop:{req['request_id']}:{req['device_id']}")
            elif region in key_regions:
                satisfied.append(f"authorized_key_release:{req['request_id']}")
        elif req["outcome"] == "denied":
            satisfied.append(f"key_request_denied:{req['request_id']}")

    # 每个 no_key 中转者都必须有 KMS 无释放审计，或已查清的拒绝回执。
    for hop in hops:
        if hop["key_control"] != "no_key":
            continue
        denied = one(
            db,
            """SELECT 1 FROM sr_key_requests
               WHERE route_id=? AND device_id=? AND status='resolved' AND outcome='denied'""",
            (route_id, hop["device_id"]),
        )
        no_release = _has_claim(db, route_id, hop["device_id"], "no_key_release")
        if not denied and not no_release:
            unresolved.append(f"missing_key_boundary_proof:{hop['device_id']}")

    # 客户/合规授权；原始路径、临时绕路、南区再封装不能互相替代。
    auths = rows(
        db,
        "SELECT * FROM sr_authorizations WHERE route_id=? AND status='approved' ORDER BY rowid",
        (route_id,),
    )
    valid_auth_kinds = set()
    expired_auth_ids = []
    for auth in auths:
        if auth["path_commitment"] != route["commitment"]:
            violations.append(f"authorization_commitment_mismatch:{auth['id']}")
            continue
        if at is not None and not (auth["valid_from"] <= at <= auth["valid_until"]):
            expired_auth_ids.append(auth["id"])
            continue
        if not auth["customer_actor"] or not auth["compliance_actor"]:
            violations.append(f"authorization_missing_dual_approval:{auth['id']}")
            continue
        valid_auth_kinds.add(auth["kind"])

    def require_auth(kind, accepted_kinds=None):
        accepted = set(accepted_kinds or [kind])
        if accepted & valid_auth_kinds:
            satisfied.append(f"path_authorized:{kind}")
        elif expired_auth_ids:
            unresolved.append(f"authorization_expired_or_inactive:{expired_auth_ids[-1]}")
        else:
            unresolved.append(f"missing_authorization:{kind}")

    if route["route_kind"] == "repack":
        require_auth("repack")
    elif route["route_kind"] == "detour":
        require_auth("detour")
    else:
        require_auth("original_path", {"original_path", "route"})

    # 实际路径与纯密文独立日志（送达阶段强制）。
    actual_path = _actual_path(db, route_id)
    if stage == "delivery":
        touches = rows(
            db,
            """SELECT * FROM sr_touches
               WHERE route_id=? AND action!='parked'
               ORDER BY at, seq IS NULL, seq, rowid""",
            (route_id,),
        )
        if not touches:
            unresolved.append("no_actual_device_path_evidence")
        actual_devices = []
        for touch in touches:
            if not actual_devices or actual_devices[-1] != touch["device_id"]:
                actual_devices.append(touch["device_id"])
            device = _device(db, touch["device_id"])
            if not device:
                violations.append(f"unknown_actual_handler:{touch['device_id']}")
                continue
            location = _location_at(db, touch["device_id"], touch["at"])
            if not location:
                unresolved.append(f"missing_actual_location:{touch['id']}:{touch['device_id']}")
                region = None
            else:
                region = location["region"]
            hop = hop_by_device.get(touch["device_id"])
            if not hop:
                violations.append(f"unlisted_actual_handler:{touch['device_id']}")
                continue
            visibility = touch["visibility"] or hop["visibility"]
            if visibility == "plaintext":
                if region != plain_region or not device["certified"]:
                    violations.append(f"unauthorized_unseal_or_plaintext_exposure:{touch['id']}:{touch['device_id']}")
            elif region and region != plain_region:
                transfer = _has_claim(db, route_id, touch["device_id"], "packet_transfer_log")
                cipher_only = _has_claim(db, route_id, touch["device_id"], "ciphertext_only")
                if not transfer:
                    unresolved.append(f"missing_packet_transfer_log:{touch['device_id']}")
                if not cipher_only:
                    unresolved.append(f"missing_independent_ciphertext_only_proof:{touch['device_id']}")
                if transfer:
                    payload = _json(transfer["payload"], {})
                    logged_packet = payload.get("packet_id")
                    if logged_packet and logged_packet != touch["packet_id"]:
                        violations.append(f"transfer_log_packet_mismatch:{touch['device_id']}")

        planned_devices = [h["device_id"] for h in hops]
        if actual_devices and actual_devices != planned_devices:
            violations.append(
                "actual_path_differs_from_approved_route:"
                + "actual=" + ">".join(actual_devices)
                + ";approved=" + ">".join(planned_devices)
            )

        if route["route_kind"] == "repack":
            repack = one(db, "SELECT * FROM sr_repacks WHERE route_id=?", (route_id,))
            if not repack:
                unresolved.append("missing_south_repack_record")
            else:
                evidence = one(db, "SELECT * FROM sr_evidence WHERE id=?", (repack["attestation_evidence_id"],))
                if not evidence or not evidence["independent"] or evidence["claim"] != "south_repack_attestation":
                    unresolved.append("missing_independent_south_repack_attestation")
                elif repack["new_packet"] != route["final_packet"]:
                    violations.append("repack_final_packet_mismatch")

    # 去重并保持稳定顺序。
    violations = list(dict.fromkeys(violations))
    unresolved = list(dict.fromkeys(unresolved))
    satisfied = list(dict.fromkeys(satisfied))
    production = not violations and not unresolved

    if violations:
        decision = "route_rejected"
    elif unresolved:
        decision = "parked_evidence"
    else:
        decision = "ready_for_production"

    parking = _active_parking(db, route_id)
    return {
        "decision": decision,
        "route_id": route_id,
        "stage": stage,
        "at": at,
        "production": production,
        "violations": violations,
        "unresolved": unresolved,
        "blockers": violations + unresolved,
        "satisfied": satisfied,
        "route_commitment": route["commitment"],
        "actual_device_path": actual_path,
        "key_control": {
            "key_id": route["key_id"],
            "contract_key_holder": route["key_holder"],
            "requests": key_requests,
        },
        "parked_packet": _parking_view(parking),
    }


def _actual_path(db, route_id):
    touches = rows(
        db,
        "SELECT * FROM sr_touches WHERE route_id=? ORDER BY at, seq IS NULL, seq, rowid",
        (route_id,),
    )
    path = []
    for touch in touches:
        device = _device(db, touch["device_id"])
        location = _location_at(db, touch["device_id"], touch["at"])
        path.append({
            "at": touch["at"],
            "seq": touch["seq"],
            "device_id": touch["device_id"],
            "device_kind": device["kind"] if device else None,
            "cloud_label_not_evidence": device["cloud_label"] if device else None,
            "actual_region": location["region"] if location else "location-unverified",
            "site": location["site"] if location else None,
            "location_source": location["source_kind"] if location else None,
            "location_evidence_id": location["id"] if location else None,
            "action": touch["action"],
            "packet_id": touch["packet_id"],
            "visibility": touch["visibility"],
            "key_holder": touch["key_holder"],
            "evidence_id": touch["evidence_id"],
            "digest": touch["digest"],
        })
    return path


def _stop_for_verdict(db, route, verdict, at):
    blockers = verdict["blockers"] or ["route_not_ready"]
    hard = verdict["violations"]
    packet = one(
        db,
        "SELECT * FROM sr_packets WHERE route_id=? ORDER BY rowid DESC LIMIT 1",
        (route["id"],),
    )
    packet_id = packet["packet_id"] if packet else route["initial_packet"]
    device_id = packet["current_device_id"] if packet and packet["current_device_id"] else None
    if not device_id:
        first = one(db, "SELECT device_id FROM sr_route_hops WHERE route_id=? ORDER BY seq LIMIT 1", (route["id"],))
        device_id = first["device_id"] if first else route["target_device_id"]
    return _park(
        db, route["id"], packet_id, at if at is not None else route["created_at"],
        device_id, blockers[0], "quarantined" if hard else "parked",
    )


def activate_route(db, a):
    ensure_schema(db)
    route_id = a.get("route_id") or a.get("id")
    at = a.get("at")
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,))
    if not route:
        return {"decision": "missing_route"}
    if route["status"] == "delivered":
        return {"decision": "route_delivered", "route_id": route_id}
    if at is None:
        return {"decision": "activation_at_required", "route_id": route_id}
    verdict = evaluate_route(db, route_id, at=at, stage="production")
    if not verdict["production"]:
        parking = _stop_for_verdict(db, route, verdict, at if at is not None else route["created_at"])
        return {
            "decision": "not_producible",
            "verdict": verdict,
            "parking": _parking_view(parking),
            "recovery_token": parking["recovery_token"],
        }
    db.execute("UPDATE sr_routes SET status='production', blocker=NULL WHERE id=?", (route_id,))
    return {
        "decision": "production",
        "route_id": route_id,
        "route_commitment": route["commitment"],
        "verdict": verdict,
    }


# 更贴近业务语言的别名。
promote_route = activate_route
productionize_route = activate_route


def provisional_delivery(db, permit_or_route_id, step=None, at=None, **options):
    """安全版 provisional_delivery：未通过区域/密钥门时绝不调用 delivery.plan。"""
    ensure_schema(db)
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (permit_or_route_id,))
    if not route and isinstance(step, dict) and step.get("id"):
        route = one(db, "SELECT * FROM sr_routes WHERE plan_id=?", (step["id"],))
    if not route:
        route = one(db, "SELECT * FROM sr_routes WHERE permit_id=?", (permit_or_route_id,))
    if not route:
        permit = one(db, "SELECT * FROM region_permits WHERE id=?", (permit_or_route_id,))
        if permit:
            return {
                "decision": "sovereign_route_required",
                "conventional_permit": dict(permit),
                "reason": "approved_region_and_cloud_label_do_not_prove_device_path_or_key_control",
            }
        return {"decision": "missing_sovereign_route"}

    if at is None and isinstance(step, dict):
        at = step.get("at")
    if at is None:
        at = route["created_at"]

    verdict = evaluate_route(db, route["id"], at=at, stage="production")
    if not verdict["production"]:
        parking = _stop_for_verdict(db, route, verdict, at)
        return {
            "decision": "parked_sovereign_route",
            "verdict_decision": verdict["decision"],
            "blockers": verdict["blockers"],
            "parking": _parking_view(parking),
            "recovery_token": parking["recovery_token"],
        }

    db.execute("UPDATE sr_routes SET status='production', blocker=NULL WHERE id=?", (route["id"],))
    if step is None:
        return {"decision": "production", "route_id": route["id"], "route_commitment": route["commitment"]}

    delivery_result = delivery.run(db, step)
    return {
        **delivery_result,
        "sovereign_route_id": route["id"],
        "route_commitment": route["commitment"],
    }


def verify_delivery_receipt(db, r):
    ensure_schema(db)
    receipt_id = r.get("id") or r.get("receipt_id")
    route_id = r.get("route_id")
    at = r.get("at")
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,))
    if not receipt_id or not route or at is None:
        return {"decision": "invalid_delivery_receipt"}

    old = one(db, "SELECT * FROM sr_receipts WHERE id=?", (receipt_id,))
    if old:
        same = (
            old["route_id"] == route_id and old["packet_id"] == r.get("packet_id", old["packet_id"])
            and old["at"] == at and old["route_commitment"] == r.get("route_commitment", old["route_commitment"])
        )
        return {"decision": "reused" if same else "receipt_identity_conflict"}

    if route["status"] != "production":
        verdict = evaluate_route(db, route_id, at=at, stage="delivery")
        parking = _stop_for_verdict(db, route, verdict, at) if not verdict["production"] else None
        return {
            "decision": "route_not_in_production",
            "verdict": verdict,
            "parking": _parking_view(parking) if parking else _active_parking(db, route_id),
        }

    verdict = evaluate_route(db, route_id, at=at, stage="delivery")
    if not verdict["production"]:
        parking = _stop_for_verdict(db, route, verdict, at)
        return {
            "decision": "receipt_rejected_route_not_verifiable",
            "verdict": verdict,
            "parking": _parking_view(parking),
            "recovery_token": parking["recovery_token"],
        }

    packet_id = r.get("packet_id")
    if packet_id != route["final_packet"]:
        return {"decision": "receipt_packet_does_not_match_approved_route",
                "expected_packet": route["final_packet"], "actual_packet": packet_id}
    supplied_commitment = r.get("route_commitment")
    if not supplied_commitment:
        return {"decision": "receipt_missing_route_commitment"}
    if supplied_commitment != route["commitment"]:
        return {"decision": "receipt_route_commitment_mismatch"}
    target_uid = r.get("target_uid", route["target_uid"])
    target_generation = r.get("target_generation", route["target_generation"])
    target_device = r.get("target_device_id", route["target_device_id"])
    if (target_uid, int(target_generation), target_device) != (
        route["target_uid"], route["target_generation"], route["target_device_id"]
    ):
        return {"decision": "receipt_target_binding_mismatch"}
    attestation_digest = r.get("attestation_digest")
    if not attestation_digest:
        return {"decision": "missing_target_attestation"}

    attestation_claims = {"target_attestation", "delivery_attestation", "target_receipt_attestation"}
    attestation = None
    if r.get("attestation_evidence_id"):
        candidate = one(db, "SELECT * FROM sr_evidence WHERE id=?", (r["attestation_evidence_id"],))
        if (
            candidate and candidate["independent"] and candidate["device_id"] == target_device
            and candidate["claim"] in attestation_claims
            and candidate["digest"] == attestation_digest
        ):
            attestation = candidate
    else:
        attestation = one(
            db,
            """SELECT * FROM sr_evidence
               WHERE route_id=? AND device_id=? AND independent=1
                 AND claim IN ('target_attestation','delivery_attestation','target_receipt_attestation')
                 AND digest=?
               ORDER BY rowid DESC LIMIT 1""",
            (route_id, target_device, attestation_digest),
        )
    if not attestation:
        return {
            "decision": "missing_independent_target_attestation",
            "required_claims": sorted(attestation_claims),
        }

    location = _location_at(db, target_device, at)
    db.execute(
        """INSERT INTO sr_receipts(id,route_id,at,target_uid,target_generation,
           target_device_id,packet_id,route_commitment,attestation_digest,
           location_evidence_id,verified,result)
           VALUES(?,?,?,?,?,?,?,?,?,?,1,'verified')""",
        (
            receipt_id, route_id, at, target_uid, target_generation, target_device,
            packet_id, route["commitment"], r["attestation_digest"],
            location["id"] if location else r.get("location_evidence_id"),
        ),
    )
    db.execute("UPDATE sr_routes SET status='delivered' WHERE id=?", (route_id,))
    db.execute("UPDATE sr_packets SET state='delivered' WHERE packet_id=?", (packet_id,))
    active = _active_parking(db, route_id)
    if active and active["status"] == "parked":
        db.execute(
            "UPDATE sr_parked SET status='released', resumed_at=?, resolution='delivered_to_bound_target' WHERE id=?",
            (at, active["id"]),
        )

    delivery_result = None
    if route["plan_id"] and r.get("write_legacy_receipt", True):
        legacy_id = r.get("legacy_receipt_id") or f"legacy-{receipt_id}"
        delivery_result = delivery.run(db, {
            "op": "receipt", "id": legacy_id, "plan": route["plan_id"],
            "uid": target_uid, "kind": "delivered", "packet": packet_id, "at": at,
        })

    return {
        "decision": "delivered",
        "receipt_id": receipt_id,
        "route_id": route_id,
        "packet_id": packet_id,
        "route_commitment": route["commitment"],
        "customer_proof": customer_view(db, route_id),
        "legacy_delivery": delivery_result,
    }


def customer_view(db, route_id):
    ensure_schema(db)
    route = one(db, "SELECT * FROM sr_routes WHERE id=?", (route_id,))
    if not route:
        return {"decision": "missing_route"}
    contract = one(db, "SELECT * FROM sr_contracts WHERE id=?", (route["contract_id"],))
    auths = rows(db, "SELECT * FROM sr_authorizations WHERE route_id=? ORDER BY rowid", (route_id,))
    receipts = rows(db, "SELECT * FROM sr_receipts WHERE route_id=? ORDER BY at, rowid", (route_id,))
    packets = rows(db, "SELECT * FROM sr_packets WHERE route_id=? ORDER BY rowid", (route_id,))
    parkings = rows(db, "SELECT * FROM sr_parked WHERE route_id=? ORDER BY rowid", (route_id,))
    repacks = rows(db, "SELECT * FROM sr_repacks WHERE route_id=? ORDER BY rowid", (route_id,))
    key_requests = rows(db, "SELECT * FROM sr_key_requests WHERE route_id=? ORDER BY requested_at", (route_id,))
    active_parking = _active_parking(db, route_id)
    return {
        "route_id": route_id,
        "status": route["status"],
        "route_kind": route["route_kind"],
        "route_commitment": route["commitment"],
        "material": {"secret": route["secret"], "generation": route["gen"]},
        "contract": {
            "id": contract["id"],
            "customer": contract["customer"],
            "version": contract["contract_version"],
            "commitment": contract["commitment"],
            "valid_from": contract["valid_from"],
            "valid_until": contract["valid_until"],
            "plaintext_region": contract["plaintext_region"],
            "ciphertext_regions": _json(contract["ciphertext_regions"], []),
            "key_regions": _json(contract["key_regions"], []),
        } if contract else None,
        "target": {
            "uid": route["target_uid"],
            "generation": route["target_generation"],
            "device_id": route["target_device_id"],
        },
        "planned_device_path": rows(
            db, "SELECT seq,device_id,role,visibility,key_control,key_holder FROM sr_route_hops WHERE route_id=? ORDER BY seq",
            (route_id,),
        ),
        "actual_device_path": _actual_path(db, route_id),
        "authorizations": [{
            "id": a["id"], "kind": a["kind"], "customer_actor": a["customer_actor"],
            "compliance_actor": a["compliance_actor"], "valid_from": a["valid_from"],
            "valid_until": a["valid_until"], "status": a["status"],
            "commitment": a["commitment"],
        } for a in auths],
        "key_control": {
            "key_id": route["key_id"],
            "contract_key_holder": route["key_holder"],
            "requests": key_requests,
        },
        "packets": packets,
        "packet_lineage": {
            "initial_packet": route["initial_packet"],
            "final_packet": route["final_packet"],
            "records": packets,
        },
        "repacks": repacks,
        "parked_packet": _parking_view(active_parking),
        "parking_history": [_parking_view(p) for p in parkings],
        "receipts": receipts,
        "delivery_at": receipts[-1]["at"] if receipts else None,
        "eta_seconds": route["eta_seconds"],
        "blocker": route["blocker"],
    }


def run(db, cmd):
    ensure_schema(db)
    op = cmd.get("op")
    if op in ("contract", "bind_contract"):
        return bind_contract(db, cmd)
    if op in ("device", "register_device"):
        return register_device(db, cmd)
    if op in ("reachability", "set_reachability"):
        return set_device_reachability(db, cmd)
    if op in ("rebuild_instance", "rebuild"):
        return rebuild_instance(db, cmd)
    if op in ("location", "record_location"):
        return record_location(db, cmd)
    if op in ("evidence", "add_evidence"):
        return add_evidence(db, cmd)
    if op in ("key_request", "request_key"):
        return request_key(db, cmd)
    if op in ("key_receipt", "resolve_key_request"):
        return resolve_key_request(db, cmd)
    if op in ("authorization", "authorize", "approve"):
        return authorize(db, cmd)
    if op in ("route", "create_route"):
        return create_route(db, cmd)
    if op in ("enqueue", "enqueue_packet"):
        return enqueue_packet(db, cmd)
    if op in ("park", "park_packet"):
        return park_packet(db, cmd)
    if op in ("resume", "resume_packet"):
        return resume_packet(db, cmd)
    if op in ("recover_to_route", "recover"):
        return recover_to_route(db, cmd)
    if op in ("touch", "observe_touch"):
        return observe_touch(db, cmd)
    if op in ("advance", "forward"):
        return advance_packet(db, cmd)
    if op in ("repack", "repack_packet"):
        return repack_packet(db, cmd)
    if op in ("activate", "productionize", "promote"):
        return activate_route(db, cmd)
    if op in ("evaluate", "inspect"):
        return evaluate_route(db, cmd.get("route_id") or cmd.get("id"), cmd.get("at"), cmd.get("stage", "production"))
    if op in ("provisional_delivery", "safe_plan"):
        return provisional_delivery(
            db, cmd.get("route_id") or cmd.get("permit_id") or cmd.get("id"),
            cmd.get("step"), cmd.get("at"),
        )
    if op in ("receipt", "deliver", "verify_receipt"):
        return verify_delivery_receipt(db, cmd)
    if op in ("customer_view", "proof"):
        return customer_view(db, cmd.get("route_id") or cmd.get("id"))
    raise ValueError(f"unknown sovereign_route op: {op}")


# 常见业务命名别名，便于调用方按术语使用；权威入口仍是 run(db, command)。
register_physical_device = register_device
record_location_evidence = record_location
record_evidence = add_evidence
register_route = create_route
approve_route = authorize
authorize_route = authorize
verify_route = evaluate_route
gate_route = evaluate_route
safe_provisional_delivery = provisional_delivery
verify_receipt = verify_delivery_receipt
deliver_receipt = verify_delivery_receipt
route_proof = customer_view
customer_evidence = customer_view
