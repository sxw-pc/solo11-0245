"""Boundary-conserving environmental ledger for customer statements.

One ledger per metering period and site.  Grid, diesel and battery
inputs must balance against rack submeters, shared cooling/UPS loss
and an explicit unexplained remainder before any customer statement
is issued; the remainder is reported at boundary level, never
smuggled into a tenant to make the books balance.  Battery discharge
inherits the emission factor of the charging period instead of
counting as new purchases, green certificates are checked (holder,
generation period, region, external retirements) and retired at most
once across all recalibrations, and the shared-loss allocation method
is filed with both customers at the start of the period and locked
afterwards.  Delivery receipts, purchase serials and self-reported
kWh play no role in attribution.
"""
from fractions import Fraction

from .store import one, rows

METHODS = ("reserved_capacity", "occupied_time")
SELECTION_GRACE = 3 * 86400  # the method must be filed at the start of the period

SCHEMA = """
CREATE TABLE IF NOT EXISTS env_site(id INTEGER PRIMARY KEY CHECK(id=1),holder TEXT,region TEXT);
CREATE TABLE IF NOT EXISTS env_periods(period TEXT PRIMARY KEY,start_ts INTEGER,end_ts INTEGER,revision INTEGER);
CREATE TABLE IF NOT EXISTS env_sources(period TEXT,source TEXT,kwh INTEGER,factor REAL,at INTEGER,PRIMARY KEY(period,source));
CREATE TABLE IF NOT EXISTS env_cooling(period TEXT PRIMARY KEY,kwh INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS env_battery_events(id TEXT PRIMARY KEY,period TEXT,kind TEXT,kwh INTEGER,source TEXT,factor REAL,at INTEGER);
CREATE TABLE IF NOT EXISTS env_battery_use(discharge TEXT,charge TEXT,kwh INTEGER,PRIMARY KEY(discharge,charge));
CREATE TABLE IF NOT EXISTS env_devices(device TEXT PRIMARY KEY,customer TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS env_serials(serial TEXT PRIMARY KEY,device TEXT,activated_at INTEGER,retired_at INTEGER);
CREATE TABLE IF NOT EXISTS env_rack_readings(id TEXT PRIMARY KEY,period TEXT,device TEXT,kwh INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS env_reservations(period TEXT,customer TEXT,slots INTEGER,PRIMARY KEY(period,customer));
CREATE TABLE IF NOT EXISTS env_occupancy(period TEXT,customer TEXT,hours INTEGER,PRIMARY KEY(period,customer));
CREATE TABLE IF NOT EXISTS env_methods(period TEXT PRIMARY KEY,selection_id TEXT,method TEXT,at INTEGER,filed_to TEXT);
CREATE TABLE IF NOT EXISTS env_certificates(id TEXT PRIMARY KEY,holder TEXT,kwh INTEGER,gen_period TEXT,region TEXT,retired_external INTEGER);
CREATE TABLE IF NOT EXISTS env_green_retired(period TEXT,customer TEXT,kwh INTEGER,PRIMARY KEY(period,customer));
CREATE TABLE IF NOT EXISTS env_cert_retirements(period TEXT,certificate TEXT,kwh INTEGER,PRIMARY KEY(period,certificate));
CREATE TABLE IF NOT EXISTS env_calibrations(id TEXT PRIMARY KEY,period TEXT,kind TEXT,ref TEXT,old_kwh INTEGER,new_kwh INTEGER,reason TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS env_statements(id TEXT PRIMARY KEY,period TEXT,customer TEXT,revision INTEGER,method TEXT,active_kwh REAL,shared_kwh REAL,green_kwh REAL,emissions REAL,at INTEGER,supersedes TEXT);
"""


def _schema(db):
    db.executescript(SCHEMA)


def _fr(value):
    if isinstance(value, Fraction):
        return value
    if isinstance(value, float):
        return Fraction(repr(value))
    return Fraction(value)


def _num(value):
    value = _fr(value)
    if value.denominator == 1:
        return value.numerator
    return float(value)


def _largest_remainder(shares, total):
    result = {key: int(share) for key, share in shares.items()}
    rest = total - sum(result.values())
    order = sorted(shares, key=lambda key: (int(shares[key]) - shares[key], key))
    for key in order[:rest]:
        result[key] += 1
    return result


def configure_site(db, holder, region):
    _schema(db)
    old = one(db, "SELECT * FROM env_site WHERE id=1", ())
    if old:
        if old["holder"] == holder and old["region"] == region:
            return {"decision": "reused"}
        return {"decision": "conflict"}
    db.execute("INSERT INTO env_site VALUES(1,?,?)", (holder, region))
    return {"decision": "configured"}


def open_period(db, period, start_ts, end_ts):
    _schema(db)
    old = one(db, "SELECT * FROM env_periods WHERE period=?", (period,))
    if old:
        if old["start_ts"] == start_ts and old["end_ts"] == end_ts:
            return {"decision": "reused", "revision": old["revision"]}
        return {"decision": "conflict"}
    if end_ts <= start_ts:
        return {"decision": "invalid_period"}
    db.execute("INSERT INTO env_periods VALUES(?,?,?,0)", (period, start_ts, end_ts))
    return {"decision": "opened", "revision": 0}


def record_source(db, period, source, kwh, factor, at):
    _schema(db)
    old = one(db, "SELECT * FROM env_sources WHERE period=? AND source=?", (period, source))
    if old:
        if old["kwh"] == kwh and old["factor"] == factor:
            return {"decision": "reused"}
        return {"decision": "conflict"}
    if source == "battery":
        return {"decision": "battery_via_discharge_event"}
    if kwh < 0 or factor < 0:
        return {"decision": "invalid"}
    if not one(db, "SELECT period FROM env_periods WHERE period=?", (period,)):
        return {"decision": "unknown_period"}
    db.execute("INSERT INTO env_sources VALUES(?,?,?,?,?)", (period, source, kwh, factor, at))
    return {"decision": "recorded"}


def record_cooling(db, period, kwh, at):
    _schema(db)
    old = one(db, "SELECT * FROM env_cooling WHERE period=?", (period,))
    if old:
        if old["kwh"] == kwh:
            return {"decision": "reused"}
        return {"decision": "conflict"}
    if kwh < 0:
        return {"decision": "invalid"}
    if not one(db, "SELECT period FROM env_periods WHERE period=?", (period,)):
        return {"decision": "unknown_period"}
    db.execute("INSERT INTO env_cooling VALUES(?,?,?)", (period, kwh, at))
    return {"decision": "recorded"}


def record_battery_event(db, event_id, period, kind, kwh, at, source=None, factor=None):
    _schema(db)
    old = one(db, "SELECT * FROM env_battery_events WHERE id=?", (event_id,))
    if old:
        if old["kind"] == kind and old["kwh"] == kwh:
            return {"decision": "reused", "factor": old["factor"]}
        return {"decision": "conflict"}
    if not one(db, "SELECT period FROM env_periods WHERE period=?", (period,)):
        return {"decision": "unknown_period"}
    if kwh <= 0:
        return {"decision": "invalid"}
    if kind == "charge":
        if not source or factor is None or factor < 0:
            return {"decision": "invalid"}
        db.execute("INSERT INTO env_battery_events VALUES(?,?,?,?,?,?,?)",
                   (event_id, period, "charge", kwh, source, factor, at))
        return {"decision": "charged", "factor": factor}
    if kind != "discharge":
        return {"decision": "unknown_kind"}
    # consume charge lots FIFO across all periods up to this one, so a
    # discharge keeps the factor of the charging period and the same
    # charged kWh can never be discharged twice
    remaining = kwh
    consumed = []
    traced = Fraction(0)
    lots = rows(db, "SELECT * FROM env_battery_events WHERE kind='charge' AND period<=? ORDER BY period,at,id",
                (period,))
    for lot in lots:
        used = one(db, "SELECT COALESCE(SUM(kwh),0) AS used FROM env_battery_use WHERE charge=?",
                   (lot["id"],))["used"]
        available = lot["kwh"] - used
        if available <= 0:
            continue
        take = min(available, remaining)
        consumed.append((lot, take))
        traced += Fraction(take) * _fr(lot["factor"])
        remaining -= take
        if remaining == 0:
            break
    if remaining:
        return {"decision": "insufficient_battery_balance"}
    factor_out = traced / kwh
    db.execute("INSERT INTO env_battery_events VALUES(?,?,?,?,?,?,?)",
               (event_id, period, "discharge", kwh, None, float(factor_out), at))
    for lot, take in consumed:
        db.execute("INSERT INTO env_battery_use VALUES(?,?,?)", (event_id, lot["id"], take))
    return {"decision": "discharged", "factor": _num(factor_out),
            "traced_from": [{"charge": lot["id"], "period": lot["period"], "kwh": take}
                            for lot, take in consumed]}


def register_device(db, device, customer, serial, at):
    _schema(db)
    old = one(db, "SELECT * FROM env_devices WHERE device=?", (device,))
    if old:
        if old["customer"] == customer:
            return {"decision": "reused"}
        return {"decision": "conflict"}
    clash = one(db, "SELECT * FROM env_serials WHERE serial=? AND retired_at IS NULL", (serial,))
    if clash:
        return {"decision": "serial_in_use", "device": clash["device"]}
    db.execute("INSERT INTO env_devices VALUES(?,?,?)", (device, customer, at))
    db.execute("INSERT INTO env_serials VALUES(?,?,?,NULL)", (serial, device, at))
    return {"decision": "registered"}


def swap_serial(db, device, new_serial, at):
    _schema(db)
    if not one(db, "SELECT device FROM env_devices WHERE device=?", (device,)):
        return {"decision": "unknown_device"}
    clash = one(db, "SELECT * FROM env_serials WHERE serial=? AND retired_at IS NULL", (new_serial,))
    if clash:
        return {"decision": "serial_in_use", "device": clash["device"]}
    prior = one(db, "SELECT * FROM env_serials WHERE serial=?", (new_serial,))
    if prior and prior["device"] != device:
        return {"decision": "serial_in_use", "device": prior["device"]}
    current = one(db, "SELECT * FROM env_serials WHERE device=? AND retired_at IS NULL", (device,))
    if current and current["serial"] == new_serial:
        return {"decision": "reused"}
    if current:
        db.execute("UPDATE env_serials SET retired_at=? WHERE serial=?", (at, current["serial"]))
    if prior:
        db.execute("UPDATE env_serials SET retired_at=NULL,activated_at=? WHERE serial=?", (at, new_serial))
    else:
        db.execute("INSERT INTO env_serials VALUES(?,?,?,NULL)", (new_serial, device, at))
    return {"decision": "swapped", "device": device, "serial": new_serial}


def record_rack_reading(db, reading_id, period, device, kwh, at):
    _schema(db)
    old = one(db, "SELECT * FROM env_rack_readings WHERE id=?", (reading_id,))
    if old:
        if old["period"] == period and old["device"] == device and old["kwh"] == kwh:
            return {"decision": "reused"}
        return {"decision": "conflict"}
    if not one(db, "SELECT period FROM env_periods WHERE period=?", (period,)):
        return {"decision": "unknown_period"}
    if not one(db, "SELECT device FROM env_devices WHERE device=?", (device,)):
        return {"decision": "unknown_device"}
    if kwh < 0:
        return {"decision": "invalid"}
    db.execute("INSERT INTO env_rack_readings VALUES(?,?,?,?,?)", (reading_id, period, device, kwh, at))
    return {"decision": "recorded"}


def record_reservation(db, period, customer, slots):
    _schema(db)
    old = one(db, "SELECT * FROM env_reservations WHERE period=? AND customer=?", (period, customer))
    if old:
        if old["slots"] == slots:
            return {"decision": "reused"}
        return {"decision": "conflict"}
    if slots < 0:
        return {"decision": "invalid"}
    if not one(db, "SELECT period FROM env_periods WHERE period=?", (period,)):
        return {"decision": "unknown_period"}
    db.execute("INSERT INTO env_reservations VALUES(?,?,?)", (period, customer, slots))
    return {"decision": "recorded"}


def record_occupancy(db, period, customer, hours):
    _schema(db)
    old = one(db, "SELECT * FROM env_occupancy WHERE period=? AND customer=?", (period, customer))
    if old:
        if old["hours"] == hours:
            return {"decision": "reused"}
        return {"decision": "conflict"}
    if hours < 0:
        return {"decision": "invalid"}
    if not one(db, "SELECT period FROM env_periods WHERE period=?", (period,)):
        return {"decision": "unknown_period"}
    db.execute("INSERT INTO env_occupancy VALUES(?,?,?)", (period, customer, hours))
    return {"decision": "recorded"}


def register_certificate(db, cert_id, holder, kwh, gen_period, region, retired_external=0):
    _schema(db)
    old = one(db, "SELECT * FROM env_certificates WHERE id=?", (cert_id,))
    if old:
        return {"decision": "reused"}
    if kwh < 0 or retired_external < 0 or retired_external > kwh:
        return {"decision": "invalid_certificate"}
    db.execute("INSERT INTO env_certificates VALUES(?,?,?,?,?,?)",
               (cert_id, holder, kwh, gen_period, region, retired_external))
    return {"decision": "registered"}


def select_method(db, selection_id, period, method, at, filed_to):
    _schema(db)
    boundary = one(db, "SELECT * FROM env_periods WHERE period=?", (period,))
    if not boundary:
        return {"decision": "unknown_period"}
    if method not in METHODS:
        return {"decision": "unknown_method"}
    filed = ",".join(sorted(filed_to))
    old = one(db, "SELECT * FROM env_methods WHERE period=?", (period,))
    if old:
        if old["selection_id"] == selection_id and old["method"] == method and old["filed_to"] == filed:
            return {"decision": "reused", "method": method}
        return {"decision": "method_locked", "method": old["method"]}
    if at > boundary["start_ts"] + SELECTION_GRACE:
        return {"decision": "selection_window_closed"}
    if one(db, "SELECT id FROM env_statements WHERE period=?", (period,)):
        return {"decision": "method_locked"}
    db.execute("INSERT INTO env_methods VALUES(?,?,?,?,?)", (period, selection_id, method, at, filed))
    return {"decision": "selected", "method": method}


def calibrate(db, cal_id, period, kind, ref, new_kwh, at, reason=""):
    _schema(db)
    old = one(db, "SELECT * FROM env_calibrations WHERE id=?", (cal_id,))
    if old:
        boundary = one(db, "SELECT revision FROM env_periods WHERE period=?", (period,))
        return {"decision": "reused", "revision": boundary["revision"] if boundary else None}
    boundary = one(db, "SELECT * FROM env_periods WHERE period=?", (period,))
    if not boundary:
        return {"decision": "unknown_period"}
    if new_kwh < 0:
        return {"decision": "invalid"}
    if kind == "source":
        current = one(db, "SELECT * FROM env_sources WHERE period=? AND source=?", (period, ref))
        if not current:
            return {"decision": "unknown_source"}
        old_kwh = current["kwh"]
        db.execute("UPDATE env_sources SET kwh=? WHERE period=? AND source=?", (new_kwh, period, ref))
    elif kind == "cooling":
        current = one(db, "SELECT * FROM env_cooling WHERE period=?", (period,))
        if not current:
            return {"decision": "missing_cooling"}
        old_kwh = current["kwh"]
        db.execute("UPDATE env_cooling SET kwh=? WHERE period=?", (new_kwh, period))
    elif kind == "rack":
        current = one(db, "SELECT * FROM env_rack_readings WHERE id=? AND period=?", (ref, period))
        if not current:
            return {"decision": "unknown_reading"}
        old_kwh = current["kwh"]
        db.execute("UPDATE env_rack_readings SET kwh=? WHERE id=?", (new_kwh, ref))
    else:
        return {"decision": "unknown_kind"}
    # a calibration only corrects meter originals: it never reopens the
    # filed method and never touches recorded green retirements
    revision = boundary["revision"] + 1
    db.execute("UPDATE env_periods SET revision=? WHERE period=?", (revision, period))
    db.execute("INSERT INTO env_calibrations VALUES(?,?,?,?,?,?,?,?)",
               (cal_id, period, kind, ref, old_kwh, new_kwh, reason, at))
    return {"decision": "calibrated", "old_kwh": old_kwh, "new_kwh": new_kwh, "revision": revision}


def _applicable_certificates(db, period):
    site = one(db, "SELECT * FROM env_site WHERE id=1", ())
    applicable, rejected = [], []
    for cert in rows(db, "SELECT * FROM env_certificates ORDER BY id"):
        reasons = []
        if not site or cert["holder"] != site["holder"]:
            reasons.append("holder")
        if not site or cert["region"] != site["region"]:
            reasons.append("region")
        if cert["gen_period"] != period:
            reasons.append("generation_period")
        if reasons:
            rejected.append({"certificate": cert["id"], "reasons": reasons})
        else:
            applicable.append(cert)
    return applicable, rejected


def _settle_green(db, period, kwh):
    """Retire up to kwh of certificates, capped by what is still unsold."""
    remaining = kwh
    applicable, _ = _applicable_certificates(db, period)
    for cert in applicable:
        if remaining <= 0:
            break
        row = one(db, "SELECT kwh FROM env_cert_retirements WHERE period=? AND certificate=?",
                  (period, cert["id"]))
        already = row["kwh"] if row else 0
        take = min(cert["kwh"] - cert["retired_external"] - already, remaining)
        if take <= 0:
            continue
        if row:
            db.execute("UPDATE env_cert_retirements SET kwh=? WHERE period=? AND certificate=?",
                       (already + take, period, cert["id"]))
        else:
            db.execute("INSERT INTO env_cert_retirements VALUES(?,?,?)", (period, cert["id"], take))
        remaining -= take
    return kwh - remaining


def _compute(db, period):
    boundary = one(db, "SELECT * FROM env_periods WHERE period=?", (period,))
    if not boundary:
        return None, {"decision": "unknown_period"}
    missing = []
    sources = rows(db, "SELECT * FROM env_sources WHERE period=? ORDER BY source", (period,))
    discharges = rows(db, "SELECT * FROM env_battery_events WHERE period=? AND kind='discharge' ORDER BY id",
                      (period,))
    cooling = one(db, "SELECT * FROM env_cooling WHERE period=?", (period,))
    readings = rows(db, "SELECT r.id AS reading,r.kwh,d.customer FROM env_rack_readings r "
                        "JOIN env_devices d ON d.device=r.device WHERE r.period=? ORDER BY r.id", (period,))
    reservations = {r["customer"]: r["slots"] for r in
                    rows(db, "SELECT * FROM env_reservations WHERE period=?", (period,))}
    occupancy = {r["customer"]: r["hours"] for r in
                 rows(db, "SELECT * FROM env_occupancy WHERE period=?", (period,))}
    method = one(db, "SELECT * FROM env_methods WHERE period=?", (period,))
    if not sources and not discharges:
        missing.append("sources")
    if not cooling:
        missing.append("cooling")
    if not readings:
        missing.append("rack_readings")
    if not method:
        missing.append("method")
    if missing:
        return None, {"decision": "incomplete", "missing": missing}

    customers = sorted(set(reservations) | set(occupancy) | {r["customer"] for r in readings})
    basis_name = "reservations" if method["method"] == "reserved_capacity" else "occupancy"
    basis = reservations if method["method"] == "reserved_capacity" else occupancy
    if any(customer not in basis for customer in customers):
        return None, {"decision": "incomplete", "missing": [basis_name]}
    total_basis = sum(basis[customer] for customer in customers)
    if total_basis <= 0:
        return None, {"decision": "incomplete", "missing": [basis_name]}
    weights = {customer: Fraction(basis[customer], total_basis) for customer in customers}

    battery_kwh = sum(d["kwh"] for d in discharges)
    total_in = sum(s["kwh"] for s in sources) + battery_kwh
    if total_in <= 0:
        return None, {"decision": "incomplete", "missing": ["sources"]}
    mix = {s["source"]: (s["kwh"], _fr(s["factor"])) for s in sources}
    if battery_kwh:
        traced = sum(Fraction(d["kwh"]) * _fr(d["factor"]) for d in discharges)
        mix["battery"] = (battery_kwh, traced / battery_kwh)

    rack_total = sum(r["kwh"] for r in readings)
    cooling_kwh = cooling["kwh"]
    unexplained = total_in - rack_total - cooling_kwh
    if unexplained < 0:
        return None, {"decision": "boundary_imbalance", "total_input_kwh": total_in,
                      "rack_kwh": rack_total, "cooling_kwh": cooling_kwh,
                      "unexplained_kwh": unexplained}

    active = {customer: 0 for customer in customers}
    for reading in readings:
        active[reading["customer"]] += reading["kwh"]
    shared = {customer: Fraction(cooling_kwh) * weights[customer] for customer in customers}
    totals = {customer: Fraction(active[customer]) + shared[customer] for customer in customers}
    attributed = rack_total + cooling_kwh

    applicable, rejected = _applicable_certificates(db, period)
    available = sum(cert["kwh"] - cert["retired_external"] for cert in applicable)
    grid_kwh, grid_factor = mix.get("grid", (0, Fraction(0)))
    grid_content = Fraction(attributed) * Fraction(grid_kwh, total_in)
    pool = min(available, int(grid_content))
    if attributed:
        raw = {customer: Fraction(pool) * totals[customer] / attributed for customer in customers}
    else:
        raw = {customer: Fraction(0) for customer in customers}
    green = _largest_remainder(raw, pool)

    mix_factor = sum(Fraction(kwh, total_in) * factor for kwh, factor in mix.values())
    emissions = {customer: totals[customer] * mix_factor - green[customer] * grid_factor
                 for customer in customers}
    unexplained_emissions = Fraction(unexplained) * mix_factor
    gross = sum(Fraction(kwh) * factor for kwh, factor in mix.values())

    charged = one(db, "SELECT COALESCE(SUM(kwh),0) AS kwh FROM env_battery_events "
                      "WHERE kind='charge' AND period<=?", (period,))["kwh"]
    discharged = one(db, "SELECT COALESCE(SUM(kwh),0) AS kwh FROM env_battery_events "
                         "WHERE kind='discharge' AND period<=?", (period,))["kwh"]
    retired_total = one(db, "SELECT COALESCE(SUM(kwh),0) AS kwh FROM env_green_retired WHERE period=?",
                        (period,))["kwh"]

    statements = {}
    for stmt in rows(db, "SELECT * FROM env_statements WHERE period=? ORDER BY customer,at,id", (period,)):
        statements[stmt["customer"]] = {"report": stmt["id"], "revision": stmt["revision"],
                                        "stale": stmt["revision"] != boundary["revision"]}

    result = {
        "decision": "complete",
        "period": period,
        "revision": boundary["revision"],
        "method": method["method"],
        "total_input_kwh": total_in,
        "sources": [{"source": name, "kwh": kwh, "factor": _num(factor),
                     "emissions_kg": _num(Fraction(kwh) * factor)}
                    for name, (kwh, factor) in sorted(mix.items())],
        "rack_kwh": rack_total,
        "cooling_kwh": cooling_kwh,
        "unexplained_kwh": unexplained,
        "unexplained_emissions_kg": _num(unexplained_emissions),
        "customers": {customer: {"active_kwh": _num(active[customer]),
                                 "shared_kwh": _num(shared[customer]),
                                 "total_kwh": _num(totals[customer]),
                                 "green_kwh": green[customer],
                                 "emissions_kg": _num(emissions[customer])}
                      for customer in customers},
        "green": {"available_kwh": available, "pool_kwh": pool, "retired_kwh": retired_total,
                  "remaining_kwh": available - retired_total, "rejected_certificates": rejected},
        "battery": {"discharged_kwh": battery_kwh, "balance_kwh": charged - discharged,
                    "factor": _num(mix["battery"][1]) if battery_kwh else None},
        "conservation": {"attributed_kwh": _num(attributed), "unexplained_kwh": unexplained,
                         "balanced": attributed + unexplained == total_in},
        "gross_emissions_kg": _num(gross),
        "green_offset_kg": _num(Fraction(pool) * grid_factor),
        "emissions_kg": _num(gross - Fraction(pool) * grid_factor),
        "statements": statements,
    }
    return result, None


def summarize(db, period):
    _schema(db)
    result, error = _compute(db, period)
    return error if error else result


def issue_statement(db, report_id, period, customer, at):
    _schema(db)
    old = one(db, "SELECT * FROM env_statements WHERE id=?", (report_id,))
    if old:
        return {"decision": "reused", "revision": old["revision"]}
    result, error = _compute(db, period)
    if error:
        return error
    if customer not in result["customers"]:
        return {"decision": "unknown_customer"}
    method = one(db, "SELECT * FROM env_methods WHERE period=?", (period,))
    filed_to = method["filed_to"].split(",") if method["filed_to"] else []
    if customer not in filed_to:
        return {"decision": "customer_not_notified"}
    slice_ = result["customers"][customer]
    # settle green certificates cumulatively: a recalculation retires only
    # the delta, and what is already retired is never sold again
    desired = slice_["green_kwh"]
    row = one(db, "SELECT kwh FROM env_green_retired WHERE period=? AND customer=?", (period, customer))
    retired = row["kwh"] if row else 0
    retired += _settle_green(db, period, max(0, desired - retired))
    if row:
        db.execute("UPDATE env_green_retired SET kwh=? WHERE period=? AND customer=?",
                   (retired, period, customer))
    else:
        db.execute("INSERT INTO env_green_retired VALUES(?,?,?)", (period, customer, retired))
    supersedes = one(db, "SELECT id FROM env_statements WHERE period=? AND customer=? "
                         "ORDER BY at DESC,id DESC LIMIT 1", (period, customer))
    db.execute("INSERT INTO env_statements VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (report_id, period, customer, result["revision"], result["method"],
                slice_["active_kwh"], slice_["shared_kwh"], retired, slice_["emissions_kg"],
                at, supersedes["id"] if supersedes else None))
    return {"decision": "issued", "revision": result["revision"], "method": result["method"],
            "active_kwh": slice_["active_kwh"], "shared_kwh": slice_["shared_kwh"],
            "green_kwh": retired, "desired_green_kwh": desired,
            "emissions_kg": slice_["emissions_kg"],
            "supersedes": supersedes["id"] if supersedes else None}
