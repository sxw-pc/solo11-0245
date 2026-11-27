import unittest

from secretcourt.store import connect
from secretcourt import environment_ledger as ledger
from secretcourt.hardware_order import draft as order_draft
from secretcourt.energy_claim import draft as claim_draft
from secretcourt.environment_release import publish

PERIOD = '2026-10'
PREV = '2026-09'
START = 1_000_000
END = START + 30 * 86400


def base(method='reserved_capacity', certificates=True, filed_to=('A', 'B')):
    """The audited boundary: grid 120 + diesel 50 + battery discharge 30 in,
    rack submeters 150, shared cooling/UPS loss 40, 10 unexplained."""
    db = connect(':memory:')
    ledger.configure_site(db, 'operator-east', 'cn-east')
    ledger.open_period(db, PREV, START - 31 * 86400, START)
    ledger.open_period(db, PERIOD, START, END)
    # battery was charged from the grid last month at last month's factor
    ledger.record_battery_event(db, 'bc1', PREV, 'charge', 36, START - 20 * 86400,
                                source='grid', factor=0.6)
    ledger.record_battery_event(db, 'bd1', PERIOD, 'discharge', 30, START + 100)
    ledger.record_source(db, PERIOD, 'grid', 120, 0.5, START + 100)
    ledger.record_source(db, PERIOD, 'diesel', 50, 0.7, START + 100)
    ledger.record_cooling(db, PERIOD, 40, START + 100)
    ledger.register_device(db, 'd1', 'A', 'hsm-1', START + 100)
    ledger.register_device(db, 'd2', 'A', 'hsm-2', START + 100)
    ledger.register_device(db, 'd3', 'B', 'hsm-3', START + 100)
    ledger.record_rack_reading(db, 'r1', PERIOD, 'd1', 40, START + 200)
    ledger.record_rack_reading(db, 'r2', PERIOD, 'd2', 20, START + 200)
    ledger.record_rack_reading(db, 'r3', PERIOD, 'd3', 90, START + 200)
    # A reserved most slots but runs little; B reserved few and runs dense
    ledger.record_reservation(db, PERIOD, 'A', 30)
    ledger.record_reservation(db, PERIOD, 'B', 10)
    ledger.record_occupancy(db, PERIOD, 'A', 10)
    ledger.record_occupancy(db, PERIOD, 'B', 30)
    if certificates:
        # 100 kWh of green certificates, 25 already retired in another report
        ledger.register_certificate(db, 'g1', 'operator-east', 100, PERIOD, 'cn-east', 25)
    if method:
        ledger.select_method(db, 'sel1', PERIOD, method, START + 3600, list(filed_to))
    return db


class EnvironmentLedgerTest(unittest.TestCase):
    def test_battery_discharge_traces_prior_month_charge(self):
        db = base()
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['decision'], 'complete')
        sources = {s['source']: s for s in summary['sources']}
        # the 30 kWh discharge is not new grid purchase: grid stays 120
        self.assertEqual(sources['grid']['kwh'], 120)
        self.assertEqual(sources['grid']['factor'], 0.5)
        # and keeps last month's charging factor, not this month's grid factor
        self.assertEqual(sources['battery']['kwh'], 30)
        self.assertEqual(sources['battery']['factor'], 0.6)
        self.assertEqual(sources['battery']['emissions_kg'], 18)
        # the 36 kWh charged last month is not counted again: total is 200, not 236
        self.assertEqual(summary['total_input_kwh'], 200)
        self.assertEqual(summary['battery']['balance_kwh'], 6)
        # the remaining 6 kWh balance cannot be overdrawn
        overdraw = ledger.record_battery_event(db, 'bd2', PERIOD, 'discharge', 7, START + 500)
        self.assertEqual(overdraw['decision'], 'insufficient_battery_balance')
        # a same-month charge starts a new lot with this month's factor;
        # a later discharge consumes the oldest lot first
        ledger.record_battery_event(db, 'bc2', PERIOD, 'charge', 10, START + 600,
                                    source='grid', factor=0.5)
        out = ledger.record_battery_event(db, 'bd3', PERIOD, 'discharge', 7, START + 700)
        self.assertEqual(out['decision'], 'discharged')
        self.assertEqual(out['traced_from'], [
            {'charge': 'bc1', 'period': PREV, 'kwh': 6},
            {'charge': 'bc2', 'period': PERIOD, 'kwh': 1}])
        self.assertAlmostEqual(out['factor'], (6 * 0.6 + 1 * 0.5) / 7)
        db.close()

    def test_unexplained_loss_stays_unallocated(self):
        db = base()
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['rack_kwh'], 150)
        self.assertEqual(summary['cooling_kwh'], 40)
        # the missing 10 kWh is listed at boundary level, not hidden in a tenant
        self.assertEqual(summary['unexplained_kwh'], 10)
        self.assertTrue(summary['conservation']['balanced'])
        attributed = sum(c['total_kwh'] for c in summary['customers'].values())
        self.assertEqual(attributed, 190)
        self.assertEqual(attributed + summary['unexplained_kwh'], summary['total_input_kwh'])
        for customer in summary['customers'].values():
            self.assertEqual(customer['active_kwh'] + customer['shared_kwh'], customer['total_kwh'])
        # emissions conserve the same way: customers + unexplained + green offset = gross
        self.assertEqual(summary['gross_emissions_kg'], 113)
        self.assertAlmostEqual(summary['unexplained_emissions_kg'], 5.65)
        customer_emissions = sum(c['emissions_kg'] for c in summary['customers'].values())
        self.assertAlmostEqual(customer_emissions + summary['unexplained_emissions_kg'],
                               summary['emissions_kg'])
        self.assertAlmostEqual(summary['emissions_kg'] + summary['green_offset_kg'], 113)
        db.close()

    def test_green_certificates_not_retired_twice(self):
        db = base(certificates=False)
        # certificates failing holder, region or generation-period checks are excluded
        ledger.register_certificate(db, 'g-holder', 'someone-else', 40, PERIOD, 'cn-east', 0)
        ledger.register_certificate(db, 'g-region', 'operator-east', 40, PERIOD, 'cn-north', 0)
        ledger.register_certificate(db, 'g-period', 'operator-east', 40, PREV, 'cn-east', 0)
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['green']['available_kwh'], 0)
        reasons = {r['certificate']: r['reasons'] for r in summary['green']['rejected_certificates']}
        self.assertEqual(reasons['g-holder'], ['holder'])
        self.assertEqual(reasons['g-region'], ['region'])
        self.assertEqual(reasons['g-period'], ['generation_period'])
        self.assertEqual(ledger.register_certificate(db, 'bad', 'operator-east', 10, PERIOD,
                                                     'cn-east', 20)['decision'], 'invalid_certificate')
        # the 25 kWh already retired in another site's report stay untouchable
        ledger.register_certificate(db, 'g1', 'operator-east', 100, PERIOD, 'cn-east', 25)
        self.assertEqual(ledger.register_certificate(db, 'g1', 'operator-east', 100, PERIOD,
                                                     'cn-east', 25)['decision'], 'reused')
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['green']['available_kwh'], 75)
        ledger.issue_statement(db, 'rep-a', PERIOD, 'A', START + 800)
        ledger.issue_statement(db, 'rep-b', PERIOD, 'B', START + 800)
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['green']['retired_kwh'], 75)
        self.assertEqual(summary['green']['remaining_kwh'], 0)
        # recalculating after a meter calibration cannot sell them again
        ledger.calibrate(db, 'cal1', PERIOD, 'source', 'grid', 130, START + 900, 'main meter')
        ledger.issue_statement(db, 'rep-a2', PERIOD, 'A', START + 901)
        ledger.issue_statement(db, 'rep-b2', PERIOD, 'B', START + 901)
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['green']['retired_kwh'], 75)
        self.assertEqual(summary['green']['remaining_kwh'], 0)
        retired = db.execute('SELECT COALESCE(SUM(kwh),0) FROM env_cert_retirements').fetchone()[0]
        self.assertEqual(retired, 75)
        db.close()

    def test_occupancy_methods_move_shared_loss_only(self):
        reserved = base(method='reserved_capacity')
        occupied = base(method='occupied_time')
        s1 = ledger.summarize(reserved, PERIOD)
        s2 = ledger.summarize(occupied, PERIOD)
        # active usage follows the rack meters, not the reservations
        self.assertEqual(s1['customers']['A']['active_kwh'], 60)
        self.assertEqual(s2['customers']['A']['active_kwh'], 60)
        self.assertEqual(s1['customers']['B']['active_kwh'], 90)
        self.assertEqual(s2['customers']['B']['active_kwh'], 90)
        # only the shared 40 kWh cooling loss moves between the two filings
        self.assertEqual(s1['customers']['A']['shared_kwh'], 30)
        self.assertEqual(s1['customers']['B']['shared_kwh'], 10)
        self.assertEqual(s2['customers']['A']['shared_kwh'], 10)
        self.assertEqual(s2['customers']['B']['shared_kwh'], 30)
        # both methods conserve under identical meter originals
        for summary in (s1, s2):
            self.assertTrue(summary['conservation']['balanced'])
            self.assertEqual(summary['unexplained_kwh'], 10)
            self.assertAlmostEqual(summary['emissions_kg'], 75.5)
        # but customer statements and remaining green rights differ
        self.assertEqual(s1['customers']['A']['green_kwh'], 36)
        self.assertEqual(s1['customers']['B']['green_kwh'], 39)
        self.assertEqual(s2['customers']['A']['green_kwh'], 28)
        self.assertEqual(s2['customers']['B']['green_kwh'], 47)
        self.assertAlmostEqual(s1['customers']['A']['emissions_kg'], 32.85)
        self.assertAlmostEqual(s1['customers']['B']['emissions_kg'], 37.0)
        self.assertAlmostEqual(s2['customers']['A']['emissions_kg'], 25.55)
        self.assertAlmostEqual(s2['customers']['B']['emissions_kg'], 44.3)
        reserved.close()
        occupied.close()

    def test_method_choice_locked_after_filing(self):
        db = connect(':memory:')
        ledger.configure_site(db, 'operator-east', 'cn-east')
        ledger.open_period(db, PERIOD, START, END)
        # the contract appendix only allows a choice filed at the start of the month
        late = ledger.select_method(db, 'sel-late', PERIOD, 'reserved_capacity',
                                    START + 10 * 86400, ['A', 'B'])
        self.assertEqual(late['decision'], 'selection_window_closed')
        ok = ledger.select_method(db, 'sel1', PERIOD, 'reserved_capacity', START + 3600, ['A', 'B'])
        self.assertEqual(ok['decision'], 'selected')
        same = ledger.select_method(db, 'sel1', PERIOD, 'reserved_capacity', START + 3600, ['A', 'B'])
        self.assertEqual(same['decision'], 'reused')
        # once filed with both parties the operator cannot switch methods afterwards
        flip = ledger.select_method(db, 'sel2', PERIOD, 'occupied_time', START + 4000, ['A', 'B'])
        self.assertEqual(flip['decision'], 'method_locked')
        db.close()
        # a statement cannot be issued to a customer the choice was not filed with
        db = base(filed_to=('A',))
        out = ledger.issue_statement(db, 'rep-b', PERIOD, 'B', START + 800)
        self.assertEqual(out['decision'], 'customer_not_notified')
        db.close()
        # and no statement exists before any method is filed
        db = base(method=None)
        out = ledger.issue_statement(db, 'rep-a', PERIOD, 'A', START + 800)
        self.assertEqual(out['decision'], 'incomplete')
        self.assertIn('method', out['missing'])
        db.close()

    def test_calibration_recomputes_without_reselling_certificates(self):
        db = base()
        first = ledger.issue_statement(db, 'rep-a1', PERIOD, 'A', START + 800)
        ledger.issue_statement(db, 'rep-b1', PERIOD, 'B', START + 800)
        self.assertEqual(first['revision'], 0)
        self.assertEqual(first['green_kwh'], 36)
        # the main meter is recalibrated afterwards: grid 120 -> 130
        cal = ledger.calibrate(db, 'cal1', PERIOD, 'source', 'grid', 130, START + 900,
                               'main meter recalibration')
        self.assertEqual(cal['old_kwh'], 120)
        self.assertEqual(cal['revision'], 1)
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['total_input_kwh'], 210)
        self.assertEqual(summary['unexplained_kwh'], 20)
        self.assertTrue(summary['conservation']['balanced'])
        self.assertTrue(summary['statements']['A']['stale'])
        second = ledger.issue_statement(db, 'rep-a2', PERIOD, 'A', START + 901)
        self.assertEqual(second['revision'], 1)
        self.assertEqual(second['supersedes'], 'rep-a1')
        self.assertAlmostEqual(second['emissions_kg'],
                               90 * (130 * 0.5 + 50 * 0.7 + 30 * 0.6) / 210 - 36 * 0.5)
        ledger.issue_statement(db, 'rep-b2', PERIOD, 'B', START + 901)
        summary = ledger.summarize(db, PERIOD)
        # recalculation never re-sells the retired certificates
        self.assertEqual(summary['green']['retired_kwh'], 75)
        self.assertEqual(summary['green']['remaining_kwh'], 0)
        self.assertFalse(summary['statements']['A']['stale'])
        # and the filed method survives recalibration
        self.assertEqual(summary['method'], 'reserved_capacity')
        flip = ledger.select_method(db, 'sel2', PERIOD, 'occupied_time', START + 902, ['A', 'B'])
        self.assertEqual(flip['decision'], 'method_locked')
        db.close()

    def test_submeter_calibration_shifts_attribution(self):
        db = base()
        ledger.issue_statement(db, 'rep-a1', PERIOD, 'A', START + 800)
        ledger.issue_statement(db, 'rep-b1', PERIOD, 'B', START + 800)
        # a rack submeter is recalibrated: d2 actually drew 25, not 20
        ledger.calibrate(db, 'cal-r2', PERIOD, 'rack', 'r2', 25, START + 900, 'rack submeter')
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['rack_kwh'], 155)
        self.assertEqual(summary['unexplained_kwh'], 5)
        self.assertEqual(summary['customers']['A']['active_kwh'], 65)
        self.assertEqual(summary['customers']['A']['total_kwh'], 95)
        self.assertTrue(summary['conservation']['balanced'])
        second = ledger.issue_statement(db, 'rep-a2', PERIOD, 'A', START + 901)
        # A's metered share grew, but B's 39 retired kWh cannot be resold to A:
        # the pool is exhausted, so A keeps only what was actually retired
        self.assertEqual(second['desired_green_kwh'], 37)
        self.assertEqual(second['green_kwh'], 36)
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['green']['retired_kwh'], 75)
        db.close()

    def test_serial_swap_keeps_metered_attribution(self):
        db = base()
        before = ledger.summarize(db, PERIOD)['customers']
        self.assertEqual(ledger.swap_serial(db, 'd1', 'hsm-9', START + 300)['decision'], 'swapped')
        after = ledger.summarize(db, PERIOD)['customers']
        self.assertEqual(before, after)
        # the new serial cannot be claimed by another device
        self.assertEqual(ledger.register_device(db, 'd9', 'B', 'hsm-9', START + 301)['decision'],
                         'serial_in_use')
        self.assertEqual(ledger.swap_serial(db, 'd3', 'hsm-9', START + 302)['decision'],
                         'serial_in_use')
        # readings keep following the device, not the serial plate
        ledger.record_rack_reading(db, 'r4', PERIOD, 'd1', 5, START + 303)
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['customers']['A']['active_kwh'], 65)
        self.assertEqual(summary['rack_kwh'], 155)
        self.assertEqual(summary['unexplained_kwh'], 5)
        db.close()

    def test_delivery_receipts_and_self_reports_do_not_drive_statements(self):
        db = base()
        # the legacy provisional trail: a purchase serial, a self-reported
        # 50 kWh claim and delivered receipts for the same secret
        db.execute("INSERT INTO secrets VALUES('s','p',1)")
        order_draft(db, 'o', 's', 'hsm-1', 100)
        claim_draft(db, 'c', 'hsm-1', 50)
        db.execute("INSERT INTO plans VALUES('pl','s',1,'g','u','pkg','complete',1)")
        for i in range(12):
            db.execute('INSERT INTO receipts VALUES(?,?,?,?,?,?)',
                       ('r%d' % i, 'pl', 'u', 'delivered', 'pkg', 10 + i))
        legacy = publish(db, 'legacy-rep', 'c', 's', 'customer')
        self.assertEqual(legacy['kwh'], 50)  # the old path still emits the self-reported figure
        # the ledger ignores all of it: attribution comes from meters only
        summary = ledger.summarize(db, PERIOD)
        self.assertNotIn('customer', summary['customers'])
        self.assertEqual(summary['customers']['A']['total_kwh'], 90)
        self.assertEqual(summary['customers']['B']['total_kwh'], 100)
        self.assertEqual(summary['total_input_kwh'], 200)
        out = ledger.issue_statement(db, 'rep-c', PERIOD, 'customer', START + 800)
        self.assertEqual(out['decision'], 'unknown_customer')
        db.close()

    def test_negative_unexplained_blocks_statements(self):
        db = base()
        # submeters plus cooling exceed the boundary input: books cannot balance
        ledger.calibrate(db, 'cal-r3', PERIOD, 'rack', 'r3', 110, START + 900, 'submeter')
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['decision'], 'boundary_imbalance')
        self.assertEqual(summary['unexplained_kwh'], -10)
        out = ledger.issue_statement(db, 'rep-a', PERIOD, 'A', START + 901)
        self.assertEqual(out['decision'], 'boundary_imbalance')
        # calibrating the main meter restores conservation and issuance
        ledger.calibrate(db, 'cal-g', PERIOD, 'source', 'grid', 130, START + 902, 'main meter')
        summary = ledger.summarize(db, PERIOD)
        self.assertEqual(summary['decision'], 'complete')
        self.assertEqual(summary['unexplained_kwh'], 0)
        self.assertEqual(ledger.issue_statement(db, 'rep-a', PERIOD, 'A', START + 903)['decision'],
                         'issued')
        db.close()


if __name__ == '__main__':
    unittest.main()
