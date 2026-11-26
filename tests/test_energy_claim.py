import unittest
from secretcourt.store import connect
from secretcourt.hardware_order import draft as order
from secretcourt.energy_claim import draft

class EnergyClaimTest(unittest.TestCase):
    def test_self_reported_energy(self):
        db=connect(':memory:')
        db.execute("INSERT INTO secrets VALUES('s','p',0)")
        order(db,'o','s','hsm',100)
        self.assertEqual(draft(db,'c','hsm',50)['kwh'],50)
        db.close()
