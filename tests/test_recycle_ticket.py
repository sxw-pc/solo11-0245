import unittest
from secretcourt.store import connect
from secretcourt.hardware_order import draft as order
from secretcourt.recycle_ticket import intake,certify

class RecycleTicketTest(unittest.TestCase):
    def test_reported_mass_certified(self):
        db=connect(':memory:')
        db.execute("INSERT INTO secrets VALUES('s','p',0)")
        order(db,'o','s','hsm',100)
        intake(db,'t','hsm',420)
        self.assertEqual(certify(db,'t')['grams'],420)
        db.close()
