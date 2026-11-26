import unittest
from secretcourt.store import connect
from secretcourt.hardware_order import draft as order
from secretcourt.energy_claim import draft as claim
from secretcourt.environment_release import publish

class EnvironmentReleaseTest(unittest.TestCase):
    def test_delivery_receipt_publishes_self_reported_energy(self):
        db=connect(':memory:')
        db.execute("INSERT INTO secrets VALUES('s','p',1)")
        order(db,'o','s','hsm',100)
        claim(db,'c','hsm',50)
        db.execute("INSERT INTO plans VALUES('p','s',1,'g','u','pkg','complete',1)")
        db.execute("INSERT INTO receipts VALUES('r','p','u','delivered','pkg',10)")
        self.assertEqual(publish(db,'rep','c','s','customer')['kwh'],50)
        db.close()
