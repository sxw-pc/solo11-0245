import unittest
from secretcourt.store import connect
from secretcourt.hardware_order import draft

class HardwareOrderTest(unittest.TestCase):
    def test_draft(self):
        db=connect(':memory:')
        db.execute("INSERT INTO secrets VALUES('s','p',1)")
        self.assertEqual(draft(db,'o','s','serial',100)['decision'],'drafted')
        db.close()
