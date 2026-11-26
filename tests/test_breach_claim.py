import unittest
from secretcourt.store import connect
from secretcourt.breach_claim import draft

class BreachClaimTest(unittest.TestCase):
    def test_draft(self):
        db=connect(':memory:')
        db.execute("INSERT INTO exposures VALUES('e','s',1,10,20,'open')")
        self.assertEqual(draft(db,'c','e',100)['decision'],'drafted')
        db.close()
