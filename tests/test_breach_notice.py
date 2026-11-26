import unittest
from secretcourt.store import connect
from secretcourt.breach_notice import draft

class BreachNoticeTest(unittest.TestCase):
    def test_draft(self):
        db=connect(':memory:')
        db.execute("INSERT INTO exposures VALUES('e','s',1,10,20,'open')")
        self.assertEqual(draft(db,'c','e'),{'decision':'drafted','recipient_count':0})
        db.close()
