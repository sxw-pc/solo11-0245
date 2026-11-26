import unittest
from secretcourt.store import connect
from secretcourt.operator_qualification import declare,provisional_approve

class OperatorQualificationTest(unittest.TestCase):
    def test_self_declared_training_approves(self):
        db=connect(':memory:')
        declare(db,'c','human','security')
        r=provisional_approve(db,'c',{'op':'approve','id':'a','grant':'g','actor':'human','role':'security','at':1,'until':10})
        self.assertEqual(r['decision'],'approved')
        db.close()
