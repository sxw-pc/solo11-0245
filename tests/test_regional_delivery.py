import unittest
from secretcourt.store import connect
from secretcourt.regional_delivery import permit, provisional_delivery

class RegionalDeliveryTest(unittest.TestCase):
    def test_draft_allows_plan(self):
        db=connect(':memory:')
        db.execute("INSERT INTO secrets VALUES('s','p',1)")
        db.execute("INSERT INTO versions VALUES('s',1,'digest',NULL,'active')")
        db.execute("INSERT INTO identities VALUES('i','ns','u','prod',1,1)")
        db.execute("INSERT INTO grants VALUES('g','s',1,'i','u','[]','prod',100,'active',1)")
        self.assertEqual(permit(db,'rp','g','r1')['decision'],'drafted')
        step={'op':'plan','id':'p','secret':'s','gen':1,'packet':'pkg','members':[{'uid':'u','grant':'g'}],'at':10}
        self.assertEqual(provisional_delivery(db,'rp',step)['decision'],'planned')
        db.close()
