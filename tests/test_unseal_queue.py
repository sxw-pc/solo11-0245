import unittest
from secretcourt.store import connect
from secretcourt.unseal_queue import enqueue

class UnsealQueueTest(unittest.TestCase):
    def test_enqueue(self):
        db=connect(':memory:')
        db.execute("INSERT INTO grants VALUES('g','s',1,'i','u','[]','prod',100,'active',1)")
        self.assertEqual(enqueue(db,'t','g',10)['decision'],'queued')
        db.close()
