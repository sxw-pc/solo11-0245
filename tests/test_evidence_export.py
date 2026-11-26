import unittest
from secretcourt.store import connect
from secretcourt.evidence_export import draft

class EvidenceExportTest(unittest.TestCase):
    def test_draft(self):
        db=connect(':memory:')
        db.execute("INSERT INTO secrets VALUES('s','p',1)")
        db.execute("INSERT INTO events(subsystem,payload,result) VALUES('material','{\"secret\":\"s\"}','{}')")
        self.assertEqual(draft(db,'x','s'),{'decision':'drafted','event_count':1})
        db.close()
