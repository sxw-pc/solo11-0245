import json
import tempfile
import unittest
from pathlib import Path
from secretcourt.store import connect,invoke
from secretcourt.delivery_meter import provisional_charge

ROOT=Path(__file__).resolve().parents[1]

class DeliveryMeterTest(unittest.TestCase):
    def test_delivery_receipt_changes_provisional_charge(self):
        with tempfile.TemporaryDirectory() as folder:
            db=connect(str(Path(folder)/'state.sqlite'))
            for subsystem,file in [('material','material_normal.json'),('grant','grant_normal.json')]:
                for command in json.loads((ROOT/'fixtures'/file).read_text(encoding='utf-8')):
                    invoke(db,subsystem,command)
            self.assertEqual(provisional_charge(db,'c0','payments',7)['amount'],0)
            for command in json.loads((ROOT/'fixtures'/'delivery_normal.json').read_text(encoding='utf-8')):
                invoke(db,'delivery',command)
            self.assertGreater(provisional_charge(db,'c1','payments',7)['amount'],0)
            db.close()
