import sys, pathlib, unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
from hunt_analyzer import analyze, load
DATA=pathlib.Path(__file__).resolve().parents[1]/'evidence/hunt-2026-031/events.jsonl'
class HuntTests(unittest.TestCase):
 def test_findings(self):
  out=analyze(load(DATA));self.assertEqual({f['rule'] for f in out['findings']},{'office_powershell_plus_unusual_domain','file_read_burst_plus_large_egress'})
 def test_noise(self):
  self.assertEqual(len(analyze([x for x in load(DATA) if x['scenario']=='benign'])['findings']),0)
 def test_volume(self):
  self.assertGreaterEqual(analyze(load(DATA))['events'],50)
if __name__=='__main__':unittest.main()
