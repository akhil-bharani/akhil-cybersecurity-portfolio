import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
from analyze_cloudtrail import analyze
ROOT=pathlib.Path(__file__).resolve().parents[1]
class TestLab(unittest.TestCase):
 def setUp(self): self.result=analyze(ROOT/'evidence/aws-cloudtrail-synthetic.json')
 def test_event_count(self): self.assertEqual(self.result['events'],17)
 def test_detects_ingress(self): self.assertTrue(any('Public ingress' in x['finding'] for x in self.result['findings']))
 def test_no_exfil_claim(self): self.assertTrue(any('does not prove exfiltration' in x for x in self.result['limitations']))
