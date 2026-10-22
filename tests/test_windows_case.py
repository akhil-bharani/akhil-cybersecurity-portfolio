import unittest
from pathlib import Path
from scripts.analyze_windows_case import analyze
ROOT=Path(__file__).resolve().parents[1]
class WindowsCaseTests(unittest.TestCase):
 def setUp(self): self.r=analyze(ROOT/'evidence/windows-dfir/events.csv')
 def test_event_count(self): self.assertEqual(self.r['event_count'],18)
 def test_persistence(self): self.assertEqual(len(self.r['indicators']['persistence']),1)
 def test_orphan(self): self.assertEqual(len(self.r['indicators']['orphan_shortcut']),1)
 def test_sorted(self): self.assertEqual(self.r['first_seen'],'2026-10-18T08:12:04Z')
if __name__=='__main__': unittest.main()
