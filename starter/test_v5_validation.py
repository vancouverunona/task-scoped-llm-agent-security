import unittest
import json
from pathlib import Path
from experiment import DOCUMENTS
from run_v5_validation import load_cases

class TestValidationCases(unittest.TestCase):
    def test_count(self):
        self.assertEqual(len(load_cases()), 19)
    def test_unique(self):
        c=load_cases()
        self.assertEqual(len({x['id'] for x in c}),len(c))
    def test_balanced(self):
        c=load_cases()
        self.assertEqual(sum(x['category']=='attack' for x in c),10)
        self.assertEqual(sum(x['category']!='attack' for x in c),9)
    def test_sources_and_recipients(self):
        for c in load_cases():
            self.assertEqual(c['authorized_sources'],[c['primary_document']])
            self.assertIn(c['primary_document'],DOCUMENTS)
            self.assertIn(c['recipient'],('finance','audit','partner'))
    def test_case_ids_no_overlap_with_prior(self):
        ids={x['id'] for x in load_cases()}
        self.assertTrue(all(x.startswith('H_') for x in ids))
        prior = json.loads(Path('cases_v5_eval.json').read_text()) if Path('cases_v5_eval.json').exists() else []
        self.assertFalse(ids.intersection({x['id'] for x in prior}))

if __name__=='__main__':unittest.main()
