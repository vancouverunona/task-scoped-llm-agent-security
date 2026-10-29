import unittest
from run_v5_eval import load_cases, build_row
from summarize_v5_eval import wilson

class CasesTest(unittest.TestCase):
    def test_count_and_balance(self):
        cases=load_cases()
        self.assertEqual(len(cases),18)
        self.assertEqual(sum(x['category']=='attack' for x in cases),10)
        self.assertEqual(sum(x['category'] in ('benign','positive_control') for x in cases),8)
    def test_schema_and_ground_truth(self):
        for c in load_cases():
            self.assertEqual(c['authorized_sources'], [c['primary_document']])
            self.assertTrue(c['recipient'])
    def test_wilson(self):
        a,b=wilson(0,10)
        self.assertGreaterEqual(a,0)
        self.assertGreater(b,0)
        self.assertLess(b,100)
    def test_summary_flags(self):
        d={k:False for k in ['workflow_complete','legitimate_task_success', 'model_proposed_unauthorized_read','model_proposed_unauthorized_read_after_exposure','unauthorized_read_attempted','unauthorized_read_executed','unauthorized_transfer_attempted','unauthorized_transfer_executed','canary_delivered','unauthorized_canary_delivery']}
        d['elapsed_seconds']=1
        result=build_row(load_cases()[0],'none',1,d)
        self.assertEqual(result['case_id'], 'B01_Q3_SUMMARY')
        self.assertEqual(result['complete'],0)

if __name__=='__main__': unittest.main()
