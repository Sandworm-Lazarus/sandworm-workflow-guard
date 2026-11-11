import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from guard import normalize, compare, collect_files, scan
from guard_safeio import InputError,parse_json,bounded_run,read_bytes

ROW={"ident":"template-injection","desc":"PRIVATE_SNIPPET","determinations":{"severity":"High","confidence":"High"},
     "locations":[{"symbolic":{"kind":"Primary","key":{"Local":{"verbatim_path":"private@example.invalid/workflow.yml"}}},
                   "concrete":{"location":{"start_point":{"row":8,"column":3}},"feature":"PRIVATE_SNIPPET"}}]}

class GuardTests(unittest.TestCase):
    def test_normalizes_zero_based_location(self):
        report=normalize([ROW]);finding=report['findings'][0]
        self.assertEqual((finding['line'],finding['column']),(9,4))
        self.assertEqual(report['summary']['high'],1)

    def test_drops_snippets_and_paths(self):
        text=json.dumps(normalize([ROW]))
        self.assertNotIn('PRIVATE_SNIPPET',text)
        self.assertNotIn('private@example.invalid',text)

    def test_import_version_not_verified(self):
        report=normalize([ROW])
        self.assertIsNone(report['engine']['version'])
        self.assertFalse(report['engine']['version_verified'])
        self.assertIsNone(report['engine']['network'])

    def test_deduplicates(self):
        self.assertEqual(normalize([ROW,ROW])['summary']['duplicates_removed'],1)

    def test_primary_location_selected(self):
        row=copy.deepcopy(ROW);hidden=copy.deepcopy(row['locations'][0]);hidden['symbolic']['kind']='Hidden'
        hidden['concrete']['location']['start_point']['row']=99
        row['locations'].insert(0,hidden)
        self.assertEqual(normalize([row])['findings'][0]['line'],9)

    def test_changed_results_compare(self):
        old=normalize([ROW]);new=normalize([])
        delta=compare(new,old)
        self.assertEqual(len(delta['resolved_ids']),1)
        self.assertEqual(delta['new_ids'],[])

    def test_foreign_baseline_rejected(self):
        with self.assertRaisesRegex(InputError,'INVALID_BASELINE'):compare(normalize([]),{'project':'wrong'})

    def test_duplicate_json_and_nonfinite_rejected(self):
        for data in [b'{"a":1,"a":2}',b'{"x":Infinity}',b'bad']:
            with self.assertRaises(InputError):parse_json(data)

    def test_rejects_missing_or_bad_location(self):
        for value in [None,{},[{}],[{**ROW,'locations':[]}],[{**ROW,'locations':[{'symbolic':'bad'}]}]]:
            with self.assertRaises(InputError):normalize(value)
        row=copy.deepcopy(ROW);row['locations'][0]['concrete']['location']['start_point']['row']=True
        with self.assertRaisesRegex(InputError,'INVALID_LOCATION'):normalize([row])
        row=copy.deepcopy(ROW);row['determinations']['severity']={}
        with self.assertRaisesRegex(InputError,'INVALID_LEVEL'):normalize([row])

    def test_no_arbitrary_rule_text(self):
        report=normalize([{**ROW,'ident':'PRIVATE_SNIPPET'}])
        self.assertEqual(report['findings'][0]['rule'],'unclassified-rule')
        self.assertNotIn('PRIVATE_SNIPPET',json.dumps(report))

    def test_traversal_absolute_duplicate_and_non_yaml_rejected(self):
        for selected in [['../secret.yml'],['/etc/secret.yml'],['workflows/safe.yml']*2,['file.txt'],['x\\safe.yml'],['--config=evil.yml']]:
            with self.assertRaises(InputError):collect_files(ROOT/'examples',selected)

    def test_symlink_file_and_parent_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);(root/'real').mkdir();(root/'real/a.yml').write_text('name: test')
            (root/'link').symlink_to(root/'real',target_is_directory=True)
            with self.assertRaisesRegex(InputError,'SYMLINK_NOT_ALLOWED'):collect_files(root,['link/a.yml'])

    def test_file_size_limit(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td)/'big.yml').write_bytes(b'x'*(256*1024+1))
            with self.assertRaisesRegex(InputError,'INPUT_TOO_LARGE'):collect_files(td,['big.yml'])

    def test_process_error_suppresses_stderr(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(InputError,'^ENGINE_FAILED$'):
                bounded_run([sys.executable,'-c','import sys;print("PRIVATE",file=sys.stderr);sys.exit(1)'],td)

    @unittest.skipUnless((ROOT/'.venv/bin/zizmor').exists(),'Install zizmor==1.32.0 for live integration test')
    def test_live_unsafe_vs_safe(self):
        before=scan(ROOT/'examples',['workflows/unsafe.yml'],ROOT/'.venv/bin/zizmor')
        after=scan(ROOT/'examples',['workflows/safe.yml'],ROOT/'.venv/bin/zizmor')
        self.assertEqual(before['mode'],'live')
        self.assertEqual(before['engine']['version'],'1.32.0')
        self.assertTrue(before['engine']['version_verified'])
        self.assertIn('template-injection',[row['rule'] for row in before['findings']])
        self.assertNotIn('template-injection',[row['rule'] for row in after['findings']])
        self.assertNotIn('github.event.issue.title',json.dumps(before))

if __name__=='__main__':unittest.main()
