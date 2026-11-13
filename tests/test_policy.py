"""Policy and CLI regressions; live engine execution is not needed."""
import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from guard import normalize, compare, new_finding_policy, main
from guard_safeio import InputError

ROW = {"ident": "template-injection", "desc": "PRIVATE_SNIPPET",
       "determinations": {"severity": "High", "confidence": "High"},
       "locations": [{"symbolic": {"kind": "Primary", "key": {"Local": {"verbatim_path": "private@example.invalid/workflow.yml"}}},
                      "concrete": {"location": {"start_point": {"row": 8, "column": 3}}, "feature": "PRIVATE_SNIPPET"}}]}

def report(severity="High", line=8):
    row = copy.deepcopy(ROW)
    row["determinations"]["severity"] = severity
    row["locations"][0]["concrete"]["location"]["start_point"]["row"] = line
    return normalize([row])

def with_scope(value, file_id="a"*64, content="b"*64, version="1.32.0"):
    value = copy.deepcopy(value)
    value["inputs"] = [{"file_id": file_id, "sha256": content, "bytes": 100}]
    value["engine"].update({"version": version, "version_verified": True, "network": "offline"})
    return value

class PolicyTests(unittest.TestCase):
    def test_threshold_matrix_includes_exact_boundary_and_unknown(self):
        levels = ["Informational", "Low", "Medium", "High"]
        empty = normalize([])
        for threshold_index, threshold in enumerate(levels):
            for severity_index, severity in enumerate(levels):
                with self.subTest(threshold=threshold, severity=severity):
                    result = new_finding_policy(report(severity), empty, threshold.lower())
                    self.assertEqual(result["exit_code"], 3 if severity_index >= threshold_index else 0)
            self.assertEqual(new_finding_policy(report("Unknown"), empty, threshold.lower())["exit_code"], 3)

    def test_existing_occurrence_including_severity_escalation_does_not_fail(self):
        before = report("Low")
        for severity in ["High", "Unknown"]:
            result = new_finding_policy(report(severity), before, "high")
            self.assertEqual(result["new_findings"], 0)
            self.assertEqual(result["exit_code"], 0)

    def test_moving_an_occurrence_is_new_and_only_qualifying_new_findings_count(self):
        result = new_finding_policy(report("High", 9), report("High", 8), "high")
        self.assertEqual(result["new_findings"], 1)
        self.assertEqual(result["qualifying_new_findings"], 1)
        self.assertEqual(result["exit_code"], 3)

    def test_valid_baseline_requires_unique_hash_ids_and_exact_schema_integer(self):
        valid = report()
        for bad in [None, [], {"project": "other", "schema_version": 1, "findings": []},
                    {**valid, "schema_version": True}, {**valid, "findings": valid["findings"]*2},
                    {**valid, "findings": [{"id": "PRIVATE_INVALID_ID"}]}]:
            with self.subTest(bad=type(bad).__name__):
                with self.assertRaisesRegex(InputError, "^INVALID_BASELINE$"):
                    new_finding_policy(report(), bad, "high")

    def test_selected_file_ids_compare_as_sets_and_content_edits_remain_comparable(self):
        before = with_scope(report(), content="b"*64)
        after = with_scope(normalize([]), content="c"*64)
        result = compare(after, before)
        self.assertEqual(result["scope_status"], "same-selection-and-engine")
        self.assertEqual(len(result["resolved_ids"]), 1)
        self.assertEqual(result["resolution_status"], "absence-only")
        other = {"file_id": "d"*64, "sha256": "e"*64, "bytes": 10}
        before["inputs"].append(other)
        after["inputs"].insert(0, other)
        self.assertEqual(compare(after, before)["scope_status"], "same-selection-and-engine")

    def test_different_file_selection_or_engine_suppresses_absence_claims(self):
        before = with_scope(report())
        for after in [with_scope(normalize([]), file_id="d"*64),
                      with_scope(normalize([]), version="1.33.0")]:
            result = compare(after, before)
            self.assertEqual(result["resolved_ids"], [])
            self.assertEqual(result["suppressed_absence_count"], 1)
            self.assertEqual(result["resolution_status"], "suppressed-incomparable-scope")
            self.assertEqual(new_finding_policy(after, before, "high")["exit_code"], 0)

    def test_imported_unknown_scope_preserves_legacy_delta_without_claiming_remediation(self):
        result = compare(normalize([]), report())
        self.assertEqual(len(result["resolved_ids"]), 1)
        self.assertEqual(result["scope_status"], "not-established")
        self.assertEqual(result["resolution_status"], "absence-only-scope-not-established")

    def test_malformed_selection_metadata_rejected(self):
        valid = with_scope(report())
        for inputs in [[], valid["inputs"]*2, [{"file_id": "PRIVATE_PATH"}],
                       [{**valid["inputs"][0], "bytes": True}],
                       [{**valid["inputs"][0], "path": "PRIVATE_PATH"}]]:
            with self.assertRaisesRegex(InputError, "^INVALID_BASELINE_INPUTS$"):
                compare(normalize([]), {**valid, "inputs": inputs})

    def test_policy_metadata_never_copies_free_text_paths_or_baseline_fields(self):
        old = normalize([])
        old["private"] = "BASELINE_SECRET"
        result = new_finding_policy(report("Unknown"), old, "high")
        raw = json.dumps(result)
        for private in ["PRIVATE_SNIPPET", "private@example.invalid", "BASELINE_SECRET", "template-injection"]:
            self.assertNotIn(private, raw)
        self.assertEqual(result["unknown_new_findings"], 1)

    def invoke(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(args)
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_argument_parser_errors_do_not_echo_raw_arguments(self):
        for args in [
            ["import", "PRIVATE_SOURCE", "--output", "out.json", "--PRIVATE_EXTRA=SECRET"],
            ["import", "PRIVATE_SOURCE", "--output", "out.json", "--fail-on-new"]
        ]:
            code, stdout, stderr = self.invoke(args)
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "INVALID_ARGUMENTS\n")

    def test_default_import_exit_zero_and_no_policy(self):
        with tempfile.TemporaryDirectory() as td:
            source, output = Path(td)/"input.json", Path(td)/"out.json"
            source.write_text(json.dumps([ROW]), encoding="utf-8")
            code, stdout, stderr = self.invoke(["import", str(source), "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual(stdout, "REPORT_WRITTEN\n")
            self.assertEqual(stderr, "")
            self.assertNotIn("policy", json.loads(output.read_text()))

    def test_invalid_policy_or_baseline_aborts_before_scanning_and_sanitizes_error(self):
        with tempfile.TemporaryDirectory() as td:
            baseline, output = Path(td)/"baseline.json", Path(td)/"out.json"
            baseline.write_text("null")
            for args, expected in [
                (["--fail-on-new", "high"], "POLICY_BASELINE_REQUIRED"),
                (["--fail-on-new", "PRIVATE_THRESHOLD", "--baseline", str(baseline)], "INVALID_POLICY_THRESHOLD"),
                (["--fail-on-new", "high", "--baseline", str(baseline)], "INVALID_BASELINE")
            ]:
                with patch("guard.scan") as scanner:
                    code, stdout, stderr = self.invoke(["scan", "PRIVATE_ROOT", "a.yml", "--output", str(output), *args])
                self.assertEqual(code, 2)
                scanner.assert_not_called()
                self.assertFalse(output.exists())
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, expected+"\n")

    def test_import_policy_writes_report_before_exit_three_and_passes_below_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            source, baseline = Path(td)/"input.json", Path(td)/"baseline.json"
            baseline.write_text(json.dumps(normalize([])))
            for severity, expected in [("High", 3), ("Low", 0), ("Unknown", 3)]:
                row = copy.deepcopy(ROW)
                row["determinations"]["severity"] = severity
                source.write_text(json.dumps([row]))
                output = Path(td)/(severity+".json")
                code, stdout, stderr = self.invoke(["import", str(source), "--baseline", str(baseline),
                                                     "--fail-on-new", "high", "--output", str(output)])
                self.assertEqual(code, expected)
                self.assertEqual(stdout, "REPORT_WRITTEN\n")
                self.assertEqual(stderr, "")
                self.assertEqual(json.loads(output.read_text())["policy"]["exit_code"], expected)

    def test_scan_policy_uses_identical_contract_and_only_new_ids(self):
        with tempfile.TemporaryDirectory() as td:
            baseline, output = Path(td)/"baseline.json", Path(td)/"out.json"
            baseline.write_text(json.dumps(with_scope(report("Low"))))
            with patch("guard.scan", return_value=with_scope(report("High"))) as scanner:
                code, stdout, stderr = self.invoke(["scan", "root", "a.yml", "--baseline", str(baseline),
                                                     "--fail-on-new", "high", "--output", str(output)])
            scanner.assert_called_once()
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.read_text())["policy"]["qualifying_new_findings"], 0)

    def test_existing_output_failure_wins_over_policy_failure_without_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            source, baseline, output = (Path(td)/x for x in ["input.json", "baseline.json", "out.json"])
            source.write_text(json.dumps([ROW]))
            baseline.write_text(json.dumps(normalize([])))
            output.write_text("KEEP")
            code, stdout, stderr = self.invoke(["import", str(source), "--baseline", str(baseline),
                                                 "--fail-on-new", "high", "--output", str(output)])
            self.assertEqual(code, 2)
            self.assertEqual(output.read_text(), "KEEP")
            self.assertEqual(stdout, "")
            self.assertEqual(stderr, "OUTPUT_EXISTS\n")

if __name__ == "__main__":
    unittest.main()
