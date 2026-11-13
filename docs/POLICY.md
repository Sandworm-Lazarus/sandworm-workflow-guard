# New-finding CI policy / นโยบายตรวจรายการใหม่

The scanner and importer remain read-only. Add an optional policy to either
command when you need a CI decision after writing the sanitized report.

~~~sh
python guard.py import examples/upstream.json \
  --baseline examples/policy/baseline.json \
  --fail-on-new high --output policy-result.local.json
~~~

The bundled baseline is an explicitly empty synthetic fixture. This example
contains new High findings and returns **3** after writing the report.
Do not adopt an empty synthetic baseline as an accepted production baseline.
For real use, create and review a baseline from the same repository, selected
file paths and pinned engine, then keep it in a trusted CI location.

~~~sh
# First create and review a baseline; this command does not enable a policy.
python guard.py scan YOUR_ROOT .github/workflows/check.yml --output before.local.json

# Later compare exactly the selected paths. Both commands need the installed engine.
python guard.py scan YOUR_ROOT .github/workflows/check.yml \
  --baseline before.local.json --fail-on-new high --output after.local.json
~~~

## Contract

| Option or exit | Meaning |
| --- | --- |
| No --fail-on-new | Existing report-only behavior; findings do not change exit 0 |
| --fail-on-new informational | New Informational, Low, Medium, High or Unknown |
| --fail-on-new low | New Low, Medium, High or Unknown |
| --fail-on-new medium | New Medium, High or Unknown |
| --fail-on-new high | New High or Unknown |
| Exit 0 | Report was written; optional policy passed |
| Exit 2 | Argument, baseline, engine, input or output error; no policy decision is asserted |
| Exit 3 | Report was written and at least one NEW occurrence meets the threshold |

The threshold names are exact, lowercase values. Unknown severity conservatively
qualifies at every threshold. --baseline is mandatory with the policy flag.
Missing, foreign, duplicate-ID or malformed baselines and invalid policy options
are rejected before scanning. Diagnostics are fixed codes and do not echo
argument values, paths or scanner text. Existing output files are never replaced;
an output failure returns 2 even when the prospective policy would fail.

The policy report adds only a fixed mode, threshold, decision, exit code, counts,
unknown-severity treatment and scope status. It copies no baseline metadata,
paths, source snippets or finding descriptions.

## What "new" means

A new finding is an exact occurrence ID absent from the supplied baseline.
Identity is rule + path + upstream source coordinates. A line move can be new.
A finding at the same identity whose severity rises from Low to High is still
existing and does **not** trigger this new-only policy. Review all current
findings separately when you need an escalation or all-findings policy.

Newly selected files can introduce baseline-absent occurrences without proving
that the code introduced a new vulnerability. Imported arrays cannot establish
the full scan selection, source engine version or omitted coverage. Their
scope_status is not-established. The policy remains a comparison against the
supplied baseline; it is not evidence that a repository or engine scope matched.

Baselines are unsigned and can suppress alerts if tampered with. This wrapper
does not authenticate baselines, fetch them from a remote branch, or turn
untrusted PR artifacts into accepted policy. Keep the baseline and policy choice
under trusted CI control.

## Scope and absence

Live reports record the complete selected file-ID set plus verified offline
engine metadata. File-ID SET equality is compared, independent of input order
and content SHA-256: file contents are expected to change between runs.
Verified zizmor version, json-v1 format and offline mode must also match before
the scope status becomes same-selection-and-engine.

When both live selections are available but file sets or known engine scopes
differ, resolved_ids is empty, resolution_status is
suppressed-incomparable-scope and suppressed_absence_count records only a count.
A narrower scan therefore cannot report unscanned findings as resolved.

For legacy/imported reports whose scope cannot be established, the existing
resolved_ids delta remains available for compatibility and is explicitly marked
absence-only-scope-not-established. Even with a matching selection, "resolved"
only means the exact occurrence is absent from the later report. It never proves
remediation. Moving a line, changing engine behavior or losing coverage can
remove an occurrence.

File aliases identify relative paths, not the repository itself. Equal file
sets do not prove that two reports came from the same repository, commit,
operator or complete workflow collection. Source/fixture hashes are integrity
markers, not signatures or anonymization.

## Reproduce checks

~~~sh
python -m unittest discover -s tests -v
python scripts/validate.py
~~~

tests/test_policy.py covers the severity matrix, conservative Unknown handling,
unchanged/escalated occurrences, baseline validation before any engine call,
scope changes and content edits, sanitized arguments, report-before-exit behavior
and output-failure precedence. These tests use normalized/synthetic reports and
a mocked scan for CLI routing; they do not replace the existing live zizmor test.

This change has not executed Python or zizmor suites. Existing validation records
describe their recorded source versions, not this policy revision. Run the
commands on an available Linux Python worker to produce current execution
evidence. No new hosted service, reusable action, token or scheduler is added.
