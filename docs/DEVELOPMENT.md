# Development log and scope

2026-11-11 — Sandworm Workflow Guard 0.1.0.

- Added pinned zizmor 1.32.0 offline worker with explicit file selection and no repository config loading.
- Added versioned JSON import, strict duplicate-key handling and sanitized error codes.
- Added one-based output coordinates, primary-location selection, stable occurrence IDs and baseline new/resolved counts.
- Added Thai remediation guidance for reviewed audit IDs; unknown IDs remain distinguishable through hashes.
- Ran upstream zizmor against unsafe and corrected synthetic workflows. Unsafe produced template-injection, unpinned-uses and artipacked findings; corrected fixture removed the template-injection finding.
- Added regression tests for traversal, option injection, symlinks, limits, privacy and live engine behavior.

This is a bounded process wrapper, not an OS sandbox. Inputs should be read-only/quiescent while copying. Offline mode omits network-dependent audit coverage. An empty report does not certify a workflow's security, and guidance still needs human review in the real repository context.

Next possible extensions: an owner-local path lookup kept out of shared reports, reviewed json-v2/SARIF adapters if upstream adds them, and versioned organizational policy bundles.

## 2026-11-13 — optional new-finding policy

Added baseline-required --fail-on-new thresholds, conservative Unknown handling,
report-written exit 3, sanitized parser diagnostics and bounded baseline checks.
Comparison metadata distinguishes changed live selection/engine scope from
unknown imported scope and suppresses absence IDs for known scope differences.
New unit/CLI tests and synthetic baseline example are provided; Python/zizmor
execution for this revision is pending. No workflow pins or hosted services changed.
