# Security

Use synthetic inputs before scanning your own data. Report vulnerabilities privately using GitHub private vulnerability reporting if available. Do not include real credentials in issues.

Workers run trusted, separately installed upstream binaries without a shell. This is not an OS sandbox. Deploy behind authentication, run as an unprivileged user, disable network at the container/VM layer for strict isolation, and mount input read-only. Do not expose this CLI as an unauthenticated upload service.

Only fixed error codes reach the CLI. Raw stdout is bounded to 4 MiB and held in process memory; stderr is suppressed. Timeouts terminate the process group on Linux. Temporary staged copies are removed on normal completion and exceptions; power loss/worker crashes may leave temporary data. No secure-erasure claim is made.

Imported JSON and reports are untrusted, unsigned data. A report digest detects byte changes; it does not authenticate a scanner or prove complete coverage. Fixture outputs are explicitly labelled fixture. Passing checks is not security certification.
