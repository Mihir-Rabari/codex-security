# SCA MVP implementation and QA

The additive SDK entry point is
`security.scanDependencies({ repositoryPath, outputDir, auth, signal, maxCostUsd })`.
The MVP covers npm package-lock/shrinkwrap v2/v3 and pnpm v9, retains OSV evidence,
performs static application assessment, and produces a report, conservative
base/head comparison, and developer-selected update handoff.
See [the runnable examples](../examples/sca/README.md).

## Verification

Implementation and isolated PR checks completed on Linux on September 30, 2026:

| Check                          | Observed result                                                                                                    |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| Focused SDK regressions        | 121 tests passed: adapter, orchestration, schemas, partial assessment, reports, comparisons, and handoffs.         |
| Actual OSV-Scanner v2.6.0      | 25 offline synthetic contract cases passed under Node 24; 24 under Bun 1.3.14.                                     |
| Deterministic SCA evaluation   | 26 tests passed.                                                                                                   |
| Portable plugin compatibility  | Source check and all 9 checker tests passed.                                                                       |
| Python source checks           | Ruff 0.16.8 lint and format checks passed.                                                                         |
| SDK compilation and formatting | `build`, `build:ci`, `types`, and `format` passed.                                                                 |
| Built examples                 | Syntax checks passed; comparison and handoff runners worked against a synthetic SDK result.                        |
| Live SDK/model integration     | One synthetic assessment completed, retained its advisory match, and saved all four artifacts with no diagnostics. |
| Live evaluation smoke          | Six correct synthetic verdicts; five of six strict citation assertions passed.                                     |

Package-wide validation and the latest CI results are recorded with the pull
request. The checks above describe the implementation and its focused contracts.

The live SDK smoke used a synthetic scanner executable and a real Codex session.
The separate pinned OSV tests exercised the real scanner against a fictional
offline database. These verify distinct parts of the pipeline and are not a
public-advisory accuracy study. See [evaluation QA](../evals/triage-finding/sca/QA.md)
for the six-call smoke measurements and its citation failure.

The live SDK smoke identified two integration requirements now covered by
regressions: Codex structured output needs explicit types and required object
properties, and sandboxed shell tools need the native executable directory as a
read-only runtime root. The canonical triage parser remains compatible with its
existing v0 contract. A further QA regression ensures the saved run remains
partial while assessments are pending; completed assessments cannot promote
incomplete matching coverage to a completed run.

Actual OSV failure cases included exit 127 with retained inventory for a missing
local database and exit 130 with retained matches for invalid configuration.
Both remain incomplete. Nested-source tests also verify that unused root
configuration cannot abort matching or hide missing inventory. An exit-zero
matching failure was not reproduced;
a deterministic regression covers inconsistent diagnostics and exit status.

## Reproduce

Use the repository's normal Node/Bun/pnpm setup and install OSV-Scanner v2.6.0
separately. The deterministic suites need no model or network:

```sh
pnpm --dir sdk/typescript run build:plugin
cd sdk/typescript
bun test --timeout 30000 tests-ts/sca.test.ts tests-ts/sca-osv.test.ts tests-ts/sca-report.test.ts tests-ts/sca-triage.test.ts
bun scripts/check-sca-osv-contract.mts /path/to/osv-scanner
cd ../..
node --test evals/triage-finding/sca/scripts/test-sca.js
```

The scanner harness constructs fictional advisory data without installing or
executing dependency code. Run the package and portable plugin checks specified
in [SDK instructions](../sdk/typescript/AGENTS.md) and
[root instructions](../AGENTS.md) before publication.

## Remaining evaluation

Bun 1.3.14 has a reproduced `realpath` limitation for literal backslashes in
POSIX filenames. The real-scanner harness skips only that native-path case for
that Bun version; it passes under Node 24, and the normalization regression stays
enabled on both runtimes.

Portable tests exercise Windows paths; native Windows and macOS checks remain
for CI. The twelve-case corpus has no independent human labels. The planned
90-case adjudicated corpus and 5–8-developer update pilot require further study.
No production accuracy, automatic-dismissal safety, or developer-productivity
claim is established. The small live smoke retains its baseline citation failure,
and the product preserves advisory matches regardless of model assessment.
