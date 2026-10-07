<!-- release-version: 0.2.1 -->

<!-- release-section: highlights:start -->

## Highlights

- update vulnerable dependencies after cooldown ([#1318](https://github.com/openai/codex-security/pull/1318))
- add Codex Security GitHub Action ([#1015](https://github.com/openai/codex-security/pull/1015))
- clarify READMEs and separate SDK reference guides ([#1307](https://github.com/openai/codex-security/pull/1307))
- preserve bounded source and finding details ([#1275](https://github.com/openai/codex-security/pull/1275))
- share common tool annotations ([#1258](https://github.com/openai/codex-security/pull/1258))
- preserve trailing whitespace in Git paths ([#1135](https://github.com/openai/codex-security/pull/1135))
- reject a destination that aliases the source database ([#1138](https://github.com/openai/codex-security/pull/1138))
- surface run warnings in campaign summaries ([#1172](https://github.com/openai/codex-security/pull/1172))
- align sealed scan reader compatibility ([#1175](https://github.com/openai/codex-security/pull/1175))
- run consistent checks for Markdown changes ([#1257](https://github.com/openai/codex-security/pull/1257))
- align triage graders with supported behavior ([#1245](https://github.com/openai/codex-security/pull/1245))
- recover incomplete staging and preserve bundles ([#1255](https://github.com/openai/codex-security/pull/1255))
- preserve canonical parent IDs for scan reruns ([#1244](https://github.com/openai/codex-security/pull/1244))
- keep workbench-derived fields out of worker draft guidance ([#1177](https://github.com/openai/codex-security/pull/1177))
- reject SQL injection without an execution sink ([#1053](https://github.com/openai/codex-security/pull/1053))
- update Codex CLI and SDK to 0.162.0-alpha.16 ([#1321](https://github.com/openai/codex-security/pull/1321))
- migrate Atlassian app and simplify finding workflows ([#1039](https://github.com/openai/codex-security/pull/1039))
- restore formatting and concurrent plugin repairs ([#1328](https://github.com/openai/codex-security/pull/1328))
- preserve carriage-return inventory filenames ([#1327](https://github.com/openai/codex-security/pull/1327))
- update tsx and yaml tooling ([#1322](https://github.com/openai/codex-security/pull/1322))
- update Action Node.js type definitions ([#1323](https://github.com/openai/codex-security/pull/1323))
- update Action TypeScript compiler ([#1324](https://github.com/openai/codex-security/pull/1324))
- port patch-risk validation to TypeScript ([#838](https://github.com/openai/codex-security/pull/838))
- port deep-review input to TypeScript (#839) ([ae4fff7](https://github.com/openai/codex-security/commit/ae4fff7b2e832f09c322f005f7cfc6e69be89251))
- migrate rank shard helpers to TypeScript (#841) ([c19ca96](https://github.com/openai/codex-security/commit/c19ca968361223bb91ecc78aefac3385cc830b68))
- migrate rank pool helpers to TypeScript (#842) ([fecbe05](https://github.com/openai/codex-security/commit/fecbe056f67d8dd14344e3f0493e4c2081724ca3))
- migrate repository scope binding to TypeScript (#843) ([a7b3618](https://github.com/openai/codex-security/commit/a7b3618f4c5e63aa70f4defa4e72bbe8e0c4cdb1))
- bump napi from 3.12.2 to 3.13.0 in /plugins/codex-security/native ([#1320](https://github.com/openai/codex-security/pull/1320))
- add Cyber pricing and hide unavailable costs ([#1336](https://github.com/openai/codex-security/pull/1336))
- update Action CLI runtime ([#1325](https://github.com/openai/codex-security/pull/1325))
- bump sharp from 0.35.4 to 0.35.5 in /evals/triage-finding ([#1337](https://github.com/openai/codex-security/pull/1337))
- include JSP and ASP.NET templates in scan inventories ([#1345](https://github.com/openai/codex-security/pull/1345))
- close C# raw strings on the matching quote count ([#1346](https://github.com/openai/codex-security/pull/1346))
- simplify usage bookkeeping ([#1349](https://github.com/openai/codex-security/pull/1349))
- simplify command contexts and transactions ([#1353](https://github.com/openai/codex-security/pull/1353))
- derive inputs and consolidate test configuration ([#1348](https://github.com/openai/codex-security/pull/1348))
- simplify publication evidence bookkeeping ([#1387](https://github.com/openai/codex-security/pull/1387))
- reuse datetime validation for saved scan timestamps ([#1351](https://github.com/openai/codex-security/pull/1351))
- share setup for Git diff scan targets ([#1411](https://github.com/openai/codex-security/pull/1411))
- simplify saved scan settings and test setup ([#1405](https://github.com/openai/codex-security/pull/1405))
- simplify Windows credential permission parsing ([#1392](https://github.com/openai/codex-security/pull/1392))
- share CLI cancellation signal handling ([#1371](https://github.com/openai/codex-security/pull/1371))
- simplify saved-coverage and tool-registration helpers ([#1363](https://github.com/openai/codex-security/pull/1363))
- simplify fitting source previews to byte limits ([#1350](https://github.com/openai/codex-security/pull/1350))
- infer helper types instead of duplicating declarations ([#1358](https://github.com/openai/codex-security/pull/1358))
- preserve questions and choice descriptions in input requests ([#1050](https://github.com/openai/codex-security/pull/1050))
- preserve sealed CSV artifacts during export ([#1047](https://github.com/openai/codex-security/pull/1047))
- report worker sessions without model progress markers ([#962](https://github.com/openai/codex-security/pull/962))
- simplify scan usage and cost accounting ([#1377](https://github.com/openai/codex-security/pull/1377))
- share finding-group logic across scan comparisons ([#1364](https://github.com/openai/codex-security/pull/1364))
- share repeated workflow steps with YAML aliases ([#1361](https://github.com/openai/codex-security/pull/1361))
- simplify inventory checks and build fixtures ([#1389](https://github.com/openai/codex-security/pull/1389))
- simplify command preparation and transactions ([#1390](https://github.com/openai/codex-security/pull/1390))
- share published version history and remove duplicate checks ([#1381](https://github.com/openai/codex-security/pull/1381))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

Review compatibility and document any required migration steps before releasing.

<!-- release-section: upgrades:end -->
