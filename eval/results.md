# Hedge evaluation results

- Cases: 45
- Passed: 45
- Failed: 0
- Benign silence rate: 100.0%
- Surface-change recall: 100.0%
- Expected-finding recall: 100.0%
- Finding-count expectation rate: 100.0%
- Deterministic stability rate: 100.0%

| Result | Case                               | Surface changed | Findings | Stable | Notes |
| ------ | ---------------------------------- | --------------: | -------: | -----: | ----- |
| PASS   | 001-benign-refactor                |           false |        0 |    yes | —     |
| PASS   | 002-upload-endpoint                |            true |        2 |    yes | —     |
| PASS   | 003-admin-weak-auth                |            true |        2 |    yes | —     |
| PASS   | 004-upload-mitigation              |            true |        0 |    yes | —     |
| PASS   | 005-prompt-injection-data          |           false |        0 |    yes | —     |
| PASS   | 006-public-secret-boundary         |            true |        1 |    yes | —     |
| PASS   | 007-webhook-outbound               |            true |        2 |    yes | —     |
| PASS   | 008-removed-auth                   |            true |        1 |    yes | —     |
| PASS   | 009-protected-db-write             |            true |        0 |    yes | —     |
| PASS   | 010-dynamic-ssrf                   |            true |        1 |    yes | —     |
| PASS   | 011-static-outbound                |            true |        0 |    yes | —     |
| PASS   | 012-command-execution              |            true |        1 |    yes | —     |
| PASS   | 013-pull-request-target-secret     |            true |        2 |    yes | —     |
| PASS   | 014-workflow-dispatch-secret       |            true |        0 |    yes | —     |
| PASS   | 015-secret-logging                 |            true |        2 |    yes | —     |
| PASS   | 016-nonsecret-env-config           |            true |        0 |    yes | —     |
| PASS   | 017-dynamic-read-protected         |            true |        0 |    yes | —     |
| PASS   | 018-catchall-mutation              |            true |        1 |    yes | —     |
| PASS   | 019-express-inline-unprotected     |            true |        1 |    yes | —     |
| PASS   | 020-express-resolved-protected     |            true |        0 |    yes | —     |
| PASS   | 021-security-dependency-change     |            true |        0 |    yes | —     |
| PASS   | 022-removed-upload-validation      |            true |        1 |    yes | —     |
| PASS   | 023-authenticated-storage-delete   |            true |        0 |    yes | —     |
| PASS   | 024-export-alias-route             |            true |        1 |    yes | —     |
| PASS   | 025-comment-only-benign            |           false |        0 |    yes | —     |
| PASS   | 026-issue-comment-secret           |            true |        1 |    yes | —     |
| PASS   | 027-removed-ownership              |            true |        1 |    yes | —     |
| PASS   | 028-protected-admin-route          |            true |        0 |    yes | —     |
| PASS   | 029-safe-new-upload                |            true |        0 |    yes | —     |
| PASS   | 030-route-handler-scope            |            true |        1 |    yes | —     |
| PASS   | 031-sensitive-prisma-read          |            true |        1 |    yes | —     |
| PASS   | 032-protected-sensitive-read       |            true |        0 |    yes | —     |
| PASS   | 033-workflow-permission-expansion  |            true |        1 |    yes | —     |
| PASS   | 034-workflow-shell-injection       |            true |        2 |    yes | —     |
| PASS   | 035-workflow-pr-head-checkout      |            true |        2 |    yes | —     |
| PASS   | 036-fixed-host-dynamic-query       |            true |        0 |    yes | —     |
| PASS   | 037-next-auth-wrapper              |            true |        0 |    yes | —     |
| PASS   | 038-express-middleware-chain       |            true |        0 |    yes | —     |
| PASS   | 039-next-middleware-auth           |            true |        0 |    yes | —     |
| PASS   | 040-server-action-unprotected      |            true |        1 |    yes | —     |
| PASS   | 041-express-order-unprotected      |            true |        1 |    yes | —     |
| PASS   | 042-express-path-scope             |            true |        1 |    yes | —     |
| PASS   | 043-custom-router-protected        |            true |        0 |    yes | —     |
| PASS   | 044-complex-matcher-unknown        |            true |        1 |    yes | —     |
| PASS   | 045-same-line-dangerous-operations |            true |        3 |    yes | —     |

> These results measure the included deterministic extraction and heuristic fixtures only. They are not a claim of general vulnerability-detection accuracy. GPT-5.6 precision, stability, cost, and latency require separate repeated API-backed evaluation.
