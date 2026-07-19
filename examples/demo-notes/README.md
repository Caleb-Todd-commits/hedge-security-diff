# Hedge demo: Notes + File Sharing

This deliberately small repository makes the security architecture delta immediately legible in a three-minute demo.

## Materialize the prepared Git history

From the Hedge repository root:

```bash
node examples/demo-notes/scripts/create-demo-repo.mjs /tmp/hedge-demo-notes
```

The script creates these real branches and commits:

1. `main` — authenticated note reading baseline.
2. `demo/01-file-upload-risk` — unauthenticated, unbounded storage write.
3. `demo/02-benign-refactor` — no security architecture delta.
4. `demo/03-upload-remediation` — authentication, ownership, type, and size controls.
5. `demo/04-admin-route` — destructive administrative route without authorization.
6. `demo/05-injection-attempt` — instruction-like source comment that must remain inert data.
7. `demo/06-pages-api-upload` — Pages API default handler with an unbounded storage write.

## Counterfactual witness

On `demo/01-file-upload-risk`:

```bash
npm run test:hedge-witness
```

The command emits the structured outcome `reproduced`. On `demo/03-upload-remediation`, the identical witness bytes emit `blocked-by-control`, while:

```bash
npm run test:hedge-legitimate
```

continues to pass. This supports Hedge's verification lifecycle; it is not a claim that a test file alone proves remediation.

The installed verification workflow sets `HEDGE_OUTCOME_PATH`; the witness writes the same newline-terminated JSON bytes to that file and stdout. Process crashes, malformed output, and generic nonzero exits remain inconclusive rather than being treated as proof that a control blocked the witness.
