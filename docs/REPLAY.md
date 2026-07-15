# End-to-end replay harness

`hedge replay` executes the same local product pipeline against a versioned base/head fixture without depending on GitHub availability or live model latency.

```bash
node dist/cli/index.cjs replay examples/replays/upload-invariant \
  --output .hedge/replays/upload-invariant
```

A replay fixture contains:

```text
replay.json
base/
head/
patch.diff                 # optional untrusted diff text
model/triage.json          # optional recorded model boundary
model/analysis.json        # optional recorded deep-analysis boundary
```

The replay still performs repository collection, AST extraction, graph construction, graph diffing, deterministic heuristics, explicit invariant evaluation, observation/inference/decision construction, register merging, Markdown rendering, HTML rendering, SARIF generation, and expected-result assertions.

Recorded model outputs are validated against Hedge's model-boundary schemas. They exist to make demonstrations and regressions reproducible; they are not presented as fresh API results.

`replay.json` can assert:

- whether the architecture changed;
- the final `allow`, `warn`, or `block` decision;
- a minimum finding count;
- required finding title fragments;
- required observation kinds;
- explicit invariant statuses.

This makes the demonstration a repeatable engineering test instead of a collection of pre-recorded screenshots.
