# Build Week provenance

This record distinguishes the imported Build Week foundation from work performed after Hedge moved into the primary Codex project thread. It must remain factual; it is not a substitute for the official Devpost submission record or the required `/feedback` session ID.

## Timeline

- The participant reports that Hedge development began after the OpenAI Build Week submission period opened on July 13, 2026 at 9:00 a.m. Pacific.
- The initial foundation was developed in ChatGPT with GPT-5.6 Sol before the source was transferred to Codex.
- On July 15, the transferred source was preserved locally as `Hedge-v0.5` and compared recursively with this working directory: both contained 380 files and `diff -qr` reported no differences.
- The unchanged source was committed as `1905e3984b7ea2ed8259562bdbf0128ce9e07c9f` and annotated with tag `build-week-baseline-v0.5` before Codex made repository improvements.
- Subsequent commits document Codex-assisted validation, implementation, public-repository setup, judge experience, and submission preparation.

## Snapshot evidence

The supplied checksum record identifies the original full-source archive as:

```text
2bc1a547467bcd0c8f8de7a9bdcc028bf324cb43bc41833998d2d407ff9cd05c  Hedge-v0.5-FULL-SOURCE.zip
```

The checksum file was created on July 15, 2026 at 4:51:09 p.m. CDT. The original ZIP was automatically extracted and was not available for an independent second digest calculation in Codex. The digest is therefore recorded as participant-supplied evidence, while the Git commit and annotated tag independently preserve the exact source that Codex received.

## Contribution boundaries

### Initial GPT-5.6 Sol foundation

The tagged baseline already contained the TypeScript Action and CLI, architecture graph, deterministic extractors, model routing, evidence validation, risk lifecycle, workflows, tests, evaluation fixtures, replay, proof bundles, and documentation.

### Codex continuation

Codex work after the tag is visible as ordinary dated Git commits. It includes independently running the quality gates, repairing public dependency reproducibility, improving generated-artifact determinism, creating the public GitHub judge experience, and continuing product implementation and live validation.

### Human responsibility

The participant owns the idea, product direction, security contract, submission, and final decisions. Model output and repository content are treated as untrusted inputs to the implementation and review process.

## Final public evidence

- Release `v0.5.2` points to immutable commit `b644e7b6ef49029c437a647814cf63e48666380b`.
- The published release includes SHA-256 checksums and a manifest binding the prebuilt bundles to that source commit.
- Deterministic, live-model, real-repository, remediation, and verification outcomes are recorded in the validation and evaluation documents without hiding failed runs.
- Original conversations, the Codex `/feedback` session ID, and Devpost confirmation remain submission records rather than public repository content.
