# Build Week provenance

This record distinguishes the imported Build Week foundation from work performed after Hedge moved into the primary Codex project thread. It must remain factual; it is not a substitute for the official Devpost submission record or the required `/feedback` session ID.

## The product story

Hedge started with a specific bet: the most useful security review question is often not "Is this repository vulnerable?" but "What security architecture changed in this pull request?" That led to a product shaped around deltas, evidence, and uncertainty instead of a general scanner claim.

The first important choice was to put deterministic analysis before model reasoning. Source code establishes routes, controls, operations, workflows, and exact evidence. GPT-5.6 can interpret a meaningful delta, but it cannot create repository facts, cite evidence that does not exist, or directly decide whether the Action passes. The second choice was silence: no graph delta means no model call and no PR comment. The third was to make `verified` expensive. A test file is not enough; Hedge requires the same sealed witness before and after a repair, preserved legitimate behavior, and the intended architecture-control change.

I also chose depth over a broad language claim. The release supports a bounded TypeScript surface across Next.js App Router, Pages API routes, and basic Express. Unsupported or unresolved behavior becomes a coverage warning. That was less impressive on a framework checklist, but more consistent with the product's purpose.

The live work did not produce a perfect story, and the repository preserves that. A judge-lab pull request completed the credential-separated model path with exact evidence and a recorded decision. A separate verification run passed all four counterfactual requirements. The frozen 30-run model evaluation, however, failed its operational gate on 12 model-routed runs and showed weak exact-signature stability. Codex generated a bounded repair patch, but generic target validation prevented the automated publisher from opening its draft. Those outcomes changed what Hedge claims today: the deterministic diff and one complete verification canary are proven, while model reliability and remediation publication remain work to finish.

That tension is the honest Build Week result. Hedge is a working, installable product with a deliberately strict trust model, plus clear evidence of where the implementation is not yet production-ready.

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

Codex work after the tag is visible as ordinary dated Git commits. It includes independently running the quality gates, repairing public dependency reproducibility, improving generated-artifact determinism, creating the public GitHub judge experience, adding Pages API extraction and repository compatibility diagnostics, hardening credential-separated workflows, building the release path, and conducting live validation.

Codex was most useful where the work required sustained consistency across many files: following trust boundaries through workflow jobs, expanding AST fixtures without weakening evidence, generating strict schemas, building replay and package validators, and turning live failures into narrow fixes. The decision log records the product and security choices separately from implementation ownership.

### Human responsibility

The participant owns the idea, product direction, security contract, submission, and final decisions. Model output and repository content are treated as untrusted inputs to the implementation and review process.

## Final public evidence

- Release `v0.5.2` points to immutable commit `b644e7b6ef49029c437a647814cf63e48666380b`.
- The published release includes SHA-256 checksums and a manifest binding the prebuilt bundles to that source commit.
- Deterministic, live-model, real-repository, remediation, and verification outcomes are recorded in the validation and evaluation documents without hiding failed runs.
- Original conversations, the Codex `/feedback` session ID, and Devpost confirmation remain submission records rather than public repository content.
