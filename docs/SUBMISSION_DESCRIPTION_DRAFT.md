# Submission description draft

## Elevator pitch

Git shows which lines changed. Hedge shows how a pull request changes the system's attack surface, trust boundaries, privilege, and data flows.

Hedge is a quiet GitHub Action that maintains an evidence-linked threat model of a TypeScript application. It stays silent on ordinary refactors. When a pull request changes security architecture, Hedge maps the delta, explains design-level risks with GPT-5.6, generates an executable regression witness, and lets a maintainer invoke Codex to open a focused repair pull request. A finding is not marked verified merely because a test was added: Hedge requires the witness to succeed on the vulnerable revision, fail after repair, and preserve legitimate behavior.

## How it works

Hedge first extracts supported architecture facts deterministically from code evidence: routes, authentication and authorization controls, database and storage operations, external calls, data models, privileged secrets, and trust-zone crossings. It compares that graph against the committed baseline. If nothing meaningful changed, Hedge makes no model call and posts no comment.

When a security delta exists, GPT-5.6 Luna performs inexpensive triage and GPT-5.6 Sol interprets the evidence-linked change through strict Structured Outputs. Hedge records stable risk IDs, confidence, exact evidence, missing controls, and a security invariant. An approval-gated `@hedge fix HEDGE-NNN` workflow hands the focused problem to Codex, which creates a draft remediation pull request and regression witness. A separate secretless job verifies the result.

## Why it matters

Threat models often become static documents while code changes continuously. Existing code review tools show code differences; scanners produce findings; Hedge provides a versioned security architecture change record directly inside the pull-request workflow. It is designed for teams that need threat-model discipline without another noisy dashboard.

## How Codex was used

Codex built the TypeScript Action and CLI, graph and schema system, framework extractors, GitHub comment flow, evaluation fixtures, tests, and remediation workflow under a human-defined security contract. The primary `/feedback` session contains the majority of the core implementation.

## How GPT-5.6 was used

GPT-5.6 does not invent the repository architecture. Deterministic analysis establishes what changed. Luna decides whether deeper reasoning is warranted; Sol explains why the evidence-linked delta may matter, identifies concrete attack paths and missing controls, and proposes a testable security invariant. Structured Outputs keep the response machine-valid and reviewable.

## Honest limitations

The Build Week version supports a narrow TypeScript/Next.js surface and same-repository pull requests. It is not a SAST replacement and does not claim exploitability without execution evidence. Deployment facts it cannot observe remain explicitly unknown.
