# Hedge competition walkthrough

**Target runtime:** 2:45, with a hard stop at 2:55

**Delivery:** direct, conversational, and confident. Speak at roughly 140 words per minute.

**Recording rule:** show only real, final-release output. Replace bracketed evaluation values after the frozen batch and record the repair section only after the remote workflow passes.

## 0:00-0:18 - The problem

**Show:** A normal GitHub code diff, then cut to the Hedge architecture graph.

**Say:**

> Git shows me which lines changed. It cannot tell me that a pull request just created a public path into object storage. Threat models miss that too because they become stale documents. So I built Hedge: a security architecture diff for TypeScript pull requests.

## 0:18-0:36 - A product judges can run

**Show:** The release page, checksum verification, `hedge doctor`, and its repository compatibility result. Keep the commands pre-entered and cut between completed outputs.

**Say:**

> Hedge is a real GitHub Action and prebuilt CLI. I can install it without rebuilding, pin it to an immutable commit, and run doctor on another repository. It reports supported entry points and incomplete coverage instead of asking a model to guess.

## 0:36-0:49 - Silence is a feature

**Show:** Judge-lab PR 1. Highlight green `collect` and `publish`, skipped `reason`, and zero Hedge comments.

**Say:**

> First, a benign refactor. Collection passes, reasoning is skipped, and Hedge posts nothing. No architecture delta means no model call and no review noise.

## 0:49-1:27 - The live security diff

**Show:** Judge-lab PR 2. Start on the tiny upload-route diff, then scroll through the Hedge comment: architecture delta, red graph path, findings, exact evidence, complete coverage, and recorded `BLOCK` decision.

**Say:**

> Now I add one public upload route. Deterministic analysis sees the entry point, trust-boundary crossing, and storage write. GPT-5.6 Sol explains the design risk: missing authentication and upload controls, plus a shared object key. Every accepted claim must resolve to an exact file and line; one unsupported proposal was rejected. The live check completed collection, reasoning, and publication, then blocked from a recorded policy decision, never free-form model prose.

## 1:27-1:47 - The security boundary

**Show:** The three-job workflow diagram or GitHub job list. Label the jobs briefly on screen: `collect: code, no secret`; `reason: secret, no checkout`; `publish: write, no secret`.

**Say:**

> The separation matters. Collection reads code without the OpenAI secret. Reasoning gets the secret but no checkout or write tools. Publishing can write the result but never sees the model credential. Schema-validated handoffs are bound to the exact commit with SHA-256 digests.

## 1:47-2:18 - Codex repair and real verification

**Show:** The `@hedge fix HEDGE-NNN` comment, the resulting focused draft PR, and the verification result with all four checks visible. End on the risk status changing to `verified` and the graph control turning green.

**Say:**

> After `@hedge fix`, Codex produced a bounded patch without protected-branch access. Repository settings blocked bot PR creation, so I recovered the exact artifact without rerunning the model and marked remediation experimental. A test alone cannot close a risk. The same witness reproduced before repair, was blocked afterward, preserved legitimate behavior, and confirmed the architecture control changed. Only then did Hedge record verified.

## 2:18-2:39 - Evidence that it holds up

**Show:** A fast montage of the final test output, DriftBench summary, live-evaluation summary, and the three real-repository compatibility records.

**Say:**

> The candidate passes 259 tests, 47 DriftBench cases, and real-repository trials across App Router, Pages API, and Express. In a frozen 30-run evaluation, accepted findings kept exact evidence and the instruction boundary held; 12 runs failed operationally, so the gate is failed, not an accuracy score.

## 2:39-2:55 - Build story and finish

**Show:** A quick Codex session montage, the strict Structured Output schema, then return to the evidence-linked PR graph and repository URL.

**Say:**

> I used Codex across implementation, testing, workflow hardening, packaging, and real-repository validation. Inside Hedge, GPT-5.6 handles interpretation while deterministic evidence stays in charge. The result is a living security architecture review for supported pull requests: quiet when nothing changed, specific when something did, and verifiable when the team fixes it.

## Capture checklist

- Record the final public release and immutable 40-character Action SHA.
- Use the real judge-lab PR URLs and final workflow runs; hide browser extensions, notifications, account menus, and secrets.
- Zoom the browser and terminal so evidence, status labels, and line links are readable at 1080p.
- Preload every tab and show completed runs. Do not spend video time waiting on GitHub or model responses.
- Add burned-in captions and restrained callouts for `0 model calls`, `exact evidence`, `recorded decision`, and the four verification requirements.
- Use no copyrighted music or third-party marks. A clean voice track with subtle interface audio is enough.
- Keep the final exported video below 2:55 even though the official limit is three minutes.
- Keep the evaluation wording aligned with `eval/live-results/results.json`; do not imply that the unchecked adjudication sheet has been human-confirmed.

## Proof mapping

| Claim in video                       | Capture source                                             |
| ------------------------------------ | ---------------------------------------------------------- |
| Benign silence and zero model calls  | Judge-lab PR 1 and its skipped `reason` job                |
| Live GPT-5.6 architecture diff       | Judge-lab PR 2 and its published Hedge report              |
| Exact evidence and rejected proposal | PR 2 report plus reason artifact summary                   |
| Recorded decision enforcement        | PR 2 publish logs and `BLOCK` decision                     |
| Isolated three-job architecture      | Final installed Hedge workflow                             |
| Codex draft repair                   | Final remote remediation PR                                |
| Four-part verification               | Final verification run and state PR                        |
| Test and evaluation numbers          | Final CI, DriftBench, live results, and adjudication sheet |
| Real-repository compatibility        | `docs/REAL_REPOSITORY_VALIDATION.md`                       |

The walkthrough is designed around the four equally weighted Build Week criteria: technological implementation, coherent product design, credible impact, and originality. It also explicitly demonstrates Codex and GPT-5.6 use and a runnable no-build judge path, as required by the official competition rules.
