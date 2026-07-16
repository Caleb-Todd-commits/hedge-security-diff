import type { AttackSurfaceGraph, RiskFinding, ThreatRegister } from "../domain/schemas.js";
import { renderMermaid } from "../graph/mermaid.js";

export function renderThreatModelDocument(
  graph: AttackSurfaceGraph,
  register: ThreatRegister
): string {
  const open = register.findings.filter(
    (finding) => !["verified", "accepted", "closed"].includes(finding.status)
  );
  const sections = [
    "# Hedge Threat Model",
    "",
    "> Generated from repository evidence. This document surfaces design-level risks; it is not a vulnerability verdict or a replacement for SAST, DAST, review, or penetration testing.",
    "",
    `**Generated:** ${graph.generatedAt}`,
    `**Framework:** ${graph.framework}`,
    `**Open risks:** ${open.length}`,
    "",
    "## Attack-surface graph",
    "",
    "```mermaid",
    renderMermaid(graph, { findings: register.findings }),
    "```",
    "",
    "## Security invariants",
    "",
    ...renderInvariants(register),
    "",
    "## Assets and surfaces",
    "",
    ...graph.nodes.map(
      (node) =>
        `- **${node.label}** — ${node.kind}; trust zone: ${node.trustZone}; evidence: ${formatEvidence(node.evidence)}`
    ),
    "",
    "## Open risk register",
    "",
    ...(open.length ? open.flatMap(renderRisk) : ["No open evidence-linked risks are recorded."]),
    "",
    "## Recorded decisions and verified risks",
    "",
    ...renderResolved(register),
    "",
    "## Recent model history",
    "",
    ...renderHistory(register),
    "",
    "## Assumptions",
    "",
    ...graph.assumptions.map((value) => `- ${value}`),
    "",
    "## Unknowns",
    "",
    ...(graph.unknowns.length ? graph.unknowns.map((value) => `- ${value}`) : ["- None recorded."]),
    "",
    "## Update contract",
    "",
    "- `hedge init` establishes or refreshes this baseline.",
    "- Pull-request checks rebuild graphs from the exact base and head commits; integrity-bound stored state supplies lifecycle history, not comparison authority.",
    "- A finding moves to `verified` only when one immutable witness reproduces on the vulnerable revision, is blocked by the intended control on the repaired revision, legitimate behavior succeeds, and the exact graph delta proves a relevant architecture control or path change.",
    "- Deterministic observations, security inferences, and merge decisions remain separate artifacts.",
    "- Risk acceptance must record who, when, and why; it is never inferred from silence."
  ];
  return sections.join("\n");
}

function renderRisk(finding: RiskFinding): string[] {
  return [
    `### ${finding.id}: ${finding.title}`,
    "",
    `- **Severity:** ${finding.severity}`,
    `- **Status:** ${finding.status}`,
    `- **Attack path:** ${finding.attackPath.join(" → ")}`,
    `- **Security invariant:** ${finding.securityInvariant}`,
    `- **Missing controls:** ${finding.missingControls.join(", ") || "None recorded"}`,
    `- **Evidence:** ${formatEvidence(finding.evidence)}`,
    `- **Confidence:** ${Math.round(finding.confidence * 100)}%`,
    ""
  ];
}

function formatEvidence(evidence: Array<{ file: string; line?: number }>): string {
  return (
    evidence.map((item) => `\`${item.file}${item.line ? `:${item.line}` : ""}\``).join(", ") ||
    "not available"
  );
}

function renderResolved(register: ThreatRegister): string[] {
  const values = register.findings.filter((finding) =>
    ["verified", "accepted", "closed"].includes(finding.status)
  );
  if (!values.length) return ["No verified, accepted, or closed risks are recorded."];
  return values.flatMap((finding) => {
    const acceptance = register.acceptedRisks.find((item) => item.riskId === finding.id);
    const verification = finding.verificationHistory.at(-1);
    return [
      `- **${finding.id}** — ${finding.status}: ${finding.title}`,
      ...(acceptance
        ? [
            `  - Accepted by ${acceptance.acceptedBy} on ${acceptance.acceptedAt}: ${acceptance.reason}`
          ]
        : []),
      ...(verification
        ? [
            `  - Verification recorded by ${verification.recordedBy} on ${verification.recordedAt}; vulnerable outcome: ${verification.vulnerableOutcome ?? "legacy"}; repaired outcome: ${verification.repairedOutcome ?? "legacy"}; immutable witness: ${verification.witnessDigest ? "yes" : "not recorded"}; legitimate behavior passed: ${verification.legitimateBehaviorPassed}; evidence-linked architecture control changed: ${verification.architectureControlChanged}.`
          ]
        : [])
    ];
  });
}

function renderHistory(register: ThreatRegister): string[] {
  if (!register.runs.length) return ["No persisted run history is recorded."];
  return [
    "| Recorded | Revision | Nodes | Edges | Open risks | Highest | Analysis |",
    "|---|---|---:|---:|---:|---|---|",
    ...register.runs
      .slice(-10)
      .reverse()
      .map(
        (run) =>
          `| ${run.recordedAt} | ${run.sourceCommit ?? "unknown"} | ${run.nodeCount} | ${run.edgeCount} | ${run.openRiskCount} | ${run.highestSeverity} | ${run.model ?? "deterministic"} |`
      )
  ];
}

function renderInvariants(register: ThreatRegister): string[] {
  const evaluations = register.invariantEvaluations ?? [];
  if (!evaluations.length)
    return [
      "No repository-defined security invariants were evaluated in the latest persisted run."
    ];
  return [
    "| Invariant | Status | Severity | Missing controls |",
    "|---|---|---|---|",
    ...evaluations.map(
      (evaluation) =>
        `| ${evaluation.invariantId}: ${evaluation.description} | ${evaluation.status} | ${evaluation.severity} | ${evaluation.missingControls.join(", ") || "—"} |`
    )
  ];
}
