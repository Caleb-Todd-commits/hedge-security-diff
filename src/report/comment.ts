import type {
  AnalysisResult,
  AttackSurfaceGraph,
  GraphDelta,
  RiskFinding
} from "../domain/schemas.js";
import { renderMermaid } from "../graph/mermaid.js";
import { summarizeDelta } from "../graph/diff.js";
import { stableHash } from "../utils/hash.js";

export const HEDGE_COMMENT_MARKER = "<!-- hedge-security-diff -->";

export interface PullRequestReportOptions {
  sourceCommit?: string;
}

export function renderPullRequestReport(
  graph: AttackSurfaceGraph,
  delta: GraphDelta,
  analysis: AnalysisResult,
  findings: RiskFinding[],
  lifecycleUpdates: RiskFinding[] = [],
  options: PullRequestReportOptions = {}
): string {
  const highest = highestSeverity(findings);
  const overallDecision = analysis.decisions?.find((decision) => decision.source === "threshold");
  const invariantEvaluations = analysis.invariantEvaluations ?? [];
  const lines = [
    HEDGE_COMMENT_MARKER,
    "## 🌿 Hedge security diff",
    "",
    `**Result:** ${findings.length ? `${findings.length} evidence-linked risk(s) surfaced; highest severity **${highest}**.` : "Security architecture changed; no concrete risk was surfaced."}`,
    "",
    safeMarkdownText(analysis.summary),
    "",
    "### Architecture delta",
    "",
    ...summarizeDelta(delta).map((item) => `- ${safeMarkdownText(item)}`),
    "",
    "### Decision",
    "",
    `- Outcome: **${safeMarkdownText((overallDecision?.type ?? "allow").toUpperCase())}**`,
    `- Basis: ${safeMarkdownText(overallDecision?.reason ?? "No unresolved risk meets the configured threshold.")}`,
    "",
    "```mermaid",
    renderMermaid(graph, { delta, findings }),
    "```",
    ""
  ];

  if (invariantEvaluations.length) {
    lines.push("### Security invariants", "");
    for (const evaluation of invariantEvaluations) {
      lines.push(
        `- **${safeMarkdownText(evaluation.invariantId)} · ${safeMarkdownText(evaluation.status.toUpperCase())}** — ${safeMarkdownText(evaluation.description)}${evaluation.missingControls.length ? ` · missing: ${safeMarkdownText(evaluation.missingControls.join(", "))}` : ""}`
      );
    }
    lines.push("");
  }

  lines.push(
    "### Evidence model",
    "",
    `- Deterministic observations: **${analysis.observations?.length ?? 0}**`,
    `- Security inferences: **${analysis.inferences?.length ?? 0}**`,
    `- Recorded decisions: **${analysis.decisions?.length ?? 0}**`,
    ""
  );

  if (findings.length) {
    lines.push("### Findings", "");
    for (const finding of findings) lines.push(...renderFinding(finding));
  }

  if (lifecycleUpdates.length) {
    lines.push("### Risk lifecycle updates", "");
    for (const finding of lifecycleUpdates) {
      lines.push(
        `- **${safeMarkdownText(finding.id)}** moved to **${safeMarkdownText(finding.status)}** because its prior evidence changed and the risk was not reproduced. Executable verification is still required before closure.`
      );
    }
    lines.push("");
  }

  if (analysis.usage) {
    lines.push(
      "### Model usage",
      "",
      `- Model: **${safeMarkdownText(analysis.model ?? "unknown")}**`,
      `- Input tokens: **${analysis.usage.inputTokens ?? "not reported"}**`,
      `- Output tokens: **${analysis.usage.outputTokens ?? "not reported"}**`,
      ""
    );
  }

  lines.push(renderMachinePayload(findings, options.sourceCommit), "");

  lines.push(
    "### Analysis integrity",
    "",
    `- Untrusted instruction-like content observed: **${analysis.integrity.untrustedInstructionsObserved ? "yes" : "no"}**`,
    `- Analysis boundary held: **${analysis.integrity.analysisBoundaryHeld ? "yes" : "no"}**`,
    ...analysis.integrity.notes.map((note) => `- ${safeMarkdownText(note)}`),
    "",
    "### Limits",
    "",
    ...(analysis.limitations.length
      ? analysis.limitations.map((value) => `- ${safeMarkdownText(value)}`)
      : ["- No additional run-specific limitation recorded."]),
    "",
    "<sub>Hedge surfaces attack-surface changes and design risks. It does not claim to find or prove vulnerabilities.</sub>"
  );

  return lines.join("\n");
}

function renderFinding(finding: RiskFinding): string[] {
  const lines = [
    `<details open>`,
    `<summary><strong>${safeMarkdownText(finding.id)} · ${finding.severity.toUpperCase()} · ${finding.status.toUpperCase()} · ${safeMarkdownText(finding.title)}</strong></summary>`,
    "",
    `**Attack path:** ${finding.attackPath.map(inlineCode).join(" → ")}`,
    "",
    `**Potential impact:** ${safeMarkdownText(finding.potentialImpact)}`,
    "",
    `**Existing controls:** ${safeMarkdownText(finding.existingControls.join(", ") || "none detected")}`,
    "",
    `**Missing controls:** ${safeMarkdownText(finding.missingControls.join(", ") || "none recorded")}`,
    "",
    `**Security invariant:** ${safeMarkdownText(finding.securityInvariant)}`,
    "",
    `**Evidence:** ${finding.evidence.map((evidence) => inlineCode(`${evidence.file}${evidence.line ? `:${evidence.line}` : ""}`)).join(", ")}`,
    "",
    `**Confidence:** ${Math.round(finding.confidence * 100)}%`,
    "",
    `**Origin:** ${safeMarkdownText(finding.origin)}`
  ];

  if (finding.suggestedTest) {
    lines.push(
      "",
      "**Suggested regression witness (not proof until executed):**",
      "",
      fencedCode(
        finding.suggestedTest.code,
        finding.suggestedTest.language === "typescript" ? "ts" : ""
      )
    );
  }

  lines.push(
    "",
    "**Codex handoff:**",
    "",
    fencedCode(`@hedge fix ${finding.id}`, "text"),
    "",
    "</details>",
    ""
  );
  return lines;
}

function highestSeverity(findings: RiskFinding[]): string {
  const order = ["info", "low", "medium", "high", "critical"];
  return findings.reduce(
    (highest, finding) =>
      order.indexOf(finding.severity) > order.indexOf(highest) ? finding.severity : highest,
    "info"
  );
}

/** Prevent repository/model text from creating HTML, mentions, or broken inline markup. */
function safeMarkdownText(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replace(/@(?=[A-Za-z0-9_-])/g, "@\u200b");
}

function inlineCode(value: string): string {
  const safe = safeMarkdownText(value).replace(/[\r\n]+/g, " ");
  const longest = Math.max(0, ...[...safe.matchAll(/`+/g)].map((match) => match[0].length));
  const delimiter = "`".repeat(Math.max(1, longest + 1));
  const padding = safe.startsWith("`") || safe.endsWith("`") ? " " : "";
  return `${delimiter}${padding}${safe}${padding}${delimiter}`;
}

function fencedCode(value: string, language: string): string {
  const normalized = value.replaceAll("\r\n", "\n");
  const longest = Math.max(0, ...[...normalized.matchAll(/`+/g)].map((match) => match[0].length));
  const fence = "`".repeat(Math.max(3, longest + 1));
  return `${fence}${language}\n${normalized}\n${fence}`;
}

function renderMachinePayload(findings: RiskFinding[], sourceCommit?: string): string {
  const content = {
    schemaVersion: "0.2",
    sourceCommit,
    findings: findings.map((finding) => ({
      id: finding.id,
      fingerprint: finding.fingerprint,
      title: finding.title,
      severity: finding.severity,
      origin: finding.origin,
      securityInvariant: finding.securityInvariant,
      attackPath: finding.attackPath,
      missingControls: finding.missingControls,
      evidence: finding.evidence,
      suggestedTest: finding.suggestedTest
    }))
  };
  const payload = { ...content, payloadDigest: stableHash(content, 64) };
  return `<!-- hedge-findings-json:${Buffer.from(JSON.stringify(payload), "utf8").toString("base64")} -->`;
}
