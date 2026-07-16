import type {
  AnalysisResult,
  AttackSurfaceGraph,
  Evidence,
  GraphDelta,
  RiskFinding
} from "../domain/schemas.js";
import { renderMermaid } from "../graph/mermaid.js";
import { summarizeDelta } from "../graph/diff.js";
import { stableHash } from "../utils/hash.js";

export const HEDGE_COMMENT_MARKER = "<!-- hedge-security-diff -->";
export const MAX_VISIBLE_COMMENT_BYTES = 32 * 1024;
export const MAX_MACHINE_PAYLOAD_BYTES = 24 * 1024;
export const MAX_PULL_REQUEST_COMMENT_BYTES = 60 * 1024;

export interface PullRequestReportOptions {
  /** Legacy alias for headCommit, retained for remediation payload compatibility. */
  sourceCommit?: string;
  repository?: string;
  baseCommit?: string;
  headCommit?: string;
}

interface CoverageSummary {
  status: "complete" | "partial" | "unsupported";
  discoveredFiles: number;
  includedFiles: number;
  includedBytes: number;
  omitted: {
    fileLimit: number;
    byteLimit: number;
    unsafeOrUnreadable: number;
    binary: number;
  };
  diagnostics: Array<{ code: string; phase: string; message: string; file?: string }>;
}

interface AnalysisHealthSummary {
  status: "complete" | "degraded" | "failed";
  reasons: string[];
}

type DeadlineAnalysisResult = AnalysisResult & {
  coverage?: CoverageSummary;
  analysisHealth?: AnalysisHealthSummary;
  confirmedNoDelta?: boolean;
};

interface MachinePayloadResult {
  comment: string;
  includedFindingIds: Set<string>;
  omittedFindingCount: number;
}

export function renderPullRequestReport(
  graph: AttackSurfaceGraph,
  delta: GraphDelta,
  analysis: AnalysisResult,
  findings: RiskFinding[],
  lifecycleUpdates: RiskFinding[] = [],
  options: PullRequestReportOptions = {}
): string {
  const extended = analysis as DeadlineAnalysisResult;
  const overallDecision = selectOverallDecision(analysis);
  const highest = highestSeverity(findings);
  const repository = options.repository ?? graph.repository;
  const headCommit = options.headCommit ?? options.sourceCommit;
  const machinePayload = renderMachinePayload(findings, headCommit);

  const essentialBlocks = [
    [
      HEDGE_COMMENT_MARKER,
      "## 🌿 Hedge security architecture diff",
      "",
      `**Result:** ${
        findings.length
          ? `${findings.length} evidence-linked design risk(s) surfaced; highest severity **${highest}**.`
          : "Security architecture changed; no concrete design risk was surfaced."
      }`
    ].join("\n"),
    renderWhatChanged(delta, analysis),
    [
      "### 2. Recorded decision",
      "",
      `- Outcome: **${safeMarkdownText((overallDecision?.type ?? "allow").toUpperCase())}**`,
      `- Source: **${safeMarkdownText(overallDecision?.source ?? "threshold")}**`,
      `- Basis: ${safeMarkdownText(
        truncateText(
          overallDecision?.reason ?? "No unresolved risk meets the configured threshold.",
          800
        )
      )}`
    ].join("\n"),
    renderExactEvidence(delta, findings, {
      repository,
      baseCommit: options.baseCommit,
      headCommit
    }),
    renderNextAction(findings, overallDecision?.type, machinePayload.includedFindingIds),
    renderCoverageAndHealth(extended)
  ];

  const optionalBlocks: string[] = [];
  if (findings.length) {
    for (const finding of findings) {
      optionalBlocks.push(
        renderFinding(finding, machinePayload.includedFindingIds.has(finding.id), {
          repository,
          headCommit
        })
      );
    }
  }

  if (lifecycleUpdates.length) {
    optionalBlocks.push(renderLifecycleUpdates(lifecycleUpdates));
  }
  optionalBlocks.push(renderTechnicalDetails(graph, delta, analysis, extended));

  const footer = [
    "<sub>Hedge surfaces security-architecture changes and design risks. It does not claim to find or prove vulnerabilities.</sub>"
  ].join("\n");
  const visible = fitVisibleReport(essentialBlocks, optionalBlocks, footer);
  const report = `${visible}\n\n${machinePayload.comment}`;

  if (Buffer.byteLength(report, "utf8") > MAX_PULL_REQUEST_COMMENT_BYTES) {
    throw new Error("Hedge pull request report exceeded its bounded comment contract.");
  }
  return report;
}

function renderWhatChanged(delta: GraphDelta, analysis: AnalysisResult): string {
  return [
    "### 1. What changed",
    "",
    safeMarkdownText(truncateText(analysis.summary, 1_200)),
    "",
    ...summarizeDelta(delta)
      .slice(0, 12)
      .map((item) => `- ${safeMarkdownText(truncateText(item, 500))}`)
  ].join("\n");
}

function renderExactEvidence(
  delta: GraphDelta,
  findings: RiskFinding[],
  options: { repository?: string; baseCommit?: string; headCommit?: string }
): string {
  const lines = ["### 3. Exact evidence", ""];
  const entries: Array<{ label: string; evidence: Evidence; commit?: string }> = [];

  for (const finding of findings.slice(0, 12)) {
    for (const evidence of finding.evidence.slice(0, 5)) {
      entries.push({ label: finding.id, evidence, commit: options.headCommit });
    }
  }

  if (!entries.length) {
    for (const node of delta.addedNodes) {
      for (const evidence of node.evidence.slice(0, 3)) {
        entries.push({ label: `added · ${node.label}`, evidence, commit: options.headCommit });
      }
    }
    for (const node of delta.removedNodes) {
      for (const evidence of node.evidence.slice(0, 3)) {
        entries.push({ label: `removed · ${node.label}`, evidence, commit: options.baseCommit });
      }
    }
    for (const changed of delta.changedNodes) {
      for (const evidence of changed.before.evidence.slice(0, 2)) {
        entries.push({
          label: `before · ${changed.before.label}`,
          evidence,
          commit: options.baseCommit
        });
      }
      for (const evidence of changed.after.evidence.slice(0, 2)) {
        entries.push({
          label: `after · ${changed.after.label}`,
          evidence,
          commit: options.headCommit
        });
      }
    }
    for (const edge of delta.addedEdges) {
      for (const evidence of edge.evidence.slice(0, 2)) {
        entries.push({ label: `added edge · ${edge.kind}`, evidence, commit: options.headCommit });
      }
    }
    for (const edge of delta.removedEdges) {
      for (const evidence of edge.evidence.slice(0, 2)) {
        entries.push({
          label: `removed edge · ${edge.kind}`,
          evidence,
          commit: options.baseCommit
        });
      }
    }
  }

  const seen = new Set<string>();
  for (const entry of entries) {
    const commit = entry.evidence.commit ?? entry.commit;
    const key = `${entry.label}\0${entry.evidence.file}\0${entry.evidence.line ?? ""}\0${commit ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    lines.push(
      `- **${safeMarkdownText(truncateText(entry.label, 180))}:** ${renderEvidenceReference(
        entry.evidence,
        options.repository,
        commit
      )}`
    );
    if (seen.size >= 30) break;
  }

  if (!seen.size) lines.push("- No source location was recorded for this delta.");
  if (entries.length > seen.size) {
    lines.push(
      `- ${entries.length - seen.size} additional evidence location(s) are in the report artifact.`
    );
  }
  return lines.join("\n");
}

function renderNextAction(
  findings: RiskFinding[],
  decisionType: string | undefined,
  machineFindingIds: Set<string>
): string {
  const firstActionable = findings.find((finding) => machineFindingIds.has(finding.id));
  let action: string;
  if (firstActionable && decisionType === "block") {
    action = `Resolve the recorded decision before merge. Review the evidence, then use ${inlineCode(
      `@hedge fix ${firstActionable.id}`
    )} to request a draft repair.`;
  } else if (firstActionable) {
    action = `Review the evidence and invariant. If a repair is wanted, use ${inlineCode(
      `@hedge fix ${firstActionable.id}`
    )} to request a draft repair.`;
  } else if (findings.length) {
    action =
      "Review the full report artifact; the bounded PR comment does not contain a repair handoff for every surfaced risk.";
  } else {
    action =
      "Confirm that the changed architecture and recorded controls match the intended design.";
  }
  return ["### 4. Next action", "", action].join("\n");
}

function renderCoverageAndHealth(analysis: DeadlineAnalysisResult): string {
  const coverage = analysis.coverage;
  const health = analysis.analysisHealth;
  const lines = [
    "### 5. Coverage and health",
    "",
    `- Coverage: **${safeMarkdownText((coverage?.status ?? "not recorded").toUpperCase())}**`,
    `- Analysis health: **${safeMarkdownText((health?.status ?? "not recorded").toUpperCase())}**`,
    `- Confirmed no-delta: **${analysis.confirmedNoDelta === true ? "yes" : "no"}**`
  ];
  if (coverage) {
    lines.push(
      `- Included: **${coverage.includedFiles}/${coverage.discoveredFiles} files**, **${coverage.includedBytes} bytes**`
    );
    const omitted = Object.values(coverage.omitted).reduce((sum, count) => sum + count, 0);
    if (omitted) lines.push(`- Omitted inputs: **${omitted}** (details below)`);
  }
  for (const reason of health?.reasons.slice(0, 4) ?? []) {
    lines.push(`- Health note: ${safeMarkdownText(truncateText(reason, 400))}`);
  }
  return lines.join("\n");
}

function renderFinding(
  finding: RiskFinding,
  remediationAvailable: boolean,
  options: { repository?: string; headCommit?: string }
): string {
  const lines = [
    "<details>",
    `<summary><strong>${safeMarkdownText(finding.id)} · ${finding.severity.toUpperCase()} · ${finding.status.toUpperCase()} · ${safeMarkdownText(truncateText(finding.title, 300))}</strong></summary>`,
    "",
    `**Attack path:** ${finding.attackPath
      .slice(0, 12)
      .map((value) => inlineCode(truncateText(value, 300)))
      .join(" → ")}`,
    "",
    `**Potential impact:** ${safeMarkdownText(truncateText(finding.potentialImpact, 800))}`,
    "",
    `**Existing controls:** ${safeMarkdownText(
      truncateText(finding.existingControls.join(", ") || "none detected", 600)
    )}`,
    "",
    `**Missing controls:** ${safeMarkdownText(
      truncateText(finding.missingControls.join(", ") || "none recorded", 600)
    )}`,
    "",
    `**Security invariant:** ${safeMarkdownText(truncateText(finding.securityInvariant, 900))}`,
    "",
    `**Evidence:** ${
      finding.evidence
        .slice(0, 10)
        .map((evidence) =>
          renderEvidenceReference(
            evidence,
            options.repository,
            evidence.commit ?? options.headCommit
          )
        )
        .join(", ") || "none recorded"
    }`,
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
        truncateText(finding.suggestedTest.code, 3_000),
        finding.suggestedTest.language === "typescript" ? "ts" : ""
      )
    );
  }

  if (remediationAvailable) {
    lines.push("", "**Draft repair handoff:**", "", fencedCode(`@hedge fix ${finding.id}`, "text"));
  }
  lines.push("", "</details>");
  return lines.join("\n");
}

function renderLifecycleUpdates(lifecycleUpdates: RiskFinding[]): string {
  return [
    "<details>",
    "<summary><strong>Risk lifecycle updates</strong></summary>",
    "",
    ...lifecycleUpdates
      .slice(0, 20)
      .map(
        (finding) =>
          `- **${safeMarkdownText(finding.id)}** moved to **${safeMarkdownText(
            finding.status
          )}** because its prior evidence changed. Executable verification is still required before closure.`
      ),
    "",
    "</details>"
  ].join("\n");
}

function renderTechnicalDetails(
  graph: AttackSurfaceGraph,
  delta: GraphDelta,
  analysis: AnalysisResult,
  extended: DeadlineAnalysisResult
): string {
  const lines = [
    "<details>",
    "<summary><strong>Technical details, graph, and limitations</strong></summary>",
    "",
    "#### Architecture graph",
    "",
    "```mermaid",
    renderMermaid(graph, { delta, findings: analysis.findings }),
    "```",
    ""
  ];

  if (analysis.invariantEvaluations?.length) {
    lines.push("#### Security invariants", "");
    for (const evaluation of analysis.invariantEvaluations.slice(0, 30)) {
      lines.push(
        `- **${safeMarkdownText(evaluation.invariantId)} · ${safeMarkdownText(
          evaluation.status.toUpperCase()
        )}** — ${safeMarkdownText(truncateText(evaluation.description, 500))}${
          evaluation.missingControls.length
            ? ` · missing: ${safeMarkdownText(evaluation.missingControls.join(", "))}`
            : ""
        }`
      );
    }
    lines.push("");
  }

  lines.push(
    "#### Evidence model",
    "",
    `- Deterministic observations: **${analysis.observations?.length ?? 0}**`,
    `- Security inferences: **${analysis.inferences?.length ?? 0}**`,
    `- Recorded decisions: **${analysis.decisions?.length ?? 0}**`,
    `- Model route: **${safeMarkdownText(analysis.modelRoute ?? "not reported")}**`,
    ""
  );

  if (analysis.usage) {
    lines.push(
      "#### Model usage",
      "",
      `- Model: **${safeMarkdownText(analysis.model ?? "unknown")}**`,
      `- Calls: **${analysis.usage.modelCalls ?? "not reported"}**`,
      `- Input tokens: **${analysis.usage.inputTokens ?? "not reported"}**`,
      `- Output tokens: **${analysis.usage.outputTokens ?? "not reported"}**`,
      `- Total tokens: **${analysis.usage.totalTokens ?? "not reported"}**`,
      `- Cached input tokens: **${analysis.usage.cachedInputTokens ?? "not reported"}**`,
      `- Reasoning tokens: **${analysis.usage.reasoningTokens ?? "not reported"}**`,
      ""
    );
  }

  if (extended.coverage?.diagnostics.length) {
    lines.push("#### Coverage diagnostics", "");
    for (const diagnostic of extended.coverage.diagnostics.slice(0, 30)) {
      lines.push(
        `- **${safeMarkdownText(diagnostic.code)} · ${safeMarkdownText(
          diagnostic.phase
        )}:** ${safeMarkdownText(truncateText(diagnostic.message, 500))}${
          diagnostic.file ? ` (${inlineCode(truncateText(diagnostic.file, 300))})` : ""
        }`
      );
    }
    lines.push("");
  }

  lines.push(
    "#### Analysis integrity",
    "",
    `- Untrusted instruction-like content observed: **${
      analysis.integrity.untrustedInstructionsObserved ? "yes" : "no"
    }**`,
    `- Analysis boundary held: **${analysis.integrity.analysisBoundaryHeld ? "yes" : "no"}**`,
    ...analysis.integrity.notes
      .slice(0, 20)
      .map((note) => `- ${safeMarkdownText(truncateText(note, 500))}`),
    "",
    "#### Limits",
    "",
    ...(analysis.limitations.length
      ? analysis.limitations
          .slice(0, 30)
          .map((value) => `- ${safeMarkdownText(truncateText(value, 500))}`)
      : ["- No additional run-specific limitation recorded."]),
    "",
    "</details>"
  );
  return lines.join("\n");
}

function fitVisibleReport(
  essentialBlocks: string[],
  optionalBlocks: string[],
  footer: string
): string {
  const included = [...essentialBlocks];
  let omitted = 0;
  const reserve = Buffer.byteLength(
    "\n\n> Some detail was omitted from this bounded comment. Open the Hedge report artifact for the complete result.\n\n",
    "utf8"
  );

  for (const block of optionalBlocks) {
    const candidate = [...included, block, footer].join("\n\n");
    if (Buffer.byteLength(candidate, "utf8") + reserve <= MAX_VISIBLE_COMMENT_BYTES) {
      included.push(block);
    } else {
      omitted += 1;
    }
  }

  if (omitted) {
    included.push(
      `> ${omitted} detail section(s) were omitted from this bounded comment. Open the Hedge report artifact for the complete result.`
    );
  }
  included.push(footer);
  const visible = included.join("\n\n");
  if (Buffer.byteLength(visible, "utf8") > MAX_VISIBLE_COMMENT_BYTES) {
    throw new Error("Essential Hedge report content exceeded the visible comment budget.");
  }
  return visible;
}

function renderEvidenceReference(evidence: Evidence, repository?: string, commit?: string): string {
  const location = truncateText(`${evidence.file}${evidence.line ? `:${evidence.line}` : ""}`, 400);
  if (!isGitHubRepository(repository) || !isExactCommit(commit)) return inlineCode(location);
  const encodedPath = evidence.file.split("/").map(encodePathSegment).join("/");
  if (encodedPath.length > 1_800) return inlineCode(location);
  const lineAnchor = evidence.line
    ? `#L${evidence.line}${evidence.endLine && evidence.endLine !== evidence.line ? `-L${evidence.endLine}` : ""}`
    : "";
  const url = `https://github.com/${repository}/blob/${commit}/${encodedPath}${lineAnchor}`;
  return `[${safeMarkdownText(location)}](${url})`;
}

function encodePathSegment(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

function isGitHubRepository(value: string | undefined): value is string {
  return Boolean(value && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value));
}

function isExactCommit(value: string | undefined): value is string {
  return Boolean(value && /^[a-f0-9]{40}$/i.test(value));
}

function selectOverallDecision(
  analysis: AnalysisResult
): NonNullable<AnalysisResult["decisions"]>[number] | undefined {
  const priority = new Map([
    ["block", 5],
    ["warn", 4],
    ["verify", 3],
    ["accept", 2],
    ["allow", 1]
  ]);
  return analysis.decisions?.reduce<NonNullable<AnalysisResult["decisions"]>[number] | undefined>(
    (selected, decision) =>
      !selected || (priority.get(decision.type) ?? 0) > (priority.get(selected.type) ?? 0)
        ? decision
        : selected,
    undefined
  );
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
  return neutralizeUntrustedText(value).replace(/([\\`\[\]()])/g, "\\$1");
}

function neutralizeUntrustedText(value: string): string {
  return value
    .replace(/[\r\n\t]+/g, " ")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replace(/@(?=[A-Za-z0-9_-])/g, "@\u200b");
}

function inlineCode(value: string): string {
  const safe = neutralizeUntrustedText(value);
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

function truncateText(value: string, maxCharacters: number): string {
  if (value.length <= maxCharacters) return value;
  return `${value.slice(0, Math.max(0, maxCharacters - 1))}…`;
}

function renderMachinePayload(
  findings: RiskFinding[],
  sourceCommit?: string
): MachinePayloadResult {
  const variants = [
    findings.map((finding) => compactMachineFinding(finding, "standard")),
    findings.map((finding) => compactMachineFinding(finding, "minimal"))
  ];

  for (const candidate of variants) {
    const result = encodeMachinePayload(candidate, findings.length, sourceCommit);
    if (Buffer.byteLength(result.comment, "utf8") <= MAX_MACHINE_PAYLOAD_BYTES) return result;
  }

  const included: ReturnType<typeof compactMachineFinding>[] = [];
  for (const finding of findings) {
    const candidate = [...included, compactMachineFinding(finding, "minimal")];
    const encoded = encodeMachinePayload(candidate, findings.length, sourceCommit);
    if (Buffer.byteLength(encoded.comment, "utf8") > MAX_MACHINE_PAYLOAD_BYTES) break;
    included.push(candidate.at(-1)!);
  }
  return encodeMachinePayload(included, findings.length, sourceCommit);
}

function compactMachineFinding(finding: RiskFinding, mode: "standard" | "minimal") {
  const minimal = mode === "minimal";
  return {
    id: truncateText(finding.id, 64),
    fingerprint: truncateText(finding.fingerprint, 128),
    title: truncateText(finding.title, minimal ? 160 : 300),
    severity: finding.severity,
    origin: finding.origin,
    securityInvariant: truncateText(finding.securityInvariant, minimal ? 300 : 900),
    attackPath: finding.attackPath
      .slice(0, minimal ? 3 : 8)
      .map((value) => truncateText(value, minimal ? 100 : 240)),
    missingControls: finding.missingControls
      .slice(0, minimal ? 5 : 12)
      .map((value) => truncateText(value, 100)),
    evidence: finding.evidence.slice(0, minimal ? 2 : 8).map((evidence) => ({
      file: truncateText(evidence.file, 300),
      line: evidence.line,
      endLine: evidence.endLine,
      extractor: truncateText(evidence.extractor, 100),
      commit: evidence.commit
    })),
    ...(minimal || !finding.suggestedTest
      ? {}
      : {
          suggestedTest: {
            title: truncateText(finding.suggestedTest.title, 160),
            framework: truncateText(finding.suggestedTest.framework, 80),
            language: truncateText(finding.suggestedTest.language, 80),
            purpose: truncateText(finding.suggestedTest.purpose, 300),
            code: truncateText(finding.suggestedTest.code, 1_500)
          }
        })
  };
}

function encodeMachinePayload(
  findings: ReturnType<typeof compactMachineFinding>[],
  totalFindingCount: number,
  sourceCommit?: string
): MachinePayloadResult {
  const content = {
    schemaVersion: "0.3",
    sourceCommit,
    totalFindingCount,
    omittedFindingCount: totalFindingCount - findings.length,
    findings
  };
  const payload = { ...content, payloadDigest: stableHash(content, 64) };
  return {
    comment: `<!-- hedge-findings-json:${Buffer.from(JSON.stringify(payload), "utf8").toString("base64")} -->`,
    includedFindingIds: new Set(findings.map((finding) => finding.id)),
    omittedFindingCount: totalFindingCount - findings.length
  };
}
