import OpenAI from "openai";
import { zodTextFormat } from "openai/helpers/zod";
import type { AttackSurfaceGraph, Evidence, GraphDelta, RiskFinding } from "../domain/schemas.js";
import { stableHash } from "../utils/hash.js";
import { containsInstructionLikeContent } from "../security/untrusted.js";
import {
  ModelAnalysisSchema,
  TriageResultSchema,
  type ModelAnalysis,
  type RiskProposal,
  type TriageResult
} from "./schemas.js";
import {
  analysisInput,
  analysisSystemPrompt,
  buildPromptEvidenceIndex,
  triageInput,
  triageSystemPrompt
} from "./prompts.js";

export const MODEL_REQUEST_POLICY = {
  maxRetries: 0,
  triage: {
    maxRequestBytes: 48 * 1024,
    maxOutputTokens: 384,
    reasoningEffort: "minimal"
  },
  analysis: {
    maxRequestBytes: 160 * 1024,
    maxOutputTokens: 4_096,
    reasoningEffort: "low"
  }
} as const;

export interface ModelRouterOptions {
  apiKey: string;
  triageModel: string;
  analysisModel: string;
}

export interface ModelUsage {
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  cachedInputTokens?: number;
  reasoningTokens?: number;
  modelCalls?: number;
}

export interface TriageRunResult {
  result: TriageResult;
  model: string;
  usage?: ModelUsage;
}

export interface ModelRunResult {
  findings: RiskFinding[];
  summary: string;
  limitations: string[];
  model: string;
  integrity: {
    untrustedInstructionsObserved: boolean;
    analysisBoundaryHeld: boolean;
    notes: string[];
  };
  usage?: ModelUsage;
  rejectedProposalCount?: number;
}

export class ModelRouter {
  private readonly client: OpenAI;

  constructor(private readonly options: ModelRouterOptions) {
    this.client = new OpenAI({
      apiKey: options.apiKey,
      maxRetries: MODEL_REQUEST_POLICY.maxRetries,
      timeout: 90_000
    });
  }

  async triage(delta: GraphDelta, patch: string): Promise<TriageRunResult> {
    const input = [
      { role: "system" as const, content: triageSystemPrompt() },
      { role: "user" as const, content: triageInput(delta, patch) }
    ];
    const format = zodTextFormat(TriageResultSchema, "hedge_triage");
    assertRequestWithinByteBudget(
      { input, text: { format } },
      MODEL_REQUEST_POLICY.triage.maxRequestBytes,
      "Triage"
    );
    const response = await this.client.responses.parse({
      model: this.options.triageModel,
      input,
      max_output_tokens: MODEL_REQUEST_POLICY.triage.maxOutputTokens,
      reasoning: { effort: MODEL_REQUEST_POLICY.triage.reasoningEffort },
      store: false,
      text: { format }
    });
    assertOutputBudgetComplete(response, "Triage");
    if (!response.output_parsed) throw new Error("Triage model returned no parsed output.");
    return {
      result: response.output_parsed,
      model: this.options.triageModel,
      usage: response.usage ? toModelUsage(response.usage) : undefined
    };
  }

  async analyze(
    graph: AttackSurfaceGraph,
    delta: GraphDelta,
    patch: string
  ): Promise<ModelRunResult> {
    const input = [
      { role: "system" as const, content: analysisSystemPrompt() },
      { role: "user" as const, content: analysisInput(graph, delta, patch) }
    ];
    const format = zodTextFormat(ModelAnalysisSchema, "hedge_analysis");
    assertRequestWithinByteBudget(
      { input, text: { format } },
      MODEL_REQUEST_POLICY.analysis.maxRequestBytes,
      "Analysis"
    );
    const response = await this.client.responses.parse({
      model: this.options.analysisModel,
      input,
      max_output_tokens: MODEL_REQUEST_POLICY.analysis.maxOutputTokens,
      reasoning: { effort: MODEL_REQUEST_POLICY.analysis.reasoningEffort },
      store: false,
      text: { format }
    });
    assertOutputBudgetComplete(response, "Analysis");
    const parsed = response.output_parsed as ModelAnalysis | null;
    if (!parsed) throw new Error("Analysis model returned no parsed output.");
    assertModelIntegrity(parsed);
    const usage = response.usage ? toModelUsage(response.usage) : undefined;
    const evidenceIndex = buildEvidenceIndex(graph, delta);
    const relevantLabels = buildRelevantLabels(graph, delta);
    const rejected: string[] = [];
    const findings = parsed.findings.flatMap((proposal) => {
      const rejection = validateProposalScope(proposal, evidenceIndex, relevantLabels);
      if (rejection) {
        rejected.push(`Model proposal ${JSON.stringify(proposal.title)} was omitted: ${rejection}`);
        return [];
      }
      const finding = proposalToFinding(proposal, evidenceIndex);
      if (finding) return [finding];
      rejected.push(
        `Model proposal ${JSON.stringify(proposal.title)} was omitted because none of its evidence references resolved.`
      );
      return [];
    });
    return {
      findings,
      // Free-form model prose is not publication-ready evidence. The analysis
      // layer emits deterministic summaries and static validation notes.
      summary: "Model proposals were schema-checked and resolved against the exact graph delta.",
      limitations: [],
      model: this.options.analysisModel,
      integrity: {
        untrustedInstructionsObserved:
          parsed.integrity.untrustedInstructionsObserved || containsInstructionLikeContent(patch),
        analysisBoundaryHeld: parsed.integrity.analysisBoundaryHeld,
        notes: [
          "Structured model output passed the instruction-boundary assertion and exact evidence-reference validation."
        ]
      },
      usage,
      rejectedProposalCount: rejected.length
    };
  }
}

export function assertModelIntegrity(parsed: ModelAnalysis): void {
  if (!parsed.integrity.analysisBoundaryHeld) {
    throw new Error(
      "Analysis model reported that the untrusted-repository instruction boundary did not hold."
    );
  }
}

function proposalToFinding(
  proposal: RiskProposal,
  evidenceIndex: Map<string, Evidence>
): RiskFinding | null {
  const now = new Date().toISOString();
  const fingerprint = stableHash(
    {
      entryPoint: proposal.entryPoint,
      attackPath: proposal.attackPath,
      securityInvariant: proposal.securityInvariant,
      missingControls: proposal.missingControls
    },
    24
  );
  const evidence = proposal.evidenceRefs.flatMap((reference) => {
    const resolved = evidenceIndex.get(reference);
    return resolved ? [resolved] : [];
  });
  if (!evidence.length) return null;
  return {
    id: "HEDGE-PENDING",
    fingerprint,
    title: proposal.title,
    severity: proposal.severity,
    origin: "model",
    status: "open",
    stride: proposal.stride,
    cwe: proposal.cwe,
    asset: proposal.asset,
    attackerCapability: proposal.attackerCapability,
    entryPoint: proposal.entryPoint,
    trustBoundary: proposal.trustBoundary,
    precondition: proposal.precondition,
    attackPath: proposal.attackPath,
    potentialImpact: proposal.potentialImpact,
    existingControls: proposal.existingControls,
    missingControls: proposal.missingControls,
    securityInvariant: proposal.securityInvariant,
    evidence,
    confidence: proposal.confidence,
    ...(proposal.suggestedTest
      ? {
          suggestedTest: {
            title: proposal.suggestedTest.title,
            framework: "vitest",
            language: "typescript",
            purpose: proposal.suggestedTest.purpose,
            code: proposal.suggestedTest.code
          }
        }
      : {}),
    ...(proposal.remediationPrompt ? { remediationPrompt: proposal.remediationPrompt } : {}),
    verificationHistory: [],
    createdAt: now,
    updatedAt: now
  };
}

function buildEvidenceIndex(graph: AttackSurfaceGraph, delta: GraphDelta): Map<string, Evidence> {
  return new Map(
    Object.entries(buildPromptEvidenceIndex(graph, delta)).map(([reference, entry]) => [
      reference,
      entry.evidence
    ])
  );
}

function buildRelevantLabels(graph: AttackSurfaceGraph, delta: GraphDelta): Set<string> {
  const ids = relevantSubjectIds(delta);
  return new Set([
    ...graph.nodes.filter((node) => ids.has(node.id)).map((node) => node.label),
    ...delta.addedNodes.map((node) => node.label),
    ...delta.removedNodes.map((node) => node.label),
    ...delta.changedNodes.flatMap(({ before, after }) => [before.label, after.label])
  ]);
}

function relevantSubjectIds(delta: GraphDelta): Set<string> {
  const ids = new Set<string>();
  for (const node of delta.addedNodes) ids.add(node.id);
  for (const node of delta.removedNodes) ids.add(node.id);
  for (const pair of delta.changedNodes) ids.add(pair.after.id);
  for (const edge of delta.addedEdges) {
    ids.add(edge.id);
    ids.add(edge.from);
    ids.add(edge.to);
  }
  for (const edge of delta.removedEdges) {
    ids.add(edge.id);
    ids.add(edge.from);
    ids.add(edge.to);
  }
  for (const pair of delta.changedEdges) {
    ids.add(pair.after.id);
    ids.add(pair.after.from);
    ids.add(pair.after.to);
  }
  return ids;
}

function validateProposalScope(
  proposal: RiskProposal,
  evidenceIndex: Map<string, Evidence>,
  relevantLabels: Set<string>
): string | null {
  const unresolved = proposal.evidenceRefs.filter((reference) => !evidenceIndex.has(reference));
  if (unresolved.length) {
    return `evidence reference(s) were not part of the current architecture delta: ${unresolved.join(", ")}`;
  }
  if (!relevantLabels.has(proposal.entryPoint)) {
    return `entry point ${JSON.stringify(proposal.entryPoint)} was not part of the current architecture delta`;
  }
  return null;
}

interface ResponseUsageShape {
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  input_tokens_details: { cached_tokens: number };
  output_tokens_details: { reasoning_tokens: number };
}

function toModelUsage(usage: ResponseUsageShape): ModelUsage {
  return {
    inputTokens: usage.input_tokens,
    outputTokens: usage.output_tokens,
    totalTokens: usage.total_tokens,
    cachedInputTokens: usage.input_tokens_details.cached_tokens,
    reasoningTokens: usage.output_tokens_details.reasoning_tokens,
    modelCalls: 1
  };
}

function assertOutputBudgetComplete(
  response: {
    status?: string;
    incomplete_details: { reason?: string } | null;
  },
  stage: string
): void {
  if (
    response.status === "incomplete" &&
    response.incomplete_details?.reason === "max_output_tokens"
  ) {
    throw new Error(`${stage} model exhausted its bounded output-token budget.`);
  }
}

function assertRequestWithinByteBudget(value: unknown, maxBytes: number, stage: string): void {
  const bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (bytes > maxBytes) {
    throw new Error(`${stage} model request exceeded its ${maxBytes}-byte input budget.`);
  }
}
