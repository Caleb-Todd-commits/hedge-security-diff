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
import { analysisInput, analysisSystemPrompt, triageInput, triageSystemPrompt } from "./prompts.js";

export interface ModelRouterOptions {
  apiKey: string;
  triageModel: string;
  analysisModel: string;
}

export interface TriageRunResult {
  result: TriageResult;
  model: string;
  usage?: { inputTokens?: number; outputTokens?: number };
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
  usage?: { inputTokens?: number; outputTokens?: number };
}

export class ModelRouter {
  private readonly client: OpenAI;

  constructor(private readonly options: ModelRouterOptions) {
    this.client = new OpenAI({
      apiKey: options.apiKey,
      maxRetries: 2,
      timeout: 90_000
    });
  }

  async triage(delta: GraphDelta, patch: string): Promise<TriageRunResult> {
    const response = await this.client.responses.parse({
      model: this.options.triageModel,
      input: [
        { role: "system", content: triageSystemPrompt() },
        { role: "user", content: triageInput(delta, patch) }
      ],
      text: { format: zodTextFormat(TriageResultSchema, "hedge_triage") }
    });
    if (!response.output_parsed) throw new Error("Triage model returned no parsed output.");
    return {
      result: response.output_parsed,
      model: this.options.triageModel,
      usage: response.usage
        ? { inputTokens: response.usage.input_tokens, outputTokens: response.usage.output_tokens }
        : undefined
    };
  }

  async analyze(
    graph: AttackSurfaceGraph,
    delta: GraphDelta,
    patch: string
  ): Promise<ModelRunResult> {
    const response = await this.client.responses.parse({
      model: this.options.analysisModel,
      input: [
        { role: "system", content: analysisSystemPrompt() },
        { role: "user", content: analysisInput(graph, delta, patch) }
      ],
      text: { format: zodTextFormat(ModelAnalysisSchema, "hedge_analysis") }
    });
    const parsed = response.output_parsed as ModelAnalysis | null;
    if (!parsed) throw new Error("Analysis model returned no parsed output.");
    assertModelIntegrity(parsed);
    const usage = response.usage
      ? {
          inputTokens: response.usage.input_tokens,
          outputTokens: response.usage.output_tokens
        }
      : undefined;
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
      summary: parsed.summary,
      limitations: [...parsed.limitations, ...rejected],
      model: this.options.analysisModel,
      integrity: {
        untrustedInstructionsObserved:
          parsed.integrity.untrustedInstructionsObserved || containsInstructionLikeContent(patch),
        analysisBoundaryHeld: parsed.integrity.analysisBoundaryHeld,
        notes: parsed.integrity.notes
      },
      usage
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
    suggestedTest: proposal.suggestedTest
      ? {
          title: proposal.suggestedTest.title,
          framework: "vitest",
          language: "typescript",
          purpose: proposal.suggestedTest.purpose,
          code: proposal.suggestedTest.code
        }
      : undefined,
    remediationPrompt: proposal.remediationPrompt,
    verificationHistory: [],
    createdAt: now,
    updatedAt: now
  };
}

function buildEvidenceIndex(graph: AttackSurfaceGraph, delta: GraphDelta): Map<string, Evidence> {
  const relevant = relevantSubjectIds(delta);
  const result = new Map<string, Evidence>();
  for (const node of graph.nodes) {
    if (!relevant.has(node.id)) continue;
    node.evidence.forEach((evidence, index) => result.set(`${node.id}#${index}`, evidence));
  }
  for (const edge of graph.edges) {
    if (!relevant.has(edge.id)) continue;
    edge.evidence.forEach((evidence, index) => result.set(`${edge.id}#${index}`, evidence));
  }
  return result;
}

function buildRelevantLabels(graph: AttackSurfaceGraph, delta: GraphDelta): Set<string> {
  const ids = relevantSubjectIds(delta);
  return new Set(graph.nodes.filter((node) => ids.has(node.id)).map((node) => node.label));
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
