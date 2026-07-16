import type {
  Evidence,
  GraphDelta,
  RiskFinding,
  SurfaceEdge,
  SurfaceNode
} from "../domain/schemas.js";
import { stableHash } from "../utils/hash.js";

export interface ArchitectureControlProof {
  changed: boolean;
  graphDeltaDigest: string;
  architectureEvidence: Evidence[];
  subjectIds: string[];
}

interface ProofOptions {
  baseCommit: string;
  headCommit: string;
}

/**
 * Derive architecture-change proof from an exact graph delta. A generic graph
 * change is insufficient: the change must affect the finding's entry point,
 * attack path, or evidence-bearing subject and must alter a control/path fact.
 */
export function deriveArchitectureControlProof(
  delta: GraphDelta,
  finding: RiskFinding,
  options: ProofOptions
): ArchitectureControlProof {
  const nodes = [
    ...delta.addedNodes,
    ...delta.removedNodes,
    ...delta.changedNodes.flatMap(({ before, after }) => [before, after])
  ];
  const findingFiles = new Set(finding.evidence.map((item) => item.file));
  const terms = [finding.entryPoint, ...finding.attackPath]
    .map(normalizeTerm)
    .filter((term) => term.length >= 4);
  const relevantNodeIds = new Set(
    nodes
      .filter(
        (node) =>
          terms.some((term) => subjectMatches(node, term)) ||
          node.evidence.some((item) => findingFiles.has(item.file))
      )
      .map((node) => node.id)
  );

  const proof: Array<{
    subjectId: string;
    before?: SurfaceNode | SurfaceEdge;
    after?: SurfaceNode | SurfaceEdge;
  }> = [];

  for (const pair of delta.changedNodes) {
    if (!relevantNodeIds.has(pair.before.id)) continue;
    if (!nodeControlOrPathChanged(pair.before, pair.after)) continue;
    proof.push({ subjectId: pair.after.id, before: pair.before, after: pair.after });
  }
  for (const node of delta.removedNodes) {
    if (relevantNodeIds.has(node.id)) proof.push({ subjectId: node.id, before: node });
  }

  const relevantEdge = (edge: SurfaceEdge): boolean =>
    relevantNodeIds.has(edge.from) ||
    relevantNodeIds.has(edge.to) ||
    edge.evidence.some((item) => findingFiles.has(item.file));

  for (const pair of delta.changedEdges) {
    if (!relevantEdge(pair.before) && !relevantEdge(pair.after)) continue;
    if (!edgeControlOrPathChanged(pair.before, pair.after)) continue;
    proof.push({ subjectId: pair.after.id, before: pair.before, after: pair.after });
  }
  for (const edge of delta.removedEdges) {
    if (relevantEdge(edge)) proof.push({ subjectId: edge.id, before: edge });
  }
  for (const edge of delta.addedEdges) {
    if (relevantEdge(edge)) proof.push({ subjectId: edge.id, after: edge });
  }

  // A newly modeled control node counts only when the exact delta also links it
  // to a relevant risk subject. Merely adding a test or an isolated auth-looking
  // component does not establish a changed architecture control.
  const linkedNewNodeIds = new Set(
    delta.addedEdges.filter((edge) => relevantEdge(edge)).flatMap((edge) => [edge.from, edge.to])
  );
  for (const node of delta.addedNodes) {
    if (!linkedNewNodeIds.has(node.id) || !isControlNode(node)) continue;
    proof.push({ subjectId: node.id, after: node });
  }

  const architectureEvidence = dedupeEvidence(
    proof.flatMap((item) => [
      ...exactEvidence(item.before?.evidence ?? [], "base", options.baseCommit, item.subjectId),
      ...exactEvidence(item.after?.evidence ?? [], "head", options.headCommit, item.subjectId)
    ])
  );

  return {
    changed: proof.length > 0 && architectureEvidence.length > 0,
    graphDeltaDigest: stableHash(delta, 64),
    architectureEvidence,
    subjectIds: [...new Set(proof.map((item) => item.subjectId))].sort()
  };
}

function subjectMatches(node: SurfaceNode, term: string): boolean {
  const id = normalizeTerm(node.id);
  const label = normalizeTerm(node.label);
  return id === term || label === term || id.includes(term) || label.includes(term);
}

function normalizeTerm(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, " ");
}

function nodeControlOrPathChanged(before: SurfaceNode, after: SurfaceNode): boolean {
  return (
    before.kind !== after.kind ||
    before.label !== after.label ||
    before.trustZone !== after.trustZone ||
    stableHash(controlFacts(before.controls)) !== stableHash(controlFacts(after.controls))
  );
}

function edgeControlOrPathChanged(before: SurfaceEdge, after: SurfaceEdge): boolean {
  return (
    before.from !== after.from ||
    before.to !== after.to ||
    before.kind !== after.kind ||
    before.label !== after.label ||
    stableHash(controlFacts(before.controls)) !== stableHash(controlFacts(after.controls))
  );
}

function controlFacts(controls: SurfaceNode["controls"]): unknown {
  return controls.map((control) => ({
    type: control.type,
    label: control.label,
    assurance: control.assurance
  }));
}

function isControlNode(node: SurfaceNode): boolean {
  return (
    ["middleware", "auth-control", "authorization-control"].includes(node.kind) ||
    node.controls.length > 0
  );
}

function exactEvidence(
  evidence: Evidence[],
  snapshot: "base" | "head",
  commit: string,
  subjectId: string
): Evidence[] {
  return evidence.map((item) => ({ ...item, commit, snapshot, subjectId }));
}

function dedupeEvidence(evidence: Evidence[]): Evidence[] {
  const byKey = new Map<string, Evidence>();
  for (const item of evidence) {
    const key = [
      item.snapshot,
      item.commit,
      item.subjectId,
      item.file,
      item.line ?? "",
      item.endLine ?? "",
      item.extractor
    ].join("\u0000");
    byKey.set(key, item);
  }
  return [...byKey.values()].sort((left, right) =>
    `${left.snapshot}:${left.file}:${left.line ?? 0}:${left.subjectId}`.localeCompare(
      `${right.snapshot}:${right.file}:${right.line ?? 0}:${right.subjectId}`
    )
  );
}
