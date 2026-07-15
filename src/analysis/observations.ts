import type {
  GraphDelta,
  Inference,
  InvariantEvaluation,
  Observation,
  RiskFinding
} from "../domain/schemas.js";
import { stableHash } from "../utils/hash.js";

export function buildObservations(
  delta: GraphDelta,
  invariantEvaluations: InvariantEvaluation[] = []
): Observation[] {
  const observations: Observation[] = [];

  for (const node of delta.addedNodes) {
    observations.push(
      observation("node-added", `Added ${node.kind}: ${node.label}`, [node.id], node.evidence, {
        trustZone: node.trustZone,
        controls: node.controls.map((control) => control.type)
      })
    );
  }
  for (const node of delta.removedNodes) {
    observations.push(
      observation("node-removed", `Removed ${node.kind}: ${node.label}`, [node.id], node.evidence, {
        trustZone: node.trustZone,
        controls: node.controls.map((control) => control.type)
      })
    );
  }
  for (const pair of delta.changedNodes) {
    observations.push(
      observation(
        "node-changed",
        `Changed ${pair.after.kind}: ${pair.after.label}`,
        [pair.after.id],
        pair.after.evidence,
        {
          beforeControls: pair.before.controls.map((control) => control.type),
          afterControls: pair.after.controls.map((control) => control.type),
          beforeTrustZone: pair.before.trustZone,
          afterTrustZone: pair.after.trustZone
        }
      )
    );
  }
  for (const edge of delta.addedEdges) {
    observations.push(
      observation(
        "edge-added",
        `Added relationship ${edge.kind}: ${edge.from} → ${edge.to}`,
        [edge.id, edge.from, edge.to],
        edge.evidence,
        { relationship: edge.kind, label: edge.label }
      )
    );
  }
  for (const edge of delta.removedEdges) {
    observations.push(
      observation(
        "edge-removed",
        `Removed relationship ${edge.kind}: ${edge.from} → ${edge.to}`,
        [edge.id, edge.from, edge.to],
        edge.evidence,
        { relationship: edge.kind, label: edge.label }
      )
    );
  }
  for (const pair of delta.changedEdges) {
    observations.push(
      observation(
        "edge-changed",
        `Changed relationship ${pair.after.kind}: ${pair.after.from} → ${pair.after.to}`,
        [pair.after.id, pair.after.from, pair.after.to],
        pair.after.evidence,
        {
          beforeConfidence: pair.before.confidence,
          afterConfidence: pair.after.confidence,
          beforeControls: pair.before.controls.map((control) => control.type),
          afterControls: pair.after.controls.map((control) => control.type)
        }
      )
    );
  }

  for (const evaluation of invariantEvaluations) {
    observations.push(
      observation(
        "invariant-evaluated",
        `${evaluation.invariantId} is ${evaluation.status}: ${evaluation.description}`,
        evaluation.matchedNodeIds,
        evaluation.evidence,
        {
          invariantId: evaluation.invariantId,
          status: evaluation.status,
          missingControls: evaluation.missingControls
        }
      )
    );
  }

  return observations.sort((a, b) => a.id.localeCompare(b.id));
}

export function buildInferences(
  findings: RiskFinding[],
  observations: Observation[],
  model?: string
): Inference[] {
  return findings.map((finding) => {
    const observationIds = observations
      .filter(
        (observation) =>
          evidenceOverlaps(finding, observation) || subjectOverlaps(finding, observation)
      )
      .map((observation) => observation.id);
    return {
      id: `INF-${stableHash({ fingerprint: finding.fingerprint, observationIds }, 18)}`,
      hypothesis: `${finding.title}: ${finding.potentialImpact}`,
      confidence: finding.confidence,
      observationIds,
      assumptions: [finding.precondition],
      riskFingerprint: finding.fingerprint,
      origin: finding.origin,
      ...(finding.origin === "model" && model ? { model } : {})
    };
  });
}

function observation(
  kind: Observation["kind"],
  summary: string,
  subjectIds: string[],
  evidence: Observation["evidence"],
  metadata: Record<string, unknown>
): Observation {
  return {
    id: `OBS-${stableHash({ kind, summary, subjectIds, evidence, metadata }, 18)}`,
    kind,
    summary,
    subjectIds: [...new Set(subjectIds)],
    evidence,
    source: "deterministic",
    metadata
  };
}

function evidenceOverlaps(finding: RiskFinding, observation: Observation): boolean {
  const keys = new Set(
    finding.evidence.map(
      (evidence) => `${evidence.file}:${evidence.line ?? ""}:${evidence.extractor}`
    )
  );
  return observation.evidence.some((evidence) =>
    keys.has(`${evidence.file}:${evidence.line ?? ""}:${evidence.extractor}`)
  );
}

function subjectOverlaps(finding: RiskFinding, observation: Observation): boolean {
  const normalized = finding.attackPath.map((value) => value.toLowerCase());
  return observation.subjectIds.some((subject) =>
    normalized.some((value) => value.includes(subject.toLowerCase()))
  );
}
