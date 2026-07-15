import type {
  Decision,
  Inference,
  InvariantEvaluation,
  Observation,
  RiskFinding,
  Severity
} from "../domain/schemas.js";
import { stableHash } from "../utils/hash.js";

const severityOrder: Severity[] = ["info", "low", "medium", "high", "critical"];

export function buildDecisions(
  findings: RiskFinding[],
  invariantEvaluations: InvariantEvaluation[],
  observations: Observation[],
  inferences: Inference[],
  failOn: Severity
): Decision[] {
  const unresolved = findings.filter(
    (finding) => !["verified", "accepted", "closed"].includes(finding.status)
  );
  const blocking = unresolved.filter(
    (finding) => severityOrder.indexOf(finding.severity) >= severityOrder.indexOf(failOn)
  );
  const violated = invariantEvaluations.filter((evaluation) => evaluation.status === "violated");
  const type: Decision["type"] = blocking.length ? "block" : unresolved.length ? "warn" : "allow";
  const reason = blocking.length
    ? `${blocking.length} unresolved finding(s) meet or exceed the ${failOn} failure threshold.`
    : unresolved.length
      ? `${unresolved.length} unresolved finding(s) remain below the ${failOn} failure threshold.`
      : violated.length
        ? "Invariant violations were recorded but no unresolved finding remains."
        : "No unresolved evidence-linked risk meets the configured threshold.";

  const overall: Decision = {
    id: `DEC-${stableHash({ type, failOn, risks: unresolved.map((item) => item.fingerprint) }, 18)}`,
    type,
    reason,
    source: "threshold",
    riskFingerprints: unresolved.map((finding) => finding.fingerprint),
    invariantIds: violated.map((evaluation) => evaluation.invariantId),
    observationIds: observations.map((observation) => observation.id),
    inferenceIds: inferences.map((inference) => inference.id)
  };

  const invariantDecisions = violated.map<Decision>((evaluation) => {
    const relatedFindings = findings.filter(
      (finding) =>
        finding.origin === "invariant" && finding.securityInvariant === evaluation.description
    );
    return {
      id: `DEC-${stableHash({ invariant: evaluation.invariantId, status: evaluation.status }, 18)}`,
      type:
        severityOrder.indexOf(evaluation.severity) >= severityOrder.indexOf(failOn)
          ? "block"
          : "warn",
      reason: evaluation.reason,
      source: "invariant",
      riskFingerprints: relatedFindings.map((finding) => finding.fingerprint),
      invariantIds: [evaluation.invariantId],
      observationIds: observations
        .filter((observation) => observation.metadata.invariantId === evaluation.invariantId)
        .map((observation) => observation.id),
      inferenceIds: inferences
        .filter((inference) =>
          relatedFindings.some((finding) => finding.fingerprint === inference.riskFingerprint)
        )
        .map((inference) => inference.id)
    };
  });

  return [overall, ...invariantDecisions];
}
