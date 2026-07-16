import {
  VerificationEvidenceSchema,
  type RiskFinding,
  type VerificationEvidence,
  type VerificationEvidenceInput
} from "../domain/schemas.js";

const SHA256_DIGEST = /^[a-f0-9]{64}$/;
const EXACT_GIT_REVISION = /^[a-f0-9]{40,64}$/;

export interface VerificationAssessment {
  verified: boolean;
  evidenceAvailable: boolean;
  reasons: string[];
}

/**
 * Evaluate the durable verification contract without executing repository code.
 *
 * The legacy booleans remain in the schema so old registers can be read, but
 * they are not sufficient for a new verified transition. Structured evidence
 * must bind one immutable witness to exact revisions and an evidence-linked
 * architecture delta.
 */
export function assessVerificationEvidence(evidence: VerificationEvidence): VerificationAssessment {
  const reasons: string[] = [];
  const vulnerableRevision = evidence.vulnerableRevision ?? "";
  const repairedRevision = evidence.repairedRevision ?? "";

  if (!EXACT_GIT_REVISION.test(vulnerableRevision)) {
    reasons.push("vulnerable revision is not an exact Git object ID");
  }
  if (!EXACT_GIT_REVISION.test(repairedRevision)) {
    reasons.push("repaired revision is not an exact Git object ID");
  }
  if (vulnerableRevision && vulnerableRevision === repairedRevision) {
    reasons.push("vulnerable and repaired revisions must differ");
  }
  if (!evidence.witnessDigest || !SHA256_DIGEST.test(evidence.witnessDigest)) {
    reasons.push("immutable witness digest is missing");
  }
  if (evidence.vulnerableOutcome !== "reproduced") {
    reasons.push("vulnerable witness outcome was not reproduced");
  }
  if (evidence.repairedOutcome !== "blocked-by-control") {
    reasons.push("repaired witness outcome was not blocked-by-control");
  }
  if (!evidence.vulnerableRevisionWitnessSucceeded) {
    reasons.push("legacy vulnerable witness flag disagrees with the structured outcome");
  }
  if (!evidence.repairedRevisionWitnessBlocked) {
    reasons.push("legacy repaired witness flag disagrees with the structured outcome");
  }
  if (!evidence.legitimateBehaviorPassed) {
    reasons.push("legitimate behavior did not succeed");
  }
  if (!evidence.architectureControlChanged) {
    reasons.push("a relevant architecture control or path change was not established");
  }
  if (!evidence.graphDeltaDigest || !SHA256_DIGEST.test(evidence.graphDeltaDigest)) {
    reasons.push("architecture graph-delta digest is missing");
  }
  if (!evidence.architectureEvidence.length) {
    reasons.push("architecture change has no exact evidence");
  } else if (
    evidence.architectureEvidence.some((item) => {
      if (!item.commit || !item.snapshot || !item.subjectId) return true;
      return item.snapshot === "base"
        ? item.commit !== vulnerableRevision
        : item.commit !== repairedRevision;
    })
  ) {
    reasons.push("architecture evidence is not bound to the exact compared revisions");
  }

  return {
    verified: reasons.length === 0,
    evidenceAvailable:
      evidence.vulnerableOutcome !== undefined ||
      evidence.repairedOutcome !== undefined ||
      evidence.vulnerableRevisionWitnessSucceeded ||
      evidence.repairedRevisionWitnessBlocked,
    reasons
  };
}

export function applyVerification(
  finding: RiskFinding,
  input: VerificationEvidenceInput
): RiskFinding {
  const evidence = VerificationEvidenceSchema.parse(input);
  const assessment = assessVerificationEvidence(evidence);

  return {
    ...finding,
    status: assessment.verified
      ? "verified"
      : assessment.evidenceAvailable
        ? "verification-available"
        : "mitigation-detected",
    verificationHistory: [...finding.verificationHistory, evidence],
    updatedAt: new Date().toISOString()
  };
}
