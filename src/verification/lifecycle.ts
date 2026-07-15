import {
  VerificationEvidenceSchema,
  type RiskFinding,
  type VerificationEvidenceInput
} from "../domain/schemas.js";

export function applyVerification(
  finding: RiskFinding,
  input: VerificationEvidenceInput
): RiskFinding {
  const evidence = VerificationEvidenceSchema.parse(input);
  const fullyVerified =
    evidence.vulnerableRevisionWitnessSucceeded &&
    evidence.repairedRevisionWitnessBlocked &&
    evidence.legitimateBehaviorPassed &&
    evidence.architectureControlChanged;

  return {
    ...finding,
    status: fullyVerified
      ? "verified"
      : evidence.repairedRevisionWitnessBlocked
        ? "verification-available"
        : "mitigation-detected",
    verificationHistory: [...finding.verificationHistory, evidence],
    updatedAt: new Date().toISOString()
  };
}
