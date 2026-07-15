import type { RiskFinding, RiskStatusSchema } from "../domain/schemas.js";
import type { z } from "zod";

export type RiskStatus = z.infer<typeof RiskStatusSchema>;

const UNRESOLVED_STATUSES = new Set<RiskStatus>([
  "open",
  "mitigation-detected",
  "verification-available"
]);

export function isUnresolvedRisk(finding: Pick<RiskFinding, "status">): boolean {
  return UNRESOLVED_STATUSES.has(finding.status);
}

export function isResolvedRisk(finding: Pick<RiskFinding, "status">): boolean {
  return !isUnresolvedRisk(finding);
}
