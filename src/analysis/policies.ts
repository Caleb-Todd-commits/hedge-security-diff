import type { CustomPolicy, GraphDelta, RiskFinding, SurfaceNode } from "../domain/schemas.js";
import { stableHash } from "../utils/hash.js";

export function analyzeWithCustomPolicies(
  delta: GraphDelta,
  policies: CustomPolicy[]
): RiskFinding[] {
  if (!policies.length) return [];
  const candidates = [...delta.addedNodes, ...delta.changedNodes.map((pair) => pair.after)];
  const findings: RiskFinding[] = [];
  for (const policy of policies) {
    for (const node of candidates) {
      if (!matches(node, policy)) continue;
      const controls = new Set(node.controls.map((control) => control.type));
      const missing = policy.require_controls.filter((control) => !controls.has(control));
      if (!missing.length) continue;
      const now = new Date().toISOString();
      findings.push({
        id: "HEDGE-PENDING",
        fingerprint: stableHash({ policy: policy.id, node: node.id, missing }, 24),
        title: `${policy.name}: ${missing.join(", ")} not detected`,
        severity: policy.severity,
        origin: "policy",
        status: "open",
        stride: policy.stride,
        cwe: policy.cwe,
        asset: policy.asset,
        attackerCapability: policy.attacker_capability,
        entryPoint: node.label,
        trustBoundary: `${node.trustZone} architecture surface governed by ${policy.id}`,
        precondition: `The changed component matches organization policy ${policy.id}.`,
        attackPath: [node.label, `Policy ${policy.id}`, `Missing ${missing.join(", ")}`],
        potentialImpact: policy.potential_impact,
        existingControls: node.controls.map((control) => control.label),
        missingControls: missing,
        securityInvariant: policy.security_invariant,
        evidence: node.evidence,
        confidence: 1,
        suggestedTest: {
          title: `Organization policy witness for ${policy.id}`,
          framework: "vitest",
          language: "typescript",
          purpose: policy.security_invariant,
          code: `it(${JSON.stringify(policy.security_invariant)}, async () => {\n  // Replace this placeholder with an executable witness against ${node.label}.\n  expect.fail("Implement organization policy witness ${policy.id}");\n});`
        },
        remediationPrompt: [
          `Satisfy organization-defined Hedge policy ${policy.id}: ${policy.name}.`,
          `Security invariant: ${policy.security_invariant}`,
          `Matched component: ${node.label}`,
          `Missing controls: ${missing.join(", ")}.`,
          "Make the smallest focused change and add an executable regression witness."
        ].join("\n"),
        verificationHistory: [],
        createdAt: now,
        updatedAt: now
      });
    }
  }
  return deduplicate(findings);
}

function matches(node: SurfaceNode, policy: CustomPolicy): boolean {
  if (policy.match.kinds.length && !policy.match.kinds.includes(node.kind)) return false;
  if (policy.match.trust_zones.length && !policy.match.trust_zones.includes(node.trustZone))
    return false;
  if (policy.match.methods.length) {
    const method = String(node.metadata.method ?? "").toUpperCase();
    if (!policy.match.methods.map((value) => value.toUpperCase()).includes(method)) return false;
  }
  if (policy.match.label_pattern && !globMatch(node.label, policy.match.label_pattern))
    return false;
  return true;
}

function globMatch(value: string, pattern: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

function deduplicate(findings: RiskFinding[]): RiskFinding[] {
  return [...new Map(findings.map((finding) => [finding.fingerprint, finding])).values()];
}
