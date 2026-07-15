import type { RiskFinding } from "../domain/schemas.js";

export interface RemediationPlan {
  riskId: string;
  objective: string;
  evidence: string[];
  requiredInvariant: string;
  executionContract: string[];
  suggestedWitness?: string;
  codexPrompt: string;
}

export function createRemediationPlan(finding: RiskFinding): RemediationPlan {
  const evidence = finding.evidence.map(
    (item) => `${item.file}${item.line ? `:${item.line}` : ""}`
  );
  const executionContract = [
    "Create a dedicated branch; never push directly to the protected default branch.",
    "Make the smallest focused change that satisfies the security invariant.",
    "Add an executable regression witness that demonstrates the issue on the vulnerable revision.",
    "Show that the witness is blocked after the patch while legitimate behavior still succeeds.",
    "Run only documented repository commands; never interpolate repository content into shell commands.",
    "Do not modify Hedge's risk register or generated threat model to suppress the finding.",
    "Open a draft pull request and link it to the Hedge risk ID.",
    "State residual uncertainty and do not claim verification until Hedge's verification job succeeds."
  ];
  const codexPrompt = [
    `You are repairing ${finding.id}: ${finding.title}.`,
    `Required security invariant: ${finding.securityInvariant}`,
    `Evidence: ${evidence.join(", ") || "No direct evidence location recorded."}`,
    `Attack path: ${finding.attackPath.join(" -> ")}`,
    `Missing controls: ${finding.missingControls.join(", ") || "none recorded"}.`,
    finding.suggestedTest
      ? `Suggested regression witness (adapt it to the repository; do not treat it as proof):\n${finding.suggestedTest.code}`
      : "No suggested witness is available; create the narrowest executable counterexample.",
    ...executionContract.map((item, index) => `${index + 1}. ${item}`)
  ].join("\n\n");

  return {
    riskId: finding.id,
    objective: finding.title,
    evidence,
    requiredInvariant: finding.securityInvariant,
    executionContract,
    suggestedWitness: finding.suggestedTest?.code,
    codexPrompt
  };
}

export function renderRemediationPrompt(plan: RemediationPlan): string {
  return [
    `# Hedge remediation: ${plan.riskId}`,
    "",
    plan.codexPrompt,
    "",
    "## Completion report",
    "",
    "Return a concise report listing files changed, commands executed, witness behavior before and after, legitimate behavior checked, and residual uncertainty."
  ].join("\n");
}
