import { z } from "zod";

export const TriageResultSchema = z.object({
  deepAnalysisRequired: z.boolean(),
  reason: z.string(),
  categories: z.array(
    z.enum([
      "entrypoint",
      "trust-boundary",
      "privilege",
      "data-flow",
      "dependency",
      "control-change",
      "none"
    ])
  )
});

export const RiskProposalSchema = z.object({
  title: z.string(),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  stride: z.array(
    z.enum([
      "Spoofing",
      "Tampering",
      "Repudiation",
      "Information Disclosure",
      "Denial of Service",
      "Elevation of Privilege"
    ])
  ),
  cwe: z.array(z.string()),
  asset: z.string(),
  attackerCapability: z.string(),
  entryPoint: z.string(),
  trustBoundary: z.string(),
  precondition: z.string(),
  attackPath: z.array(z.string()).min(2),
  potentialImpact: z.string(),
  existingControls: z.array(z.string()),
  missingControls: z.array(z.string()),
  securityInvariant: z.string(),
  evidenceRefs: z.array(z.string()).min(1),
  confidence: z.number().min(0).max(1),
  suggestedTest: z
    .object({
      title: z.string(),
      purpose: z.string(),
      code: z.string()
    })
    .optional(),
  remediationPrompt: z.string().optional()
});

export const ModelAnalysisSchema = z.object({
  summary: z.string(),
  findings: z.array(RiskProposalSchema).max(10),
  integrity: z.object({
    untrustedInstructionsObserved: z.boolean(),
    analysisBoundaryHeld: z.boolean(),
    notes: z.array(z.string())
  }),
  limitations: z.array(z.string())
});

export type TriageResult = z.infer<typeof TriageResultSchema>;
export type ModelAnalysis = z.infer<typeof ModelAnalysisSchema>;
export type RiskProposal = z.infer<typeof RiskProposalSchema>;
