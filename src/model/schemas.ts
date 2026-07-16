import { z } from "zod";

export const TriageResultSchema = z.object({
  deepAnalysisRequired: z.boolean()
});

export const RiskProposalSchema = z.object({
  title: z.string().min(1).max(160),
  severity: z.enum(["info", "low", "medium", "high", "critical"]),
  stride: z
    .array(
      z.enum([
        "Spoofing",
        "Tampering",
        "Repudiation",
        "Information Disclosure",
        "Denial of Service",
        "Elevation of Privilege"
      ])
    )
    .max(3),
  cwe: z.array(z.string().min(1).max(32)).max(4),
  asset: z.string().min(1).max(160),
  attackerCapability: z.string().min(1).max(240),
  entryPoint: z.string().min(1).max(240),
  trustBoundary: z.string().min(1).max(240),
  precondition: z.string().min(1).max(320),
  attackPath: z.array(z.string().min(1).max(360)).min(2).max(6),
  potentialImpact: z.string().min(1).max(480),
  existingControls: z.array(z.string().min(1).max(240)).max(6),
  missingControls: z.array(z.string().min(1).max(240)).max(6),
  securityInvariant: z.string().min(1).max(500),
  evidenceRefs: z.array(z.string().min(1).max(200)).min(1).max(8),
  confidence: z.number().min(0).max(1),
  suggestedTest: z
    .object({
      title: z.string().min(1).max(160),
      purpose: z.string().min(1).max(400),
      code: z.string().min(1).max(1_200)
    })
    .nullable(),
  remediationPrompt: z.string().min(1).max(800).nullable()
});

export const ModelAnalysisSchema = z.object({
  findings: z.array(RiskProposalSchema).max(3),
  integrity: z.object({
    untrustedInstructionsObserved: z.boolean(),
    analysisBoundaryHeld: z.boolean()
  })
});

export type TriageResult = z.infer<typeof TriageResultSchema>;
export type ModelAnalysis = z.infer<typeof ModelAnalysisSchema>;
export type RiskProposal = z.infer<typeof RiskProposalSchema>;
