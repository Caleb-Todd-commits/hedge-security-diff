import { z } from "zod";

export const EvidenceSchema = z.object({
  file: z.string(),
  line: z.number().int().positive().optional(),
  endLine: z.number().int().positive().optional(),
  snippet: z.string().optional(),
  extractor: z.string(),
  commit: z.string().optional(),
  snapshot: z.enum(["base", "head"]).optional(),
  subjectId: z.string().optional()
});

export const NodeKindSchema = z.enum([
  "entrypoint",
  "middleware",
  "auth-control",
  "authorization-control",
  "database",
  "data-model",
  "storage",
  "external-service",
  "secret",
  "dependency",
  "component"
]);

export const EdgeKindSchema = z.enum([
  "calls",
  "reads",
  "writes",
  "authenticates",
  "authorizes",
  "crosses-trust-boundary",
  "uses-secret",
  "depends-on"
]);

export const TrustZoneSchema = z.enum([
  "public",
  "application",
  "privileged",
  "data",
  "external",
  "unknown"
]);

export const ControlTypeSchema = z.enum([
  "authentication",
  "authorization",
  "validation",
  "rate-limit",
  "size-limit",
  "content-type",
  "encryption",
  "logging",
  "ownership",
  "other"
]);

export const ControlAssuranceSchema = z.enum(["trusted", "confirmed", "inferred", "unknown"]);

export const ControlSchema = z.object({
  type: ControlTypeSchema,
  label: z.string(),
  evidence: z.array(EvidenceSchema).default([]),
  confidence: z.number().min(0).max(1).default(1),
  // Existing v0.x registers omitted this field. Parsing those controls must
  // never silently promote them to confirmed semantic evidence.
  assurance: ControlAssuranceSchema.default("inferred")
});

export const CoverageDiagnosticSchema = z.object({
  code: z.string(),
  phase: z.enum(["collection", "parsing", "framework", "patch", "analysis"]),
  message: z.string(),
  file: z.string().optional(),
  snapshot: z.enum(["base", "head"]).optional()
});

export const CoverageSchema = z.object({
  status: z.enum(["complete", "partial", "unsupported"]),
  discoveredFiles: z.number().int().nonnegative(),
  includedFiles: z.number().int().nonnegative(),
  includedBytes: z.number().int().nonnegative(),
  omitted: z.object({
    fileLimit: z.number().int().nonnegative(),
    byteLimit: z.number().int().nonnegative(),
    unsafeOrUnreadable: z.number().int().nonnegative(),
    binary: z.number().int().nonnegative()
  }),
  diagnostics: z.array(CoverageDiagnosticSchema).default([])
});

export const AnalysisHealthSchema = z.object({
  status: z.enum(["complete", "degraded", "failed"]),
  reasons: z.array(z.string()).default([])
});

export const SurfaceNodeSchema = z.object({
  id: z.string(),
  kind: NodeKindSchema,
  label: z.string(),
  trustZone: TrustZoneSchema.default("unknown"),
  evidence: z.array(EvidenceSchema).default([]),
  controls: z.array(ControlSchema).default([]),
  metadata: z.record(z.string(), z.unknown()).default({})
});

export const SurfaceEdgeSchema = z.object({
  id: z.string(),
  from: z.string(),
  to: z.string(),
  kind: EdgeKindSchema,
  label: z.string().optional(),
  evidence: z.array(EvidenceSchema).default([]),
  controls: z.array(ControlSchema).default([]),
  confidence: z.number().min(0).max(1).default(1)
});

export const AttackSurfaceGraphSchema = z.object({
  schemaVersion: z.literal("0.1"),
  generatedAt: z.string(),
  repository: z.string().default("local"),
  sourceCommit: z.string().optional(),
  framework: z.string().default("unknown"),
  nodes: z.array(SurfaceNodeSchema),
  edges: z.array(SurfaceEdgeSchema),
  assumptions: z.array(z.string()).default([]),
  unknowns: z.array(z.string()).default([]),
  coverage: CoverageSchema.optional()
});

export const GraphDeltaSchema = z.object({
  addedNodes: z.array(SurfaceNodeSchema),
  removedNodes: z.array(SurfaceNodeSchema),
  changedNodes: z.array(z.object({ before: SurfaceNodeSchema, after: SurfaceNodeSchema })),
  addedEdges: z.array(SurfaceEdgeSchema),
  removedEdges: z.array(SurfaceEdgeSchema),
  changedEdges: z.array(z.object({ before: SurfaceEdgeSchema, after: SurfaceEdgeSchema }))
});

export const SeveritySchema = z.enum(["info", "low", "medium", "high", "critical"]);

export const CustomPolicySchema = z.object({
  id: z.string().regex(/^[A-Za-z][A-Za-z0-9_.-]{2,63}$/),
  name: z.string().min(3),
  severity: SeveritySchema.default("high"),
  match: z
    .object({
      kinds: z.array(NodeKindSchema).default([]),
      trust_zones: z.array(TrustZoneSchema).default([]),
      methods: z.array(z.string()).default([]),
      label_pattern: z.string().optional()
    })
    .default({ kinds: [], trust_zones: [], methods: [] }),
  require_controls: z.array(ControlTypeSchema).min(1),
  security_invariant: z.string().min(5),
  potential_impact: z.string().min(5),
  asset: z.string().default("Organization-defined protected asset"),
  attacker_capability: z.string().default("Reach the matched architecture surface"),
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
    .default([]),
  cwe: z.array(z.string()).default([])
});

export const SecurityInvariantDefinitionSchema = z.object({
  id: z.string().regex(/^[A-Za-z][A-Za-z0-9_.-]{2,63}$/),
  description: z.string().min(5),
  severity: SeveritySchema.default("high"),
  applies_to: z
    .object({
      kinds: z.array(NodeKindSchema).default([]),
      trust_zones: z.array(TrustZoneSchema).default([]),
      methods: z.array(z.string()).default([]),
      label_pattern: z.string().optional()
    })
    .default({ kinds: [], trust_zones: [], methods: [] }),
  requires: z.object({ controls: z.array(ControlTypeSchema).min(1) }),
  rationale: z.string().default("Repository-defined security invariant"),
  enabled: z.boolean().default(true)
});

export const InvariantStatusSchema = z.enum(["satisfied", "violated", "not-applicable", "unknown"]);

export const InvariantEvaluationSchema = z.object({
  invariantId: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  status: InvariantStatusSchema,
  matchedNodeIds: z.array(z.string()).default([]),
  missingControls: z.array(ControlTypeSchema).default([]),
  evidence: z.array(EvidenceSchema).default([]),
  reason: z.string()
});

export const ObservationKindSchema = z.enum([
  "node-added",
  "node-removed",
  "node-changed",
  "edge-added",
  "edge-removed",
  "edge-changed",
  "invariant-evaluated"
]);

export const ObservationSchema = z.object({
  id: z.string(),
  kind: ObservationKindSchema,
  summary: z.string(),
  subjectIds: z.array(z.string()).default([]),
  evidence: z.array(EvidenceSchema).default([]),
  source: z.literal("deterministic").default("deterministic"),
  metadata: z.record(z.string(), z.unknown()).default({})
});

export const InferenceSchema = z.object({
  id: z.string(),
  hypothesis: z.string(),
  confidence: z.number().min(0).max(1),
  observationIds: z.array(z.string()).default([]),
  assumptions: z.array(z.string()).default([]),
  riskFingerprint: z.string().optional(),
  origin: z.enum(["deterministic", "policy", "invariant", "model", "unknown"]),
  model: z.string().optional()
});

export const DecisionSchema = z.object({
  id: z.string(),
  type: z.enum(["allow", "warn", "block", "accept", "verify"]),
  reason: z.string(),
  source: z.enum(["threshold", "invariant", "policy", "human", "lifecycle", "analysis-health"]),
  riskFingerprints: z.array(z.string()).default([]),
  invariantIds: z.array(z.string()).default([]),
  observationIds: z.array(z.string()).default([]),
  inferenceIds: z.array(z.string()).default([])
});

export const RiskOriginSchema = z.enum([
  "deterministic",
  "policy",
  "invariant",
  "model",
  "unknown"
]);

export const RiskStatusSchema = z.enum([
  "open",
  "mitigation-detected",
  "verification-available",
  "verified",
  "accepted",
  "closed"
]);

export const VerificationEvidenceSchema = z.object({
  recordedAt: z.string().default(() => new Date().toISOString()),
  recordedBy: z.string().default("unknown"),
  vulnerableRevision: z.string().optional(),
  repairedRevision: z.string().optional(),
  vulnerableRevisionWitnessSucceeded: z.boolean(),
  repairedRevisionWitnessBlocked: z.boolean(),
  legitimateBehaviorPassed: z.boolean(),
  architectureControlChanged: z.boolean(),
  witnessDigest: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
  vulnerableOutcome: z.enum(["reproduced", "blocked-by-control", "inconclusive"]).optional(),
  repairedOutcome: z.enum(["reproduced", "blocked-by-control", "inconclusive"]).optional(),
  graphDeltaDigest: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
  architectureEvidence: z.array(EvidenceSchema).default([]),
  commands: z.array(z.string()).default([]),
  notes: z.array(z.string()).default([]),
  artifacts: z.array(z.string()).default([])
});

export const SuggestedTestSchema = z.object({
  title: z.string(),
  framework: z.string().default("vitest"),
  language: z.string().default("typescript"),
  code: z.string(),
  purpose: z.string()
});

export const RiskFindingSchema = z.object({
  id: z.string(),
  fingerprint: z.string(),
  title: z.string(),
  severity: SeveritySchema,
  origin: RiskOriginSchema.default("unknown"),
  status: RiskStatusSchema.default("open"),
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
    .default([]),
  cwe: z.array(z.string()).default([]),
  asset: z.string(),
  attackerCapability: z.string(),
  entryPoint: z.string(),
  trustBoundary: z.string(),
  precondition: z.string(),
  attackPath: z.array(z.string()),
  potentialImpact: z.string(),
  existingControls: z.array(z.string()).default([]),
  missingControls: z.array(z.string()).default([]),
  securityInvariant: z.string(),
  evidence: z.array(EvidenceSchema),
  confidence: z.number().min(0).max(1),
  suggestedTest: SuggestedTestSchema.optional(),
  remediationPrompt: z.string().optional(),
  verificationHistory: z.array(VerificationEvidenceSchema).default([]),
  createdAt: z.string(),
  updatedAt: z.string()
});

export const AnalysisResultSchema = z.object({
  summary: z.string(),
  surfaceChanged: z.boolean(),
  confirmedNoDelta: z.boolean().optional(),
  modelRoute: z
    .enum(["none", "deterministic", "triage", "analysis", "triage-analysis", "fallback"])
    .optional(),
  coverage: CoverageSchema.optional(),
  analysisHealth: AnalysisHealthSchema.optional(),
  observations: z.array(ObservationSchema).optional(),
  inferences: z.array(InferenceSchema).optional(),
  decisions: z.array(DecisionSchema).optional(),
  invariantEvaluations: z.array(InvariantEvaluationSchema).optional(),
  findings: z.array(RiskFindingSchema),
  integrity: z.object({
    untrustedInstructionsObserved: z.boolean(),
    analysisBoundaryHeld: z.boolean(),
    notes: z.array(z.string()).default([])
  }),
  limitations: z.array(z.string()).default([]),
  model: z.string().optional(),
  usage: z
    .object({
      inputTokens: z.number().int().nonnegative().optional(),
      outputTokens: z.number().int().nonnegative().optional(),
      totalTokens: z.number().int().nonnegative().optional(),
      cachedInputTokens: z.number().int().nonnegative().optional(),
      reasoningTokens: z.number().int().nonnegative().optional(),
      modelCalls: z.number().int().nonnegative().optional()
    })
    .optional()
});

export const RunManifestSchema = z.object({
  schemaVersion: z.literal("0.1"),
  createdAt: z.string(),
  repository: z.string().min(1),
  pullRequest: z.number().int().positive().optional(),
  baseSha: z.string().min(1),
  headSha: z.string().min(1),
  workflowRef: z.string().min(1),
  actionVersion: z.string().min(1),
  extractorVersion: z.string().min(1),
  artifactSchemaVersion: z.string().min(1),
  promptVersion: z.string().min(1).optional(),
  configDigest: z.string().regex(/^[a-f0-9]{64}$/),
  contextDigest: z.string().regex(/^[a-f0-9]{64}$/),
  extractorDigest: z.string().regex(/^[a-f0-9]{64}$/),
  schemaDigest: z.string().regex(/^[a-f0-9]{64}$/),
  promptDigest: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
  model: z.string().optional(),
  coverage: CoverageSchema,
  analysisHealth: AnalysisHealthSchema,
  artifacts: z.record(z.string(), z.string().regex(/^[a-f0-9]{64}$/)),
  manifestDigest: z.string().regex(/^[a-f0-9]{64}$/)
});

export const RunRecordSchema = z.object({
  id: z.string(),
  recordedAt: z.string(),
  sourceCommit: z.string().optional(),
  graphHash: z.string(),
  nodeCount: z.number().int().nonnegative(),
  edgeCount: z.number().int().nonnegative(),
  openRiskCount: z.number().int().nonnegative(),
  highestSeverity: SeveritySchema,
  architectureChanged: z.boolean(),
  model: z.string().optional(),
  modelRoute: z
    .enum(["none", "deterministic", "triage", "analysis", "triage-analysis", "fallback"])
    .optional(),
  inputTokens: z.number().int().nonnegative().optional(),
  outputTokens: z.number().int().nonnegative().optional(),
  totalTokens: z.number().int().nonnegative().optional(),
  cachedInputTokens: z.number().int().nonnegative().optional(),
  reasoningTokens: z.number().int().nonnegative().optional(),
  modelCalls: z.number().int().nonnegative().optional()
});

export const ThreatRegisterSchema = z.object({
  schemaVersion: z.literal("0.1"),
  generatedAt: z.string(),
  stateIntegrity: z
    .object({
      graphHash: z.string(),
      registerHash: z.string().optional(),
      algorithm: z.enum(["sha256-stable-json-v2", "legacy-graph-only"]).optional(),
      configHash: z.string().optional(),
      contextHash: z.string().optional(),
      sourceCommit: z.string().optional(),
      toolVersion: z.string().default("0.5.2")
    })
    .optional(),
  nextRiskNumber: z.number().int().positive(),
  graph: AttackSurfaceGraphSchema.optional(),
  findings: z.array(RiskFindingSchema),
  invariantEvaluations: z.array(InvariantEvaluationSchema).optional(),
  runs: z.array(RunRecordSchema).default([]),
  acceptedRisks: z
    .array(
      z.object({
        riskId: z.string(),
        reason: z.string(),
        acceptedBy: z.string(),
        acceptedAt: z.string()
      })
    )
    .default([])
});

export const HedgeContextSchema = z.object({
  sensitive_assets: z.array(z.string()).default([]),
  internet_facing: z.array(z.string()).default([]),
  authentication: z.array(z.string()).default([]),
  privileged_roles: z.array(z.string()).default([]),
  trusted_external_services: z.array(z.string()).default([]),
  notes: z.array(z.string()).default([])
});

export const HedgeConfigSchema = z.object({
  framework: z.enum(["nextjs", "express", "auto"]).default("auto"),
  fail_on: SeveritySchema.default("high"),
  ignored_paths: z.array(z.string()).default([]),
  models: z
    .object({
      triage: z.string().default("gpt-5.6-luna"),
      analysis: z.string().default("gpt-5.6-sol")
    })
    .default({ triage: "gpt-5.6-luna", analysis: "gpt-5.6-sol" }),
  policies: z.array(CustomPolicySchema).default([]),
  invariants: z.array(SecurityInvariantDefinitionSchema).default([]),
  limits: z
    .object({
      max_files: z.number().int().positive().default(120),
      max_bytes: z.number().int().positive().default(350000)
    })
    .default({ max_files: 120, max_bytes: 350000 })
});

export const CollectionBundleSchema = z.object({
  schemaVersion: z.literal("0.1"),
  repository: z.string().min(1),
  pullRequest: z.number().int().positive(),
  baseSha: z.string().regex(/^[a-f0-9]{40,64}$/),
  headSha: z.string().regex(/^[a-f0-9]{40,64}$/),
  workflowRef: z.string().min(1),
  actionVersion: z.string().min(1),
  config: HedgeConfigSchema,
  context: HedgeContextSchema,
  baseline: AttackSurfaceGraphSchema,
  graph: AttackSurfaceGraphSchema,
  delta: GraphDeltaSchema,
  patch: z.string().max(400_000),
  coverage: CoverageSchema,
  analysisHealth: AnalysisHealthSchema,
  exactRevisions: z.literal(true),
  analysis: AnalysisResultSchema,
  register: ThreatRegisterSchema.optional()
});

export const ReasonBundleSchema = z.object({
  schemaVersion: z.literal("0.1"),
  repository: z.string().min(1),
  pullRequest: z.number().int().positive(),
  baseSha: z.string().regex(/^[a-f0-9]{40,64}$/),
  headSha: z.string().regex(/^[a-f0-9]{40,64}$/),
  workflowRef: z.string().min(1),
  actionVersion: z.string().min(1),
  collectionManifestDigest: z.string().regex(/^[a-f0-9]{64}$/),
  analysis: AnalysisResultSchema,
  lifecycleUpdates: z.array(RiskFindingSchema).default([])
});

export type Evidence = z.infer<typeof EvidenceSchema>;
export type Coverage = z.infer<typeof CoverageSchema>;
export type AnalysisHealth = z.infer<typeof AnalysisHealthSchema>;
export type ControlAssurance = z.infer<typeof ControlAssuranceSchema>;
export type SurfaceNode = z.infer<typeof SurfaceNodeSchema>;
export type SurfaceEdge = z.infer<typeof SurfaceEdgeSchema>;
export type AttackSurfaceGraph = z.infer<typeof AttackSurfaceGraphSchema>;
export type GraphDelta = z.infer<typeof GraphDeltaSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type RiskFinding = z.infer<typeof RiskFindingSchema>;
export type AnalysisResult = z.infer<typeof AnalysisResultSchema>;
export type ThreatRegister = z.infer<typeof ThreatRegisterSchema>;
export type RunRecord = z.infer<typeof RunRecordSchema>;
export type VerificationEvidence = z.infer<typeof VerificationEvidenceSchema>;
export type VerificationEvidenceInput = z.input<typeof VerificationEvidenceSchema>;
export type HedgeConfig = z.infer<typeof HedgeConfigSchema>;
export type CustomPolicy = z.infer<typeof CustomPolicySchema>;
export type SecurityInvariantDefinition = z.infer<typeof SecurityInvariantDefinitionSchema>;
export type InvariantEvaluation = z.infer<typeof InvariantEvaluationSchema>;
export type Observation = z.infer<typeof ObservationSchema>;
export type Inference = z.infer<typeof InferenceSchema>;
export type Decision = z.infer<typeof DecisionSchema>;
export type HedgeContext = z.infer<typeof HedgeContextSchema>;
export type RunManifest = z.infer<typeof RunManifestSchema>;
export type CollectionBundle = z.infer<typeof CollectionBundleSchema>;
export type ReasonBundle = z.infer<typeof ReasonBundleSchema>;
