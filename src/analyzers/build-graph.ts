import { basename } from "node:path";
import YAML from "yaml";
import type {
  AttackSurfaceGraph,
  ControlSchema,
  Evidence,
  HedgeConfig,
  SurfaceEdge,
  SurfaceNode
} from "../domain/schemas.js";
import type { z } from "zod";
import { stableHash } from "../utils/hash.js";
import { loadHedgeContext } from "../config/context.js";
import type { HedgeContext } from "../domain/schemas.js";
import { lineNumberAt, lineSnippet } from "../utils/lines.js";
import { collectSourceFileInventory, type SourceFile } from "./files.js";
import { detectFramework } from "./framework.js";
import { redactSensitiveContent } from "../security/untrusted.js";
import {
  extractTypeScriptFacts,
  nextMiddlewareMatchesPath,
  type AstControl,
  type AstEntrypoint,
  type AstOperation,
  type AstSecretUse
} from "./typescript-ast.js";

type Control = z.infer<typeof ControlSchema>;

export interface BuildGraphOptions {
  root: string;
  config: HedgeConfig;
  repository?: string;
  context?: HedgeContext;
}

export async function buildAttackSurfaceGraph(
  options: BuildGraphOptions
): Promise<AttackSurfaceGraph> {
  const [inventory, loadedContext] = await Promise.all([
    collectSourceFileInventory(options.root, options.config),
    options.context ? Promise.resolve(options.context) : loadHedgeContext(options.root)
  ]);
  const { files, stats: collectionStats } = inventory;
  const context = loadedContext;
  const framework = detectFramework(files, options.config);
  const nodes = new Map<string, SurfaceNode>();
  const edges = new Map<string, SurfaceEdge>();
  const unknowns: string[] = [];
  const filesByPath = new Map(files.map((file) => [file.path, file]));
  const astFacts = new Map(
    files
      .filter((file) => /\.[cm]?[jt]sx?$/.test(file.path))
      .map((file) => [file.path, extractTypeScriptFacts(file, framework)] as const)
  );
  const nextMiddlewareRules = [...astFacts.values()].flatMap((facts) => facts.middlewareRules);
  for (const rule of nextMiddlewareRules) {
    if (
      rule.matchers.some(
        (matcher) => matcher.includes("(") || matcher.includes("[") || matcher.includes("{")
      )
    ) {
      unknowns.push(
        `Complex Next.js middleware matcher in ${rule.sourcePath} was not used to assert route protection.`
      );
    }
  }

  for (const file of files) {
    analyzePackage(file, nodes);
    analyzeActionMetadata(file, nodes, edges);
    analyzeWorkflowMetadata(file, nodes, edges);
    analyzePrisma(file, nodes);

    if (/\.[cm]?[jt]sx?$/.test(file.path)) {
      const facts = astFacts.get(file.path) ?? extractTypeScriptFacts(file, framework);
      for (const diagnostic of facts.parseDiagnostics.slice(0, 2)) {
        unknowns.push(`Parser diagnostic in ${file.path}: ${diagnostic}`);
      }
      for (const secret of facts.allSecrets) addSecretNode(file, secret, nodes);
      for (const entrypoint of facts.entrypoints) {
        const inheritedControls =
          entrypoint.framework === "nextjs"
            ? nextMiddlewareRules
                .filter((rule) => nextMiddlewareMatchesPath(rule.matchers, entrypoint.path))
                .flatMap((rule) => rule.controls)
            : [];
        addAstEntrypoint(
          file,
          { ...entrypoint, controls: [...entrypoint.controls, ...inheritedControls] },
          nodes,
          edges,
          filesByPath
        );
      }
    }
  }

  connectDatabaseModels(nodes, edges);
  applyManualContext(context, nodes);

  if (![...nodes.values()].some((node) => node.kind === "entrypoint")) {
    unknowns.push(
      "No supported HTTP or workflow entry points were detected. Framework support is intentionally narrow."
    );
  }

  if (collectionStats.omittedByFileLimit || collectionStats.omittedByByteLimit) {
    unknowns.push(
      `Analysis coverage was bounded: ${collectionStats.includedFiles}/${collectionStats.discoveredFiles} candidate files (${collectionStats.includedBytes} bytes) were inspected; ${collectionStats.omittedByFileLimit} exceeded the file limit and ${collectionStats.omittedByByteLimit} exceeded the byte budget.`
    );
  }
  if (collectionStats.omittedUnsafeOrUnreadable || collectionStats.omittedBinary) {
    unknowns.push(
      `Analysis skipped ${collectionStats.omittedUnsafeOrUnreadable} unsafe or unreadable path(s) and ${collectionStats.omittedBinary} binary-looking file(s).`
    );
  }

  return {
    schemaVersion: "0.1",
    generatedAt: new Date().toISOString(),
    repository: options.repository ?? "local",
    framework,
    nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
    edges: [...edges.values()].sort((a, b) => a.id.localeCompare(b.id)),
    assumptions: [
      ...contextAssumptions(context),
      "Detected controls are evidence that relevant code exists, not proof that the control is correct or complete.",
      "Public exposure is inferred from supported route and workflow conventions and must be confirmed against deployment configuration.",
      "AST analysis is handler-scoped for supported TypeScript and JavaScript entry points; same-file helpers and supported Next.js middleware are followed, while arbitrary imported helper behavior remains partially unknown.",
      `Repository evidence coverage: ${collectionStats.includedFiles}/${collectionStats.discoveredFiles} candidate files and ${collectionStats.includedBytes} bytes analyzed.`
    ],
    unknowns: [...new Set([...unknowns, ...contextUnknowns(context)])]
  };
}

function addAstEntrypoint(
  file: SourceFile,
  entrypoint: AstEntrypoint,
  nodes: Map<string, SurfaceNode>,
  edges: Map<string, SurfaceEdge>,
  filesByPath: Map<string, SourceFile>
): void {
  const label = `${entrypoint.method} ${entrypoint.path}`;
  const id = `entrypoint:${stableHash({ label, file: file.path })}`;
  const evidence = makeEvidence(file, entrypoint.line, `${entrypoint.framework}-ast-route`);
  const controls = dedupeGraphControls(
    entrypoint.controls.map((control) =>
      astControl(filesByPath.get(control.sourcePath ?? file.path) ?? file, control)
    )
  );

  nodes.set(id, {
    id,
    kind: "entrypoint",
    label,
    trustZone: "public",
    evidence: [evidence],
    controls,
    metadata: {
      method: entrypoint.method,
      path: entrypoint.path,
      file: file.path,
      framework: entrypoint.framework,
      handler: entrypoint.handlerName ?? "inline",
      extractor: "typescript-ast"
    }
  });

  attachControlNodes(file, id, controls, nodes, edges);
  const operationOccurrences = new Map<string, number>();
  for (const operation of entrypoint.operations) {
    const identity = stableHash(operationIdentity(operation), 32);
    const occurrence = operationOccurrences.get(identity) ?? 0;
    operationOccurrences.set(identity, occurrence + 1);
    attachAstOperation(file, id, operation, occurrence, controls, nodes, edges);
  }
  for (const secret of entrypoint.secrets) {
    const secretId = addSecretNode(file, secret, nodes);
    if (!secretId) continue;
    const edgeId = `edge:${stableHash({ from: id, to: secretId, kind: "uses-secret" })}`;
    edges.set(edgeId, {
      id: edgeId,
      from: id,
      to: secretId,
      kind: "uses-secret",
      label: `Reads ${secret.name}`,
      evidence: [makeEvidence(file, secret.line, "typescript-ast-secret-use")],
      controls,
      confidence: 0.96
    });
  }
}

function attachControlNodes(
  file: SourceFile,
  entrypointId: string,
  controls: Control[],
  nodes: Map<string, SurfaceNode>,
  edges: Map<string, SurfaceEdge>
): void {
  for (const control of controls) {
    if (!["authentication", "authorization", "ownership"].includes(control.type)) continue;
    const controlKind =
      control.type === "authentication" ? "auth-control" : "authorization-control";
    const controlFile = control.evidence[0]?.file ?? file.path;
    const controlId = `${controlKind}:${stableHash({ entrypointId, type: control.type, label: control.label, file: controlFile })}`;
    nodes.set(controlId, {
      id: controlId,
      kind: controlKind,
      label: control.label,
      trustZone: "application",
      evidence: control.evidence,
      controls: [],
      metadata: { file: controlFile, controlType: control.type }
    });
    const edgeId = `edge:${stableHash({ from: entrypointId, to: controlId, kind: control.type })}`;
    edges.set(edgeId, {
      id: edgeId,
      from: entrypointId,
      to: controlId,
      kind: control.type === "authentication" ? "authenticates" : "authorizes",
      evidence: control.evidence,
      controls: [control],
      confidence: control.confidence
    });
  }
}

function attachAstOperation(
  file: SourceFile,
  entrypointId: string,
  operation: AstOperation,
  occurrence: number,
  controls: Control[],
  nodes: Map<string, SurfaceNode>,
  edges: Map<string, SurfaceEdge>
): void {
  const operationId = `${operation.kind}:${stableHash({ entrypointId, identity: operationIdentity(operation), occurrence })}`;
  const evidence = makeEvidence(file, operation.line, "typescript-ast-operation");
  nodes.set(operationId, {
    id: operationId,
    kind: operation.kind,
    label: operation.label,
    trustZone: operation.trustZone,
    evidence: [evidence],
    controls,
    metadata: { file: file.path, ...operation.metadata }
  });
  const edgeId = `edge:${stableHash({ from: entrypointId, to: operationId, kind: operation.edgeKind })}`;
  edges.set(edgeId, {
    id: edgeId,
    from: entrypointId,
    to: operationId,
    kind: operation.edgeKind,
    label: operation.label,
    evidence: [evidence],
    controls,
    confidence: 0.94
  });
}

function operationIdentity(operation: AstOperation): Record<string, unknown> {
  const metadata = operation.metadata;
  return {
    kind: operation.kind,
    edgeKind: operation.edgeKind,
    callee: metadata.callee,
    model: metadata.model,
    operation: metadata.operation,
    execution: metadata.execution,
    logging: metadata.logging
  };
}

function dedupeGraphControls(controls: Control[]): Control[] {
  return [
    ...new Map(
      controls.map((control) => [
        `${control.type}:${control.label}:${control.evidence[0]?.file ?? ""}:${control.evidence[0]?.line ?? ""}`,
        control
      ])
    ).values()
  ];
}

function astControl(file: SourceFile, control: AstControl): Control {
  return {
    type: control.type,
    label: control.label,
    evidence: [makeEvidence(file, control.line, "typescript-ast-control")],
    confidence: control.confidence
  };
}

function addSecretNode(
  file: SourceFile,
  secret: AstSecretUse,
  nodes: Map<string, SurfaceNode>,
  force = false
): string | null {
  if (!force && !isSensitiveSecretName(secret.name)) return null;
  const id = `secret:${stableHash(secret.name)}`;
  const existing = nodes.get(id);
  const evidence = makeEvidence(file, secret.line, "typescript-ast-secret");
  nodes.set(id, {
    id,
    kind: "secret",
    label: secret.name,
    trustZone: "privileged",
    evidence: dedupeEvidence([...(existing?.evidence ?? []), evidence]),
    controls: [],
    metadata: { name: secret.name }
  });
  return id;
}

function analyzeActionMetadata(
  file: SourceFile,
  nodes: Map<string, SurfaceNode>,
  edges: Map<string, SurfaceEdge>
): void {
  if (!/(^|\/)action\.ya?ml$/i.test(file.path)) return;
  try {
    const metadata = YAML.parse(file.content) as {
      name?: string;
      inputs?: Record<string, { description?: string }>;
    };
    const label = `GitHub Action: ${metadata.name ?? basename(file.path)}`;
    const entrypointId = `entrypoint:${stableHash({ label, file: file.path })}`;
    nodes.set(entrypointId, {
      id: entrypointId,
      kind: "entrypoint",
      label,
      trustZone: "application",
      evidence: [
        {
          file: file.path,
          line: 1,
          snippet: `name: ${metadata.name ?? "unknown"}`,
          extractor: "github-action-metadata"
        }
      ],
      controls: [],
      metadata: { method: "ACTION", file: file.path }
    });

    for (const [inputName, input] of Object.entries(metadata.inputs ?? {})) {
      if (!/(token|secret|api[-_]?key|credential)/i.test(inputName)) continue;
      const secretId = `secret:action-input:${inputName}`;
      const evidence = [
        {
          file: file.path,
          snippet: `${inputName}: ${input.description ?? "privileged input"}`,
          extractor: "github-action-metadata"
        }
      ];
      nodes.set(secretId, {
        id: secretId,
        kind: "secret",
        label: inputName,
        trustZone: "privileged",
        evidence,
        controls: [],
        metadata: { inputName }
      });
      const edgeId = `edge:${stableHash({ from: entrypointId, to: secretId, kind: "uses-secret" })}`;
      edges.set(edgeId, {
        id: edgeId,
        from: entrypointId,
        to: secretId,
        kind: "uses-secret",
        label: `${label} receives ${inputName}`,
        evidence,
        controls: [],
        confidence: 1
      });
    }
  } catch {
    // Invalid action metadata is non-fatal.
  }
}

function analyzeWorkflowMetadata(
  file: SourceFile,
  nodes: Map<string, SurfaceNode>,
  edges: Map<string, SurfaceEdge>
): void {
  if (!/(^|\/)\.github\/workflows\/.+\.ya?ml$/i.test(file.path)) return;
  try {
    const workflow = YAML.parse(file.content) as {
      name?: string;
      on?: string | string[] | Record<string, unknown>;
      permissions?: string | Record<string, string>;
      jobs?: Record<
        string,
        { permissions?: string | Record<string, string>; steps?: Array<Record<string, unknown>> }
      >;
    };
    const events = workflowEvents(workflow.on);
    const secrets = [...file.content.matchAll(/\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}/g)];
    const workflowSecurity = inspectWorkflowSecurity(workflow, file.content);
    for (const event of events.length ? events : ["unknown"]) {
      const label = `Workflow ${workflow.name ?? basename(file.path)} (${event})`;
      const id = `entrypoint:${stableHash({ label, file: file.path })}`;
      const eventIndex = file.content.indexOf(event);
      const evidence = makeEvidence(
        file,
        eventIndex >= 0 ? lineNumberAt(file.content, eventIndex) : 1,
        "github-workflow-metadata"
      );
      nodes.set(id, {
        id,
        kind: "entrypoint",
        label,
        trustZone: ["pull_request", "pull_request_target", "issue_comment"].includes(event)
          ? "public"
          : "application",
        evidence: [evidence],
        controls: [],
        metadata: {
          method: "WORKFLOW",
          event,
          file: file.path,
          pullRequestTarget: event === "pull_request_target",
          permissions: workflowSecurity.permissions,
          writePermissions: workflowSecurity.writePermissions,
          checksOutPullRequestHead: workflowSecurity.checksOutPullRequestHead,
          untrustedInterpolationInRun: workflowSecurity.untrustedInterpolationInRun,
          checkoutPersistsCredentials: workflowSecurity.checkoutPersistsCredentials
        }
      });

      for (const match of secrets) {
        const name = match[1] ?? "UNKNOWN";
        const line = lineNumberAt(file.content, match.index ?? 0);
        const secretId = addSecretNode(file, { name, line }, nodes, true);
        if (!secretId) continue;
        const edgeId = `edge:${stableHash({ from: id, to: secretId, kind: "uses-secret" })}`;
        edges.set(edgeId, {
          id: edgeId,
          from: id,
          to: secretId,
          kind: "uses-secret",
          label: `Workflow uses ${name}`,
          evidence: [makeEvidence(file, line, "github-workflow-secret")],
          controls: [],
          confidence: 1
        });
      }
    }
  } catch {
    // Invalid workflow YAML is non-fatal.
  }
}

interface WorkflowSecurityMetadata {
  permissions: Record<string, string>;
  writePermissions: string[];
  checksOutPullRequestHead: boolean;
  untrustedInterpolationInRun: boolean;
  checkoutPersistsCredentials: boolean;
}

function inspectWorkflowSecurity(
  workflow: {
    permissions?: string | Record<string, string>;
    jobs?: Record<
      string,
      { permissions?: string | Record<string, string>; steps?: Array<Record<string, unknown>> }
    >;
  },
  content: string
): WorkflowSecurityMetadata {
  const permissions: Record<string, string> = {};
  mergePermissions(permissions, workflow.permissions, "workflow");
  for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
    mergePermissions(permissions, job.permissions, `job:${jobName}`);
  }
  const writePermissions = Object.entries(permissions)
    .filter(([, value]) => value === "write" || value === "write-all")
    .map(([name]) => name)
    .sort();
  const checksOutPullRequestHead =
    /uses:\s*actions\/checkout@[^\n]+[\s\S]{0,500}?ref:\s*["']?\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}/i.test(
      content
    );
  const untrustedInterpolationInRun =
    /run:\s*(?:[|>-]\s*)?[\s\S]{0,800}?\$\{\{\s*(?:github\.event\.(?:pull_request\.(?:title|body|head\.ref)|issue\.title|comment\.body)|github\.head_ref)\s*\}\}/i.test(
      content
    );
  const hasCheckout = /uses:\s*actions\/checkout@/i.test(content);
  const checkoutPersistsCredentials = hasCheckout && !/persist-credentials:\s*false/i.test(content);
  return {
    permissions,
    writePermissions,
    checksOutPullRequestHead,
    untrustedInterpolationInRun,
    checkoutPersistsCredentials
  };
}

function mergePermissions(
  result: Record<string, string>,
  value: string | Record<string, string> | undefined,
  prefix: string
): void {
  if (!value) return;
  if (typeof value === "string") {
    result[`${prefix}:all`] = value;
    return;
  }
  for (const [name, level] of Object.entries(value)) result[`${prefix}:${name}`] = level;
}

function workflowEvents(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  if (value && typeof value === "object") return Object.keys(value as Record<string, unknown>);
  return [];
}

function analyzePackage(file: SourceFile, nodes: Map<string, SurfaceNode>): void {
  if (!file.path.endsWith("package.json")) return;
  try {
    const pkg = JSON.parse(file.content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const dependencies = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    for (const [name, version] of Object.entries(dependencies)) {
      if (!isSecurityRelevantDependency(name)) continue;
      const id = `dependency:${name}`;
      nodes.set(id, {
        id,
        kind: "dependency",
        label: `${name}@${version}`,
        trustZone: "external",
        evidence: [{ file: file.path, extractor: "package-extractor" }],
        controls: [],
        metadata: { name, version }
      });
    }
  } catch {
    // Invalid package.json is intentionally non-fatal.
  }
}

function analyzePrisma(file: SourceFile, nodes: Map<string, SurfaceNode>): void {
  if (!file.path.endsWith("schema.prisma")) return;
  const pattern = /model\s+([A-Za-z0-9_]+)\s*\{([\s\S]*?)\}/g;
  for (const match of file.content.matchAll(pattern)) {
    const model = match[1] ?? "Unknown";
    const body = match[2] ?? "";
    const line = lineNumberAt(file.content, match.index ?? 0);
    const fields = body
      .split(/\r?\n/)
      .map((value) => /^\s*([A-Za-z_][A-Za-z0-9_]*)\s+/.exec(value)?.[1])
      .filter((value): value is string => typeof value === "string" && !value.startsWith("@@"));
    const sensitiveFields = fields.filter(isSensitiveFieldName);
    const id = `data-model:${model}`;
    nodes.set(id, {
      id,
      kind: "data-model",
      label: model,
      trustZone: "data",
      evidence: [makeEvidence(file, line, "prisma-extractor")],
      controls: [],
      metadata: {
        model,
        fields,
        sensitiveFields,
        sensitive: sensitiveFields.length > 0 || isSensitiveModelName(model)
      }
    });
  }
}

function connectDatabaseModels(
  nodes: Map<string, SurfaceNode>,
  edges: Map<string, SurfaceEdge>
): void {
  const models = new Map(
    [...nodes.values()]
      .filter((node) => node.kind === "data-model")
      .map((node) => [String(node.metadata.model ?? node.label).toLowerCase(), node])
  );
  for (const operation of nodes.values()) {
    if (operation.kind !== "database") continue;
    const modelName = String(operation.metadata.model ?? "").toLowerCase();
    const model = models.get(modelName);
    if (!model) continue;
    const isWrite = /write/i.test(operation.label);
    const id = `edge:${stableHash({ from: operation.id, to: model.id, kind: isWrite ? "writes" : "reads" })}`;
    edges.set(id, {
      id,
      from: operation.id,
      to: model.id,
      kind: isWrite ? "writes" : "reads",
      label: operation.label,
      evidence: operation.evidence,
      controls: operation.controls,
      confidence: 0.95
    });
  }
}

function makeEvidence(file: SourceFile, line: number, extractor: string): Evidence {
  return {
    file: file.path,
    line,
    snippet: redactSensitiveContent(lineSnippet(file.content, line)).value,
    extractor
  };
}

function dedupeEvidence(values: Evidence[]): Evidence[] {
  return [
    ...new Map(
      values.map((value) => [`${value.file}:${value.line ?? ""}:${value.extractor}`, value])
    ).values()
  ];
}

function isSensitiveSecretName(name: string): boolean {
  return /(api.?key|secret|token|password|passwd|credential|private.?key|signing|webhook.?secret|database.?url|dsn|connection.?string)/i.test(
    name
  );
}

function isSecurityRelevantDependency(name: string): boolean {
  return /auth|passport|clerk|next-auth|jsonwebtoken|jose|aws-sdk|s3|stripe|prisma|drizzle|firebase|supabase|axios|express|next|helmet|cors|rate-limit|openai/.test(
    name
  );
}

function isSensitiveFieldName(name: string): boolean {
  return /(?:password|passwd|hash|token|secret|ssn|socialSecurity|email|phone|address|birth|dob|medical|diagnosis|payment|card|bank|routing|salary|income|tax|license|passport|biometric|mfa|otp)/i.test(
    name
  );
}

function isSensitiveModelName(name: string): boolean {
  return /(?:user|account|identity|credential|payment|invoice|patient|medical|employee|payroll|tax|session|token)/i.test(
    name
  );
}

function applyManualContext(context: HedgeContext, nodes: Map<string, SurfaceNode>): void {
  for (const asset of context.sensitive_assets) {
    const id = `data-model:context:${stableHash(asset)}`;
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        kind: "data-model",
        label: asset,
        trustZone: "data",
        evidence: [],
        controls: [],
        metadata: { manualContext: true, sensitiveAsset: true }
      });
    }
  }
  for (const service of context.trusted_external_services) {
    const id = `external-service:context:${stableHash(service)}`;
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        kind: "external-service",
        label: service,
        trustZone: "external",
        evidence: [],
        controls: [],
        metadata: { manualContext: true, trusted: true }
      });
    }
  }
  for (const mechanism of context.authentication) {
    const id = `auth-control:context:${stableHash(mechanism)}`;
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        kind: "auth-control",
        label: mechanism,
        trustZone: "application",
        evidence: [],
        controls: [],
        metadata: { manualContext: true }
      });
    }
  }
  for (const role of context.privileged_roles) {
    const id = `component:role:${stableHash(role)}`;
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        kind: "component",
        label: `Privileged role: ${role}`,
        trustZone: "privileged",
        evidence: [],
        controls: [],
        metadata: { manualContext: true, privilegedRole: true }
      });
    }
  }
}

function contextAssumptions(context: HedgeContext): string[] {
  const values: string[] = [];
  if (context.internet_facing.length)
    values.push(
      `Maintainer-confirmed internet-facing surfaces: ${context.internet_facing.join(", ")}.`
    );
  if (context.authentication.length)
    values.push(
      `Maintainer-confirmed authentication mechanisms: ${context.authentication.join(", ")}.`
    );
  if (context.privileged_roles.length)
    values.push(`Maintainer-confirmed privileged roles: ${context.privileged_roles.join(", ")}.`);
  if (context.trusted_external_services.length)
    values.push(
      `Maintainer-confirmed trusted external services: ${context.trusted_external_services.join(", ")}.`
    );
  values.push(...context.notes.map((note) => `Maintainer context: ${note}`));
  return values;
}

function contextUnknowns(context: HedgeContext): string[] {
  const values: string[] = [];
  if (!context.sensitive_assets.length)
    values.push("Sensitive assets were not confirmed in .hedge/context.yml.");
  if (!context.internet_facing.length)
    values.push("Internet-facing deployment surfaces were not confirmed in .hedge/context.yml.");
  if (!context.authentication.length)
    values.push(
      "Authentication mechanisms were inferred from code and not confirmed in .hedge/context.yml."
    );
  if (!context.privileged_roles.length)
    values.push("Privileged roles were not confirmed in .hedge/context.yml.");
  if (!context.trusted_external_services.length)
    values.push("Trusted external services were not confirmed in .hedge/context.yml.");
  return values;
}
