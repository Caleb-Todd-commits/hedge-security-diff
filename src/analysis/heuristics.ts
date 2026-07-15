import type {
  AttackSurfaceGraph,
  GraphDelta,
  RiskFinding,
  Severity,
  SurfaceEdge,
  SurfaceNode
} from "../domain/schemas.js";
import { stableHash } from "../utils/hash.js";

export function analyzeWithHeuristics(
  delta: GraphDelta,
  graph?: AttackSurfaceGraph
): RiskFinding[] {
  const findings: RiskFinding[] = [];

  for (const node of delta.addedNodes) {
    if (node.kind !== "entrypoint") continue;
    const method = String(node.metadata.method ?? "GET").toUpperCase();
    const controls = controlTypes(node);
    const mutating = ["POST", "PUT", "PATCH", "DELETE", "ACTION"].includes(method);

    if (mutating && !controls.has("authentication")) {
      findings.push(
        makeFinding({
          title: "New mutating entry point has no detected authentication control",
          severity: "high",
          stride: ["Spoofing", "Elevation of Privilege"],
          cwe: ["CWE-306"],
          asset: "Application data and privileged operations",
          attackerCapability: "Unauthenticated network access",
          entryPoint: node.label,
          trustBoundary: "Public network to application",
          precondition:
            "The route is deployed and reachable without an upstream authentication control.",
          attackPath: ["Public user", node.label, "Privileged application operation"],
          potentialImpact: "An unauthenticated actor may invoke a state-changing operation.",
          existingControls: controlLabels(node),
          missingControls: [
            "Verified authentication",
            "Authorization scoped to the target resource"
          ],
          securityInvariant: `Only authenticated and authorized principals may invoke ${node.label}.`,
          evidence: node.evidence,
          confidence: 0.9,
          testCode: unauthenticatedTest(node.label)
        })
      );
    }

    if (/\badmin\b/i.test(node.label) && !controls.has("authorization")) {
      findings.push(
        makeFinding({
          title: "New administrative entry point has no detected role or permission check",
          severity: "high",
          stride: ["Elevation of Privilege"],
          cwe: ["CWE-862"],
          asset: "Administrative capabilities",
          attackerCapability: "Authenticated or unauthenticated access to the route",
          entryPoint: node.label,
          trustBoundary: "Application user to administrative privilege",
          precondition: "The route is reachable and no upstream role enforcement exists.",
          attackPath: ["Non-admin user", node.label, "Administrative operation"],
          potentialImpact: "A non-administrator may invoke privileged behavior.",
          existingControls: controlLabels(node),
          missingControls: ["Explicit role or permission enforcement"],
          securityInvariant: `${node.label} must reject principals without the required administrative permission.`,
          evidence: node.evidence,
          confidence: 0.86,
          testCode: authorizationTest(node.label)
        })
      );
    }

    if (node.metadata.pullRequestTarget === true) {
      const secretEdges = edgesFrom(node.id, graph).filter((edge) => edge.kind === "uses-secret");
      if (secretEdges.length) {
        findings.push(
          makeFinding({
            title: "pull_request_target workflow newly combines untrusted PR context with secrets",
            severity: "critical",
            stride: ["Tampering", "Information Disclosure", "Elevation of Privilege"],
            cwe: [],
            asset: "Repository credentials and protected automation",
            attackerCapability: "Open or modify a pull request from an untrusted branch",
            entryPoint: node.label,
            trustBoundary: "Untrusted pull request metadata to privileged workflow",
            precondition:
              "The workflow consumes PR-controlled data or checks out PR code while secrets are available.",
            attackPath: ["Pull request author", node.label, "Repository secret or write token"],
            potentialImpact:
              "Untrusted contribution content may influence a secret-bearing workflow.",
            existingControls: controlLabels(node),
            missingControls: [
              "Strict separation between untrusted PR data and privileged jobs",
              "No execution of PR-controlled code in the secret-bearing job"
            ],
            securityInvariant:
              "A pull_request_target workflow must never execute or interpolate untrusted PR content in a privileged context.",
            evidence: [...node.evidence, ...secretEdges.flatMap((edge) => edge.evidence)],
            confidence: 0.94,
            testCode: workflowBoundaryTest(node.label)
          })
        );
      }
    }

    if (node.metadata.method === "WORKFLOW") {
      const event = String(node.metadata.event ?? "unknown");
      const writePermissions = Array.isArray(node.metadata.writePermissions)
        ? node.metadata.writePermissions.filter(
            (value): value is string => typeof value === "string"
          )
        : [];
      const publiclyTriggered = ["pull_request", "pull_request_target", "issue_comment"].includes(
        event
      );
      if (publiclyTriggered && writePermissions.length) {
        findings.push(
          makeFinding({
            title: "Publicly triggerable workflow adds repository write permissions",
            severity:
              event === "pull_request_target" || event === "issue_comment" ? "high" : "medium",
            stride: ["Tampering", "Elevation of Privilege"],
            cwe: [],
            asset: "Repository contents and automation identity",
            attackerCapability: `Trigger the ${event} workflow event`,
            entryPoint: node.label,
            trustBoundary: "Untrusted GitHub event to repository write token",
            precondition:
              "The workflow token receives write permission on a publicly triggerable event.",
            attackPath: [
              "External contributor",
              node.label,
              `Write permissions: ${writePermissions.join(", ")}`
            ],
            potentialImpact:
              "Untrusted event data or a compromised action step may modify repository resources.",
            existingControls: controlLabels(node),
            missingControls: [
              "Least-privilege job permissions",
              "Separate untrusted analysis from privileged publication"
            ],
            securityInvariant:
              "Publicly triggerable jobs must remain read-only unless a separate trusted approval gate authorizes a narrowly scoped write.",
            evidence: node.evidence,
            confidence: 0.86,
            testCode: workflowPermissionTest(node.label)
          })
        );
      }

      const privileged =
        writePermissions.length > 0 ||
        edgesFrom(node.id, graph).some((edge) => edge.kind === "uses-secret");
      if (node.metadata.untrustedInterpolationInRun === true && privileged) {
        findings.push(
          makeFinding({
            title: "Untrusted GitHub event text is interpolated into a privileged shell step",
            severity: "critical",
            stride: ["Tampering", "Information Disclosure", "Elevation of Privilege"],
            cwe: ["CWE-78"],
            asset: "Workflow runner, repository token, and configured secrets",
            attackerCapability: "Control pull request, issue, or comment text",
            entryPoint: node.label,
            trustBoundary: "Untrusted event text to privileged shell",
            precondition:
              "Event-controlled text is directly interpolated into a run step with privileged context.",
            attackPath: [
              "External contributor",
              node.label,
              "Shell command",
              "Repository credentials"
            ],
            potentialImpact:
              "An attacker may inject shell syntax and execute commands with the workflow job's permissions.",
            existingControls: controlLabels(node),
            missingControls: [
              "Pass untrusted values through environment variables",
              "Strict quoting and input validation",
              "Read-only permissions in the untrusted job"
            ],
            securityInvariant:
              "Untrusted event fields must never be directly interpolated into shell source code.",
            evidence: node.evidence,
            confidence: 0.96,
            testCode: workflowInterpolationTest(node.label)
          })
        );
      }

      if (node.metadata.checksOutPullRequestHead === true && privileged) {
        findings.push(
          makeFinding({
            title: "Privileged workflow checks out untrusted pull request code",
            severity: "critical",
            stride: ["Tampering", "Information Disclosure", "Elevation of Privilege"],
            cwe: [],
            asset: "Workflow credentials and runner environment",
            attackerCapability: "Modify code on the pull request head branch",
            entryPoint: node.label,
            trustBoundary: "Untrusted pull request code to privileged runner",
            precondition:
              "The job checks out the PR head while secrets or write permissions are available.",
            attackPath: ["Pull request author", "PR head code", node.label, "Privileged runner"],
            potentialImpact:
              "Repository-controlled scripts or build steps may execute with credentials available to the job.",
            existingControls: controlLabels(node),
            missingControls: [
              "Never execute PR head code in the privileged job",
              "Artifact-only handoff to a separate credential-free verification job"
            ],
            securityInvariant:
              "A secret-bearing or write-capable workflow must not execute code from an untrusted pull request revision.",
            evidence: node.evidence,
            confidence: 0.97,
            testCode: workflowCheckoutBoundaryTest(node.label)
          })
        );
      }
    }
  }

  for (const pair of delta.changedNodes) {
    if (pair.after.kind !== "entrypoint") continue;
    const removed = removedControlTypes(pair.before, pair.after);
    const method = String(pair.after.metadata.method ?? "GET").toUpperCase();
    const mutating = ["POST", "PUT", "PATCH", "DELETE", "ACTION"].includes(method);
    const important = removed.filter((value) =>
      [
        "authentication",
        "authorization",
        "ownership",
        "validation",
        "size-limit",
        "content-type"
      ].includes(value)
    );

    if (important.length) {
      findings.push(
        makeFinding({
          title: `Security control removed from existing entry point: ${important.join(", ")}`,
          severity:
            important.includes("authentication") || important.includes("authorization")
              ? mutating
                ? "critical"
                : "high"
              : "high",
          stride: ["Tampering", "Elevation of Privilege"],
          cwe: [],
          asset: "Previously protected application behavior",
          attackerCapability: "Reach the modified entry point after the control regression",
          entryPoint: pair.after.label,
          trustBoundary: `${pair.after.trustZone} to application`,
          precondition: "The removed control was not replaced by an equivalent upstream control.",
          attackPath: ["User", pair.after.label, `Behavior without ${important.join("/")}`],
          potentialImpact: "A previously enforced security property may no longer hold.",
          existingControls: controlLabels(pair.after),
          missingControls: important.map((value) => `Replacement for removed ${value} control`),
          securityInvariant: `${pair.after.label} must preserve or strengthen its previously detected security controls.`,
          evidence: [...pair.before.evidence, ...pair.after.evidence],
          confidence: 0.9,
          testCode: controlRegressionTest(pair.after.label, important)
        })
      );
    }

    if (pair.after.metadata.method === "WORKFLOW") {
      const beforeWrites = new Set(
        Array.isArray(pair.before.metadata.writePermissions)
          ? pair.before.metadata.writePermissions.filter(
              (value): value is string => typeof value === "string"
            )
          : []
      );
      const afterWrites = Array.isArray(pair.after.metadata.writePermissions)
        ? pair.after.metadata.writePermissions.filter(
            (value): value is string => typeof value === "string"
          )
        : [];
      const expanded = afterWrites.filter((value) => !beforeWrites.has(value));
      if (expanded.length) {
        findings.push(
          makeFinding({
            title: "Existing workflow expands repository write permissions",
            severity: "high",
            stride: ["Tampering", "Elevation of Privilege"],
            cwe: [],
            asset: "Repository resources and workflow identity",
            attackerCapability: "Reach or compromise a step in the modified workflow",
            entryPoint: pair.after.label,
            trustBoundary: "Workflow execution to newly writable repository resources",
            precondition: "The modified workflow runs with the expanded token permissions.",
            attackPath: [pair.after.label, `New write permissions: ${expanded.join(", ")}`],
            potentialImpact:
              "A compromised or attacker-influenced step gains authority it did not previously possess.",
            existingControls: controlLabels(pair.after),
            missingControls: [
              "Justification and job-level least privilege for each new write scope"
            ],
            securityInvariant:
              "Workflow token permissions must not expand without a narrowly scoped, reviewable requirement.",
            evidence: [...pair.before.evidence, ...pair.after.evidence],
            confidence: 0.9,
            testCode: workflowPermissionTest(pair.after.label)
          })
        );
      }
    }
  }

  for (const edge of delta.addedEdges) {
    const source = findNode(edge.from, delta, graph);
    const target = findNode(edge.to, delta, graph);
    if (!source || !target) continue;
    const controls = new Set(
      [...edge.controls, ...source.controls, ...target.controls].map((control) => control.type)
    );

    if (
      target.kind === "storage" &&
      edge.kind === "writes" &&
      target.metadata.destructive !== true &&
      !/delete/i.test(target.label)
    ) {
      const missing = [
        !controls.has("authentication") ? "Verified authentication" : null,
        !controls.has("size-limit") ? "Payload or file size limit" : null,
        !controls.has("content-type") ? "Content type allowlist" : null,
        !controls.has("ownership") ? "Object ownership constraint" : null
      ].filter((value): value is string => Boolean(value));
      if (missing.length) {
        findings.push(
          makeFinding({
            title: "New storage write crosses a trust boundary without complete upload controls",
            severity: missing.length >= 2 ? "high" : "medium",
            stride: ["Tampering", "Denial of Service"],
            cwe: ["CWE-434"],
            asset: "Object storage and downstream file processors",
            attackerCapability: "Submit attacker-controlled content to the new entry point",
            entryPoint: source.label,
            trustBoundary: `${source.trustZone} to ${target.trustZone}`,
            precondition: "User-controlled content reaches the storage operation.",
            attackPath: ["External user", source.label, target.label],
            potentialImpact:
              "Unexpected content, oversized payloads, or cross-tenant object writes may reach privileged storage.",
            existingControls: unique([...controlLabels(source), ...controlLabels(target)]),
            missingControls: missing,
            securityInvariant:
              "Uploaded content must be authenticated, tenant-scoped, type-checked, and bounded before storage.",
            evidence: [...source.evidence, ...target.evidence],
            confidence: 0.9,
            testCode: uploadBoundaryTest(source.label)
          })
        );
      }
    }

    if (target.kind === "database" && edge.kind === "writes" && source.trustZone === "public") {
      const missing = [
        !controls.has("authentication") ? "Verified authentication" : null,
        dynamicResource(source) && !controls.has("ownership")
          ? "Resource ownership or tenant constraint"
          : null
      ].filter((value): value is string => Boolean(value));
      if (
        missing.length &&
        !findings.some(
          (finding) => finding.entryPoint === source.label && /authentication/.test(finding.title)
        )
      ) {
        findings.push(
          makeFinding({
            title: "New public route writes application data without complete access controls",
            severity: "high",
            stride: ["Tampering", "Elevation of Privilege"],
            cwe: ["CWE-862"],
            asset: target.label,
            attackerCapability:
              "Invoke the public route with attacker-selected identifiers or payloads",
            entryPoint: source.label,
            trustBoundary: "Public request to persistent application data",
            precondition: "The database operation is reachable through the new route.",
            attackPath: ["External user", source.label, target.label],
            potentialImpact:
              "Unauthorized or cross-tenant records may be created, modified, or deleted.",
            existingControls: controlLabels(source),
            missingControls: missing,
            securityInvariant:
              "Every persistent write must be authenticated and constrained to resources the principal may modify.",
            evidence: [...source.evidence, ...target.evidence],
            confidence: 0.84,
            testCode: ownershipTest(source.label)
          })
        );
      }
    }

    if (target.kind === "database" && edge.kind === "reads" && source.trustZone === "public") {
      const modelNodes = edgesFrom(target.id, graph)
        .filter((candidate) => candidate.kind === "reads")
        .map((candidate) => findNode(candidate.to, delta, graph))
        .filter((candidate): candidate is SurfaceNode => Boolean(candidate));
      const sensitive = modelNodes.filter((candidate) => candidate.metadata.sensitive === true);
      if (sensitive.length) {
        const missing = [
          !controls.has("authentication") ? "Verified authentication" : null,
          dynamicResource(source) && !controls.has("ownership")
            ? "Resource ownership or tenant constraint"
            : null
        ].filter((value): value is string => Boolean(value));
        if (missing.length) {
          const fields = sensitive.flatMap((candidate) =>
            Array.isArray(candidate.metadata.sensitiveFields)
              ? candidate.metadata.sensitiveFields.filter(
                  (value): value is string => typeof value === "string"
                )
              : []
          );
          findings.push(
            makeFinding({
              title: "Public route reads a sensitive data model without complete access controls",
              severity: "high",
              stride: ["Information Disclosure", "Elevation of Privilege"],
              cwe: ["CWE-862"],
              asset: sensitive.map((candidate) => candidate.label).join(", "),
              attackerCapability: "Invoke the route and choose identifiers or query parameters",
              entryPoint: source.label,
              trustBoundary: "Public request to sensitive persistent data",
              precondition:
                "The database read result is reachable through the public request flow.",
              attackPath: [
                "External user",
                source.label,
                ...sensitive.map((candidate) => candidate.label)
              ],
              potentialImpact: fields.length
                ? `Sensitive fields may be read without complete access control: ${unique(fields).join(", ")}.`
                : "Sensitive account or identity records may be read without complete access control.",
              existingControls: controlLabels(source),
              missingControls: missing,
              securityInvariant:
                "Sensitive records must be authenticated and constrained to records the principal is authorized to view.",
              evidence: [
                ...source.evidence,
                ...target.evidence,
                ...sensitive.flatMap((candidate) => candidate.evidence)
              ],
              confidence: 0.82,
              testCode: sensitiveReadTest(source.label)
            })
          );
        }
      }
    }

    if (edge.kind === "uses-secret" && source.trustZone === "public") {
      findings.push(
        makeFinding({
          title: "Public entry point newly depends on a privileged secret",
          severity: "medium",
          stride: ["Information Disclosure"],
          cwe: [],
          asset: target.label,
          attackerCapability:
            "Repeatedly invoke the public route and influence error paths or outbound requests",
          entryPoint: source.label,
          trustBoundary: "Public request to privileged credential",
          precondition: "The route consumes the secret during request processing.",
          attackPath: ["External user", source.label, target.label],
          potentialImpact:
            "Error handling, logging, or request construction could expose or misuse the credential.",
          existingControls: controlLabels(source),
          missingControls: [
            "Secret-safe error handling",
            "Outbound destination allowlist where relevant",
            "Log redaction"
          ],
          securityInvariant:
            "A public request must never control, reveal, or redirect use of a privileged credential.",
          evidence: [...source.evidence, ...target.evidence],
          confidence: 0.72,
          testCode: secretBoundaryTest(source.label)
        })
      );
    }

    if (
      target.kind === "external-service" &&
      target.metadata.destination === "dynamic" &&
      target.metadata.userControlledHost === true
    ) {
      if (!controls.has("validation")) {
        findings.push(
          makeFinding({
            title: "New outbound request uses a dynamic destination without a detected allowlist",
            severity: "medium",
            stride: ["Tampering", "Information Disclosure"],
            cwe: ["CWE-918"],
            asset: "Internal network reachability and outbound credentials",
            attackerCapability: "Influence the destination used by the public entry point",
            entryPoint: source.label,
            trustBoundary: `${source.trustZone} to external network`,
            precondition: "Request-controlled data can reach the outbound destination argument.",
            attackPath: ["External user", source.label, target.label],
            potentialImpact:
              "The server may be induced to contact unintended internal or external destinations.",
            existingControls: controlLabels(source),
            missingControls: ["Destination allowlist or strict URL validation"],
            securityInvariant:
              "Outbound destinations derived from requests must be restricted to approved hosts and schemes.",
            evidence: [...source.evidence, ...target.evidence],
            confidence: 0.68,
            testCode: outboundDestinationTest(source.label)
          })
        );
      }
    }

    if (target.metadata.execution === true && source.trustZone === "public") {
      const requestInfluenced = target.metadata.userControlled === true;
      findings.push(
        makeFinding({
          title: requestInfluenced
            ? "Public entry point passes request-influenced data to privileged code or command execution"
            : "Public entry point newly reaches privileged code or command execution",
          severity: requestInfluenced ? "critical" : "high",
          stride: ["Tampering", "Elevation of Privilege"],
          cwe: ["CWE-78", "CWE-94"],
          asset: "Application host and runtime identity",
          attackerCapability: requestInfluenced
            ? "Influence arguments reaching an execution primitive"
            : "Trigger a privileged execution path through the public entry point",
          entryPoint: source.label,
          trustBoundary: "Public request to host execution",
          precondition: requestInfluenced
            ? "Request-controlled data reaches the execution call directly or indirectly."
            : "The public route can trigger the execution primitive; argument influence was not established.",
          attackPath: ["External user", source.label, target.label],
          potentialImpact: requestInfluenced
            ? "An attacker may execute commands or code with the application runtime's privileges."
            : "An attacker may repeatedly trigger a privileged host operation or reach an execution path whose argument safety requires review.",
          existingControls: controlLabels(source),
          missingControls: [
            "Eliminate dynamic execution",
            "Strict fixed-command allowlist and argument isolation"
          ],
          securityInvariant:
            "Untrusted request data must never become executable code, a shell command, or command arguments.",
          evidence: [...source.evidence, ...target.evidence],
          confidence: requestInfluenced ? 0.92 : 0.72,
          testCode: commandExecutionTest(source.label)
        })
      );
    }

    if (target.metadata.logging === true && target.metadata.secretReferenced === true) {
      const secretUse = edgesFrom(source.id, graph).find(
        (candidate) => candidate.kind === "uses-secret"
      );
      if (secretUse) {
        const secret = findNode(secretUse.to, delta, graph);
        findings.push(
          makeFinding({
            title: "New logging path exists in a request flow that consumes a privileged secret",
            severity: "medium",
            stride: ["Information Disclosure"],
            cwe: ["CWE-532"],
            asset: secret?.label ?? "Privileged credential",
            attackerCapability: "Trigger error or diagnostic paths through the public entry point",
            entryPoint: source.label,
            trustBoundary: "Privileged request state to external logs",
            precondition:
              "Secret-bearing values or error objects may be included in log arguments.",
            attackPath: ["External user", source.label, target.label],
            potentialImpact: "Credentials or sensitive request context may be retained in logs.",
            existingControls: controlLabels(source),
            missingControls: ["Explicit structured log redaction"],
            securityInvariant:
              "Credentials and secret-bearing objects must never be serialized to logs.",
            evidence: [...source.evidence, ...target.evidence, ...(secret?.evidence ?? [])],
            confidence: 0.62,
            testCode: logRedactionTest(source.label)
          })
        );
      }
    }
  }

  return deduplicate(findings);
}

interface FindingInput {
  title: string;
  severity: Severity;
  stride: RiskFinding["stride"];
  cwe: string[];
  asset: string;
  attackerCapability: string;
  entryPoint: string;
  trustBoundary: string;
  precondition: string;
  attackPath: string[];
  potentialImpact: string;
  existingControls: string[];
  missingControls: string[];
  securityInvariant: string;
  evidence: RiskFinding["evidence"];
  confidence: number;
  testCode: string;
}

function makeFinding(input: FindingInput): RiskFinding {
  const now = new Date().toISOString();
  const fingerprint = stableHash(
    {
      title: input.title,
      entryPoint: input.entryPoint,
      attackPath: input.attackPath,
      missingControls: input.missingControls
    },
    24
  );
  return {
    id: "HEDGE-PENDING",
    fingerprint,
    title: input.title,
    severity: input.severity,
    origin: "deterministic",
    status: "open",
    stride: input.stride,
    cwe: input.cwe,
    asset: input.asset,
    attackerCapability: input.attackerCapability,
    entryPoint: input.entryPoint,
    trustBoundary: input.trustBoundary,
    precondition: input.precondition,
    attackPath: input.attackPath,
    potentialImpact: input.potentialImpact,
    existingControls: input.existingControls,
    missingControls: input.missingControls,
    securityInvariant: input.securityInvariant,
    evidence: input.evidence,
    confidence: input.confidence,
    suggestedTest: {
      title: `Regression witness for ${input.entryPoint}`,
      framework: "vitest",
      language: "typescript",
      purpose: input.securityInvariant,
      code: input.testCode
    },
    remediationPrompt: remediationPrompt(input),
    verificationHistory: [],
    createdAt: now,
    updatedAt: now
  };
}

function findNode(
  id: string,
  delta: GraphDelta,
  graph?: AttackSurfaceGraph
): SurfaceNode | undefined {
  return (
    delta.addedNodes.find((node) => node.id === id) ??
    delta.changedNodes.find((pair) => pair.after.id === id)?.after ??
    graph?.nodes.find((node) => node.id === id)
  );
}

function edgesFrom(id: string, graph?: AttackSurfaceGraph): SurfaceEdge[] {
  return graph?.edges.filter((edge) => edge.from === id) ?? [];
}

function controlTypes(node: SurfaceNode): Set<string> {
  return new Set(node.controls.map((control) => control.type));
}

function controlLabels(node: SurfaceNode): string[] {
  return node.controls.map((control) => control.label);
}

function removedControlTypes(before: SurfaceNode, after: SurfaceNode): string[] {
  const current = controlTypes(after);
  return [...controlTypes(before)].filter((value) => !current.has(value));
}

function dynamicResource(node: SurfaceNode): boolean {
  return /[:*][A-Za-z0-9_]+/.test(String(node.metadata.path ?? node.label));
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function deduplicate(findings: RiskFinding[]): RiskFinding[] {
  return [...new Map(findings.map((finding) => [finding.fingerprint, finding])).values()];
}

function remediationPrompt(input: FindingInput): string {
  return [
    `Remediate this evidence-backed Hedge finding: ${input.title}.`,
    `Security invariant: ${input.securityInvariant}`,
    `Entry point: ${input.entryPoint}`,
    `Missing controls: ${input.missingControls.join(", ") || "none recorded"}.`,
    "Make the smallest focused change, add a regression witness that fails on the vulnerable revision and passes after the fix, preserve legitimate behavior, run the relevant tests, and explain residual uncertainty."
  ].join("\n");
}

function unauthenticatedTest(entryPoint: string): string {
  return `it("rejects unauthenticated access to ${entryPoint}", async () => {\n  const response = await requestWithoutSession();\n  expect([401, 403]).toContain(response.status);\n});`;
}

function authorizationTest(entryPoint: string): string {
  return `it("rejects a non-admin principal at ${entryPoint}", async () => {\n  const response = await requestAs({ role: "user" });\n  expect(response.status).toBe(403);\n});`;
}

function uploadBoundaryTest(entryPoint: string): string {
  return `it("enforces upload boundaries for ${entryPoint}", async () => {\n  const response = await uploadFixture({ type: "application/x-executable", bytes: MAX_ALLOWED_BYTES + 1 });\n  expect([400, 413, 415]).toContain(response.status);\n});`;
}

function secretBoundaryTest(entryPoint: string): string {
  return `it("does not expose privileged credentials through ${entryPoint}", async () => {\n  const response = await triggerFailurePath();\n  expect(JSON.stringify(response)).not.toMatch(/api[_-]?key|secret|token/i);\n});`;
}

function ownershipTest(entryPoint: string): string {
  return `it("prevents cross-tenant writes through ${entryPoint}", async () => {\n  const response = await requestAsTenant("tenant-a", { targetTenant: "tenant-b" });\n  expect(response.status).toBe(403);\n});`;
}

function outboundDestinationTest(entryPoint: string): string {
  return `it("rejects unapproved outbound destinations at ${entryPoint}", async () => {\n  const response = await requestWithDestination("http://169.254.169.254/latest/meta-data/");\n  expect([400, 403]).toContain(response.status);\n});`;
}

function commandExecutionTest(entryPoint: string): string {
  return `it("does not execute request-controlled command input at ${entryPoint}", async () => {\n  const response = await requestWithPayload({ command: "echo HEDGE_SENTINEL" });\n  expect(await commandWasExecuted("HEDGE_SENTINEL")).toBe(false);\n  expect([400, 403]).toContain(response.status);\n});`;
}

function logRedactionTest(entryPoint: string): string {
  return `it("redacts secrets from logs triggered through ${entryPoint}", async () => {\n  await triggerFailurePath();\n  expect(capturedLogs()).not.toMatch(/api[_-]?key|secret|token/i);\n});`;
}

function workflowBoundaryTest(entryPoint: string): string {
  return `it("keeps untrusted pull request content outside the privileged workflow ${entryPoint}", async () => {\n  const result = await simulateForkPullRequest({ changedScript: "exfiltrate-secrets" });\n  expect(result.secretBearingJobExecutedUntrustedCode).toBe(false);\n});`;
}

function sensitiveReadTest(entryPoint: string): string {
  return `it("prevents unauthorized sensitive-record reads through ${entryPoint}", async () => {\n  const response = await requestAsTenant("tenant-a", { targetTenant: "tenant-b" });\n  expect([403, 404]).toContain(response.status);\n});`;
}

function workflowPermissionTest(entryPoint: string): string {
  return `it("keeps ${entryPoint} at least privilege", async () => {\n  const permissions = await resolvedWorkflowPermissions();\n  expect(permissions).not.toContain("write-all");\n});`;
}

function workflowInterpolationTest(entryPoint: string): string {
  return `it("does not interpolate untrusted event text into shell source in ${entryPoint}", async () => {\n  const result = await simulateEventText("$(echo HEDGE_SENTINEL)");\n  expect(result.shellSource).not.toContain("HEDGE_SENTINEL");\n});`;
}

function workflowCheckoutBoundaryTest(entryPoint: string): string {
  return `it("does not execute pull request head code with privileged credentials in ${entryPoint}", async () => {\n  const result = await simulateForkPullRequest({ changedScript: "exfiltrate-secrets" });\n  expect(result.privilegedJobExecutedPullRequestCode).toBe(false);\n});`;
}

function controlRegressionTest(entryPoint: string, removed: string[]): string {
  return `it("preserves security controls for ${entryPoint}", async () => {\n  const result = await exerciseProtectedPath();\n  expect(result.enforcedControls).toEqual(expect.arrayContaining(${JSON.stringify(removed)}));\n});`;
}
