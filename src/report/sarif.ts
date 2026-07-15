import type { AnalysisResult, RiskFinding } from "../domain/schemas.js";
import { HEDGE_VERSION } from "../version.js";

export interface SarifLog {
  version: "2.1.0";
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        informationUri: string;
        semanticVersion: string;
        rules: SarifRule[];
      };
    };
    invocations: Array<{
      executionSuccessful: boolean;
      properties: Record<string, unknown>;
    }>;
    results: SarifResult[];
  }>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  defaultConfiguration: { level: "error" | "warning" | "note" };
  properties: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note";
  message: { text: string; markdown: string };
  locations: SarifLocation[];
  relatedLocations: SarifLocation[];
  partialFingerprints: Record<string, string>;
  properties: Record<string, unknown>;
}

interface SarifLocation {
  id?: number;
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: "%SRCROOT%" };
    region?: { startLine: number; endLine?: number; snippet?: { text: string } };
  };
  message?: { text: string };
}

export function renderSarif(
  findings: RiskFinding[],
  analysis?: AnalysisResult,
  version = HEDGE_VERSION
): SarifLog {
  const rules = findings.map((finding) => findingRule(finding));
  const results = findings.map((finding, index) => findingResult(finding, index));
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Hedge",
            informationUri: "https://github.com/hedge-security/hedge",
            semanticVersion: version,
            rules
          }
        },
        invocations: [
          {
            executionSuccessful: analysis?.integrity.analysisBoundaryHeld ?? true,
            properties: {
              surfaceChanged: analysis?.surfaceChanged ?? findings.length > 0,
              model: analysis?.model ?? "deterministic",
              untrustedInstructionsObserved:
                analysis?.integrity.untrustedInstructionsObserved ?? false,
              limitations: analysis?.limitations ?? [],
              decision:
                analysis?.decisions?.find((item) => item.source === "threshold")?.type ?? "allow",
              observationCount: analysis?.observations?.length ?? 0,
              inferenceCount: analysis?.inferences?.length ?? 0,
              invariantEvaluations: analysis?.invariantEvaluations ?? []
            }
          }
        ],
        results
      }
    ]
  };
}

function findingRule(finding: RiskFinding): SarifRule {
  const level = sarifLevel(finding.severity);
  return {
    id: finding.id,
    name: toRuleName(finding.title),
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.potentialImpact },
    help: {
      text: finding.securityInvariant,
      markdown: [
        `### ${finding.title}`,
        "",
        `**Security invariant:** ${finding.securityInvariant}`,
        "",
        `**Attack path:** ${finding.attackPath.join(" → ")}`,
        "",
        `**Missing controls:** ${finding.missingControls.join(", ") || "None recorded"}`
      ].join("\n")
    },
    defaultConfiguration: { level },
    properties: {
      tags: ["security", "architecture", "threat-model", ...finding.stride],
      precision:
        finding.confidence >= 0.85 ? "high" : finding.confidence >= 0.65 ? "medium" : "low",
      securitySeverity: securitySeverity(finding.severity),
      cwe: finding.cwe,
      stride: finding.stride,
      origin: finding.origin
    }
  };
}

function findingResult(finding: RiskFinding, ruleIndex: number): SarifResult {
  const evidence = finding.evidence.filter((item) => item.file);
  const primary = evidence[0];
  const locations = primary ? [location(primary, undefined)] : [];
  const relatedLocations = evidence
    .slice(1)
    .map((item, index) => location(item, index + 1, `Additional evidence for ${finding.id}`));
  return {
    ruleId: finding.id,
    ruleIndex,
    level: sarifLevel(finding.severity),
    message: {
      text: `${finding.title}. ${finding.potentialImpact}`,
      markdown: [
        `**${finding.id} · ${finding.severity.toUpperCase()}**`,
        "",
        finding.potentialImpact,
        "",
        `Attack path: ${finding.attackPath.map((part) => `\`${part}\``).join(" → ")}`,
        "",
        `Security invariant: ${finding.securityInvariant}`
      ].join("\n")
    },
    locations,
    relatedLocations,
    partialFingerprints: {
      "hedgeFinding/v1": finding.fingerprint
    },
    properties: {
      hedgeRiskId: finding.id,
      fingerprint: finding.fingerprint,
      origin: finding.origin,
      status: finding.status,
      severity: finding.severity,
      confidence: finding.confidence,
      asset: finding.asset,
      entryPoint: finding.entryPoint,
      trustBoundary: finding.trustBoundary,
      attackerCapability: finding.attackerCapability,
      existingControls: finding.existingControls,
      missingControls: finding.missingControls,
      suggestedTest: finding.suggestedTest,
      remediationCommand: `@hedge fix ${finding.id}`
    }
  };
}

function location(
  evidence: RiskFinding["evidence"][number],
  id?: number,
  message?: string
): SarifLocation {
  const region = evidence.line
    ? {
        startLine: evidence.line,
        ...(evidence.endLine ? { endLine: evidence.endLine } : {}),
        ...(evidence.snippet ? { snippet: { text: evidence.snippet } } : {})
      }
    : undefined;
  return {
    ...(id ? { id } : {}),
    physicalLocation: {
      artifactLocation: {
        uri: normalizeUri(evidence.file),
        uriBaseId: "%SRCROOT%"
      },
      ...(region ? { region } : {})
    },
    ...(message ? { message: { text: message } } : {})
  };
}

function normalizeUri(value: string): string {
  return value.replaceAll("\\", "/").replace(/^\.\//, "");
}

function sarifLevel(severity: RiskFinding["severity"]): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function securitySeverity(severity: RiskFinding["severity"]): string {
  return { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "1.0" }[severity];
}

function toRuleName(value: string): string {
  const words = value
    .replace(/[^A-Za-z0-9]+/g, " ")
    .trim()
    .split(/\s+/);
  return words
    .map((word, index) =>
      index === 0 ? word.toLowerCase() : word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
    )
    .join("")
    .slice(0, 80);
}
