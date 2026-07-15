import type { RiskFinding } from "../domain/schemas.js";

export interface HedgeAnnotation {
  level: "error" | "warning" | "notice";
  message: string;
  title: string;
  file?: string;
  startLine?: number;
  endLine?: number;
}

export function createFindingAnnotations(
  findings: RiskFinding[],
  maxAnnotations = 20
): HedgeAnnotation[] {
  const annotations: HedgeAnnotation[] = [];
  for (const finding of findings) {
    const evidence = finding.evidence[0];
    annotations.push({
      level: annotationLevel(finding.severity),
      title: `${finding.id} · ${finding.severity.toUpperCase()} · ${finding.title}`,
      message: [
        finding.potentialImpact,
        `Security invariant: ${finding.securityInvariant}`,
        `Attack path: ${finding.attackPath.join(" → ")}`,
        `Missing controls: ${finding.missingControls.join(", ") || "none recorded"}`
      ].join("\n"),
      ...(evidence?.file ? { file: evidence.file } : {}),
      ...(evidence?.line ? { startLine: evidence.line } : {}),
      ...(evidence?.endLine ? { endLine: evidence.endLine } : {})
    });
    if (annotations.length >= maxAnnotations) break;
  }
  return annotations;
}

function annotationLevel(severity: RiskFinding["severity"]): HedgeAnnotation["level"] {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "notice";
}
