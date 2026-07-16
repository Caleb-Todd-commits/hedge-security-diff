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
      title: boundedAnnotationText(
        `${finding.id} · ${finding.severity.toUpperCase()} · ${finding.title}`,
        240,
        false
      ),
      message: boundedAnnotationText(
        [
          finding.potentialImpact,
          `Security invariant: ${finding.securityInvariant}`,
          `Attack path: ${finding.attackPath.join(" → ")}`,
          `Missing controls: ${finding.missingControls.join(", ") || "none recorded"}`
        ].join("\n"),
        4_000,
        true
      ),
      ...(evidence?.file ? { file: evidence.file } : {}),
      ...(evidence?.line ? { startLine: evidence.line } : {}),
      ...(evidence?.endLine ? { endLine: evidence.endLine } : {})
    });
    if (annotations.length >= maxAnnotations) break;
  }
  return annotations;
}

function boundedAnnotationText(
  value: string,
  maxLength: number,
  preserveNewlines: boolean
): string {
  const normalized = value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/@(?=[A-Za-z0-9_-])/g, "@\u200b");
  const safe = preserveNewlines
    ? normalized.replace(/\r\n?/g, "\n")
    : normalized.replace(/\s+/g, " ");
  return safe.length <= maxLength ? safe : `${safe.slice(0, Math.max(0, maxLength - 1))}…`;
}

function annotationLevel(severity: RiskFinding["severity"]): HedgeAnnotation["level"] {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "notice";
}
