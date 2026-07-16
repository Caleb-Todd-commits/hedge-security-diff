import type { AnalysisHealth, Coverage } from "../domain/schemas.js";

export function deriveAnalysisHealth(
  coverage: Coverage | undefined,
  options: { modelDegraded?: boolean; modelReason?: string; reasons?: string[] } = {}
): AnalysisHealth {
  const reasons = [...(options.reasons ?? [])];

  if (!coverage) {
    reasons.push("Coverage metadata was unavailable, so this run cannot be confirmed complete.");
  } else if (coverage.status !== "complete") {
    reasons.push(
      coverage.status === "unsupported"
        ? "The repository or changed surface is outside Hedge's supported analysis scope."
        : "Repository evidence coverage was partial; omitted or unresolved evidence may affect the result."
    );
  }

  if (options.modelDegraded) {
    reasons.push(options.modelReason ?? "Requested model reasoning was unavailable.");
  }

  return {
    status:
      coverage?.status === "unsupported"
        ? "failed"
        : reasons.length || coverage?.status === "partial" || !coverage
          ? "degraded"
          : "complete",
    reasons: [...new Set(reasons)]
  };
}
