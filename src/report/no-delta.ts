import type { AnalysisResult } from "../domain/schemas.js";
import { HEDGE_COMMENT_MARKER } from "./comment.js";

/** Render an honest local artifact even when no graph delta was observed. */
export function renderNoDeltaReport(analysis: AnalysisResult): string {
  const coverage = analysis.coverage?.status ?? "unsupported";
  const health = analysis.analysisHealth?.status ?? "failed";
  return [
    HEDGE_COMMENT_MARKER,
    "## Hedge security architecture diff",
    "",
    analysis.summary,
    "",
    `- Coverage: **${coverage.toUpperCase()}**`,
    `- Analysis health: **${health.toUpperCase()}**`,
    `- Confirmed no-delta: **${analysis.confirmedNoDelta === true ? "yes" : "no"}**`,
    "- Model request: **none**",
    "",
    analysis.confirmedNoDelta
      ? "No PR comment is created; a previous Hedge report may be removed."
      : "This result is not a confirmed healthy comparison and must not advance lifecycle state."
  ].join("\n");
}
