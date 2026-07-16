import type { AttackSurfaceGraph, Coverage } from "../domain/schemas.js";

export function comparisonCoverage(
  base: AttackSurfaceGraph,
  head: AttackSurfaceGraph,
  additionalDiagnostics: Coverage["diagnostics"] = []
): Coverage {
  const baseCoverage = normalizeCoverage(base, "base");
  const headCoverage = normalizeCoverage(head, "head");
  const diagnostics = [
    ...baseCoverage.diagnostics.map((item) => ({
      ...item,
      snapshot: item.snapshot ?? ("base" as const)
    })),
    ...headCoverage.diagnostics.map((item) => ({
      ...item,
      snapshot: item.snapshot ?? ("head" as const)
    })),
    ...additionalDiagnostics
  ];
  const statuses = [baseCoverage.status, headCoverage.status];
  const status: Coverage["status"] = statuses.includes("unsupported")
    ? "unsupported"
    : statuses.includes("partial") || additionalDiagnostics.length
      ? "partial"
      : "complete";

  return {
    status,
    discoveredFiles: baseCoverage.discoveredFiles + headCoverage.discoveredFiles,
    includedFiles: baseCoverage.includedFiles + headCoverage.includedFiles,
    includedBytes: baseCoverage.includedBytes + headCoverage.includedBytes,
    omitted: {
      fileLimit: baseCoverage.omitted.fileLimit + headCoverage.omitted.fileLimit,
      byteLimit: baseCoverage.omitted.byteLimit + headCoverage.omitted.byteLimit,
      unsafeOrUnreadable:
        baseCoverage.omitted.unsafeOrUnreadable + headCoverage.omitted.unsafeOrUnreadable,
      binary: baseCoverage.omitted.binary + headCoverage.omitted.binary
    },
    diagnostics
  };
}

function normalizeCoverage(graph: AttackSurfaceGraph, snapshot: "base" | "head"): Coverage {
  if (graph.coverage) return graph.coverage;
  return {
    status: "partial",
    discoveredFiles: 0,
    includedFiles: 0,
    includedBytes: 0,
    omitted: { fileLimit: 0, byteLimit: 0, unsafeOrUnreadable: 0, binary: 0 },
    diagnostics: [
      {
        code: "coverage-metadata-unavailable",
        phase: "analysis",
        snapshot,
        message: `Coverage metadata was unavailable for the ${snapshot} graph.`
      }
    ]
  };
}
