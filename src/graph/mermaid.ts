import type { AttackSurfaceGraph, GraphDelta, RiskFinding } from "../domain/schemas.js";

export interface MermaidOptions {
  delta?: GraphDelta;
  findings?: RiskFinding[];
}

export function renderMermaid(graph: AttackSurfaceGraph, options: MermaidOptions = {}): string {
  const addedNodeIds = new Set(options.delta?.addedNodes.map((node) => node.id) ?? []);
  const addedEdgeIds = new Set(options.delta?.addedEdges.map((edge) => edge.id) ?? []);
  const openFindings = (options.findings ?? []).filter(
    (finding) => !["verified", "closed", "accepted"].includes(finding.status)
  );
  const verifiedFindings = (options.findings ?? []).filter((finding) =>
    ["verified", "closed"].includes(finding.status)
  );
  const riskyNodeIds = findingNodeIds(graph, openFindings);
  const verifiedNodeIds = findingNodeIds(graph, verifiedFindings);
  const lines = ["flowchart LR"];

  for (const node of graph.nodes) {
    const id = mermaidId(node.id);
    const shape =
      node.kind === "entrypoint" ? `([${escape(node.label)}])` : `[${escape(node.label)}]`;
    lines.push(`  ${id}${shape}`);
    const className = riskyNodeIds.has(node.id)
      ? "risk"
      : verifiedNodeIds.has(node.id)
        ? "verified"
        : addedNodeIds.has(node.id)
          ? "added"
          : zoneClass(node.trustZone);
    lines.push(`  class ${id} ${className};`);
  }

  const linkStyles: string[] = [];
  graph.edges.forEach((edge, index) => {
    const from = mermaidId(edge.from);
    const to = mermaidId(edge.to);
    const label = edge.label ? `|${escape(edge.label)}|` : `|${escape(edge.kind)}|`;
    lines.push(`  ${from} -->${label} ${to}`);
    if (riskyNodeIds.has(edge.from) || riskyNodeIds.has(edge.to)) {
      linkStyles.push(`  linkStyle ${index} stroke:#dc2626,stroke-width:3px;`);
    } else if (verifiedNodeIds.has(edge.from) || verifiedNodeIds.has(edge.to)) {
      linkStyles.push(`  linkStyle ${index} stroke:#16a34a,stroke-width:3px;`);
    } else if (addedEdgeIds.has(edge.id)) {
      linkStyles.push(`  linkStyle ${index} stroke:#d97706,stroke-width:2px;`);
    }
  });
  lines.push(...linkStyles);

  lines.push("  classDef public fill:#f4f4f5,stroke:#71717a,color:#18181b;");
  lines.push("  classDef application fill:#dcfce7,stroke:#15803d,color:#14532d;");
  lines.push("  classDef privileged fill:#fef3c7,stroke:#b45309,color:#78350f;");
  lines.push("  classDef data fill:#dbeafe,stroke:#1d4ed8,color:#1e3a8a;");
  lines.push("  classDef external fill:#ede9fe,stroke:#7c3aed,color:#4c1d95;");
  lines.push("  classDef unknown fill:#f4f4f5,stroke:#a1a1aa,color:#3f3f46,stroke-dasharray: 5 5;");
  lines.push("  classDef added fill:#ecfccb,stroke:#65a30d,color:#365314,stroke-width:2px;");
  lines.push("  classDef verified fill:#dcfce7,stroke:#16a34a,color:#14532d,stroke-width:3px;");
  lines.push("  classDef risk fill:#fee2e2,stroke:#dc2626,color:#7f1d1d,stroke-width:3px;");

  return lines.join("\n");
}

function findingNodeIds(graph: AttackSurfaceGraph, findings: RiskFinding[]): Set<string> {
  return new Set(
    findings.flatMap((finding) =>
      graph.nodes
        .filter(
          (node) => finding.attackPath.includes(node.label) || finding.entryPoint === node.label
        )
        .map((node) => node.id)
    )
  );
}

function mermaidId(value: string): string {
  return `n_${value.replace(/[^A-Za-z0-9_]/g, "_")}`;
}

function escape(value: string): string {
  return value
    .replace(/[\r\n\t]+/g, " ")
    .replaceAll('"', "'")
    .replace(/[|;#]/g, "/")
    .replace(/[\[\]{}()]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 90);
}

function zoneClass(zone: string): string {
  return ["public", "application", "privileged", "data", "external"].includes(zone)
    ? zone
    : "unknown";
}
