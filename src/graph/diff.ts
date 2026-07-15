import type {
  AttackSurfaceGraph,
  GraphDelta,
  SurfaceEdge,
  SurfaceNode
} from "../domain/schemas.js";
import { stableHash } from "../utils/hash.js";

export function diffGraphs(before: AttackSurfaceGraph, after: AttackSurfaceGraph): GraphDelta {
  const beforeNodes = new Map(before.nodes.map((node) => [node.id, node]));
  const afterNodes = new Map(after.nodes.map((node) => [node.id, node]));
  const beforeEdges = new Map(before.edges.map((edge) => [edge.id, edge]));
  const afterEdges = new Map(after.edges.map((edge) => [edge.id, edge]));

  return {
    addedNodes: after.nodes.filter((node) => !beforeNodes.has(node.id)),
    removedNodes: before.nodes.filter((node) => !afterNodes.has(node.id)),
    changedNodes: changedPairs(beforeNodes, afterNodes, normalizeNode),
    addedEdges: after.edges.filter((edge) => !beforeEdges.has(edge.id)),
    removedEdges: before.edges.filter((edge) => !afterEdges.has(edge.id)),
    changedEdges: changedPairs(beforeEdges, afterEdges, normalizeEdge)
  };
}

export function hasSecurityArchitectureDelta(delta: GraphDelta): boolean {
  return (
    delta.addedNodes.length > 0 ||
    delta.removedNodes.length > 0 ||
    delta.changedNodes.length > 0 ||
    delta.addedEdges.length > 0 ||
    delta.removedEdges.length > 0 ||
    delta.changedEdges.length > 0
  );
}

export function summarizeDelta(delta: GraphDelta): string[] {
  const items: string[] = [];
  if (delta.addedNodes.length) items.push(`+${delta.addedNodes.length} security-relevant node(s)`);
  if (delta.addedEdges.length) items.push(`+${delta.addedEdges.length} attack-surface edge(s)`);
  if (delta.changedNodes.length)
    items.push(`${delta.changedNodes.length} control or component change(s)`);
  if (delta.removedNodes.length)
    items.push(`-${delta.removedNodes.length} security-relevant node(s)`);
  if (delta.removedEdges.length) items.push(`-${delta.removedEdges.length} attack-surface edge(s)`);
  return items.length ? items : ["No evidence-linked security architecture delta"];
}

function changedPairs<T extends { id: string }>(
  before: Map<string, T>,
  after: Map<string, T>,
  normalize: (value: T) => unknown
): Array<{ before: T; after: T }> {
  const changed: Array<{ before: T; after: T }> = [];
  for (const [id, beforeValue] of before) {
    const afterValue = after.get(id);
    if (!afterValue) continue;
    if (stableHash(normalize(beforeValue)) !== stableHash(normalize(afterValue))) {
      changed.push({ before: beforeValue, after: afterValue });
    }
  }
  return changed;
}

function normalizeNode(node: SurfaceNode): unknown {
  return {
    kind: node.kind,
    label: node.label,
    trustZone: node.trustZone,
    controls: node.controls.map((control) => ({ type: control.type, label: control.label })),
    metadata: node.metadata
  };
}

function normalizeEdge(edge: SurfaceEdge): unknown {
  return {
    from: edge.from,
    to: edge.to,
    kind: edge.kind,
    label: edge.label,
    controls: edge.controls.map((control) => ({ type: control.type, label: control.label })),
    confidence: edge.confidence
  };
}
