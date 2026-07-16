import { buildAttackSurfaceGraph } from "../analyzers/build-graph.js";
import type { AttackSurfaceGraph, HedgeConfig, HedgeContext } from "../domain/schemas.js";
import { collectGitSourceFileInventory } from "./snapshot.js";

export interface ExactGraphOptions {
  root: string;
  revision: string;
  config: HedgeConfig;
  repository?: string;
  context?: HedgeContext;
  snapshot: "base" | "head";
}

export interface ExactGraphResult {
  commit: string;
  graph: AttackSurfaceGraph;
}

/** Build a graph from exact Git object bytes without changing the checkout. */
export async function buildAttackSurfaceGraphAtCommit(
  options: ExactGraphOptions
): Promise<ExactGraphResult> {
  const source = await collectGitSourceFileInventory({
    root: options.root,
    revision: options.revision,
    config: options.config
  });
  const graph = await buildAttackSurfaceGraph({
    root: source.repositoryRoot,
    config: options.config,
    repository: options.repository,
    context: options.context,
    sourceInventory: source.inventory,
    sourceCommit: source.commit,
    snapshot: options.snapshot
  });
  return { commit: source.commit, graph };
}
