import type { HedgeConfig } from "../domain/schemas.js";
import type { SourceFile } from "./files.js";

export function detectFramework(files: SourceFile[], config: HedgeConfig): string {
  if (config.framework !== "auto") return config.framework;
  let hasExpressDependency = false;
  const packageFile = files.find((file) => file.path.endsWith("package.json"));
  if (packageFile) {
    try {
      const pkg = JSON.parse(packageFile.content) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
      if (deps.next) return "nextjs";
      hasExpressDependency = Boolean(deps.express);
    } catch {
      // A malformed package file is reported as an unknown rather than crashing analysis.
    }
  }
  if (files.some((file) => /(^|\/)app\/.+\/route\.[jt]sx?$/.test(file.path))) return "nextjs";
  if (files.some((file) => /(^|\/)pages\/api\/.+\.[cm]?[jt]sx?$/.test(file.path))) return "nextjs";
  if (hasExpressDependency) return "express";
  if (files.some((file) => /express\s*\(/.test(file.content))) return "express";
  return "unknown";
}
