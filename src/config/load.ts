import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import YAML from "yaml";
import { HedgeConfigSchema, type HedgeConfig } from "../domain/schemas.js";

export function parseConfigText(content: string | undefined): HedgeConfig {
  if (!content?.trim()) return HedgeConfigSchema.parse({});
  const parsed = YAML.parse(content) as unknown;
  return HedgeConfigSchema.parse(parsed ?? {});
}

export async function loadConfig(root: string, configPath = ".hedge.yml"): Promise<HedgeConfig> {
  const absolute = resolve(root, configPath);
  try {
    return parseConfigText(await readFile(absolute, "utf8"));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return HedgeConfigSchema.parse({});
    throw error;
  }
}
