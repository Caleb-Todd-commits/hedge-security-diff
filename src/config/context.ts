import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import YAML from "yaml";
import { HedgeContextSchema, type HedgeContext } from "../domain/schemas.js";
import { writeTextFile } from "../utils/fs.js";

export const DEFAULT_CONTEXT_PATH = ".hedge/context.yml";

export function parseContextText(content: string | undefined): HedgeContext {
  if (!content?.trim()) return HedgeContextSchema.parse({});
  return HedgeContextSchema.parse(YAML.parse(content) as unknown);
}

export async function loadHedgeContext(
  root: string,
  contextPath = DEFAULT_CONTEXT_PATH
): Promise<HedgeContext> {
  try {
    return parseContextText(await readFile(resolve(root, contextPath), "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return HedgeContextSchema.parse({});
    throw error;
  }
}

export async function saveHedgeContext(
  root: string,
  context: HedgeContext,
  contextPath = DEFAULT_CONTEXT_PATH
): Promise<string> {
  const path = resolve(root, contextPath);
  const normalized = HedgeContextSchema.parse(context);
  await writeTextFile(
    path,
    YAML.stringify({
      sensitive_assets: normalized.sensitive_assets,
      internet_facing: normalized.internet_facing,
      authentication: normalized.authentication,
      privileged_roles: normalized.privileged_roles,
      trusted_external_services: normalized.trusted_external_services,
      notes: normalized.notes
    })
  );
  return path;
}
