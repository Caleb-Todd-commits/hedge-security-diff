import { resolve } from "node:path";
import { format, resolveConfig } from "prettier";
import { runEvalSuite, renderEvalSummary } from "./runner.js";
import { writeTextFile } from "../utils/fs.js";

const root = resolve(process.argv[2] ?? "eval/fixtures");
const summary = await runEvalSuite(root);
const renderedSummary = renderEvalSummary(summary);
const prettierConfig = (await resolveConfig(resolve(".prettierrc.json"))) ?? {};
const markdown = await format(renderedSummary, { ...prettierConfig, parser: "markdown" });
const json = await format(JSON.stringify(summary, null, 2), {
  ...prettierConfig,
  parser: "json"
});
await writeTextFile(resolve("eval/results.md"), markdown);
await writeTextFile(resolve("eval/results.json"), json);
console.log(markdown.trimEnd());
if (summary.failed > 0) process.exitCode = 1;
