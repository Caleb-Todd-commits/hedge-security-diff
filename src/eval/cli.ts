import { resolve } from "node:path";
import { runEvalSuite, renderEvalSummary } from "./runner.js";
import { writeTextFile, writeJsonFile } from "../utils/fs.js";

const root = resolve(process.argv[2] ?? "eval/fixtures");
const summary = await runEvalSuite(root);
await writeTextFile(resolve("eval/results.md"), renderEvalSummary(summary));
await writeJsonFile(resolve("eval/results.json"), summary);
console.log(renderEvalSummary(summary));
if (summary.failed > 0) process.exitCode = 1;
