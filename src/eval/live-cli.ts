import { resolve } from "node:path";
import {
  authorizeLiveEval,
  createOpenAiLiveModelRunner,
  parseLiveEvalRepeats,
  renderLiveEvalSummary,
  runLiveEvalSuite,
  safeLiveEvalError,
  writeLiveEvalResults
} from "./live-runner.js";

let authorization: ReturnType<typeof authorizeLiveEval> | undefined;

try {
  authorization = authorizeLiveEval(process.env);
  const repeats = parseLiveEvalRepeats(process.env.HEDGE_LIVE_EVAL_REPEATS);
  const fixturesRoot = resolve("eval/heldout-fixtures");
  const caseConfigPath = resolve("eval/live-eval-cases.json");
  const outputDirectory = resolve(
    process.env.HEDGE_LIVE_EVAL_OUTPUT_DIR?.trim() || "eval/live-results"
  );
  const summary = await runLiveEvalSuite({
    fixturesRoot,
    caseConfigPath,
    repeats,
    runner: createOpenAiLiveModelRunner(authorization.apiKey)
  });
  const paths = await writeLiveEvalResults(outputDirectory, summary, authorization.forbiddenValues);
  console.log(renderLiveEvalSummary(summary));
  console.log(`\nJSON: ${paths.jsonPath}\nMarkdown: ${paths.markdownPath}`);
  if (!summary.operationalGatePassed) process.exitCode = 1;
} catch (error) {
  console.error(
    `Hedge live evaluation did not run: ${safeLiveEvalError(
      error,
      authorization?.forbiddenValues ?? []
    )}`
  );
  process.exitCode = 1;
}
