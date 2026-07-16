import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileExists } from "../utils/fs.js";

export interface InstallOptions {
  root: string;
  actionRef: string;
  force?: boolean;
  full?: boolean;
}

export interface InstallResult {
  written: string[];
  skipped: string[];
}

export async function installHedge(options: InstallOptions): Promise<InstallResult> {
  validateActionRef(options.actionRef);
  const main = (await exampleWorkflow("hedge.yml")).replaceAll(
    "YOUR_ORG/hedge@PINNED_COMMIT_SHA",
    options.actionRef
  );
  const files = new Map<string, string>([
    [".hedge.yml", configTemplate()],
    [".hedge/context.yml", contextTemplate()],
    [".github/workflows/hedge.yml", main]
  ]);
  if (options.full) {
    files.set(
      ".github/workflows/hedge-fix.yml",
      (await exampleWorkflow("hedge-fix.yml")).replaceAll(
        "YOUR_ORG/hedge@PINNED_COMMIT_SHA",
        options.actionRef
      )
    );
    files.set(
      ".github/workflows/hedge-verify.yml",
      (await exampleWorkflow("hedge-verify.yml")).replaceAll(
        "YOUR_ORG/hedge@PINNED_COMMIT_SHA",
        options.actionRef
      )
    );
    files.set(".github/workflows/hedge-refresh.yml", refreshWorkflow(options.actionRef));
    files.set(".github/workflows/hedge-prune.yml", pruneWorkflow(options.actionRef));
  }

  const written: string[] = [];
  const skipped: string[] = [];
  for (const [relative, content] of files) {
    const target = resolve(options.root, relative);
    if (!options.force && (await fileExists(target))) {
      skipped.push(relative);
      continue;
    }
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content, "utf8");
    written.push(relative);
  }
  return { written, skipped };
}

function validateActionRef(value: string): void {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40,64}$/.test(value)) {
    throw new Error("--action-ref must be owner/repository@ followed by a full commit SHA");
  }
}

function configTemplate(): string {
  return `framework: auto
fail_on: high
ignored_paths:
  - docs/**
  - "**/*.test.ts"
models:
  triage: gpt-5.6-luna
  analysis: gpt-5.6-sol
# Optional organization-specific architecture constraints:
# policies:
#   - id: billing-rate-limit
#     name: Billing endpoints require rate limiting
#     severity: high
#     match:
#       kinds: [entrypoint]
#       trust_zones: [public]
#       label_pattern: "* /api/billing/*"
#     require_controls: [authentication, rate-limit]
#     security_invariant: Public billing endpoints must authenticate and enforce rate limits.
#     potential_impact: Automated abuse may create fraudulent or excessive billing operations.
limits:
  max_files: 120
  max_bytes: 350000
`;
}

function contextTemplate(): string {
  return `# Review these five facts. Leave unknown values empty rather than guessing.
sensitive_assets: []
internet_facing: []
authentication: []
privileged_roles: []
trusted_external_services: []
notes: []
`;
}

function refreshWorkflow(actionRef: string): string {
  return `name: Refresh Hedge model
on:
  push:
    branches: [main]
permissions:
  contents: write
  pull-requests: write
jobs:
  refresh:
    if: github.actor != 'github-actions[bot]'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          ref: \${{ github.sha }}
          fetch-depth: 0
      - uses: ${actionRef}
        with:
          command: init
          github-token: \${{ github.token }}
          dry-run: true
      - name: Open reviewable model update
        env:
          GH_TOKEN: \${{ github.token }}
        run: |
          if git diff --quiet -- THREATMODEL.md threatmodel.json .hedge/graph.json; then exit 0; fi
          BRANCH="hedge/model-\${GITHUB_SHA::8}-\${GITHUB_RUN_ID}"
          git switch -c "$BRANCH"
          git config user.name "hedge-bot"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add THREATMODEL.md threatmodel.json .hedge/graph.json
          git commit -m "chore: refresh Hedge security model"
          git push origin "$BRANCH"
          gh pr create --base "$GITHUB_REF_NAME" --head "$BRANCH" --title "Hedge: refresh security model" --body "Review the evidence-linked architecture update generated from $GITHUB_SHA."
`;
}

function pruneWorkflow(actionRef: string): string {
  return `name: Hedge risk acceptance
on:
  issue_comment:
    types: [created]
permissions:
  contents: write
  pull-requests: write
  issues: read
jobs:
  prune:
    if: github.event.issue.pull_request && startsWith(github.event.comment.body, '@hedge prune ')
    runs-on: ubuntu-latest
    steps:
      - name: Authorize and parse risk acceptance
        id: command
        uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9
        with:
          script: |
            const body = context.payload.comment.body.trim();
            const match = /^@hedge\\s+prune\\s+(HEDGE-\\d{3,})\\s+reason:["']([^"']+)["']$/i.exec(body);
            if (!match) return core.setFailed('Use: @hedge prune HEDGE-NNN reason:"documented reason"');
            const actor = context.payload.comment.user.login;
            const access = await github.rest.repos.getCollaboratorPermissionLevel({...context.repo, username: actor});
            if (!['admin','maintain','write'].includes(access.data.permission)) return core.setFailed('Write permission is required.');
            const pr = await github.rest.pulls.get({...context.repo, pull_number: context.issue.number});
            core.setOutput('risk_id', match[1].toUpperCase());
            core.setOutput('reason_b64', Buffer.from(match[2], 'utf8').toString('base64'));
            core.setOutput('actor', actor);
            core.setOutput('base_ref', pr.data.base.ref);
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          ref: \${{ steps.command.outputs.base_ref }}
          fetch-depth: 0
      - name: Record acceptance in trusted state
        uses: ${actionRef}
        with:
          command: prune
          risk-id: \${{ steps.command.outputs.risk_id }}
          acceptance-reason-b64: \${{ steps.command.outputs.reason_b64 }}
          actor: \${{ steps.command.outputs.actor }}
      - name: Open state update pull request
        env:
          GH_TOKEN: \${{ github.token }}
          RISK_ID: \${{ steps.command.outputs.risk_id }}
        run: |
          BRANCH="hedge/accept-\${RISK_ID,,}-\${GITHUB_RUN_ID}"
          git switch -c "$BRANCH"
          git config user.name "hedge-bot"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add threatmodel.json THREATMODEL.md
          git commit -m "chore: accept \${RISK_ID}"
          git push origin "$BRANCH"
          gh pr create --base "\${{ steps.command.outputs.base_ref }}" --head "$BRANCH" --title "Hedge: accept \${RISK_ID}" --body "Records a maintainer-authorized risk acceptance with actor, time, and reason."
`;
}

async function exampleWorkflow(name: string): Promise<string> {
  const candidates: string[] = [];

  // The bundled CommonJS CLI has a concrete module filename even when invoked
  // through a package-manager shim.
  if (typeof __filename === "string") {
    candidates.push(resolve(dirname(__filename), "..", "workflows", name));
  }

  // Published CLI bundles copy these assets beside dist/cli. Resolve the real
  // executable first so global package-manager shims and symlinks still work.
  if (process.argv[1]) {
    try {
      const executable = await realpath(process.argv[1]);
      candidates.push(resolve(dirname(executable), "..", "workflows", name));
      candidates.push(resolve(dirname(executable), "..", "..", "examples", "workflows", name));
    } catch {
      // A test runner or embedding process may not expose a resolvable argv[1].
    }
  }

  // npm and ordinary source execution expose package-root candidates without
  // coupling template loading to the caller's current working directory.
  if (process.env.npm_package_json) {
    candidates.push(resolve(dirname(process.env.npm_package_json), "examples", "workflows", name));
  }
  if (process.env.INIT_CWD) {
    candidates.push(resolve(process.env.INIT_CWD, "examples", "workflows", name));
  }
  candidates.push(resolve(process.cwd(), "examples", "workflows", name));

  for (const source of [...new Set(candidates)]) {
    try {
      return await readFile(source, "utf8");
    } catch {
      // Try the next package/source layout before reporting one bounded error.
    }
  }

  throw new Error(
    `Unable to locate bundled workflow template ${name}; checked ${candidates.length} package location(s).`
  );
}
