import * as github from "@actions/github";
import { HEDGE_COMMENT_MARKER, MAX_PULL_REQUEST_COMMENT_BYTES } from "../report/comment.js";

export async function upsertPullRequestComment(token: string, body: string): Promise<void> {
  const pullRequest = github.context.payload.pull_request;
  if (!pullRequest) return;
  if (Buffer.byteLength(body, "utf8") > MAX_PULL_REQUEST_COMMENT_BYTES) {
    throw new Error(
      `Hedge PR comment exceeds the ${MAX_PULL_REQUEST_COMMENT_BYTES}-byte publication limit.`
    );
  }
  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;
  const issueNumber = pullRequest.number;
  const comments = await octokit.paginate(octokit.rest.issues.listComments, {
    owner,
    repo,
    issue_number: issueNumber,
    per_page: 100
  });
  const existing = comments
    .filter(
      (comment) => comment.user?.type === "Bot" && comment.body?.includes(HEDGE_COMMENT_MARKER)
    )
    .sort((left, right) => right.id - left.id);
  const newest = existing[0];
  if (newest) {
    await octokit.rest.issues.updateComment({ owner, repo, comment_id: newest.id, body });
    for (const duplicate of existing.slice(1)) {
      await octokit.rest.issues.deleteComment({ owner, repo, comment_id: duplicate.id });
    }
    return;
  }
  await octokit.rest.issues.createComment({ owner, repo, issue_number: issueNumber, body });
}

/** Remove stale Hedge output after an exact, complete, confirmed no-delta run. */
export async function removePullRequestComments(token: string): Promise<void> {
  const pullRequest = github.context.payload.pull_request;
  if (!pullRequest) return;
  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;
  const comments = await octokit.paginate(octokit.rest.issues.listComments, {
    owner,
    repo,
    issue_number: pullRequest.number,
    per_page: 100
  });
  const existing = comments.filter(
    (comment) => comment.user?.type === "Bot" && comment.body?.includes(HEDGE_COMMENT_MARKER)
  );
  for (const comment of existing) {
    await octokit.rest.issues.deleteComment({ owner, repo, comment_id: comment.id });
  }
}
