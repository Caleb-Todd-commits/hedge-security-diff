import * as github from "@actions/github";
import { HEDGE_COMMENT_MARKER } from "../report/comment.js";

export async function upsertPullRequestComment(token: string, body: string): Promise<void> {
  const pullRequest = github.context.payload.pull_request;
  if (!pullRequest) return;
  const octokit = github.getOctokit(token);
  const { owner, repo } = github.context.repo;
  const issueNumber = pullRequest.number;
  const comments = await octokit.rest.issues.listComments({
    owner,
    repo,
    issue_number: issueNumber,
    per_page: 100
  });
  const existing = comments.data.find(
    (comment) => comment.user?.type === "Bot" && comment.body?.includes(HEDGE_COMMENT_MARKER)
  );
  if (existing) {
    await octokit.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
    return;
  }
  await octokit.rest.issues.createComment({ owner, repo, issue_number: issueNumber, body });
}
