import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  listComments: vi.fn(),
  updateComment: vi.fn(),
  deleteComment: vi.fn(),
  createComment: vi.fn(),
  paginate: vi.fn(),
  getOctokit: vi.fn(),
  context: {
    payload: { pull_request: { number: 17 } },
    repo: { owner: "example", repo: "app" }
  }
}));

vi.mock("@actions/github", () => ({
  context: mocks.context,
  getOctokit: mocks.getOctokit
}));

import { removePullRequestComments, upsertPullRequestComment } from "../../src/github/comment.js";
import { HEDGE_COMMENT_MARKER, MAX_PULL_REQUEST_COMMENT_BYTES } from "../../src/report/comment.js";

describe("GitHub PR comment publication", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getOctokit.mockReturnValue({
      paginate: mocks.paginate,
      rest: {
        issues: {
          listComments: mocks.listComments,
          updateComment: mocks.updateComment,
          deleteComment: mocks.deleteComment,
          createComment: mocks.createComment
        }
      }
    });
    mocks.updateComment.mockResolvedValue({});
    mocks.deleteComment.mockResolvedValue({});
    mocks.createComment.mockResolvedValue({});
    mocks.paginate.mockImplementation(
      async (method: (options: unknown) => Promise<{ data: unknown[] }>, options: unknown) => {
        const result = await method(options);
        return result.data;
      }
    );
  });

  it("updates the newest Hedge comment and removes older bot duplicates", async () => {
    mocks.listComments.mockResolvedValue({
      data: [
        { id: 11, user: { type: "Bot" }, body: HEDGE_COMMENT_MARKER },
        { id: 25, user: { type: "Bot" }, body: `newer ${HEDGE_COMMENT_MARKER}` },
        { id: 30, user: { type: "User" }, body: HEDGE_COMMENT_MARKER }
      ]
    });

    await upsertPullRequestComment("token", `${HEDGE_COMMENT_MARKER}\nupdated`);

    expect(mocks.updateComment).toHaveBeenCalledWith({
      owner: "example",
      repo: "app",
      comment_id: 25,
      body: `${HEDGE_COMMENT_MARKER}\nupdated`
    });
    expect(mocks.deleteComment).toHaveBeenCalledTimes(1);
    expect(mocks.deleteComment).toHaveBeenCalledWith({
      owner: "example",
      repo: "app",
      comment_id: 11
    });
    expect(mocks.createComment).not.toHaveBeenCalled();
  });

  it("rejects an oversized body before calling GitHub", async () => {
    await expect(
      upsertPullRequestComment("token", "x".repeat(MAX_PULL_REQUEST_COMMENT_BYTES + 1))
    ).rejects.toThrow("publication limit");
    expect(mocks.getOctokit).not.toHaveBeenCalled();
  });

  it("removes stale bot reports after a confirmed no-delta result", async () => {
    mocks.listComments.mockResolvedValue({
      data: [
        { id: 11, user: { type: "Bot" }, body: HEDGE_COMMENT_MARKER },
        { id: 12, user: { type: "User" }, body: HEDGE_COMMENT_MARKER },
        { id: 13, user: { type: "Bot" }, body: "unrelated" }
      ]
    });
    await removePullRequestComments("token");
    expect(mocks.deleteComment).toHaveBeenCalledTimes(1);
    expect(mocks.deleteComment).toHaveBeenCalledWith({
      owner: "example",
      repo: "app",
      comment_id: 11
    });
  });
});
