const RISK_RELEVANT_PATHS = [
  /(^|\/)app\/.+\/route\.[jt]sx?$/i,
  /(^|\/)pages\/api\//i,
  /(^|\/)api\//i,
  /route|router|controller|handler/i,
  /middleware/i,
  /auth|session|permission|policy|access/i,
  /upload|storage|s3|blob|bucket/i,
  /prisma|schema|migration|database|db/i,
  /package\.json$/i,
  /docker|terraform|cloudformation|serverless|\.github\/workflows/i,
  /\.env|config|secret/i
];

export function isRiskRelevantPath(path: string): boolean {
  return RISK_RELEVANT_PATHS.some((pattern) => pattern.test(path));
}

export function prefilterChangedFiles(paths: string[]): { relevant: string[]; ignored: string[] } {
  const relevant: string[] = [];
  const ignored: string[] = [];
  for (const path of paths) {
    (isRiskRelevantPath(path) ? relevant : ignored).push(path);
  }
  return { relevant, ignored };
}
