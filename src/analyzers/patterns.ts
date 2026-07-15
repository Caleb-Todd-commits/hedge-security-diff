import { redactSensitiveContent } from "../security/untrusted.js";
import type { SourceFile } from "./files.js";
import type { ControlSchema } from "../domain/schemas.js";
import type { z } from "zod";
import { lineNumberAt, lineSnippet } from "../utils/lines.js";

type Control = z.infer<typeof ControlSchema>;

export interface PatternMatch {
  label: string;
  line: number;
  snippet: string;
}

export function findMatches(file: SourceFile, pattern: RegExp, label: string): PatternMatch[] {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const globalPattern = new RegExp(pattern.source, flags);
  const matches: PatternMatch[] = [];
  for (const match of file.content.matchAll(globalPattern)) {
    const index = match.index ?? 0;
    const line = lineNumberAt(file.content, index);
    matches.push({
      label,
      line,
      snippet: redactSensitiveContent(lineSnippet(file.content, line)).value
    });
  }
  return matches;
}

export function detectControls(file: SourceFile): Control[] {
  const controls: Control[] = [];
  const candidates: Array<[Control["type"], string, RegExp]> = [
    [
      "authentication",
      "Authentication check",
      /\b(auth|getServerSession|requireAuth|currentUser|clerkClient|validateSession)\s*\(/i
    ],
    [
      "authorization",
      "Authorization or role check",
      /\b(authorize|requireRole|hasPermission|isAdmin|role\s*[!=]==?|permissions?)\b/i
    ],
    [
      "ownership",
      "Resource ownership check",
      /(?:\b(ownerId|userId|tenantId|accountId)\b|session\.user\.id)/i
    ],
    ["validation", "Input validation", /\b(zod|safeParse|parse|validate|schema)\b/i],
    ["rate-limit", "Rate limiting", /\b(rateLimit|ratelimit|throttle)\b/i],
    [
      "size-limit",
      "Payload or file size limit",
      /\b(maxFileSize|sizeLimit|content-length|file\.size\s*[<>]=?)\b/i
    ],
    [
      "content-type",
      "Content type allowlist",
      /\b(contentType|mime|mimetype|allowedTypes|accept)\b/i
    ],
    ["encryption", "Encryption control", /\b(encrypt|aes|kms|cipher)\b/i]
  ];

  for (const [type, label, pattern] of candidates) {
    const match = pattern.exec(file.content);
    if (!match) continue;
    const line = lineNumberAt(file.content, match.index);
    controls.push({
      type,
      label,
      evidence: [
        {
          file: file.path,
          line,
          snippet: redactSensitiveContent(lineSnippet(file.content, line)).value,
          extractor: "control-patterns"
        }
      ],
      confidence: type === "ownership" || type === "authorization" ? 0.7 : 0.8
    });
  }

  return controls;
}
