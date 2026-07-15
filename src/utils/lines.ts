export function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

export function lineSnippet(content: string, line: number): string {
  return content.split("\n")[line - 1]?.trim().slice(0, 220) ?? "";
}
