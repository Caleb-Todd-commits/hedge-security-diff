export interface HedgeFixCommand {
  riskId: string;
}

export interface HedgePruneCommand {
  riskId: string;
  reason: string;
}

export function parseFixCommand(body: string): HedgeFixCommand | null {
  const match = /(?:^|\s)@hedge\s+fix\s+(HEDGE-\d{3,})\b/i.exec(body);
  return match?.[1] ? { riskId: match[1].toUpperCase() } : null;
}

export function parsePruneCommand(body: string): HedgePruneCommand | null {
  const match = /(?:^|\s)@hedge\s+prune\s+(HEDGE-\d{3,})\s+reason:["']([^"']+)["']/i.exec(body);
  return match?.[1] && match[2]
    ? { riskId: match[1].toUpperCase(), reason: match[2].trim() }
    : null;
}
