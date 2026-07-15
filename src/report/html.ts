import type {
  AnalysisResult,
  AttackSurfaceGraph,
  GraphDelta,
  RiskFinding,
  SurfaceNode
} from "../domain/schemas.js";
import { summarizeDelta } from "../graph/diff.js";

export interface HtmlReportOptions {
  repository?: string;
  baseLabel?: string;
  headLabel?: string;
}

export function renderHtmlReport(
  baseline: AttackSurfaceGraph,
  graph: AttackSurfaceGraph,
  delta: GraphDelta,
  analysis: AnalysisResult,
  findings: RiskFinding[],
  options: HtmlReportOptions = {}
): string {
  const payload = safeJson({ baseline, graph, delta, analysis, findings, options });
  const counts = severityCounts(findings);
  const deltaSummary = summarizeDelta(delta);
  const activeFindings = findings.filter(
    (finding) => !["verified", "accepted", "closed"].includes(finding.status)
  );
  const highest = highestSeverity(activeFindings);
  const added = new Set(delta.addedNodes.map((node) => node.id));
  const changed = new Set(delta.changedNodes.map((pair) => pair.after.id));
  const riskyLabels = new Set(activeFindings.flatMap((finding) => finding.attackPath));
  const invariantEvaluations = analysis.invariantEvaluations ?? [];
  const violatedInvariants = invariantEvaluations.filter((item) => item.status === "violated");
  const observations = analysis.observations ?? [];
  const inferences = analysis.inferences ?? [];
  const decisions = analysis.decisions ?? [];
  const overallDecision = decisions.find((decision) => decision.source === "threshold");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Hedge security diff</title>
<style>
:root{color-scheme:dark;--bg:#07100c;--panel:#0d1812;--panel2:#111f17;--line:#24372b;--text:#edf7f0;--muted:#99ad9f;--green:#52e08b;--green2:#1f9d59;--red:#ff6b6b;--amber:#ffc857;--blue:#62a8ff;--purple:#b795ff;--shadow:0 22px 60px rgba(0,0,0,.34)}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0%,#12311f 0,transparent 32%),var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input{font:inherit}.shell{max-width:1480px;margin:auto;padding:28px}.hero{display:flex;gap:24px;align-items:flex-end;justify-content:space-between;padding:24px 26px;border:1px solid var(--line);background:linear-gradient(140deg,rgba(25,70,43,.75),rgba(9,21,14,.96));border-radius:20px;box-shadow:var(--shadow)}.brand{display:flex;gap:13px;align-items:center}.mark{width:45px;height:45px;border:1px solid #3bb66d;border-radius:13px;display:grid;place-items:center;background:#10291a;font-size:24px}.eyebrow{text-transform:uppercase;letter-spacing:.16em;color:var(--green);font-size:11px;font-weight:800}.hero h1{margin:2px 0 5px;font-size:31px;letter-spacing:-.04em}.sub{color:var(--muted);max-width:760px}.result{padding:10px 13px;border-radius:999px;border:1px solid ${activeFindings.length ? "#6f3434" : "#2c6b47"};background:${activeFindings.length ? "#2b1515" : "#102b1b"};font-weight:800;color:${activeFindings.length ? "#ffb1b1" : "#9df0bb"};white-space:nowrap}.metrics{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin:16px 0}.metric{border:1px solid var(--line);background:rgba(13,24,18,.93);border-radius:15px;padding:15px}.metric .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.12em}.metric .v{font-size:24px;font-weight:850;margin-top:3px}.v.red{color:var(--red)}.v.amber{color:var(--amber)}.v.green{color:var(--green)}.tabs{display:flex;gap:8px;margin:19px 0 14px;position:sticky;top:0;z-index:5;padding:10px 0;background:linear-gradient(var(--bg) 70%,transparent)}.tab{border:1px solid var(--line);background:var(--panel);color:var(--muted);padding:9px 13px;border-radius:10px;cursor:pointer}.tab.active{color:#06200f;background:var(--green);border-color:var(--green);font-weight:800}.view{display:none}.view.active{display:block}.grid{display:grid;grid-template-columns:1.05fr .95fr;gap:15px}.card{border:1px solid var(--line);background:rgba(13,24,18,.96);border-radius:16px;padding:18px;box-shadow:0 12px 35px rgba(0,0,0,.14)}.card h2,.card h3{margin:0 0 12px;letter-spacing:-.025em}.card h2{font-size:18px}.card h3{font-size:15px}.delta-list{display:grid;gap:8px}.delta-item{padding:10px 12px;background:var(--panel2);border:1px solid var(--line);border-radius:10px}.model{white-space:pre-wrap;color:#cae3d2}.integrity{display:grid;grid-template-columns:repeat(2,1fr);gap:9px}.integrity>div{padding:12px;border:1px solid var(--line);border-radius:11px;background:var(--panel2)}.finding-tools{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}.filter,.search{border:1px solid var(--line);border-radius:10px;background:var(--panel);color:var(--text);padding:9px 11px}.filter{cursor:pointer}.filter.active{border-color:var(--green);color:var(--green)}.search{min-width:280px;flex:1}.findings{display:grid;gap:12px}.finding{border:1px solid var(--line);background:var(--panel);border-radius:15px;overflow:hidden}.finding.sev-critical,.finding.sev-high{border-left:4px solid var(--red)}.finding.sev-medium{border-left:4px solid var(--amber)}.finding.sev-low,.finding.sev-info{border-left:4px solid var(--blue)}.finding-head{display:flex;gap:13px;align-items:flex-start;justify-content:space-between;padding:15px 16px;background:rgba(255,255,255,.015)}.finding-title{font-size:16px;font-weight:820}.meta{display:flex;flex-wrap:wrap;gap:7px;margin-top:5px}.pill{font-size:11px;text-transform:uppercase;letter-spacing:.08em;padding:3px 7px;border:1px solid var(--line);border-radius:999px;color:var(--muted)}.pill.high,.pill.critical{color:#ffadad;border-color:#6e3939}.pill.medium{color:#ffd987;border-color:#65542e}.finding-body{padding:16px}.attack-path{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:11px 0 15px}.path-node{padding:7px 9px;background:#16251b;border:1px solid #2f4737;border-radius:8px}.arrow{color:var(--red);font-weight:900}.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}.box{padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--panel2)}.box strong{display:block;margin-bottom:5px}.evidence{display:flex;flex-wrap:wrap;gap:7px}.ev{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;padding:5px 8px;border-radius:7px;background:#07120b;border:1px solid #294030;color:#bfe7ca}.graph{display:grid;grid-template-columns:repeat(5,minmax(170px,1fr));gap:12px;overflow:auto;padding-bottom:8px}.zone{border:1px solid var(--line);border-radius:14px;background:rgba(8,18,11,.58);min-height:360px;padding:11px}.zone-title{text-transform:uppercase;letter-spacing:.13em;font-size:11px;color:var(--muted);margin-bottom:9px;display:flex;justify-content:space-between}.node{padding:9px 10px;margin:8px 0;border:1px solid #304a37;border-radius:9px;background:#102016}.node.added{border-color:var(--amber);box-shadow:inset 3px 0 var(--amber)}.node.changed{border-color:var(--blue);box-shadow:inset 3px 0 var(--blue)}.node.risky{border-color:var(--red);box-shadow:inset 3px 0 var(--red)}.node .kind{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}.node .label{font-weight:750;margin-top:2px}.edges{margin-top:14px}.edge-row{display:grid;grid-template-columns:1fr auto 1fr;gap:10px;align-items:center;padding:9px 0;border-bottom:1px solid var(--line)}.edge-row .to{text-align:right}.edge-kind{font-size:11px;color:var(--green);border:1px solid #2b6040;border-radius:999px;padding:3px 8px}.empty{padding:38px;text-align:center;color:var(--muted)}pre{white-space:pre-wrap;overflow:auto;background:#07120b;border:1px solid var(--line);border-radius:10px;padding:12px;color:#c7e5d0}footer{margin:28px 0 8px;color:var(--muted);text-align:center;font-size:12px}@media(max-width:1000px){.metrics{grid-template-columns:repeat(3,1fr)}.grid,.two{grid-template-columns:1fr}.graph{grid-template-columns:repeat(5,230px)}}@media(max-width:620px){.shell{padding:12px}.hero{align-items:flex-start;flex-direction:column}.metrics{grid-template-columns:repeat(2,1fr)}.search{min-width:100%}}
</style>
</head>
<body>
<div class="shell">
<header class="hero">
  <div><div class="brand"><div class="mark">🌿</div><div><div class="eyebrow">Hedge · security architecture diff</div><h1>${escapeHtml(options.repository ?? graph.repository)}</h1></div></div><div class="sub">${escapeHtml(analysis.summary)}</div></div>
  <div class="result">${activeFindings.length ? `${activeFindings.length} active risk${activeFindings.length === 1 ? "" : "s"} · ${highest.toUpperCase()}` : "No active risks surfaced"}</div>
</header>
<section class="metrics">
  ${metric("Surface nodes", graph.nodes.length, "")}
  ${metric("Architecture changes", deltaCount(delta), deltaCount(delta) ? "amber" : "green")}
  ${metric("Critical / high", counts.critical + counts.high, counts.critical + counts.high ? "red" : "green")}
  ${metric("Medium", counts.medium, counts.medium ? "amber" : "green")}
  ${metric("Invariant violations", violatedInvariants.length, violatedInvariants.length ? "red" : "green")}
  ${metric("Decision", (overallDecision?.type ?? "allow").toUpperCase(), overallDecision?.type === "block" ? "red" : overallDecision?.type === "warn" ? "amber" : "green")}
</section>
<nav class="tabs">
  <button class="tab active" data-tab="overview">Security diff</button>
  <button class="tab" data-tab="findings">Findings</button>
  <button class="tab" data-tab="architecture">Architecture</button>
  <button class="tab" data-tab="evidence">Evidence model</button>
</nav>
<main>
<section class="view active" id="overview">
  <div class="grid">
    <article class="card"><h2>What changed</h2><div class="delta-list">${deltaSummary.length ? deltaSummary.map((item) => `<div class="delta-item">${escapeHtml(item)}</div>`).join("") : '<div class="empty">No evidence-linked architecture delta.</div>'}</div></article>
    <article class="card"><h2>Analysis integrity</h2><div class="integrity"><div><span class="eyebrow">Boundary</span><div class="v ${analysis.integrity.analysisBoundaryHeld ? "green" : "red"}">${analysis.integrity.analysisBoundaryHeld ? "Held" : "Failed"}</div></div><div><span class="eyebrow">Instruction-like content</span><div class="v ${analysis.integrity.untrustedInstructionsObserved ? "amber" : "green"}">${analysis.integrity.untrustedInstructionsObserved ? "Observed" : "Not observed"}</div></div></div><div class="model">${analysis.integrity.notes.map(escapeHtml).join("\n") || "No additional integrity notes."}</div></article>
  </div>
  <article class="card" style="margin-top:15px"><h2>Highest-value findings</h2>${activeFindings.length ? activeFindings.slice(0, 3).map(renderFinding).join("") : '<div class="empty">Hedge detected architecture change but did not surface a concrete evidence-backed risk.</div>'}</article>
</section>
<section class="view" id="findings">
  <article class="card"><div class="finding-tools"><button class="filter active" data-severity="all">All</button><button class="filter" data-severity="critical">Critical</button><button class="filter" data-severity="high">High</button><button class="filter" data-severity="medium">Medium</button><button class="filter" data-severity="low">Low</button><input class="search" id="findingSearch" placeholder="Search risks, controls, paths, files…" /></div><div class="findings" id="findingList">${findings.length ? findings.map(renderFinding).join("") : '<div class="empty">No findings.</div>'}</div></article>
</section>
<section class="view" id="architecture">
  <article class="card"><h2>Evidence-linked attack surface</h2><div class="graph">${renderZones(graph.nodes, added, changed, riskyLabels)}</div><div class="edges"><h3>Security-relevant relationships</h3>${graph.edges.length ? graph.edges.map((edge) => `<div class="edge-row"><div>${escapeHtml(nodeLabel(graph.nodes, edge.from))}</div><div class="edge-kind">${escapeHtml(edge.label ?? edge.kind)}</div><div class="to">${escapeHtml(nodeLabel(graph.nodes, edge.to))}</div></div>`).join("") : '<div class="empty">No relationships extracted.</div>'}</div></article>
</section>
<section class="view" id="evidence">
  <div class="grid"><article class="card"><h2>Deterministic observations</h2>${observations.length ? `<ul>${observations.map((item) => `<li><strong>${escapeHtml(item.kind)}</strong> — ${escapeHtml(item.summary)}</li>`).join("")}</ul>` : '<div class="empty">No architecture observations.</div>'}</article><article class="card"><h2>Security inferences</h2>${inferences.length ? `<ul>${inferences.map((item) => `<li>${escapeHtml(item.hypothesis)} <span class="pill">${Math.round(item.confidence * 100)}%</span></li>`).join("")}</ul>` : '<div class="empty">No security hypotheses.</div>'}</article></div>
  <div class="grid" style="margin-top:15px"><article class="card"><h2>Invariant evaluations</h2>${invariantEvaluations.length ? `<ul>${invariantEvaluations.map((item) => `<li><strong>${escapeHtml(item.invariantId)} · ${escapeHtml(item.status)}</strong> — ${escapeHtml(item.reason)}</li>`).join("")}</ul>` : '<div class="empty">No explicit invariants configured.</div>'}</article><article class="card"><h2>Decisions</h2>${decisions.length ? `<ul>${decisions.map((item) => `<li><strong>${escapeHtml(item.type.toUpperCase())}</strong> — ${escapeHtml(item.reason)}</li>`).join("")}</ul>` : '<div class="empty">No decision record.</div>'}</article></div>
  <div class="grid" style="margin-top:15px"><article class="card"><h2>Limitations</h2>${analysis.limitations.length ? `<ul>${analysis.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : '<div class="empty">No run-specific limitation recorded.</div>'}</article><article class="card"><h2>Repository uncertainty</h2>${graph.unknowns.length ? `<ul>${graph.unknowns.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : '<div class="empty">No repository unknowns recorded.</div>'}</article></div>
  <article class="card" style="margin-top:15px"><h2>Machine-readable report</h2><pre id="rawJson"></pre></article>
</section>
</main>
<footer>Hedge surfaces evidence-linked architecture changes and design risks. It does not claim to find or prove vulnerabilities.</footer>
</div>
<script id="hedge-data" type="application/json">${payload}</script>
<script>
const data=JSON.parse(document.getElementById('hedge-data').textContent);
document.getElementById('rawJson').textContent=JSON.stringify({delta:data.delta,analysis:data.analysis,findings:data.findings},null,2);
for(const tab of document.querySelectorAll('.tab')) tab.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));tab.classList.add('active');document.getElementById(tab.dataset.tab).classList.add('active')});
let severity='all';const search=document.getElementById('findingSearch');
function apply(){const q=(search?.value||'').toLowerCase();document.querySelectorAll('#findingList .finding').forEach(card=>{const matchSeverity=severity==='all'||card.dataset.severity===severity;const matchText=!q||card.textContent.toLowerCase().includes(q);card.style.display=matchSeverity&&matchText?'block':'none'})}
document.querySelectorAll('.filter').forEach(btn=>btn.addEventListener('click',()=>{document.querySelectorAll('.filter').forEach(x=>x.classList.remove('active'));btn.classList.add('active');severity=btn.dataset.severity;apply()}));if(search)search.addEventListener('input',apply);
</script>
</body></html>`;
}

function renderFinding(finding: RiskFinding): string {
  const evidence = finding.evidence
    .map(
      (item) =>
        `<span class="ev">${escapeHtml(item.file)}${item.line ? `:${item.line}` : ""}</span>`
    )
    .join("");
  return `<article class="finding sev-${finding.severity}" data-severity="${finding.severity}"><div class="finding-head"><div><div class="finding-title">${escapeHtml(finding.title)}</div><div class="meta"><span class="pill ${finding.severity}">${finding.severity}</span><span class="pill">${escapeHtml(finding.id)}</span><span class="pill">${escapeHtml(finding.status)}</span><span class="pill">${Math.round(finding.confidence * 100)}% confidence</span></div></div></div><div class="finding-body"><div>${escapeHtml(finding.potentialImpact)}</div><div class="attack-path">${finding.attackPath.map((part, index) => `${index ? '<span class="arrow">→</span>' : ""}<span class="path-node">${escapeHtml(part)}</span>`).join("")}</div><div class="two"><div class="box"><strong>Security invariant</strong>${escapeHtml(finding.securityInvariant)}</div><div class="box"><strong>Missing controls</strong>${escapeHtml(finding.missingControls.join(", ") || "None recorded")}</div></div><div style="margin-top:12px"><strong>Evidence</strong><div class="evidence">${evidence || '<span class="ev">No file evidence</span>'}</div></div></div></article>`;
}

function renderZones(
  nodes: SurfaceNode[],
  added: Set<string>,
  changed: Set<string>,
  riskyLabels: Set<string>
): string {
  const zones = ["public", "application", "privileged", "data", "external"];
  return zones
    .map((zone) => {
      const values = nodes.filter((node) => node.trustZone === zone);
      return `<section class="zone"><div class="zone-title"><span>${zone}</span><span>${values.length}</span></div>${
        values
          .map((node) => {
            const classes = [
              "node",
              added.has(node.id) ? "added" : "",
              changed.has(node.id) ? "changed" : "",
              riskyLabels.has(node.label) ? "risky" : ""
            ]
              .filter(Boolean)
              .join(" ");
            return `<div class="${classes}"><div class="kind">${escapeHtml(node.kind)}</div><div class="label">${escapeHtml(node.label)}</div></div>`;
          })
          .join("") || '<div class="empty">No nodes</div>'
      }</section>`;
    })
    .join("");
}

function nodeLabel(nodes: SurfaceNode[], id: string): string {
  return nodes.find((node) => node.id === id)?.label ?? id;
}

function metric(key: string, value: string | number, className: string): string {
  return `<div class="metric"><div class="k">${escapeHtml(key)}</div><div class="v ${className}">${escapeHtml(String(value))}</div></div>`;
}

function severityCounts(findings: RiskFinding[]): Record<RiskFinding["severity"], number> {
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) counts[finding.severity]++;
  return counts;
}

function highestSeverity(findings: RiskFinding[]): RiskFinding["severity"] {
  const order: RiskFinding["severity"][] = ["info", "low", "medium", "high", "critical"];
  return findings.reduce<RiskFinding["severity"]>(
    (highest, finding) =>
      order.indexOf(finding.severity) > order.indexOf(highest) ? finding.severity : highest,
    "info"
  );
}

function deltaCount(delta: GraphDelta): number {
  return (
    delta.addedNodes.length +
    delta.removedNodes.length +
    delta.changedNodes.length +
    delta.addedEdges.length +
    delta.removedEdges.length +
    delta.changedEdges.length
  );
}

function safeJson(value: unknown): string {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026");
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
