import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import cytoscape from "cytoscape";
import { api } from "./api";

type ViewId =
  | "overview"
  | "graph"
  | "web"
  | "workflow"
  | "runner"
  | "compare"
  | "inspector"
  | "findings"
  | "mitigation"
  | "reports";

const NAV: { id: ViewId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "graph", label: "Knowledge graph" },
  { id: "web", label: "Synthetic web" },
  { id: "workflow", label: "Agent workflow" },
  { id: "runner", label: "Experiment runner" },
  { id: "compare", label: "Research comparison" },
  { id: "inspector", label: "Simulation inspector" },
  { id: "findings", label: "Security findings" },
  { id: "mitigation", label: "Mitigation testing" },
  { id: "reports", label: "Reporting" },
];

function viewFromHash(): ViewId {
  const value = window.location.hash.replace("#", "") as ViewId;
  return NAV.some((item) => item.id === value) ? value : "overview";
}

export function App() {
  const [view, setView] = useState<ViewId>(viewFromHash);
  useEffect(() => {
    const onHash = () => setView(viewFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  function open(next: ViewId) {
    window.location.hash = next;
    setView(next);
  }
  return (
    <div className="min-h-screen bg-ink text-[#e7ecdf]">
      <div className="grid min-h-screen grid-cols-[240px_1fr]">
        <aside className="border-r border-line bg-panel px-4 py-6">
          <div className="px-2">
            <div className="font-mono text-xs uppercase tracking-[0.22em] text-lime">Nymbric</div>
            <div className="mt-1 text-sm text-moss">Context-aware agent security</div>
          </div>
          <nav className="mt-8 space-y-1">
            {NAV.map((item) => (
              <button
                key={item.id}
                onClick={() => open(item.id)}
                className={`block w-full rounded px-3 py-2 text-left text-sm ${view === item.id ? "bg-lime text-ink" : "text-[#e7ecdf] hover:bg-[#222a20]"}`}
              >
                {item.label}
              </button>
            ))}
          </nav>
        </aside>
        <main className="px-8 py-6">
          {view === "overview" && <Overview />}
          {view === "graph" && <GraphExplorer />}
          {view === "web" && <WebExplorer />}
          {view === "workflow" && <WorkflowExplorer />}
          {view === "runner" && <Runner />}
          {view === "compare" && <Comparison />}
          {view === "inspector" && <Inspector />}
          {view === "findings" && <Findings />}
          {view === "mitigation" && <Mitigation />}
          {view === "reports" && <Reports />}
        </main>
      </div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-panel p-4">
      <h2 className="mb-3 font-mono text-xs uppercase tracking-widest text-moss">{title}</h2>
      {children}
    </section>
  );
}

function Overview() {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<Record<string, unknown>>("/api/overview").then(setData).catch((err: Error) => setError(err.message));
  }, []);
  if (error) return <ErrorText message={error} />;
  if (!data) return <p className="text-moss">Loading recorded experiments…</p>;
  const runs = (data.runs as Record<string, unknown>[]) || [];
  const worlds = (data.worlds as Record<string, unknown>[]) || [];
  const findings = (data.findings as Record<string, unknown>[]) || [];
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Overview</h1>
        <p className="mt-2 max-w-3xl text-sm text-moss">
          Figures on this page come from the local experiment database. An empty board means no run has been recorded yet.
        </p>
      </header>
      <div className="grid grid-cols-3 gap-4">
        <Metric label="Worlds" value={String(worlds.length)} />
        <Metric label="Recent runs" value={String(runs.length)} />
        <Metric label="Finding groups" value={String(findings.length)} />
      </div>
      <Panel title="Connected model configuration">
        <pre className="overflow-auto font-mono text-xs text-tide">{JSON.stringify(data.models, null, 2)}</pre>
      </Panel>
      <Panel title="Recent runs">
        {runs.length === 0 ? (
          <p className="text-sm text-moss">No runs yet. Use the experiment runner or `nymbric run pkg-risk --provider mock`.</p>
        ) : (
          <RunTable runs={runs} />
        )}
      </Panel>
      <Panel title="Findings by severity">
        {findings.length === 0 ? <p className="text-sm text-moss">No findings recorded.</p> : <SeverityList rows={findings} />}
      </Panel>
    </div>
  );
}

function GraphExplorer() {
  const [worlds, setWorlds] = useState<{ world_id: string }[]>([]);
  const [world, setWorld] = useState("");
  const [relationship, setRelationship] = useState("");
  const [sensitivity, setSensitivity] = useState("");
  const [elements, setElements] = useState<{ nodes: unknown[]; edges: unknown[] }>({ nodes: [], edges: [] });
  useEffect(() => {
    api<{ world_id: string }[]>("/api/worlds").then((rows) => {
      setWorlds(rows);
      if (rows[0]) setWorld(rows[0].world_id);
    });
  }, []);
  useEffect(() => {
    if (!world) return;
    const params = new URLSearchParams({ limit: "80" });
    if (relationship) params.set("relationship", relationship);
    if (sensitivity) params.set("sensitivity", sensitivity);
    api<{ nodes: unknown[]; edges: unknown[] }>(`/api/worlds/${world}/graph?${params}`).then(setElements);
  }, [world, relationship, sensitivity]);
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Knowledge graph</h1>
      <div className="flex gap-3">
        <Select value={world} onChange={setWorld} options={worlds.map((item) => item.world_id)} />
        <Select value={relationship} onChange={setRelationship} options={["", "friend_of", "reports_to", "family_member", "works_with", "communicated_with", "attended_meeting"]} />
        <Select value={sensitivity} onChange={setSensitivity} options={["", "low", "medium", "high", "restricted"]} />
      </div>
      <Cy elements={elements} empty="Generate a world to inspect fictional entities." />
    </div>
  );
}

function WebExplorer() {
  const [worlds, setWorlds] = useState<{ world_id: string }[]>([]);
  const [world, setWorld] = useState("");
  const [query, setQuery] = useState("directory");
  const [results, setResults] = useState<Record<string, unknown>[]>([]);
  const [page, setPage] = useState<Record<string, unknown> | null>(null);
  useEffect(() => {
    api<{ world_id: string }[]>("/api/worlds").then((rows) => {
      setWorlds(rows);
      if (rows[0]) setWorld(rows[0].world_id);
    });
  }, []);
  async function search() {
    const payload = await api<{ results: Record<string, unknown>[] }>(`/api/worlds/${world}/search?q=${encodeURIComponent(query)}`);
    setResults(payload.results || []);
    setPage(null);
  }
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Synthetic web</h1>
      <div className="flex gap-3">
        <Select value={world} onChange={setWorld} options={worlds.map((item) => item.world_id)} />
        <input value={query} onChange={(event) => setQuery(event.target.value)} className="rounded border border-line bg-ink px-3 py-2 text-sm" />
        <button onClick={search} className="rounded bg-lime px-3 py-2 text-sm text-ink">Search</button>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <Panel title="Ranked results">
          {results.length === 0 ? <p className="text-sm text-moss">Run a search against the indexed fictional corpus.</p> : results.map((hit) => (
            <button key={String(hit.page_id)} className="mb-3 block text-left" onClick={() => api<Record<string, unknown>>(`/api/worlds/${world}/pages/${hit.page_id}`).then(setPage)}>
              <div className="text-sm text-tide">{String(hit.title)}</div>
              <div className="font-mono text-xs text-moss">{String(hit.snippet || "")}</div>
            </button>
          ))}
        </Panel>
        <Panel title="Page">
          {page ? <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap font-mono text-xs">{String(page.body)}</pre> : <p className="text-sm text-moss">Open a result to read the fictional page.</p>}
        </Panel>
      </div>
    </div>
  );
}

function WorkflowExplorer() {
  const [runs, setRuns] = useState<Record<string, unknown>[]>([]);
  const [run, setRun] = useState("");
  const [elements, setElements] = useState<{ nodes: unknown[]; edges: unknown[] }>({ nodes: [], edges: [] });
  useEffect(() => {
    api<Record<string, unknown>>("/api/overview").then((data) => {
      const rows = (data.runs as Record<string, unknown>[]) || [];
      setRuns(rows);
      if (rows[0]) setRun(String(rows[0].run_id));
    });
  }, []);
  useEffect(() => {
    if (!run) return;
    api<{ nodes: unknown[]; edges: unknown[] }>(`/api/runs/${run}/workflow`).then(setElements);
  }, [run]);
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Agent workflow</h1>
      <Select value={run} onChange={setRun} options={runs.map((item) => String(item.run_id))} />
      <Cy elements={elements} empty="No delegated tasks are stored for this run." />
    </div>
  );
}

function Runner() {
  const [form, setForm] = useState({ personas: 12, seed: 1, trials: 2, provider: "mock", defender_mode: "familiarity_biased", threat: "unauthorized_calendar", conditions: "all" });
  const [job, setJob] = useState<string | null>(null);
  const [status, setStatus] = useState<string>("");
  async function submit() {
    const body = { ...form, conditions: form.conditions.split(",").map((item) => item.trim()) };
    const started = await api<{ experiment_id: string }>("/api/experiments/pkg-risk", { method: "POST", body: JSON.stringify(body) });
    setJob(started.experiment_id);
    setStatus("running");
  }
  useEffect(() => {
    if (!job || status === "completed" || status === "failed") return;
    const timer = window.setInterval(() => {
      api<Record<string, unknown>>(`/api/experiments/${job}`).then((payload) => {
        if (payload.status === "running") setStatus("running");
        else if (payload.runs) setStatus("completed");
        else if (payload.status === "failed") setStatus(`failed: ${payload.detail || ""}`);
      }).catch(() => undefined);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [job, status]);
  return (
    <div className="max-w-xl space-y-4">
      <h1 className="text-2xl font-semibold">Experiment runner</h1>
      <p className="text-sm text-moss">Mock mode runs the full pipeline locally. Ollama is used only when you select it, and a failed check stops the job.</p>
      <label className="block text-sm">Personas <input className="mt-1 w-full rounded border border-line bg-ink px-3 py-2" type="number" value={form.personas} onChange={(event) => setForm({ ...form, personas: Number(event.target.value) })} /></label>
      <label className="block text-sm">Trials <input className="mt-1 w-full rounded border border-line bg-ink px-3 py-2" type="number" value={form.trials} onChange={(event) => setForm({ ...form, trials: Number(event.target.value) })} /></label>
      <label className="block text-sm">Seed <input className="mt-1 w-full rounded border border-line bg-ink px-3 py-2" type="number" value={form.seed} onChange={(event) => setForm({ ...form, seed: Number(event.target.value) })} /></label>
      <label className="block text-sm">Provider <input className="mt-1 w-full rounded border border-line bg-ink px-3 py-2" value={form.provider} onChange={(event) => setForm({ ...form, provider: event.target.value })} /></label>
      <label className="block text-sm">Defender <input className="mt-1 w-full rounded border border-line bg-ink px-3 py-2" value={form.defender_mode} onChange={(event) => setForm({ ...form, defender_mode: event.target.value })} /></label>
      <label className="block text-sm">Conditions <input className="mt-1 w-full rounded border border-line bg-ink px-3 py-2" value={form.conditions} onChange={(event) => setForm({ ...form, conditions: event.target.value })} /></label>
      <button onClick={submit} className="rounded bg-lime px-4 py-2 text-sm text-ink">Run PKG-Risk</button>
      {job && <p className="font-mono text-sm text-tide">{job}: {status}</p>}
    </div>
  );
}

function Comparison() {
  const [experiments, setExperiments] = useState<{ experiment_id: string }[]>([]);
  const [id, setId] = useState("");
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  useEffect(() => {
    api<{ experiment_id: string }[]>("/api/experiments").then((rows) => {
      setExperiments(rows);
      if (rows[0]) setId(rows[0].experiment_id);
    });
  }, []);
  useEffect(() => {
    if (!id) return;
    api<Record<string, unknown>>(`/api/experiments/${id}/compare`).then(setData);
  }, [id]);
  const comparisons = ((data?.primary as { comparisons?: Record<string, unknown>[] } | undefined)?.comparisons) || [];
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Research comparison</h1>
      <Select value={id} onChange={setId} options={experiments.map((item) => item.experiment_id)} />
      {comparisons.length === 0 ? <p className="text-sm text-moss">No paired comparison is stored for this experiment.</p> : comparisons.map((item) => (
        <Panel key={`${item.a}-${item.b}`} title={`${item.a} → ${item.b}`}>
          <p className="mb-2 text-sm text-moss">Claim level {String(item.claim_level)}. Pairs {String(item.n_pairs)}.</p>
          <MetricTable metrics={(item.metrics as Record<string, Record<string, unknown>>) || {}} />
        </Panel>
      ))}
    </div>
  );
}

function Inspector() {
  const [runs, setRuns] = useState<Record<string, unknown>[]>([]);
  const [run, setRun] = useState("");
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null);
  useEffect(() => {
    api<Record<string, unknown>>("/api/overview").then((data) => {
      const rows = (data.runs as Record<string, unknown>[]) || [];
      setRuns(rows);
      if (rows[0]) setRun(String(rows[0].run_id));
    });
  }, []);
  useEffect(() => {
    if (!run) return;
    api<Record<string, unknown>>(`/api/runs/${run}`).then(setDetail);
  }, [run]);
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Simulation inspector</h1>
      <Select value={run} onChange={setRun} options={runs.map((item) => String(item.run_id))} />
      {detail && (
        <div className="grid grid-cols-2 gap-4">
          <Panel title="Defender input"><pre className="max-h-80 overflow-auto font-mono text-xs">{JSON.stringify(detail.defender_input, null, 2)}</pre></Panel>
          <Panel title="Scenario visible to the generator"><pre className="max-h-80 overflow-auto font-mono text-xs">{JSON.stringify(detail.scenario, null, 2)}</pre></Panel>
          <Panel title="Verification"><pre className="max-h-80 overflow-auto font-mono text-xs">{JSON.stringify(detail.verification, null, 2)}</pre></Panel>
          <Panel title="Verifier binding (not shown to agents)"><pre className="max-h-80 overflow-auto font-mono text-xs">{JSON.stringify(detail.verifier_binding, null, 2)}</pre></Panel>
          <Panel title="Recipient simulation"><pre className="max-h-64 overflow-auto font-mono text-xs">{JSON.stringify(detail.recipient, null, 2)}</pre></Panel>
          <Panel title="Risk notes"><pre className="max-h-64 overflow-auto font-mono text-xs">{JSON.stringify(detail.risk, null, 2)}</pre></Panel>
        </div>
      )}
    </div>
  );
}

function Findings() {
  const [rows, setRows] = useState<Record<string, unknown>[]>([]);
  useEffect(() => {
    api<Record<string, unknown>[]>("/api/findings").then(setRows);
  }, []);
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Security findings</h1>
      {rows.length === 0 ? <p className="text-sm text-moss">No policy violations have been recorded.</p> : rows.map((row) => {
        const payload = (row.payload as Record<string, unknown>) || {};
        return (
          <Panel key={String(row.finding_id)} title={`${row.severity} · ${row.policy}`}>
            <p className="text-sm">{String(payload.title || "")}</p>
            <p className="mt-2 font-mono text-xs text-moss">Run {String(row.run_id)} · {String(payload.condition)} · {String(payload.defender_mode)} · seed {String(payload.seed)}</p>
            <p className="mt-2 text-xs text-tide">Claim level: {String(payload.claim_level)}</p>
          </Panel>
        );
      })}
    </div>
  );
}

function Mitigation() {
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true);
    setError(null);
    try {
      const payload = await api<Record<string, unknown>>("/api/counterfactuals", {
        method: "POST",
        body: JSON.stringify({
          factor: "mitigation",
          value: "require_independent_verification",
          personas: 10,
          seed: 11,
          trials: 2,
          provider: "mock",
          defender_mode: "familiarity_biased",
          conditions: ["graph"],
          threat: "unauthorized_calendar",
        }),
      });
      setResult(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Mitigation testing</h1>
      <p className="max-w-3xl text-sm text-moss">This reruns the graph condition with and without the independent-verification guardrail, holding the world, seed, identities, model, and defender policy fixed.</p>
      <button onClick={run} disabled={busy} className="rounded bg-lime px-4 py-2 text-sm text-ink">{busy ? "Running…" : "Run matched mitigation"}</button>
      {error && <ErrorText message={error} />}
      {result && <Panel title="Matched result"><pre className="max-h-[540px] overflow-auto font-mono text-xs">{JSON.stringify(result, null, 2)}</pre></Panel>}
    </div>
  );
}

function Reports() {
  const [experiments, setExperiments] = useState<{ experiment_id: string; label?: string }[]>([]);
  useEffect(() => {
    api<{ experiment_id: string; label?: string }[]>("/api/experiments").then(setExperiments);
  }, []);
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Reporting</h1>
      {experiments.length === 0 ? <p className="text-sm text-moss">Reports are created from stored experiments.</p> : experiments.map((item) => (
        <div key={item.experiment_id} className="rounded border border-line p-4">
          <div className="font-mono text-sm">{item.experiment_id}</div>
          <p className="mt-1 text-xs text-moss">{item.label}</p>
          <div className="mt-3 flex gap-4 text-sm text-tide">
            <a href={`/api/experiments/${item.experiment_id}/report.md`}>Markdown</a>
            <a href={`/api/experiments/${item.experiment_id}/report.json`}>JSON</a>
            <a href={`/api/experiments/${item.experiment_id}/report.html`}>HTML</a>
          </div>
        </div>
      ))}
    </div>
  );
}

function Cy({ elements, empty }: { elements: { nodes: unknown[]; edges: unknown[] }; empty: string }) {
  const signature = useMemo(() => JSON.stringify(elements), [elements]);
  if (!elements.nodes.length) return <p className="text-sm text-moss">{empty}</p>;
  return <CyCanvas signature={signature} elements={elements} />;
}

function CyCanvas({ elements }: { signature: string; elements: { nodes: unknown[]; edges: unknown[] } }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      elements: [...(elements.nodes as cytoscape.ElementDefinition[]), ...(elements.edges as cytoscape.ElementDefinition[])],
      style: [
        { selector: "node", style: { label: "data(label)", color: "#e7ecdf", "background-color": "#2f4428", "font-size": 10, "text-wrap": "wrap", "text-max-width": "90px" } },
        { selector: "edge", style: { label: "data(label)", color: "#9aa892", "line-color": "#8ec8c3", "font-size": 8, "curve-style": "bezier", "target-arrow-shape": "triangle", "target-arrow-color": "#8ec8c3", width: 1 } },
      ],
      layout: { name: "cose", animate: false },
    });
    return () => {
      cy.destroy();
    };
  }, [elements]);
  return <div ref={ref} className="h-[560px] rounded-lg border border-line bg-[#121810]" />;
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-line bg-panel p-4">
      <div className="font-mono text-xs uppercase tracking-widest text-moss">{label}</div>
      <div className="mt-2 text-3xl text-lime">{value}</div>
    </div>
  );
}

function RunTable({ runs }: { runs: Record<string, unknown>[] }) {
  return (
    <table className="w-full text-left text-sm">
      <thead className="text-xs uppercase text-moss"><tr><th>Run</th><th>Condition</th><th>Status</th><th>Defender</th></tr></thead>
      <tbody>
        {runs.map((run) => (
          <tr key={String(run.run_id)} className="border-t border-line">
            <td className="py-2 font-mono text-xs">{String(run.run_id)}</td>
            <td>{String(run.condition)}</td>
            <td>{String(run.status)}</td>
            <td>{String(run.defender_mode)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SeverityList({ rows }: { rows: Record<string, unknown>[] }) {
  return (
    <ul className="space-y-2 text-sm">
      {rows.map((row) => (
        <li key={String(row.severity)} className="flex justify-between border-b border-line py-1">
          <span>{String(row.severity)}</span>
          <span className="font-mono text-lime">{String(row.n)}</span>
        </li>
      ))}
    </ul>
  );
}

function MetricTable({ metrics }: { metrics: Record<string, Record<string, unknown>> }) {
  return (
    <table className="w-full text-left text-sm">
      <thead className="text-xs uppercase text-moss"><tr><th>Metric</th><th>Mean delta</th><th>95% interval</th><th>Adjusted p</th></tr></thead>
      <tbody>
        {Object.entries(metrics).map(([name, body]) => {
          const delta = (body.delta as Record<string, number | null>) || {};
          return (
            <tr key={name} className="border-t border-line">
              <td className="py-2 font-mono text-xs">{name}</td>
              <td>{fmt(delta.mean)}</td>
              <td>{fmt(delta.low)} – {fmt(delta.high)}</td>
              <td>{fmt(body.p_bonferroni as number | null)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function Select({ value, onChange, options }: { value: string; onChange: (value: string) => void; options: string[] }) {
  return (
    <select value={value} onChange={(event) => onChange(event.target.value)} className="rounded border border-line bg-ink px-3 py-2 text-sm">
      {options.map((option) => <option key={option || "blank"} value={option}>{option || "any"}</option>)}
    </select>
  );
}

function ErrorText({ message }: { message: string }) {
  return <p className="text-sm text-clay">{message}</p>;
}

function fmt(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "n/a";
  return Number(value).toFixed(3);
}
