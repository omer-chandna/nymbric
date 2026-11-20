"""Nymbric command line. The selected provider is never replaced silently."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from nymbric import __version__
from nymbric.core.config import load_models
from nymbric.core.errors import ConfigError, NymbricError, ProviderUnavailable
from nymbric.environments.sandbox import isolation_status
from nymbric.experiments.campaign import execute_campaign
from nymbric.experiments.counterfactual import run_counterfactual
from nymbric.experiments.pkg_risk import execute_pkg_risk
from nymbric.experiments.security_suite import TESTS, run_security_suite
from nymbric.experiments.spear_phish import execute_spear_phish
from nymbric.integrations.adapters import integration_status
from nymbric.mitigations.policies import list_controls
from nymbric.models.router import build_provider
from nymbric.reporting.export import html_report, markdown_report
from nymbric.storage.db import Database
from nymbric.synthetic.world import generate_world

app = typer.Typer(no_args_is_help=True, help="Adversarial security testing for context-aware agents.")
models_app = typer.Typer(no_args_is_help=True)
graph_app = typer.Typer(no_args_is_help=True)
web_app = typer.Typer(no_args_is_help=True)
agents_app = typer.Typer(no_args_is_help=True)
tests_app = typer.Typer(no_args_is_help=True)
run_app = typer.Typer(no_args_is_help=True)
findings_app = typer.Typer(no_args_is_help=True)
results_app = typer.Typer(no_args_is_help=True)
app.add_typer(models_app, name="models")
app.add_typer(graph_app, name="graph")
app.add_typer(web_app, name="web")
app.add_typer(agents_app, name="agents")
app.add_typer(tests_app, name="tests")
app.add_typer(run_app, name="run")
app.add_typer(findings_app, name="findings")
app.add_typer(results_app, name="results")

ROLES = (
    "web_research",
    "graph_research",
    "scenario",
    "defender",
    "evaluator",
    "risk_analysis",
    "recipient",
)


def _db(ctx: typer.Context) -> Database:
    home = Path(ctx.obj["home"])
    home.mkdir(parents=True, exist_ok=True)
    return Database(home / "nymbric.sqlite")


@app.callback()
def main(
    ctx: typer.Context,
    home: Path = typer.Option(Path(".nymbric"), help="Local data directory."),
) -> None:
    ctx.obj = {"home": home}


@app.command()
def init(ctx: typer.Context) -> None:
    """Create the local data directory and print the mock quickstart."""
    home = Path(ctx.obj["home"])
    home.mkdir(parents=True, exist_ok=True)
    (home / "traces").mkdir(exist_ok=True)
    Path("results").mkdir(exist_ok=True)
    typer.echo(f"Nymbric {__version__} data directory: {home.resolve()}")
    typer.echo("Next: nymbric models check --provider mock")
    typer.echo("Then: nymbric run pkg-risk --provider mock --conditions all --trials 2")
    typer.echo(json.dumps({"isolation": isolation_status(), "integrations": integration_status()}, indent=2))


@models_app.command("list")
def models_list() -> None:
    """Show the validated model assignment. Missing env vars stay empty rather than switching provider."""
    try:
        config = load_models()
    except ConfigError as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=2) from exc
    payload = {"default_provider": config.default_provider, "default_model": config.default_model, "agents": {}}
    for role in ROLES:
        agent = config.for_agent(role)
        payload["agents"][role] = agent.model_dump()
    typer.echo(json.dumps(payload, indent=2))


@models_app.command("check")
def models_check(
    provider: str = typer.Option(..., help="mock, ollama, openai, openai_compatible, or anthropic."),
    model: Optional[str] = typer.Option(None),
    base_url: Optional[str] = typer.Option(None),
    probe: bool = typer.Option(False, help="Send one structured-output probe. Opt-in; not used in CI."),
) -> None:
    from nymbric.core.config import AgentModelConfig

    chosen = model or ("mock-deterministic" if provider == "mock" else load_models().default_model)
    try:
        built = build_provider(AgentModelConfig(provider=provider, model=chosen, base_url=base_url))
        status = built.check(probe=probe)
    except (ConfigError, ProviderUnavailable) as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=2) from exc
    typer.echo(status.model_dump_json(indent=2))
    if not status.ok:
        raise typer.Exit(code=2)


@graph_app.command("generate")
def graph_generate(
    ctx: typer.Context,
    personas: int = typer.Option(24, "--personas"),
    seed: int = typer.Option(1, "--seed"),
    public_ratio: float = typer.Option(0.75),
    density: float = typer.Option(0.2),
    inference_accuracy: float = typer.Option(0.55),
) -> None:
    """Generate one fictional world, its observed graph, and the derived public web."""
    bundle = generate_world(
        personas=personas,
        seed=seed,
        public_ratio=public_ratio,
        density=density,
        inference_accuracy=inference_accuracy,
    )
    _db(ctx).persist_world(bundle)
    typer.echo(
        json.dumps(
            {
                "world_id": bundle["world_id"],
                "personas": bundle["persona_count"],
                "pages": len(bundle["pages"]),
                "relationships": len(bundle["relationships"]),
                "content_hash": bundle["content_hash"],
            },
            indent=2,
        )
    )


@web_app.command("generate")
def web_generate(ctx: typer.Context, from_graph: str = typer.Option("latest", "--from-graph")) -> None:
    """Confirm the public web that was derived from a stored world. It does not invent a second world."""
    db = _db(ctx)
    world_id = db.latest_world_id() if from_graph == "latest" else from_graph
    if not world_id:
        typer.echo("No world is stored. Run `nymbric graph generate` first.")
        raise typer.Exit(code=1)
    world = db.world_row(world_id)
    count = db.query("SELECT COUNT(*) AS n FROM pages WHERE world_id = ?", (world_id,))[0]["n"]
    if count == 0:
        typer.echo("The stored world has no pages. Generate the world again so the web stays tied to the same seed.")
        raise typer.Exit(code=1)
    typer.echo(json.dumps({"world_id": world_id, "pages": count, "content_hash": world["content_hash"]}, indent=2))


@agents_app.command("list")
def agents_list() -> None:
    typer.echo(
        json.dumps(
            {
                "orchestrator": "deterministic stage machine",
                "agents": list(ROLES),
                "note": "Specialists share the tool loop. Permissions are attached by the orchestrator.",
            },
            indent=2,
        )
    )


@tests_app.command("list")
def tests_list() -> None:
    typer.echo(json.dumps([{"id": item["id"], "primary": item["primary"]} for item in TESTS], indent=2))


@tests_app.command("run")
def tests_run(ctx: typer.Context) -> None:
    results = run_security_suite(_db(ctx))
    failed = [item["id"] for item in results if not item["compliant_passed"] or not item["noncompliant_primary_failed"]]
    typer.echo(json.dumps(results, indent=2))
    if failed:
        raise typer.Exit(code=1)


@run_app.command("pkg-risk")
def run_pkg_risk(
    ctx: typer.Context,
    provider: Optional[str] = typer.Option(None, help="Explicit provider. Omit to use configs/models.yaml."),
    model: Optional[str] = typer.Option(None),
    conditions: str = typer.Option("all", help="Comma-separated conditions, or all."),
    trials: int = typer.Option(2),
    personas: int = typer.Option(24),
    seed: int = typer.Option(1),
    defender: str = typer.Option("familiarity_biased", "--defender"),
    threat: str = typer.Option("unauthorized_calendar"),
    ablation: Optional[str] = typer.Option(None),
    mitigation: Optional[str] = typer.Option(None),
    world: Optional[str] = typer.Option(None),
    counterfactual: Optional[str] = typer.Option(None, help="mitigation:NAME or ablation:NAME"),
) -> None:
    """Run PKG-Risk. A failed provider check stops the run."""
    db = _db(ctx)
    home = Path(ctx.obj["home"])
    condition_list = [part.strip() for part in conditions.split(",") if part.strip()]
    try:
        if counterfactual:
            factor, _, value = counterfactual.partition(":")
            summary = run_counterfactual(
                db,
                factor=factor,
                value=value,
                base={
                    "provider": provider,
                    "model": model,
                    "conditions": condition_list,
                    "trials": trials,
                    "personas": personas,
                    "seed": seed,
                    "defender_mode": defender,
                    "threat": threat,
                    "world_id": world,
                    "jsonl_dir": home / "traces",
                    "include_evaluator": False,
                },
            )
        else:
            summary = execute_pkg_risk(
                db,
                provider=provider,
                model=model,
                conditions=condition_list,
                trials=trials,
                personas=personas,
                seed=seed,
                defender_mode=defender,
                threat=threat,
                ablation=ablation,
                mitigation=mitigation,
                world_id=world,
                jsonl_dir=home / "traces",
            )
    except (NymbricError, ProviderUnavailable, ValueError) as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=2) from exc
    out = Path("results")
    out.mkdir(exist_ok=True)
    target = out / f"{summary.get('experiment_id', summary.get('after_experiment', 'counterfactual'))}.json"
    target.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    typer.echo(json.dumps({"wrote": str(target), "experiment_id": summary.get("experiment_id") or summary.get("after_experiment")}, indent=2))


@run_app.command("spear-phish")
def run_spear_phish(
    ctx: typer.Context,
    provider: Optional[str] = typer.Option(None, help="Explicit provider. Omit to use configs/models.yaml."),
    model: Optional[str] = typer.Option(None),
    conditions: str = typer.Option("all", help="Comma-separated conditions, or all."),
    trials: int = typer.Option(2),
    personas: int = typer.Option(24),
    seed: int = typer.Option(1),
    target: str = typer.Option("context_sensitive", "--target", help="model, cautious, credulous, context_sensitive, or external."),
    threat: str = typer.Option("calendar_pretext_link", help="A PHISH_THREATS value, or 'all' to cycle them."),
    channel: str = typer.Option("email", help="email, direct_message, or calendar_invite."),
    ablation: Optional[str] = typer.Option(None),
    mitigation: Optional[str] = typer.Option(None, help="e.g. link_allowlisting, attachment_sandboxing, egress_filtering, require_independent_verification."),
    world: Optional[str] = typer.Option(None),
    external_cmd: Optional[str] = typer.Option(None, "--external-cmd", help="Command for target=external. The lure is passed as JSON on stdin; the action log is read from stdout."),
) -> None:
    """Run the spear-phish experiment. A failed provider check stops the run.

    Attack success is compared across information-access conditions with the
    target held fixed. Lures are inert and fictional.
    """
    db = _db(ctx)
    home = Path(ctx.obj["home"])
    condition_list = [part.strip() for part in conditions.split(",") if part.strip()]
    cmd = external_cmd.split() if external_cmd else None
    try:
        summary = execute_spear_phish(
            db,
            provider=provider,
            model=model,
            conditions=condition_list,
            trials=trials,
            personas=personas,
            seed=seed,
            target_mode=target,
            threat=threat,
            channel=channel,
            ablation=ablation,
            mitigation=mitigation,
            world_id=world,
            jsonl_dir=home / "traces",
            external_cmd=cmd,
        )
    except (NymbricError, ProviderUnavailable, ValueError) as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=2) from exc
    out = Path("results")
    out.mkdir(exist_ok=True)
    target_path = out / f"{summary['experiment_id']}.json"
    target_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    typer.echo(json.dumps({"wrote": str(target_path), "experiment_id": summary["experiment_id"]}, indent=2))


@run_app.command("campaign")
def run_campaign(
    ctx: typer.Context,
    entry: Optional[str] = typer.Option(None, "--entry", help="Entry persona id (e.g. p0000). Omit for the first persona."),
    goal: str = typer.Option("crown-jewel", "--goal", help="crown-jewel, compromise:<persona>, exfiltrate:<asset>, or nodes:<N>."),
    regime: str = typer.Option("both", "--regime", help="osint, enhanced, or both."),
    max_depth: int = typer.Option(3, "--max-depth"),
    max_nodes: int = typer.Option(12, "--max-nodes"),
    target: str = typer.Option("context_sensitive", "--target", help="Node defender: model, cautious, credulous, context_sensitive, or external."),
    mitigation: Optional[str] = typer.Option(None, "--mitigation", help="Node control, e.g. require_independent_verification, egress_filtering."),
    threat: str = typer.Option("calendar_pretext_link", help="A PHISH_THREATS value, or 'all'."),
    provider: Optional[str] = typer.Option(None, help="Explicit provider. Omit to use configs/models.yaml."),
    model: Optional[str] = typer.Option(None),
    personas: int = typer.Option(16, "--personas"),
    seed: int = typer.Option(1, "--seed"),
    world: Optional[str] = typer.Option(None),
) -> None:
    """Run the campaign emulator: a goal-directed, multi-stage kill chain over the
    synthetic world, comparing OSINT-only against breach-enhanced reach.

    Every stage is modelled on fictional data and is inert. Nothing touches a real
    device, inbox, account, or person.
    """
    db = _db(ctx)
    try:
        summary = execute_campaign(
            db,
            personas=personas,
            seed=seed,
            entry=entry,
            goal=goal,
            regime=regime,
            max_depth=max_depth,
            max_nodes=max_nodes,
            target_mode=target,
            threat=threat,
            mitigation=mitigation,
            provider=provider,
            model=model,
            world_id=world,
        )
    except (NymbricError, ProviderUnavailable, ValueError) as exc:
        typer.echo(str(exc))
        raise typer.Exit(code=2) from exc
    out = Path("results")
    out.mkdir(exist_ok=True)
    target_path = out / f"{summary['experiment_id']}.json"
    target_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    comparison = summary.get("comparison") or {}
    typer.echo(
        json.dumps(
            {
                "wrote": str(target_path),
                "experiment_id": summary["experiment_id"],
                "entry": f"{summary['entry_id']} ({summary['entry_name']})",
                "goal": summary["goal"]["description"],
                "headline": comparison.get("headline"),
            },
            indent=2,
        )
    )


@findings_app.command("list")
def findings_list(ctx: typer.Context, limit: int = typer.Option(50)) -> None:
    rows = _db(ctx).query(
        "SELECT finding_id, run_id, severity, policy, payload_json FROM findings ORDER BY rowid DESC LIMIT ?",
        (limit,),
    )
    typer.echo(json.dumps([{**dict(row), "payload": json.loads(row["payload_json"])} for row in rows], indent=2, default=str))


@results_app.command("compare")
def results_compare(ctx: typer.Context, run_a: str = typer.Option(..., "--run-a"), run_b: str = typer.Option(..., "--run-b")) -> None:
    db = _db(ctx)
    left = _load_run_or_experiment(db, run_a)
    right = _load_run_or_experiment(db, run_b)
    from nymbric.experiments.compare import compare_two_groups

    typer.echo(json.dumps(compare_two_groups(left, right, run_a, run_b), indent=2))


@app.command()
def report(ctx: typer.Context, experiment_id: str, fmt: str = typer.Option("md", "--format")) -> None:
    row = _db(ctx).query("SELECT summary_json FROM experiments WHERE experiment_id = ?", (experiment_id,))
    if not row:
        typer.echo(f"No experiment {experiment_id}.")
        raise typer.Exit(code=1)
    summary = json.loads(row[0]["summary_json"])
    if fmt == "json":
        typer.echo(json.dumps(summary, indent=2))
    elif fmt == "html":
        typer.echo(html_report(summary))
    else:
        typer.echo(markdown_report(summary))


@app.command()
def dashboard(ctx: typer.Context, host: str = typer.Option("127.0.0.1"), port: int = typer.Option(8000)) -> None:
    """Serve the API and, when built, the dashboard."""
    import os

    import uvicorn

    from nymbric.api.app import create_app

    os.environ["NYMBRIC_HOME"] = str(Path(ctx.obj["home"]))
    uvicorn.run(create_app(Path(ctx.obj["home"])), host=host, port=port)


def _load_run_or_experiment(db: Database, identifier: str) -> list[dict]:
    experiment = db.query("SELECT summary_json FROM experiments WHERE experiment_id = ?", (identifier,))
    if experiment:
        return json.loads(experiment[0]["summary_json"]).get("runs") or []
    rows = db.query("SELECT * FROM runs WHERE run_id = ?", (identifier,))
    if not rows:
        typer.echo(f"No run or experiment named {identifier}.")
        raise typer.Exit(code=1)
    row = dict(rows[0])
    row["metrics"] = json.loads(row.pop("metrics_json"))
    return [row]


@app.command("controls")
def controls() -> None:
    typer.echo(json.dumps(list_controls(), indent=2))
