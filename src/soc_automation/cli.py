"""soc-triage command-line interface.

    soc-triage run <alert.json> [--tickets DIR] [--json]
    soc-triage run <dir-of-alerts>/ ...
    soc-triage version

Exit codes: 0 = ran ok, 1 = an alert escalated (useful as a CI/pager signal),
2 = usage/IO error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from soc_automation import __version__
from soc_automation.models import Action, Alert, PipelineResult
from soc_automation.pipeline import Pipeline

app = typer.Typer(
    add_completion=False,
    help="Automated alert enrichment, triage scoring, and response on top of Wazuh.",
    no_args_is_help=True,
)

AlertArg = Annotated[Path, typer.Argument(help="A Wazuh alert JSON file or a directory of them.")]
TicketsOpt = Annotated[
    Path | None, typer.Option("--tickets", help="Directory to write incident tickets into.")
]
JsonOpt = Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON.")]


def _load_alerts(path: Path) -> list[tuple[Path, Alert]]:
    files = [path] if path.is_file() else sorted(path.glob("*.json"))
    alerts: list[tuple[Path, Alert]] = []
    for f in files:
        doc = json.loads(f.read_text(encoding="utf-8"))
        alerts.append((f, Alert.from_wazuh(doc)))
    return alerts


@app.command()
def run(alert: AlertArg, tickets: TicketsOpt = None, json_out: JsonOpt = False) -> None:
    """Run the enrich -> score -> respond pipeline over one or more alerts."""
    if not alert.exists():
        typer.secho(f"error: {alert} does not exist", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    try:
        loaded = _load_alerts(alert)
    except (json.JSONDecodeError, OSError) as exc:
        typer.secho(f"error: could not read alert(s): {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    if not loaded:
        typer.secho(f"no alert JSON files found under {alert}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(2)

    pipeline = Pipeline(tickets_dir=tickets)
    results = [pipeline.run(a) for _, a in loaded]

    if json_out:
        typer.echo(json.dumps([_result_dict(r) for r in results], indent=2))
    else:
        for r in results:
            _print_result(r)

    if any(r.verdict.action is Action.ESCALATE for r in results):
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Print the version."""
    typer.echo(f"soc-automation {__version__}")


_ACTION_COLOUR = {
    Action.ESCALATE: typer.colors.RED,
    Action.ANALYST_REVIEW: typer.colors.YELLOW,
    Action.AUTO_CLOSE: typer.colors.GREEN,
}


def _print_result(r: PipelineResult) -> None:
    colour = _ACTION_COLOUR[r.verdict.action]
    typer.secho(
        f"[{r.verdict.action.value.upper()}] risk {r.verdict.risk_score}/100 "
        f"- {r.alert.description} (rule {r.alert.rule_id})",
        fg=colour,
        bold=True,
    )
    for ioc in r.iocs:
        matches = [e for e in r.enrichments if e.ioc == ioc]
        for e in matches:
            tag = "malicious" if e.malicious else ("error" if e.error else "context")
            typer.echo(f"    {ioc}  [{e.source}] {e.summary} ({tag})")
    if r.response.ticket_path:
        typer.echo(f"    ticket: {r.response.ticket_path}")
    for step in r.response.containment:
        typer.echo(f"    {step}")
    typer.echo("")


def _result_dict(r: PipelineResult) -> dict[str, object]:
    return {
        "alert_id": r.alert.id,
        "rule_id": r.alert.rule_id,
        "description": r.alert.description,
        "risk_score": r.verdict.risk_score,
        "action": r.verdict.action.value,
        "reasons": r.verdict.reasons,
        "iocs": [str(i) for i in r.iocs],
        "enrichments": [
            {
                "source": e.source,
                "ioc": str(e.ioc),
                "malicious": e.malicious,
                "score": e.score,
                "summary": e.summary,
                "error": e.error,
            }
            for e in r.enrichments
        ],
        "ticket": r.response.ticket_path,
        "containment": r.response.containment,
    }


if __name__ == "__main__":  # pragma: no cover
    app()
