#!/usr/bin/env python3
"""
DepRadar CLI — Python dependency risk scanner.

Usage:
  depradar scan requirements.txt
  depradar scan requirements.txt --fail-on high
  depradar scan requirements.txt --fail-on critical --api http://localhost:8000
  depradar github https://github.com/owner/repo
  depradar github https://github.com/owner/repo --ref main --path requirements.txt
  depradar package requests
  depradar package requests --version 2.28.0
"""

import sys
import json
import httpx
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

app = typer.Typer(
    name="depradar",
    help="Python dependency risk scanner — checks PyPI and CVE databases.",
    add_completion=False,
)
console = Console()

RISK_LEVELS = ["ok", "low", "medium", "high", "critical"]
RISK_COLORS = {
    "ok":       "green",
    "low":      "cyan",
    "medium":   "yellow",
    "high":     "dark_orange",
    "critical": "red",
}
RISK_EMOJI = {
    "ok": "✓",
    "low": "↑",
    "medium": "⚠",
    "high": "✖",
    "critical": "☠",
}

DEFAULT_API = "http://localhost:8000"


def _risk_color(level: str) -> str:
    return RISK_COLORS.get(level, "white")


def _score_color(score: float) -> str:
    if score >= 70: return "red"
    if score >= 45: return "dark_orange"
    if score >= 20: return "yellow"
    if score > 0:   return "cyan"
    return "green"


def _print_report(report: dict, fail_on: Optional[str] = None) -> bool:
    """
    Pretty-print a scan report. Returns True if the scan should fail (exit 1).
    """
    score = report.get("risk_score") or 0
    score_color = _score_color(score)

    source_label = report.get("source", "manual")
    if report.get("github_repo"):
        source_label = f"github:{report['github_repo']}"

    # Header panel
    header = Text()
    header.append("DepRadar Scan Report\n", style="bold white")
    header.append(f"Scan ID : ", style="dim"); header.append(f"{report['scan_id']}\n", style="white")
    header.append(f"Source  : ", style="dim"); header.append(f"{source_label}\n", style="white")
    header.append(f"Packages: ", style="dim"); header.append(f"{report['package_count']}\n", style="white")
    header.append(f"Score   : ", style="dim")
    header.append(f"{score:.0f}/100", style=f"bold {score_color}")
    console.print(Panel(header, border_style="dim white", padding=(0, 2)))

    # Summary row
    console.print(
        f"  [cyan]↑ Outdated[/cyan] {report['outdated_count']}   "
        f"[yellow]⚠ Abandoned[/yellow] {report['abandoned_count']}   "
        f"[dark_orange]✖ Deprecated[/dark_orange] {report['deprecated_count']}   "
        f"[red]☠ Vulnerable[/red] {report['vulnerable_count']}"
    )
    console.print()

    # Package table
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold dim",
        padding=(0, 1),
    )
    table.add_column("Package", style="white", min_width=20)
    table.add_column("Risk", min_width=10)
    table.add_column("Pinned", style="dim", min_width=10)
    table.add_column("Latest", style="dim", min_width=10)
    table.add_column("Flags", min_width=20)
    table.add_column("CVEs", justify="right", min_width=5)

    packages = report.get("packages", [])
    has_issues = False

    for pkg in packages:
        rl = pkg.get("risk_level", "ok")
        color = _risk_color(rl)
        emoji = RISK_EMOJI.get(rl, "")

        flags = []
        if pkg.get("is_outdated"):    flags.append("[cyan]outdated[/cyan]")
        if pkg.get("is_abandoned"):   flags.append("[yellow]abandoned[/yellow]")
        if pkg.get("is_deprecated"):  flags.append("[dark_orange]deprecated[/dark_orange]")
        if pkg.get("is_vulnerable"):  flags.append("[red]CVEs[/red]")

        cve_str = str(pkg.get("cve_count", 0)) if pkg.get("cve_count", 0) > 0 else "—"
        cve_style = "red" if pkg.get("cve_count", 0) > 0 else "dim"

        table.add_row(
            pkg.get("name", ""),
            f"[{color}]{emoji} {rl.upper()}[/{color}]",
            pkg.get("pinned_version") or "—",
            pkg.get("latest_version") or "—",
            " ".join(flags) if flags else "[dim]—[/dim]",
            f"[{cve_style}]{cve_str}[/{cve_style}]",
        )

        if rl != "ok":
            has_issues = True

        # Print CVE details inline for vulnerable packages
        if pkg.get("cves"):
            for cve in pkg["cves"]:
                sev = cve.get("severity") or "unknown"
                sev_color = _risk_color(sev)
                console.print(
                    f"    [dim]└[/dim] [{sev_color}]{cve.get('id','?')}[/{sev_color}] "
                    f"[dim]{(cve.get('summary') or '')[:80]}[/dim]"
                )

    console.print(table)

    # --fail-on logic
    if fail_on and fail_on in RISK_LEVELS:
        fail_threshold_idx = RISK_LEVELS.index(fail_on)
        worst_pkg = max(
            packages,
            key=lambda p: RISK_LEVELS.index(p.get("risk_level", "ok")),
            default=None,
        )
        if worst_pkg:
            worst_idx = RISK_LEVELS.index(worst_pkg.get("risk_level", "ok"))
            if worst_idx >= fail_threshold_idx:
                console.print(
                    f"[red bold]✖ FAILED[/red bold] — packages at or above "
                    f"[{_risk_color(fail_on)}]{fail_on.upper()}[/{_risk_color(fail_on)}] risk found. "
                    f"(--fail-on {fail_on})"
                )
                return True  # signal exit 1

    if not has_issues:
        console.print("[green]✓ All packages look healthy.[/green]")

    return False


def _post(api: str, path: str, payload: dict) -> dict:
    try:
        with httpx.Client(timeout=120.0) as client:
            r = client.post(f"{api.rstrip('/')}{path}", json=payload)
            if r.status_code == 422:
                detail = r.json().get("detail", r.text)
                console.print(f"[red]Error 422:[/red] {detail}")
                raise typer.Exit(1)
            r.raise_for_status()
            return r.json()
    except httpx.ConnectError:
        console.print(f"[red]Cannot connect to API at {api}[/red]\nIs the server running? (docker compose up)")
        raise typer.Exit(1)
    except httpx.HTTPStatusError as e:
        console.print(f"[red]HTTP {e.response.status_code}:[/red] {e.response.text[:200]}")
        raise typer.Exit(1)


def _get(api: str, path: str) -> dict:
    try:
        with httpx.Client(timeout=30.0) as client:
            r = client.get(f"{api.rstrip('/')}{path}")
            r.raise_for_status()
            return r.json()
    except httpx.ConnectError:
        console.print(f"[red]Cannot connect to API at {api}[/red]")
        raise typer.Exit(1)


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command()
def scan(
    requirements_file: Path = typer.Argument(..., help="Path to requirements.txt"),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if any package reaches this risk level or higher. "
             "Values: ok, low, medium, high, critical",
        metavar="LEVEL",
    ),
    api: str = typer.Option(DEFAULT_API, "--api", help="DepRadar API base URL"),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON instead of table"),
):
    """
    Scan a requirements.txt file for dependency risks.

    Examples:\n
      depradar scan requirements.txt\n
      depradar scan requirements.txt --fail-on high\n
      depradar scan requirements.txt --fail-on critical --json\n
    """
    if not requirements_file.exists():
        console.print(f"[red]File not found:[/red] {requirements_file}")
        raise typer.Exit(1)

    content = requirements_file.read_text()
    console.print(f"[dim]Scanning {requirements_file} via {api}...[/dim]")

    report = _post(api, "/scan/requirements", {"content": content})

    if output_json:
        console.print_json(json.dumps(report))
        raise typer.Exit(0)

    should_fail = _print_report(report, fail_on=fail_on)
    raise typer.Exit(1 if should_fail else 0)


@app.command()
def github(
    repo_url: str = typer.Argument(..., help="GitHub repository URL (e.g. https://github.com/owner/repo)"),
    ref: Optional[str] = typer.Option(None, "--ref", help="Branch, tag, or commit SHA"),
    path: str = typer.Option("requirements.txt", "--path", help="Path to requirements file in repo"),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on",
        help="Exit 1 if any package is at or above this risk level",
        metavar="LEVEL",
    ),
    api: str = typer.Option(DEFAULT_API, "--api", help="DepRadar API base URL"),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON"),
):
    """
    Scan dependencies from a public GitHub repository.

    Examples:\n
      depradar github https://github.com/psf/requests\n
      depradar github https://github.com/django/django --ref stable/4.2.x --path requirements/base.txt\n
      depradar github https://github.com/owner/repo --fail-on high\n
    """
    console.print(f"[dim]Fetching requirements from {repo_url}...[/dim]")

    payload = {"repo_url": repo_url, "requirements_path": path}
    if ref:
        payload["ref"] = ref

    report = _post(api, "/scan/github", payload)

    if output_json:
        console.print_json(json.dumps(report))
        raise typer.Exit(0)

    should_fail = _print_report(report, fail_on=fail_on)
    raise typer.Exit(1 if should_fail else 0)


@app.command()
def package(
    name: str = typer.Argument(..., help="PyPI package name"),
    version: Optional[str] = typer.Option(None, "--version", "-v", help="Pinned version for CVE matching"),
    api: str = typer.Option(DEFAULT_API, "--api", help="DepRadar API base URL"),
    output_json: bool = typer.Option(False, "--json", help="Output raw JSON"),
):
    """
    Look up risk data for a single package.

    Examples:\n
      depradar package requests\n
      depradar package requests --version 2.28.0\n
    """
    path = f"/package/{name}"
    if version:
        path += f"?version={version}"

    data = _get(api, path)

    if output_json:
        console.print_json(json.dumps(data))
        return

    rl_fields = []
    if data.get("is_abandoned"):   rl_fields.append("[yellow]abandoned[/yellow]")
    if data.get("is_deprecated"):  rl_fields.append("[dark_orange]deprecated[/dark_orange]")
    if data.get("cve_count", 0) > 0: rl_fields.append(f"[red]{data['cve_count']} CVE(s)[/red]")

    body = Text()
    body.append(f"{data['name']}", style="bold white")
    if data.get("latest_version"):
        body.append(f"  v{data['latest_version']}", style="dim")
    body.append("\n")
    if data.get("summary"):
        body.append(f"{data['summary']}\n", style="dim")

    body.append(f"\nStatus : ", style="dim")
    body.append(", ".join(rl_fields) if rl_fields else "OK", style="green" if not rl_fields else "white")

    if data.get("months_since_release"):
        body.append(f"\nLast release : {data['months_since_release']}mo ago", style="dim")
    if data.get("deprecation_note"):
        body.append(f"\nDeprecation  : {data['deprecation_note']}", style="dark_orange")

    console.print(Panel(body, title=f"[dim]{data['name']}[/dim]", border_style="dim"))

    if data.get("cves"):
        console.print("[dim]CVEs:[/dim]")
        for cve in data["cves"]:
            sev = cve.get("severity") or "?"
            color = _risk_color(sev)
            console.print(
                f"  [{color}]{cve.get('id','?')}[/{color}] ({sev}) — "
                f"[dim]{(cve.get('summary') or '')[:100]}[/dim]"
            )


@app.command()
def status(
    api: str = typer.Option(DEFAULT_API, "--api", help="DepRadar API base URL"),
):
    """Check API health status."""
    data = _get(api, "/health")
    for key, val in data.items():
        color = "green" if val in ("ok", True) or str(val).startswith("ok") else "red"
        console.print(f"  [dim]{key:<12}[/dim] [{color}]{val}[/{color}]")


if __name__ == "__main__":
    app()
