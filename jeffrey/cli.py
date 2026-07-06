from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from jeffrey.investigation import investigate_build_log
from jeffrey.reporter import print_report, save_markdown_report

app = typer.Typer(help="Investigate failed CI/CD builds from local logs.")


@app.callback()
def callback() -> None:
    """Jeffrey investigates failed CI/CD builds."""


@app.command()
def scan(
    build_log: Annotated[
        Path,
        typer.Option(
            "--build-log",
            "-l",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Path to a local Jenkins build log.",
        ),
    ],
    show_all: Annotated[
        bool,
        typer.Option(
            "--show-all",
            help="Show full details for every detected finding.",
            hidden=True,
        ),
    ] = False,
    last_lines: Annotated[
        int,
        typer.Option(
            "--last-lines",
            min=1,
            help="Number of trailing lines to show when no known pattern is found.",
            hidden=True,
        ),
    ] = 80,
    no_k8s: Annotated[
        bool,
        typer.Option(
            "--no-k8s",
            help="Disable automatic Kubernetes investigation.",
        ),
    ] = False,
    kube_timeout: Annotated[
        int,
        typer.Option(
            "--kube-timeout",
            min=1,
            help="Timeout for each kubectl command in seconds.",
            hidden=True,
        ),
    ] = 15,
    show_commands: Annotated[
        bool,
        typer.Option(
            "--show-commands",
            help="Print kubectl commands Jeffrey is running.",
        ),
    ] = False,
    debug: Annotated[
        bool,
        typer.Option(
            "--debug",
            help="Print every investigation step.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            help="Print the report plus a compact investigation summary.",
        ),
    ] = False,
    save_report: Annotated[
        Path | None,
        typer.Option(
            "--save-report",
            file_okay=True,
            dir_okay=False,
            writable=True,
            help="Save a Markdown investigation report.",
        ),
    ] = None,
) -> None:
    """Scan a Jenkins build log and explain the likely root cause."""
    console = Console()
    result = investigate_build_log(
        build_log,
        last_lines=last_lines,
        collect_k8s=not no_k8s,
        kube_timeout=kube_timeout,
        show_commands=show_commands,
        debug=debug,
        console=console,
    )
    print_report(result, console=console, show_all=show_all, verbose=verbose)
    if save_report is not None:
        save_markdown_report(result, save_report)
        console.print(f"[green]✓[/green] Markdown report saved: {save_report}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
