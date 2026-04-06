"""Command-line interface for PatchGenie."""

from __future__ import annotations

import sys

import click

from patchgenie.agent import PatchGenieAgent
from patchgenie.models import VulnerabilityInput


@click.command()
@click.option("--cve-id", required=True, help="CVE or SAST alert identifier (e.g. CVE-2021-44228).")
@click.option("--description", required=True, help="Vulnerability description from the advisory.")
@click.option("--language", default="", show_default=True, help="Affected programming language.")
@click.option(
    "--vulnerable-code",
    default="",
    show_default=True,
    help="Paste the vulnerable code snippet.",
)
@click.option(
    "--context",
    default="",
    show_default=True,
    help="Additional context (framework, version, …).",
)
@click.option("--model", default=None, help="Override the OpenAI model (default: gpt-4o).")
@click.option(
    "--output",
    type=click.Path(writable=True),
    default=None,
    help="Write JSON output to this file instead of stdout.",
)
def main(
    cve_id: str,
    description: str,
    language: str,
    vulnerable_code: str,
    context: str,
    model: str | None,
    output: str | None,
) -> None:
    """PatchGenie – generate a secure patch for a CVE or SAST alert."""
    vuln = VulnerabilityInput(
        cve_id=cve_id,
        description=description,
        language=language,
        vulnerable_code=vulnerable_code,
        additional_context=context,
    )

    try:
        agent = PatchGenieAgent(model=model)
        report = agent.analyse(vuln)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    result = report.model_dump_json(indent=2)

    if output:
        with open(output, "w", encoding="utf-8") as fh:  # noqa: PTH123
            fh.write(result)
        click.echo(f"Report written to {output}")
    else:
        click.echo(result)
