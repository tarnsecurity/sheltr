"""
sheltr/cli.py

The CLI interface — what the user actually runs.
Uses `click`, the best Python CLI library.

Run with:
    sheltr scan ./myproject
    sheltr scan .env
    sheltr scan . --exclude tests/fixtures --format json
"""

import json
import sys

import click

from .scanner import scan
from .patterns import HIGH, MEDIUM, LOW

# ---------------------------------------------------------------------------
# Colors mapped to severity
# ---------------------------------------------------------------------------

SEVERITY_COLOR = {
    HIGH:   "red",
    MEDIUM: "yellow",
    LOW:    "cyan",
}

SEVERITY_ICON = {
    HIGH:   "●",
    MEDIUM: "◆",
    LOW:    "○",
}


def redact(text: str, keep: int = 6) -> str:
    """Show only the first `keep` chars of a secret, mask the rest."""
    if len(text) <= keep:
        return "*" * len(text)
    return text[:keep] + "*" * min(len(text) - keep, 20)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("0.1.0", prog_name="sheltr")
def cli():
    """sheltr — secret scanner for your codebase.

    Finds hardcoded API keys, tokens, passwords, and credentials
    before they end up somewhere they shouldn't.
    """
    pass


@cli.command("scan")
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option("--exclude", "-e", multiple=True, help="Path prefixes to exclude (repeatable)")
@click.option("--format", "-f", "output_format", default="pretty",
              type=click.Choice(["pretty", "json"]), help="Output format")
@click.option("--severity", "-s", default="low",
              type=click.Choice(["high", "medium", "low"]),
              help="Minimum severity to report")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output")
def scan_cmd(target, exclude, output_format, severity, no_color):
    """Scan TARGET for hardcoded secrets.

    TARGET can be a file or directory. Defaults to current directory.

    Examples:

    \b
        sheltr scan .
        sheltr scan ./src
        sheltr scan .env
        sheltr scan . --exclude tests --severity high
        sheltr scan . --format json > results.json
    """
    severity_rank = {LOW: 0, MEDIUM: 1, HIGH: 2}
    min_rank = severity_rank[severity]

    # Run the scan
    if output_format == "pretty":
        click.echo(click.style(f"\n  sheltr ", fg="bright_white", bold=True) +
                   click.style("scanning ", fg="bright_black") +
                   click.style(target, fg="white") + "\n")

    result = scan(target, exclude=list(exclude))

    # Filter by severity
    findings = [f for f in result.findings if severity_rank[f.severity] >= min_rank]

    # --- JSON output ---
    if output_format == "json":
        output = {
            "summary": {
                "scanned_files": result.scanned_files,
                "skipped_files": result.skipped_files,
                "total_findings": len(findings),
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
            },
            "findings": [
                {
                    "pattern": f.pattern_name,
                    "severity": f.severity,
                    "description": f.description,
                    "file": f.file_path,
                    "line": f.line_number,
                    "match": redact(f.match),
                }
                for f in findings
            ]
        }
        click.echo(json.dumps(output, indent=2))
        sys.exit(1 if findings else 0)

    # --- Pretty output ---
    if not findings:
        click.echo(click.style("  ✓ ", fg="green") +
                   click.style("No secrets found. ", fg="white") +
                   click.style(f"({result.scanned_files} files scanned)\n", fg="bright_black"))
        sys.exit(0)

    # Group findings by file for cleaner output
    by_file: dict[str, list] = {}
    for finding in findings:
        by_file.setdefault(finding.file_path, []).append(finding)

    for filepath, file_findings in by_file.items():
        click.echo(click.style(f"  {filepath}", fg="white", bold=True))

        for f in file_findings:
            color = SEVERITY_COLOR[f.severity] if not no_color else None
            icon = SEVERITY_ICON[f.severity]

            severity_badge = click.style(f" {f.severity.upper()} ", fg=color, bold=True)
            line_info = click.style(f"line {f.line_number}", fg="bright_black")
            pattern = click.style(f.pattern_name, fg="white")
            redacted = click.style(redact(f.match), fg="bright_black")

            click.echo(f"    {icon} {severity_badge} {line_info}  {pattern}")
            click.echo(click.style(f"      match: {redacted}", fg="bright_black"))

        click.echo()

    # Summary footer
    total = len(findings)
    high = sum(1 for f in findings if f.severity == HIGH)
    medium = sum(1 for f in findings if f.severity == MEDIUM)
    low = sum(1 for f in findings if f.severity == LOW)

    click.echo(click.style("  ─" * 30, fg="bright_black"))
    click.echo(
        click.style(f"\n  {total} finding{'s' if total != 1 else ''} ", fg="white") +
        click.style(f"in {result.scanned_files} files  ", fg="bright_black") +
        click.style(f"{high} high  ", fg="red") +
        click.style(f"{medium} medium  ", fg="yellow") +
        click.style(f"{low} low\n", fg="cyan")
    )

    # Exit 1 if findings found — important for CI pipelines
    sys.exit(1)


def main():
    cli()
