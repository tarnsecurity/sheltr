"""
sheltr/scanner.py

The core scanning engine. This is the heart of sheltr.

Key concepts you'll learn here:
- Walking a file tree with os.walk
- Reading files safely (handling binary files, encoding errors)
- Applying regex patterns line by line
- Building a clean result data structure
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator

from .patterns import PATTERNS

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Represents a single detected secret."""
    pattern_name: str
    severity: str
    description: str
    file_path: str
    line_number: int
    line_content: str      # the raw line (will be redacted in output)
    match: str             # the matched text


@dataclass
class ScanResult:
    """The full result of a scan."""
    scanned_files: int = 0
    skipped_files: int = 0
    findings: list = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

# Extensions we skip — binary files, images, compiled output, etc.
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".class",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv",
    ".ttf", ".otf", ".woff", ".woff2",
    ".db", ".sqlite", ".sqlite3",
}

# Directory names we always skip
SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", "dist", "build", ".eggs", "*.egg-info",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
}

# Default max file size: 5MB — avoids hanging on huge generated files
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


def should_skip_dir(dirname: str) -> bool:
    """Return True if we should skip this directory entirely."""
    return dirname in SKIP_DIRS or dirname.startswith(".")


def should_skip_file(filepath: str) -> bool:
    """Return True if we should skip this file."""
    path = Path(filepath)

    # Skip by extension
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True

    # Skip files that are too large
    try:
        if os.path.getsize(filepath) > MAX_FILE_SIZE_BYTES:
            return True
    except OSError:
        return True

    return False


# ---------------------------------------------------------------------------
# File walking
# ---------------------------------------------------------------------------

def iter_files(target: str) -> Generator[str, None, None]:
    """
    Yield file paths to scan under `target`.
    target can be a single file or a directory.
    """
    path = Path(target)

    if path.is_file():
        yield str(path)
        return

    if path.is_dir():
        for root, dirs, files in os.walk(path):
            # Prune dirs in-place so os.walk won't descend into them
            # This is a common Python pattern worth knowing
            dirs[:] = [d for d in dirs if not should_skip_dir(d)]

            for filename in files:
                filepath = os.path.join(root, filename)
                yield filepath


# ---------------------------------------------------------------------------
# Line scanning
# ---------------------------------------------------------------------------

def scan_file(filepath: str) -> tuple[list[Finding], bool]:
    """
    Scan a single file for secrets.
    Returns (findings, was_skipped).
    """
    if should_skip_file(filepath):
        return [], True

    findings = []

    try:
        # errors="ignore" skips undecodable bytes instead of crashing
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.rstrip("\n")
                for pattern_def in PATTERNS:
                    match = pattern_def["pattern"].search(line)
                    if match:
                        findings.append(Finding(
                            pattern_name=pattern_def["name"],
                            severity=pattern_def["severity"],
                            description=pattern_def["description"],
                            file_path=filepath,
                            line_number=line_number,
                            line_content=line.strip(),
                            match=match.group(0),
                        ))
    except (OSError, PermissionError):
        # Can't read the file — skip silently
        return [], True

    return findings, False


# ---------------------------------------------------------------------------
# Main scan entrypoint
# ---------------------------------------------------------------------------

def scan(target: str, exclude: list[str] | None = None) -> ScanResult:
    """
    Scan a file or directory for hardcoded secrets.

    Args:
        target:  path to file or directory to scan
        exclude: list of path prefixes to skip (e.g. ["tests/fixtures"])

    Returns:
        ScanResult with all findings
    """
    result = ScanResult()
    exclude = exclude or []

    for filepath in iter_files(target):
        # Check user-supplied excludes
        if any(filepath.startswith(ex) for ex in exclude):
            result.skipped_files += 1
            continue

        findings, skipped = scan_file(filepath)

        if skipped:
            result.skipped_files += 1
        else:
            result.scanned_files += 1
            result.findings.extend(findings)

    return result
