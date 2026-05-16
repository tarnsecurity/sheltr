"""
tests/test_scanner.py

Tests for the core scanner engine.
Run with: pytest

NOTE: Fake secret strings are base64-encoded so they're never plaintext in
the source file. They're decoded at runtime for testing only and are not
real credentials.
"""

import os
import base64
import tempfile
import pytest

from sheltr.scanner import scan, scan_file, should_skip_file, should_skip_dir
from sheltr.patterns import HIGH, MEDIUM


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_temp_file(content: str, suffix=".py") -> str:
    """Write content to a temp file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


# Fake secrets — base64-encoded so no plaintext secret exists in source.
# Decoded only at runtime when writing to temp files for testing.
_AWS_KEY   = base64.b64decode("QUtJQUlPU0ZPRE5ON0VYQU1QTEU=").decode()
_GH_TOKEN  = base64.b64decode("Z2hwX2FCY0RlRmdIaUprTG1Ob1BxUnNUdVZ3WHlaMTIzNDU2Nzg5MDEy").decode()


# ---------------------------------------------------------------------------
# Pattern detection tests
# ---------------------------------------------------------------------------

class TestPatternDetection:

    def test_detects_aws_key(self):
        path = write_temp_file(f'aws_key = "{_AWS_KEY}"\n')
        findings, skipped = scan_file(path)
        os.unlink(path)
        assert not skipped
        assert len(findings) >= 1
        assert any(f.pattern_name == "AWS Access Key ID" for f in findings)
        assert findings[0].severity == HIGH

    def test_detects_github_token(self):
        path = write_temp_file(f'token = "{_GH_TOKEN}"\n')
        findings, skipped = scan_file(path)
        os.unlink(path)
        assert any(f.pattern_name == "GitHub Token" for f in findings)

    def test_detects_stripe_secret(self):
        # X's don't match Stripe's real format so won't trigger push protection
        path = write_temp_file('STRIPE_KEY = "sk_live_XXXXXXXXXXXXXXXXXXXXXXXX"\n')
        findings, skipped = scan_file(path)
        os.unlink(path)
        assert any(f.pattern_name == "Stripe Secret Key" for f in findings)

    def test_detects_generic_password(self):
        path = write_temp_file('password = "supersecretpassword"\n')
        findings, skipped = scan_file(path)
        os.unlink(path)
        assert any(f.pattern_name == "Generic Password Assignment" for f in findings)

    def test_detects_database_url(self):
        path = write_temp_file('DATABASE_URL = "postgres://user:password123@localhost:5432/mydb"\n')
        findings, skipped = scan_file(path)
        os.unlink(path)
        assert any(f.pattern_name == "Database URL with credentials" for f in findings)

    def test_detects_rsa_private_key(self):
        path = write_temp_file('-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----\n')
        findings, skipped = scan_file(path)
        os.unlink(path)
        assert any(f.pattern_name == "RSA Private Key" for f in findings)
        assert findings[0].severity == HIGH

    def test_no_false_positive_clean_file(self):
        path = write_temp_file('def hello():\n    print("hello world")\n')
        findings, skipped = scan_file(path)
        os.unlink(path)
        assert findings == []

    def test_finding_has_correct_line_number(self):
        path = write_temp_file(f'# normal line\n# another line\n{_AWS_KEY}\n')
        findings, skipped = scan_file(path)
        os.unlink(path)
        aws_findings = [f for f in findings if f.pattern_name == "AWS Access Key ID"]
        assert aws_findings[0].line_number == 3


# ---------------------------------------------------------------------------
# File filtering tests
# ---------------------------------------------------------------------------

class TestFileFiltering:

    def test_skips_png(self):
        assert should_skip_file("image.png") is True

    def test_skips_pyc(self):
        assert should_skip_file("module.pyc") is True

    def test_does_not_skip_py(self):
        from sheltr.scanner import SKIP_EXTENSIONS
        from pathlib import Path
        assert Path("script.py").suffix.lower() not in SKIP_EXTENSIONS

    def test_skips_node_modules(self):
        assert should_skip_dir("node_modules") is True

    def test_skips_git(self):
        assert should_skip_dir(".git") is True

    def test_skips_hidden_dirs(self):
        assert should_skip_dir(".hidden") is True

    def test_does_not_skip_src(self):
        assert should_skip_dir("src") is False


# ---------------------------------------------------------------------------
# Directory scan tests
# ---------------------------------------------------------------------------

class TestDirectoryScan:

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = os.path.join(tmpdir, "config.py")
            with open(secret_file, "w") as f:
                f.write(f'API_KEY = "{_AWS_KEY}"\n')

            clean_file = os.path.join(tmpdir, "utils.py")
            with open(clean_file, "w") as f:
                f.write('def add(a, b): return a + b\n')

            result = scan(tmpdir)

            assert result.scanned_files == 2
            assert result.has_findings
            assert any(f.pattern_name == "AWS Access Key ID" for f in result.findings)

    def test_scan_respects_exclude(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "fixtures")
            os.makedirs(subdir)
            secret_file = os.path.join(subdir, "test_secrets.py")
            with open(secret_file, "w") as f:
                f.write(f'FAKE_KEY = "{_AWS_KEY}"\n')

            result = scan(tmpdir, exclude=[subdir])
            assert not result.has_findings

    def test_scan_single_file(self):
        path = write_temp_file('password = "mysecretpass123"\n')
        result = scan(path)
        os.unlink(path)
        assert result.scanned_files == 1
        assert result.has_findings
