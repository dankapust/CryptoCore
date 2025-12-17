import subprocess
import sys
from pathlib import Path

import pytest


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pycryptocore.cli", *args],
        capture_output=True,
        text=True,
    )


def test_cli_derive_basic(tmp_path: Path):
    result = run_cli(
        [
            "derive",
            "--password",
            "password",
            "--salt",
            "73616c74",
            "--iterations",
            "1",
            "--length",
            "32",
        ]
    )
    assert result.returncode == 0
    stdout = result.stdout.strip()
    assert stdout.startswith("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    assert stdout.endswith("73616c74")


def test_cli_derive_output_file(tmp_path: Path):
    out_file = tmp_path / "dk.bin"
    result = run_cli(
        [
            "derive",
            "--password",
            "password",
            "--salt",
            "73616c74",
            "--iterations",
            "2",
            "--length",
            "16",
            "--output",
            str(out_file),
        ]
    )
    assert result.returncode == 0
    assert out_file.exists()
    assert out_file.read_bytes() == bytes.fromhex("ae4d0c95af6b46d32d0adff928f06dd0")

