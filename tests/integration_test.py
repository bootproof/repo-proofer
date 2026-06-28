#!/usr/bin/env python3
"""
repo-proofer integration test — requires Docker.

Runs proofer.py end-to-end against two local fixture repos and verifies
the verdicts match expectations. This is the test that proves the full
Docker + strace path works on a real machine.

Usage:
    python tests/integration_test.py            # Run both fixtures
    python tests/integration_test.py --init-only # Just git-init the fixtures
    python tests/integration_test.py --keep-clones  # Don't clean up

Exit code:
    0  All fixtures behaved as expected.
    1  At least one fixture's verdict didn't match expectations.
    3  Docker not available.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROOFER = REPO_ROOT / "proofer.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures"

# Expected results per fixture. Each fixture is (name, dir, expected_exit_code,
# expected_stdout_substrings, expected_stderr_substrings).
# expected_*_substrings are case-insensitive substrings that MUST appear
# in the captured output. Empty list = no assertion on that stream.
FIXTURE_SPECS = [
    {
        "name": "clean-repo",
        "dir": FIXTURES / "clean-repo",
        "expected_exit": 0,
        "must_contain_stdout": [
            "BOOTS",
            "YES",
            "Files Read",
            "Processes Spawned",
        ],
        "must_not_contain_stdout": [
            "Sensitive File Access",  # should not see this for clean repo
        ],
        "description": (
            "A well-behaved Python repo. Should BOOTS:YES, exit 0, "
            "no warnings, no sensitive access."
        ),
    },
    {
        "name": "slop-repo",
        "dir": FIXTURES / "slop-repo",
        "expected_exit": 1,
        "must_contain_stdout": [
            "BOOTS",
            "NO",
            "Network Calls Attempted",
            "Sensitive File Access",
            "escalating",  # the escalation message
        ],
        "must_contain_stderr": [],
        "description": (
            "A malicious repo disguised as an AI startup. Should BOOTS:NO, "
            "exit 1, with network-attempt + sensitive-access detection."
        ),
    },
]


def ensure_fixture_is_git_repo(fixture_dir: Path) -> None:
    """Idempotently `git init` a fixture and make an initial commit.

    proofer.py uses GitPython's clone_from, which requires the source to
    be a real git repo. We init+commit the fixtures once on first run.
    """
    git_dir = fixture_dir / ".git"
    if git_dir.exists():
        return

    print(f"  [setup] Initializing git repo at {fixture_dir}")
    env = {**os.environ, "GIT_AUTHOR_NAME": "repo-proofer-test",
           "GIT_AUTHOR_EMAIL": "test@repo-proofer.local",
           "GIT_COMMITTER_NAME": "repo-proofer-test",
           "GIT_COMMITTER_EMAIL": "test@repo-proofer.local"}

    subprocess.run(["git", "init", "-b", "main", str(fixture_dir)],
                   check=True, capture_output=True, env=env)
    subprocess.run(["git", "-C", str(fixture_dir), "add", "."],
                   check=True, capture_output=True, env=env)
    subprocess.run(["git", "-C", str(fixture_dir), "commit", "-m",
                    "Test fixture for repo-proofer integration test"],
                   check=True, capture_output=True, env=env)


def run_proofer(fixture_dir: Path, work_dir: Path) -> tuple[int, str, str]:
    """Run proofer.py against a fixture via file:// URL. Returns (exit, stdout, stderr)."""
    file_url = f"file://{fixture_dir}"
    cmd = [sys.executable, str(PROOFER), file_url]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                          cwd=str(work_dir))
    return proc.returncode, proc.stdout, proc.stderr


def check_fixture(spec: dict, work_dir: Path) -> bool:
    """Run one fixture and verify the output matches expectations. Returns True on pass."""
    name = spec["name"]
    fixture_dir = spec["dir"]

    print(f"\n{'=' * 70}")
    print(f"  FIXTURE: {name}")
    print(f"  {spec['description']}")
    print(f"{'=' * 70}")

    exit_code, stdout, stderr = run_proofer(fixture_dir, work_dir)

    # Print the raw proofer output so the user sees the actual verdict.
    if stdout:
        print("\n--- proofer stdout ---")
        print(stdout)
    if stderr:
        print("\n--- proofer stderr ---")
        print(stderr)

    failures: list[str] = []

    # 1. Exit code check
    if exit_code != spec["expected_exit"]:
        failures.append(
            f"exit_code: expected {spec['expected_exit']}, got {exit_code}"
        )

    # 2. Required substrings in stdout
    combined = (stdout + "\n" + stderr).lower()
    for needle in spec.get("must_contain_stdout", []):
        if needle.lower() not in combined:
            failures.append(f"stdout missing: '{needle}'")

    # 3. Forbidden substrings in stdout
    for needle in spec.get("must_not_contain_stdout", []):
        if needle.lower() in combined:
            failures.append(f"stdout unexpectedly contains: '{needle}'")

    if failures:
        print(f"\n[FAIL] {name} — {len(failures)} assertion(s) failed:")
        for f in failures:
            print(f"       - {f}")
        return False

    print(f"\n[PASS] {name} — exit {exit_code}, all assertions passed.")
    return True


def check_docker() -> bool:
    """Verify Docker is installed and running."""
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def main() -> int:
    init_only = "--init-only" in sys.argv
    keep_clones = "--keep-clones" in sys.argv

    print("repo-proofer integration test")
    print(f"Repo root: {REPO_ROOT}")
    print(f"Fixtures:  {FIXTURES}")

    # Always ensure fixtures are git repos (needed for both init-only and full run)
    print("\n[1/3] Ensuring fixture repos are git-initialized...")
    for spec in FIXTURE_SPECS:
        ensure_fixture_is_git_repo(spec["dir"])
    print("      Done.")

    if init_only:
        print("\n[--init-only] Fixtures initialized. Exiting without running Docker.")
        return 0

    print("\n[2/3] Checking Docker daemon...")
    if not check_docker():
        print("[ERROR] Docker is not available. Install Docker and retry.")
        return 3
    print("      Docker is running.")

    print("\n[3/3] Running proofer.py against each fixture...")
    work_dir = Path(tempfile.mkdtemp(prefix="repo-proofer-inttest-"))
    try:
        results = [check_fixture(spec, work_dir) for spec in FIXTURE_SPECS]
    finally:
        if keep_clones:
            print(f"\n[dim]Clones kept at: {work_dir}[/dim]")
        else:
            shutil.rmtree(work_dir, ignore_errors=True)

    print(f"\n{'=' * 70}")
    passed = sum(results)
    total = len(results)
    print(f"  RESULT: {passed}/{total} fixtures passed")
    print(f"{'=' * 70}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
