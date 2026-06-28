#!/usr/bin/env python3
"""
repo-proofer: Deterministic slop-detector for GitHub repositories.

A developer points this tool at a public Git URL. It clones the repo,
drops it into a hardened Docker sandbox with network access disabled
and a read-only filesystem, executes the entrypoint, and prints a
brutal honest verdict: did this repo actually boot, or is it slop?

100% deterministic. No LLMs. No AI APIs. Pure subprocess + filesystem.

Usage:
    python proofer.py https://github.com/owner/repo.git
    python proofer.py https://github.com/owner/repo.git --keep-clone

Exit codes:
    0  Repo boots cleanly under sandboxed execution.
    1  Repo does NOT boot (non-zero exit, missing entrypoint, etc.).
    2  Clone failed.
    3  Docker not installed / daemon not running.
    4  Could not detect project stack.
    5  Failed to pull Docker image.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import typer
from git import Repo, GitCommandError
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

INSTALL_TIMEOUT_SEC = 60
EXEC_TIMEOUT_SEC = 30
IMAGE_PULL_TIMEOUT_SEC = 300
DOCKER_INFO_TIMEOUT_SEC = 10

MAX_STDOUT_CHARS = 500
MAX_STDERR_CHARS = 500

# Deterministic network-error patterns. No fuzzy matching, no AI.
# Any match in stdout/stderr triggers the "hidden network dependency" warning.
NETWORK_ERROR_PATTERNS = [
    r"ENOTFOUND",
    r"ECONNREFUSED",
    r"ECONNRESET",
    r"ETIMEDOUT",
    r"EHOSTUNREACH",
    r"ENETUNREACH",
    r"EAI_AGAIN",
    r"Connection refused",
    r"Network is unreachable",
    r"Temporary failure in name resolution",
    r"Name or service not known",
    r"getaddrinfo",
    r"socket\.gaierror",
    r"urllib3\.exceptions",
    r"requests\.exceptions\.ConnectionError",
    r"fetch failed",
    r"Failed to fetch",
]
NETWORK_ERROR_RE = re.compile("|".join(NETWORK_ERROR_PATTERNS), re.IGNORECASE)

# File-not-found markers — used to decide whether to try the next entrypoint.
NOT_FOUND_MARKERS = [
    "no such file or directory",
    "cannot find module",
    "can't open file",
    "no such file",
    "could not find cargo.toml",
    "error: could not find",
    "no entrypoint",
]

console = Console()


# ----------------------------------------------------------------------
# Data structures
# ----------------------------------------------------------------------

@dataclass
class StackProfile:
    """Deterministic profile for a detected project stack."""
    name: str
    image: str
    install_cmd: list[str]
    run_candidates: list[list[str]]
    env: dict[str, str] = field(default_factory=dict)
    deps_mount: Optional[str] = None  # In-container path where deps land


@dataclass
class ExecutionResult:
    """Captured output of a single docker run."""
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False


@dataclass
class Verdict:
    """Final verdict printed to the user."""
    boots: bool
    network_egress_blocked: bool
    filesystem_read_only: bool
    stdout_preview: str
    stderr_preview: str
    warnings: list[str] = field(default_factory=list)


# ----------------------------------------------------------------------
# Stack detection — deterministic, file-existence based
# ----------------------------------------------------------------------

def detect_stack(repo_path: Path) -> Optional[StackProfile]:
    """
    Detect project stack by checking for marker files in the repo root.
    Returns None if no supported stack is found.
    """
    # Node.js
    if (repo_path / "package.json").exists():
        return StackProfile(
            name="Node.js",
            image="node:20-slim",
            install_cmd=["npm", "install", "--prefix", "/tmp/npm_cache"],
            run_candidates=[
                ["node", "index.js"],
                ["node", "app.js"],
                ["npm", "start"],
            ],
            env={"NODE_PATH": "/tmp/npm_cache/node_modules"},
            deps_mount="/tmp/npm_cache",
        )

    # Python — requirements.txt OR main.py
    if (repo_path / "requirements.txt").exists() or (repo_path / "main.py").exists():
        install_cmd: list[str] = []
        if (repo_path / "requirements.txt").exists():
            install_cmd = [
                "pip", "install", "--no-cache-dir",
                "-r", "requirements.txt",
                "-t", "/tmp/pip_deps",
            ]
        # NOTE: Spec says PYTHONPATH=/tmp/pip_deps:$PYTHONPATH. The
        # python:3.11-slim image has no PYTHONPATH set by default, so
        # "/tmp/pip_deps" alone is equivalent to prepending.
        return StackProfile(
            name="Python",
            image="python:3.11-slim",
            install_cmd=install_cmd,
            run_candidates=[
                ["python", "main.py"],
                ["python", "app.py"],
            ],
            env={
                "PYTHONPATH": "/tmp/pip_deps",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            deps_mount="/tmp/pip_deps" if install_cmd else None,
        )

    # Go
    if (repo_path / "go.mod").exists():
        return StackProfile(
            name="Go",
            image="golang:1.22-alpine",
            install_cmd=[],  # Per spec: no install step for Go
            run_candidates=[["go", "run", "main.go"]],
            env={},
            deps_mount=None,
        )

    # Rust
    if (repo_path / "Cargo.toml").exists():
        return StackProfile(
            name="Rust",
            image="rust:1.75-slim",
            install_cmd=[],  # Per spec: no install step for Rust
            run_candidates=[["cargo", "run"]],
            env={},
            deps_mount=None,
        )

    return None


# ----------------------------------------------------------------------
# Docker helpers
# ----------------------------------------------------------------------

def check_docker_running() -> None:
    """Verify Docker is installed and the daemon is responding."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=DOCKER_INFO_TIMEOUT_SEC,
        )
    except FileNotFoundError:
        console.print(
            "[red]Error: 'docker' command not found. "
            "Install Docker and try again.[/red]"
        )
        raise typer.Exit(code=3)
    except subprocess.TimeoutExpired:
        console.print(
            "[red]Error: 'docker info' timed out. "
            "Is the Docker daemon responding?[/red]"
        )
        raise typer.Exit(code=3)

    if result.returncode != 0:
        console.print(
            "[red]Error: Docker daemon does not appear to be running.[/red]"
        )
        console.print(f"[dim]docker info stderr: {result.stderr.strip()}[/dim]")
        raise typer.Exit(code=3)


def ensure_image_pulled(image: str) -> None:
    """Pull image if not present locally. Idempotent."""
    try:
        check = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=15,
        )
        if check.returncode == 0:
            return  # Already pulled
    except subprocess.TimeoutExpired:
        pass  # Fall through to pull

    console.print(
        f"[dim]Pulling image {image} (one-time setup, may take a minute)...[/dim]"
    )
    try:
        result = subprocess.run(
            ["docker", "pull", image],
            capture_output=True, text=True, timeout=IMAGE_PULL_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        console.print(f"[red]Error: Timed out pulling image {image}.[/red]")
        raise typer.Exit(code=5)

    if result.returncode != 0:
        console.print(f"[red]Error: Failed to pull image {image}.[/red]")
        console.print(f"[dim]{result.stderr.strip()}[/dim]")
        raise typer.Exit(code=5)


def run_docker(args: list[str], timeout: int) -> ExecutionResult:
    """Run a docker command with timeout, capture stdout/stderr/exit_code."""
    try:
        proc = subprocess.run(
            ["docker", *args],
            capture_output=True, text=True, timeout=timeout,
        )
        return ExecutionResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            exit_code=proc.returncode,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as e:
        out = e.stdout if e.stdout else ""
        err = e.stderr if e.stderr else ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", errors="replace")
        return ExecutionResult(
            stdout=out or "",
            stderr=err or "",
            exit_code=-1,
            timed_out=True,
        )


def install_deps(
    stack: StackProfile,
    repo_path: Path,
    deps_dir: Path,
) -> Optional[ExecutionResult]:
    """
    Run the install command in a Docker sandbox with network ON.

    Security note: install is intentionally more permissive than exec —
    it needs network to fetch packages and write access to the deps
    cache directory. The repo is still mounted read-only.
    """
    if not stack.install_cmd:
        return None

    args = [
        "run", "--rm",
        "--cap-drop", "ALL",
        "--memory", "512m",
        "--cpus", "0.5",
        "--tmpfs", "/tmp",
        "-v", f"{repo_path}:/app:ro",
        "-w", "/app",
    ]
    if stack.deps_mount:
        # Writable mount: install step writes deps here. Persists to host
        # so the exec container can mount the same directory read-only.
        args += ["-v", f"{deps_dir}:{stack.deps_mount}:rw"]
    args.append(stack.image)
    args.extend(stack.install_cmd)

    return run_docker(args, timeout=INSTALL_TIMEOUT_SEC)


def execute_entrypoint(
    stack: StackProfile,
    repo_path: Path,
    deps_dir: Optional[Path],
) -> ExecutionResult:
    """
    Run the project entrypoint in a hardened sandbox.

    CRITICAL SECURITY CONSTRAINTS (do NOT remove any of these):
      --rm                  Container is removed after run.
      --read-only           Root filesystem is read-only.
      --network none        Absolutely no internet access.
      --cap-drop ALL        No Linux capabilities.
      --memory 512m         Memory cap.
      --cpus 0.5            CPU cap.
      --tmpfs /tmp          Writable in-memory /tmp.
      -v repo:/app:ro       Repo mounted READ-ONLY.

    If the app crashes because it can't reach the network, that is a
    successful detection of a hidden dependency, NOT a tool failure.
    """
    base_args = [
        "run", "--rm",
        "--read-only",
        "--network", "none",
        "--cap-drop", "ALL",
        "--memory", "512m",
        "--cpus", "0.5",
        "--tmpfs", "/tmp",
        "-v", f"{repo_path}:/app:ro",
        "-w", "/app",
    ]
    if stack.deps_mount and deps_dir is not None:
        # Deps cache mounted READ-ONLY during execution.
        base_args += ["-v", f"{deps_dir}:{stack.deps_mount}:ro"]

    for key, value in stack.env.items():
        base_args += ["-e", f"{key}={value}"]

    # Try each run candidate in order. If one exits 0, we're done.
    # If one fails with a "file not found" style error, try the next.
    # Any other failure is a real boot failure — return it for analysis.
    last_result: Optional[ExecutionResult] = None
    for candidate in stack.run_candidates:
        args = base_args + [stack.image] + candidate
        result = run_docker(args, timeout=EXEC_TIMEOUT_SEC)

        if result.exit_code == 0:
            return result

        combined = (result.stdout + "\n" + result.stderr).lower()
        if any(marker in combined for marker in NOT_FOUND_MARKERS):
            last_result = result
            continue

        return result

    if last_result is not None:
        return last_result

    return ExecutionResult(
        stdout="",
        stderr=(
            "No entrypoint candidate ran. Tried: "
            + ", ".join(" ".join(c) for c in stack.run_candidates)
        ),
        exit_code=127,
    )


# ----------------------------------------------------------------------
# Analysis — deterministic, regex-based
# ----------------------------------------------------------------------

def analyze_result(result: ExecutionResult) -> Verdict:
    """Produce a verdict from the execution result. 100% deterministic."""
    boots = (result.exit_code == 0)
    warnings: list[str] = []

    if result.timed_out:
        warnings.append(f"Execution timed out after {EXEC_TIMEOUT_SEC}s.")

    combined = result.stdout + "\n" + result.stderr
    if NETWORK_ERROR_RE.search(combined):
        warnings.append(
            "App crashed when network was blocked. "
            "May require external API to function."
        )

    return Verdict(
        boots=boots,
        network_egress_blocked=True,    # We always block.
        filesystem_read_only=True,      # We always mount read-only.
        stdout_preview=result.stdout[:MAX_STDOUT_CHARS],
        stderr_preview=result.stderr[:MAX_STDERR_CHARS],
        warnings=warnings,
    )


# ----------------------------------------------------------------------
# Output — rich panels
# ----------------------------------------------------------------------

def print_verdict(
    verdict: Verdict,
    repo_url: str,
    stack_name: str,
    install_result: Optional[ExecutionResult],
) -> None:
    """Print the brutal honest verdict via rich panels."""
    boots_str = (
        "[bold green]YES[/bold green]"
        if verdict.boots
        else "[bold red]NO[/bold red]"
    )

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column()
    table.add_row("Repository", repo_url)
    table.add_row("Detected Stack", stack_name)
    table.add_row("BOOTS", boots_str)
    table.add_row("Network Egress", "[bold red]BLOCKED[/bold red]")
    table.add_row("Filesystem", "[bold yellow]READ-ONLY[/bold yellow]")
    if verdict.warnings:
        warning_text = "\n".join(
            f"[yellow][!] {w}[/yellow]" for w in verdict.warnings
        )
        table.add_row("Warnings", warning_text)

    console.print(Panel(
        table,
        title="[bold blue]repo-proofer verdict[/bold blue]",
        border_style="blue",
        expand=False,
    ))

    if verdict.stdout_preview:
        console.print(Panel(
            verdict.stdout_preview,
            title=f"[green]stdout (first {MAX_STDOUT_CHARS} chars)[/green]",
            border_style="green",
        ))

    if verdict.stderr_preview:
        console.print(Panel(
            verdict.stderr_preview,
            title=f"[red]stderr (first {MAX_STDERR_CHARS} chars)[/red]",
            border_style="red",
        ))

    if install_result is not None and install_result.exit_code != 0:
        console.print(Panel(
            "Install step failed "
            f"(exit {install_result.exit_code}) but execution proceeded anyway.\n"
            f"Install stderr (first {MAX_STDERR_CHARS} chars):\n"
            f"{install_result.stderr[:MAX_STDERR_CHARS]}",
            title="[yellow]Install Warning[/yellow]",
            border_style="yellow",
        ))


# ----------------------------------------------------------------------
# Main flow
# ----------------------------------------------------------------------

def main(
    repo_url: str = typer.Argument(
        ...,
        help="Git URL of the repo to proof (e.g. https://github.com/owner/repo.git).",
    ),
    keep_clone: bool = typer.Option(
        False,
        "--keep-clone",
        help="Keep the cloned repo and deps cache on disk for debugging.",
    ),
) -> None:
    """Clone, sandbox, and execute a Git repo. Brutal honest verdict."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="repo-proofer-"))
    repo_dir = tmp_dir / "repo"
    deps_dir: Optional[Path] = None

    try:
        # ---- Step 0: Check Docker -----------------------------------
        # Note: no Progress wrapper here. check_docker_running() prints
        # error panels via console.print on failure, and Rich forbids
        # printing to the live console while a Progress is active.
        console.print("[dim]Checking Docker daemon...[/dim]")
        check_docker_running()

        # ---- Step 1: Clone (depth=1) --------------------------------
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            progress.add_task(
                f"Cloning {repo_url} (depth=1)...", total=None
            )
            try:
                Repo.clone_from(repo_url, repo_dir, depth=1)
            except GitCommandError as e:
                msg = e.stderr.strip() if e.stderr else str(e)
                console.print(f"[red]Clone failed: {msg}[/red]")
                raise typer.Exit(code=2)
            except Exception as e:
                console.print(f"[red]Clone failed: {e}[/red]")
                raise typer.Exit(code=2)

        # ---- Step 2: Detect stack -----------------------------------
        stack = detect_stack(repo_dir)
        if stack is None:
            console.print(
                "[red]Error: Could not detect project stack.[/red]\n"
                "[dim]Supported markers: package.json, "
                "requirements.txt, main.py, go.mod, Cargo.toml[/dim]"
            )
            raise typer.Exit(code=4)
        console.print(
            f"[cyan]Detected stack:[/cyan] [bold]{stack.name}[/bold] "
            f"(image: {stack.image})"
        )

        # ---- Ensure image is pulled (one-time setup) ---------------
        ensure_image_pulled(stack.image)

        # ---- Step 3: Install deps (network ON) ---------------------
        install_result: Optional[ExecutionResult] = None
        if stack.install_cmd:
            deps_dir = Path(tempfile.mkdtemp(prefix="repo-proofer-deps-"))
            try:
                deps_dir.chmod(0o777)
            except PermissionError:
                # On some systems non-root can't chmod; the dir is already
                # world-writable via mkdtemp defaults, so this is fine.
                pass

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                progress.add_task(
                    f"Installing dependencies "
                    f"(network ON, timeout {INSTALL_TIMEOUT_SEC}s)...",
                    total=None,
                )
                install_result = install_deps(stack, repo_dir, deps_dir)

            if install_result.exit_code != 0:
                console.print(
                    f"[yellow]Install step exited {install_result.exit_code}. "
                    "Proceeding to execution anyway (no auto-repair).[/yellow]"
                )

        # ---- Step 4: Execute (network OFF, read-only FS) -----------
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            progress.add_task(
                f"Executing entrypoint "
                f"(network OFF, read-only FS, timeout {EXEC_TIMEOUT_SEC}s)...",
                total=None,
            )
            exec_result = execute_entrypoint(stack, repo_dir, deps_dir)

        # ---- Step 5: Analyze ----------------------------------------
        verdict = analyze_result(exec_result)

        # ---- Step 6: Print verdict ----------------------------------
        print_verdict(verdict, repo_url, stack.name, install_result)

        # Exit code reflects boots status (useful for scripting / CI).
        raise typer.Exit(code=0 if verdict.boots else 1)

    finally:
        if keep_clone:
            console.print(f"[dim]Clone kept at: {tmp_dir}[/dim]")
            if deps_dir:
                console.print(f"[dim]Deps kept at: {deps_dir}[/dim]")
        else:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            if deps_dir:
                shutil.rmtree(deps_dir, ignore_errors=True)


if __name__ == "__main__":
    typer.run(main)
