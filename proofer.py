#!/usr/bin/env python3
"""
repo-proofer: Deterministic slop-detector for GitHub repositories.

A developer points this tool at a public Git URL. It clones the repo,
drops it into a hardened Docker sandbox with network access disabled
and a read-only filesystem, executes the entrypoint, and prints a
brutal honest verdict: did this repo actually boot, or is it slop?

100% deterministic. No LLMs. No AI APIs. Pure subprocess + filesystem.

Runtime Behavior Report (enterprise SBOM hook):
    When enabled (default), the entrypoint is wrapped in `strace -ff`
    inside the sandbox. After execution, the trace is parsed into a
    deterministic report of:
      - Files Read       (paths the app opened for reading)
      - Files Written    (paths opened O_WRONLY/O_RDWR/O_CREAT/etc.)
      - Processes Spawned (execve targets)
      - Network Calls Attempted (connect targets, socket AF_INET)
      - Sensitive File Access (/etc/passwd, ~/.ssh/id_rsa, .aws/creds, ...)
    Runtime noise (dynamic linker, /proc, /usr/lib, ...) is filtered
    so the report reflects what THE APP did, not what libc did.
    This is an SBOM based on actual execution, not static guessing.
    Use --no-behavior-report to skip strace overhead.

Usage:
    python proofer.py https://github.com/owner/repo.git
    python proofer.py https://github.com/owner/repo.git --keep-clone
    python proofer.py https://github.com/owner/repo.git --no-behavior-report

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

# ----------------------------------------------------------------------
# strace output patterns — for Runtime Behavior Report
# ----------------------------------------------------------------------
#
# These regexes parse strace -ff output. We focus on the syscalls that
# reveal what the app ACTUALLY DID (not what it could do).
#
# Trace file format produced by `strace -ff -o /trace/trace ...`:
#   /trace/trace.<pid>           (main process)
#   /trace/trace.<pid>.<pid>     (forked children)
# Each line is one syscall: `name(args) = retval`.

# openat/open/openat2/creat — file access. Group 1 = path, group 2 = retval.
# We accept an optional leading dirfd arg (AT_FDCWD or integer).
STRACE_OPEN_RE = re.compile(
    r'^(?:openat|open|openat2|creat)\('
    r'(?:[^,]*,\s*)?'        # optional dirfd (AT_FDCWD or fd number)
    r'"([^"]+)"'             # path (group 1)
    r'[^)]*\)'               # rest of args
    r'\s*=\s*(-?\d+)'        # return value (group 2)
)
# Write-mode flags inside the open call. If any present, classify as write.
# O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND are the markers.
STRACE_WRITE_FLAGS_RE = re.compile(r'O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND')

# execve/execveat — process spawn. Group 1 = binary path.
STRACE_EXECVE_RE = re.compile(r'^(?:execve|execveat)\("([^"]+)"')

# connect() — extract IPv4 target (port + addr).
STRACE_CONNECT_IPV4_RE = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET,\s*'
    r'sin_port=htons\((\d+)\),\s*'
    r'sin_addr=inet_addr\("([^"]+)"\)'
)
# connect() — extract IPv6 target.
STRACE_CONNECT_IPV6_RE = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6,\s*'
    r'sin6_port=htons\((\d+)\),\s*'
    r'inet_pton\(AF_INET6,\s*"([^"]+)"'
)
# connect() — AF_UNIX (local socket; usually low-signal but record anyway).
STRACE_CONNECT_UNIX_RE = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_UNIX,\s*sun_path="([^"]+)"'
)
# socket() with AF_INET/AF_INET6 — socket creation. Less informative than
# connect (no target), but still indicates network intent.
STRACE_SOCKET_INET_RE = re.compile(
    r'^socket\([^,]*AF_INET[6]?[^,]*,'
)

# Paths the runtime itself touches on every program start. Filtering
# these out keeps the report focused on what THE APP did, not what
# libc / dynamic linker / language runtime did.
RUNTIME_NOISE_PREFIXES = (
    "/etc/ld.so",            # dynamic linker cache
    "/etc/nsswitch.conf",    # name service config
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/etc/ssl/certs/",       # CA bundle reads (very common, low signal)
    "/usr/lib/",
    "/usr/share/",
    "/usr/local/lib/",
    "/usr/local/share/",
    "/lib/",
    "/lib64/",
    "/proc/",
    "/sys/",
    "/dev/null",
    "/dev/urandom",
    "/dev/random",
)

# Sensitive paths that, if accessed, indicate a likely exfil attempt.
# These are NEVER filtered out — they get their own dedicated section
# in the report so the enterprise CISO sees them immediately. This is
# the "read ~/.ssh/id_rsa" detection the enterprise story hinges on.
SENSITIVE_PATH_PATTERNS = [
    re.compile(r'^/root/\.ssh/'),
    re.compile(r'^/home/[^/]+/\.ssh/'),
    re.compile(r'^/etc/passwd$'),
    re.compile(r'^/etc/shadow$'),
    re.compile(r'^/etc/sudoers'),
    re.compile(r'\.aws/credentials'),
    re.compile(r'\.gnupg/'),
    re.compile(r'\.netrc$'),
    re.compile(r'\.npmrc$'),
    re.compile(r'\.docker/config\.json'),
    re.compile(r'\.kube/config'),
    re.compile(r'\.git-credentials'),
    re.compile(r'\.env$'),
    re.compile(r'\.env\.'),
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


@dataclass
class BehaviorReport:
    """Runtime behavior observed during sandboxed execution.

    Captured via strace inside the container. All fields are lists of
    concrete strings (file paths, process names, network targets) —
    never AI-inferred. This is the enterprise SBOM hook: an SBOM based
    on what the code ACTUALLY did, not what static analysis guesses.
    """
    files_read: list[str] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    processes_spawned: list[str] = field(default_factory=list)
    network_attempts: list[str] = field(default_factory=list)
    sensitive_access: list[str] = field(default_factory=list)
    strace_enabled: bool = False

    @property
    def has_data(self) -> bool:
        return any([
            self.files_read, self.files_written,
            self.processes_spawned, self.network_attempts,
            self.sensitive_access,
        ])


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


def ensure_strace_image(base_image: str) -> Optional[str]:
    """
    Build (and cache) a derived image with strace installed and a
    /trace mount point prepared. Returns the tag, or None on failure.

    The derived image is tagged repoproofer/strace:<base> so subsequent
    runs are instant (docker image inspect hits, no rebuild).

    Why we need a derived image: the base images (node:20-slim etc.)
    don't ship strace, and the exec phase runs with --network none so
    we can't apt-get install at runtime. We bake strace in once, then
    reuse the image forever.
    """
    safe_tag = base_image.replace(":", "_").replace("/", "_")
    tag = f"repoproofer/strace:{safe_tag}"

    # Fast path: already built
    try:
        check = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, timeout=15,
        )
        if check.returncode == 0:
            return tag
    except subprocess.TimeoutExpired:
        pass

    # Pick install command based on base image family.
    if "alpine" in base_image:
        install_cmd = "apk add --no-cache strace"
    else:
        install_cmd = (
            "apt-get update "
            "&& apt-get install -y --no-install-recommends strace "
            "&& rm -rf /var/lib/apt/lists/*"
        )

    dockerfile = (
        f"FROM {base_image}\n"
        f"RUN {install_cmd}\n"
        f"RUN mkdir -p /trace && chmod 777 /trace\n"
    )

    console.print(
        f"[dim]Building strace-enabled image (one-time setup for "
        f"{base_image})...[/dim]"
    )
    try:
        result = subprocess.run(
            ["docker", "build", "-t", tag, "-"],
            input=dockerfile,
            capture_output=True, text=True, timeout=IMAGE_PULL_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        console.print(
            "[yellow]Timed out building strace image. "
            "Behavior report will be disabled for this run.[/yellow]"
        )
        return None

    if result.returncode != 0:
        console.print(
            "[yellow]Could not build strace image. "
            "Behavior report will be disabled for this run.[/yellow]"
        )
        console.print(f"[dim]{result.stderr.strip()[-400:]}[/dim]")
        return None

    return tag


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
    image: str,
    repo_path: Path,
    deps_dir: Optional[Path],
    trace_dir: Optional[Path] = None,
) -> ExecutionResult:
    """
    Run the project entrypoint in a hardened sandbox.

    CRITICAL SECURITY CONSTRAINTS (do NOT remove any of these):
      --rm                  Container is removed after run.
      --read-only           Root filesystem is read-only.
      --network none        Absolutely no internet access.
      --cap-drop ALL        No Linux capabilities (see SYS_PTRACE note).
      --memory 512m         Memory cap.
      --cpus 0.5            CPU cap.
      --tmpfs /tmp          Writable in-memory /tmp.
      -v repo:/app:ro       Repo mounted READ-ONLY.

    If trace_dir is provided, the entrypoint is wrapped in `strace -ff`
    so we can produce a Runtime Behavior Report. This requires
    `--cap-add SYS_PTRACE` (added below). SECURITY NOTE: SYS_PTRACE
    inside a container only permits tracing of the container's own
    descendant processes — it does NOT grant access to host processes.
    The `--network none` and `--read-only` moats remain fully intact.
    The cap is ONLY added when behavior reporting is explicitly enabled.

    If the app crashes because it can't reach the network, that is a
    successful detection of a hidden dependency, NOT a tool failure.
    """
    use_strace = trace_dir is not None

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

    if use_strace:
        # Required for strace -ff to follow forked children. Does NOT
        # weaken the network/filesystem isolation moat — SYS_PTRACE in
        # a container only allows tracing the container's own descendant
        # processes, never host processes.
        base_args += ["--cap-add", "SYS_PTRACE"]
        # /trace is the strace output directory. Created in the derived
        # image (chmod 777) so non-root containers can write to it.
        base_args += ["-v", f"{trace_dir}:/trace:rw"]
        # Replace the image's ENTRYPOINT with strace itself. The candidate
        # command becomes strace's argv (after the `--` separator).
        base_args += ["--entrypoint", "/usr/bin/strace"]

    if stack.deps_mount and deps_dir is not None:
        # Deps cache mounted READ-ONLY during execution.
        base_args += ["-v", f"{deps_dir}:{stack.deps_mount}:ro"]

    for key, value in stack.env.items():
        base_args += ["-e", f"{key}={value}"]

    # Try each run candidate in order. If one exits 0, we're done.
    # If one fails with a "file not found" style error, try the next.
    # Any other failure is a real boot failure — return it for analysis.
    #
    # NOTE on strace + fallback: when use_strace is True and we fall
    # through to the next candidate, strace overwrites the trace files
    # (its default is O_TRUNC on the output file). The final trace_dir
    # therefore reflects only the LAST attempted candidate — which is
    # exactly what we want, since the successful/last attempt is the
    # one whose behavior matters.
    last_result: Optional[ExecutionResult] = None
    for candidate in stack.run_candidates:
        if use_strace:
            cmd = [
                "-ff",  # Follow forks; one output file per process.
                "-e", "trace=openat,open,openat2,creat,execve,execveat,connect,socket,unlink,unlinkat",
                "-o", "/trace/trace",
                "--",  # Stop option parsing; rest is the command to trace.
            ] + candidate
        else:
            cmd = candidate

        args = base_args + [image] + cmd
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


def parse_strace_output(trace_dir: Path) -> BehaviorReport:
    """
    Parse all strace output files in trace_dir into a BehaviorReport.

    strace -ff -o /trace/trace creates files named trace.<pid>,
    trace.<pid>.<pid> for forks, etc. We glob them all and parse line
    by line.

    Classification rules (all deterministic, all regex-based):
      - openat/open/creat with O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND
        -> files_written
      - openat/open with only O_RDONLY -> files_read
      - execve/execveat -> processes_spawned
      - connect to AF_INET/AF_INET6 -> network_attempts (with target)
      - socket with AF_INET/AF_INET6 -> network_attempts (creation only)
      - Any path matching SENSITIVE_PATH_PATTERNS -> sensitive_access
        (in addition to read/write classification, never filtered)
      - Paths under RUNTIME_NOISE_PREFIXES -> filtered out of read/write
        counts (they reflect dynamic linker / libc activity, not app)
    """
    report = BehaviorReport(strace_enabled=True)

    seen_reads: set[str] = set()
    seen_writes: set[str] = set()
    seen_procs: set[str] = set()
    seen_net: set[str] = set()
    seen_sensitive: set[str] = set()

    trace_files = sorted(trace_dir.glob("trace*"))
    if not trace_files:
        return report

    for tf in trace_files:
        try:
            text = tf.read_text(errors="replace")
        except OSError:
            continue

        for line in text.splitlines():
            # --- File access (openat / open / openat2 / creat) ---
            m = STRACE_OPEN_RE.match(line)
            if m:
                path = m.group(1)
                is_sensitive = any(
                    p.search(path) for p in SENSITIVE_PATH_PATTERNS
                )
                # Sensitive paths are ALWAYS recorded, even if they
                # also match a runtime-noise prefix (paranoid by design).
                if is_sensitive and path not in seen_sensitive:
                    seen_sensitive.add(path)

                # Filter runtime noise from read/write tallies.
                if path.startswith(RUNTIME_NOISE_PREFIXES):
                    continue

                # Classify read vs write.
                # - creat(path, mode) is by definition a write — it has
                #   no O_* flags in its signature, so the flag regex
                #   alone would miss it. Handle explicitly.
                # - openat/open/openat2 carry O_* flags; check them.
                is_write = (
                    line.startswith("creat(")
                    or bool(STRACE_WRITE_FLAGS_RE.search(line))
                )

                if is_write:
                    if path not in seen_writes:
                        seen_writes.add(path)
                else:
                    if path not in seen_reads:
                        seen_reads.add(path)
                continue

            # --- Process spawn (execve / execveat) ---
            m = STRACE_EXECVE_RE.match(line)
            if m:
                proc = m.group(1)
                if proc not in seen_procs:
                    seen_procs.add(proc)
                continue

            # --- Network: connect (preferred — carries target info) ---
            m4 = STRACE_CONNECT_IPV4_RE.search(line)
            if m4:
                entry = f"connect {m4.group(2)}:{m4.group(1)}"
                if entry not in seen_net:
                    seen_net.add(entry)
                continue
            m6 = STRACE_CONNECT_IPV6_RE.search(line)
            if m6:
                entry = f"connect [{m6.group(2)}]:{m6.group(1)}"
                if entry not in seen_net:
                    seen_net.add(entry)
                continue
            mu = STRACE_CONNECT_UNIX_RE.search(line)
            if mu:
                entry = f"connect unix:{mu.group(1)}"
                if entry not in seen_net:
                    seen_net.add(entry)
                continue
            # Bare connect call we couldn't parse — still record as attempt.
            if line.startswith("connect("):
                entry = "connect (target unparseable)"
                if entry not in seen_net:
                    seen_net.add(entry)
                continue

            # --- Network: socket creation (less informative) ---
            if STRACE_SOCKET_INET_RE.match(line):
                entry = "socket(AF_INET*)"
                if entry not in seen_net:
                    seen_net.add(entry)
                continue

    report.files_read = sorted(seen_reads)
    report.files_written = sorted(seen_writes)
    report.processes_spawned = sorted(seen_procs)
    report.network_attempts = sorted(seen_net)
    report.sensitive_access = sorted(seen_sensitive)
    return report


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


def print_behavior_report(report: BehaviorReport) -> None:
    """Print the Runtime Behavior Report (the enterprise SBOM hook)."""
    if not report.strace_enabled:
        console.print(Panel(
            "[dim]Runtime behavior report disabled for this run.\n"
            "Pass without --no-behavior-report to enable strace-based "
            "file/process/network tracking.[/dim]",
            title="[bold blue]Runtime Behavior Report[/bold blue]",
            border_style="blue",
        ))
        return

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column()
    table.add_row("Files Read", str(len(report.files_read)))
    table.add_row("Files Written", str(len(report.files_written)))
    table.add_row("Processes Spawned", str(len(report.processes_spawned)))
    table.add_row("Network Calls Attempted", str(len(report.network_attempts)))
    if report.sensitive_access:
        table.add_row(
            "Sensitive File Access",
            f"[bold red]{len(report.sensitive_access)}[/bold red] "
            f"(see below)",
        )
    else:
        table.add_row("Sensitive File Access", "[green]0[/green]")

    console.print(Panel(
        table,
        title="[bold blue]Runtime Behavior Report[/bold blue]",
        border_style="blue",
        subtitle="[dim]Generated via strace inside the zero-network sandbox[/dim]",
    ))

    # Detailed panels (only shown when non-empty)
    if report.files_written:
        console.print(Panel(
            "\n".join(f"- {p}" for p in report.files_written),
            title=f"[yellow]Files Written ({len(report.files_written)})[/yellow]",
            border_style="yellow",
        ))

    if report.processes_spawned:
        console.print(Panel(
            "\n".join(f"- {p}" for p in report.processes_spawned),
            title=f"[cyan]Processes Spawned ({len(report.processes_spawned)})[/cyan]",
            border_style="cyan",
        ))

    if report.network_attempts:
        console.print(Panel(
            "\n".join(f"- {p}" for p in report.network_attempts),
            title=(
                f"[red]Network Calls Attempted "
                f"({len(report.network_attempts)})[/red]"
            ),
            border_style="red",
        ))

    if report.sensitive_access:
        console.print(Panel(
            "\n".join(f"- {p}" for p in report.sensitive_access),
            title=(
                f"[bold red]Sensitive File Access "
                f"({len(report.sensitive_access)})[/bold red]"
            ),
            border_style="red",
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
        help="Keep the cloned repo, deps cache, and strace trace on disk for debugging.",
    ),
    no_behavior_report: bool = typer.Option(
        False,
        "--no-behavior-report",
        help=(
            "Disable Runtime Behavior Report (skip strace wrapping). "
            "Faster, but no file/process/network tracking."
        ),
    ),
) -> None:
    """Clone, sandbox, and execute a Git repo. Brutal honest verdict."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="repo-proofer-"))
    repo_dir = tmp_dir / "repo"
    deps_dir: Optional[Path] = None
    trace_dir: Optional[Path] = None

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

        # ---- Ensure base image is pulled (one-time setup) ---------
        ensure_image_pulled(stack.image)

        # ---- Build strace-enabled image (for Runtime Behavior Report)
        # The derived image is cached, so this is instant on subsequent
        # runs. If the build fails, we fall back to the base image and
        # skip strace — the core verdict still works.
        exec_image = stack.image
        if not no_behavior_report:
            strace_tag = ensure_strace_image(stack.image)
            if strace_tag is not None:
                exec_image = strace_tag
                trace_dir = Path(tempfile.mkdtemp(prefix="repo-proofer-trace-"))
                try:
                    trace_dir.chmod(0o777)
                except PermissionError:
                    pass
            else:
                console.print(
                    "[yellow]Runtime Behavior Report disabled "
                    "(could not build strace image).[/yellow]"
                )

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
            exec_result = execute_entrypoint(
                stack, exec_image, repo_dir, deps_dir, trace_dir,
            )

        # ---- Step 5: Analyze ----------------------------------------
        verdict = analyze_result(exec_result)

        # ---- Step 5b: Parse strace trace (if enabled) --------------
        behavior_report = BehaviorReport()
        if trace_dir is not None and trace_dir.exists():
            behavior_report = parse_strace_output(trace_dir)

        # ---- Step 6: Print verdict ----------------------------------
        print_verdict(verdict, repo_url, stack.name, install_result)
        print_behavior_report(behavior_report)

        # If strace caught a sensitive-file access, escalate the exit
        # code to 1 even if the app exited 0. This is the enterprise
        # gate: a clean exit doesn't matter if it tried to read ~/.ssh.
        if behavior_report.sensitive_access and verdict.boots:
            console.print(
                "[bold red][!] Escalating verdict to BOOTS: NO — "
                "sensitive file access detected despite clean exit.[/bold red]"
            )
            raise typer.Exit(code=1)

        # Exit code reflects boots status (useful for scripting / CI).
        raise typer.Exit(code=0 if verdict.boots else 1)

    finally:
        if keep_clone:
            console.print(f"[dim]Clone kept at: {tmp_dir}[/dim]")
            if deps_dir:
                console.print(f"[dim]Deps kept at: {deps_dir}[/dim]")
            if trace_dir:
                console.print(f"[dim]Trace kept at: {trace_dir}[/dim]")
        else:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            if deps_dir:
                shutil.rmtree(deps_dir, ignore_errors=True)
            if trace_dir:
                shutil.rmtree(trace_dir, ignore_errors=True)


if __name__ == "__main__":
    typer.run(main)
