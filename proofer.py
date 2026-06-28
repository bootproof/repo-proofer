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
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

__version__ = "0.3.1"

# ----------------------------------------------------------------------
# Missing-dependency guard — print a guided message instead of a raw
# traceback. This is the first code that runs; if typer/rich/gitpython
# aren't installed, the user gets a clear "run pip install" instruction
# rather than an ImportError stack trace.
# ----------------------------------------------------------------------
try:
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
except ImportError as e:
    print(f"Error: missing dependency '{e.name}'.")
    print()
    print("repo-proofer requires typer, rich, and GitPython.")
    print("Install them with:")
    print()
    print("    pip install -r requirements.txt")
    print()
    print("(If you hit 'externally-managed-environment' on macOS/Linux,")
    print(" create a venv first:  python3 -m venv .venv && source .venv/bin/activate)")
    sys.exit(1)

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

# ----------------------------------------------------------------------
# Readiness signals — used to distinguish a healthy long-running
# process (server, daemon, bot) from a crashed one.
#
# The previous logic was: exit_code == 0 -> BOOTS:YES, anything else ->
# BOOTS:NO. That meant every server, daemon, and bot (which by design
# never exit on their own) was marked "does not boot" — a false
# negative on exactly the repos people most want to triage.
#
# The new logic: if a process times out WITHOUT a crash signature in
# its stderr, it stayed alive — that's a pass for a server. If it also
# printed a readiness signal ("listening on", "started", "ready",
# "Uvicorn running", "Flask running", etc.), we upgrade to a strong
# server-detected YES with the matched signal shown.
# ----------------------------------------------------------------------
READINESS_SIGNAL_PATTERNS = [
    re.compile(r'listening\s+on\s+(?:port\s+)?\d+', re.IGNORECASE),
    re.compile(r'listening\s+at\s+', re.IGNORECASE),
    re.compile(r'server\s+started', re.IGNORECASE),
    re.compile(r'\bstarted\b.*\bserver\b', re.IGNORECASE),
    re.compile(r'\bready\b.*\b(?:listen|serv|accept)', re.IGNORECASE),
    re.compile(r'uvicorn\s+running', re.IGNORECASE),
    re.compile(r'flask\s+running', re.IGNORECASE),
    re.compile(r'gunicorn\s+\(?:starting|booting\)', re.IGNORECASE),
    re.compile(r'serving\s+(?:on|at)\s+', re.IGNORECASE),
    re.compile(r'bound\s+to\s+(?:port\s+)?\d+', re.IGNORECASE),
    re.compile(r'app\s+running', re.IGNORECASE),
    re.compile(r'webpack\s+(?:compiled|dev.*server)', re.IGNORECASE),
    re.compile(r'now\s+listening', re.IGNORECASE),
    re.compile(r'connected\s+to\s+database', re.IGNORECASE),
    re.compile(r'worker\s+(?:started|ready)', re.IGNORECASE),
]

# Crash signatures — if any of these appear in stderr, the process
# genuinely failed (not just timed out). Their presence overrides the
# "timed out = stayed alive = pass" rule.
CRASH_SIGNATURES = [
    'traceback (most recent call last)',
    'panic:',
    'fatal error:',
    'uncaught exception',
    'segmentation fault',
    'core dumped',
    'error: ',
    'killed',
    'out of memory',
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
    # True when the stack had NO runnable entrypoint candidates at all
    # (e.g. a pyproject.toml-only library like `click` or `markupsafe`).
    # This is distinct from a crash — it means there was nothing to run.
    # Used by analyze_result to produce a neutral verdict instead of red.
    no_candidates: bool = False


@dataclass
class Verdict:
    """Final verdict printed to the user."""
    boots: bool
    network_egress_blocked: bool
    filesystem_read_only: bool
    stdout_preview: str
    stderr_preview: str
    warnings: list[str] = field(default_factory=list)
    # Human-readable one-liner explaining WHY boots is YES or NO.
    # Examples: "exited 0", "long-running process (timed out at 30s, no crash)",
    #           "server detected: listening on port 8080", "exited 1 (crash)"
    detail: str = ""
    # True when the repo was detected as a known stack but had NO runnable
    # entrypoint (e.g. a pyproject.toml-only library). This gets a NEUTRAL
    # yellow verdict instead of red — a library is not slop, it just has
    # nothing to run. Without this, `click` and `markupsafe` would show
    # the same red as an SSH-key-stealing malware repo, which erodes trust.
    no_entrypoint: bool = False


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

def _detect_node_entrypoints(repo_path: Path) -> list[list[str]]:
    """Read package.json to pick entrypoints deterministically.

    Order of preference (matches how Node developers actually structure
    apps):
      1. scripts.start     (npm start — the manifest's own declaration)
      2. main field        (node <main> — the manifest's own declaration)
      3. bin field         (node <bin> — CLI tools)
      4. index.js          (Node convention)
      5. app.js            (common alt)
      6. server.js         (server convention)
      7. main.js           (alt convention)

    Falls back gracefully if package.json is malformed — never raises.
    """
    import json
    candidates: list[list[str]] = []
    try:
        pkg = json.loads((repo_path / "package.json").read_text())
    except (OSError, ValueError):
        pkg = {}

    scripts = pkg.get("scripts", {}) or {}
    if isinstance(scripts, dict) and "start" in scripts:
        candidates.append(["npm", "start"])

    main = pkg.get("main")
    if isinstance(main, str) and main:
        candidates.append(["node", main])

    bin_field = pkg.get("bin")
    if isinstance(bin_field, str) and bin_field:
        candidates.append(["node", bin_field])
    elif isinstance(bin_field, dict) and bin_field:
        # Pick the first bin entry deterministically (sorted).
        first = sorted(bin_field.keys())[0]
        candidates.append(["node", bin_field[first]])

    # Convention fallbacks (only added if the file actually exists).
    # Dedup against any candidates already added from package.json fields
    # (e.g. if main="index.js" AND index.js exists, we'd add ["node", "index.js"]
    # twice without this check).
    for f in ("index.js", "app.js", "server.js", "main.js"):
        if (repo_path / f).exists() and ["node", f] not in candidates:
            candidates.append(["node", f])

    # Always try `npm start` last as a final fallback if we haven't
    # already added it from scripts.start — npm start may work even
    # without a scripts.start if npm's defaults resolve.
    if ["npm", "start"] not in candidates:
        candidates.append(["npm", "start"])

    return candidates


def _resolve_console_script(name: str, target: str) -> list[str]:
    """Convert a console_scripts entry to a runnable `python -c` command.

    Console scripts are declared as `name = "pkg.mod:func"` in
    pyproject.toml [project.scripts] or setup.cfg console_scripts.
    The standard generated wrapper does:
        from pkg.mod import func
        sys.exit(func())
    We replicate that via `python -c` so we don't need to install the
    package — just have it importable on PYTHONPATH.

    Handles:
      - "pkg.mod:func"       -> importlib.import_module('pkg.mod'); .func()
      - "pkg.mod:obj.method" -> importlib.import_module('pkg.mod'); .obj.method()
      - "pkg.mod" (Poetry)   -> treated as "pkg.mod:main" (Poetry convention)

    Sets sys.argv=[name] so Click/Typer apps don't try to parse `-c`
    as a CLI argument.
    """
    if ":" in target:
        module, attr_path = target.split(":", 1)
    else:
        # Poetry shorthand: bare module means module:main
        module, attr_path = target, "main"

    # Build the Python -c code. Using importlib.import_module handles
    # dotted module paths correctly. getattr chain handles dotted attrs.
    code = (
        f"import sys; sys.argv=['{name}']; "
        f"import importlib; "
        f"obj = importlib.import_module('{module}')"
    )
    for attr in attr_path.split("."):
        code += f"; obj = getattr(obj, '{attr}')"
    code += "; sys.exit(obj())"
    return ["python", "-c", code]


def _parse_toml_console_scripts(repo_path: Path) -> dict[str, str]:
    """Parse pyproject.toml for console_scripts entries.

    Returns {name: target} dict, e.g. {"mytool": "mytool.cli:app"}.
    Handles both PEP 621 [project.scripts] and Poetry [tool.poetry.scripts].

    Uses tomllib (3.11+) or tomli (3.10) if available; falls back to a
    regex parser for 3.10 without tomli installed.
    """
    pyproject = repo_path / "pyproject.toml"
    if not pyproject.exists():
        return {}
    try:
        text = pyproject.read_text()
    except OSError:
        return {}

    # Try tomllib (stdlib 3.11+) or tomli (3.10 backport).
    data = None
    try:
        import tomllib
        data = tomllib.loads(text)
    except ImportError:
        try:
            import tomli
            data = tomli.loads(text)
        except ImportError:
            pass  # Fall through to regex

    if data is not None:
        scripts: dict[str, str] = {}
        # PEP 621: [project.scripts]
        project_scripts = data.get("project", {}).get("scripts", {})
        if isinstance(project_scripts, dict):
            scripts.update(project_scripts)
        # Poetry: [tool.poetry.scripts]
        poetry_scripts = data.get("tool", {}).get("poetry", {}).get("scripts", {})
        if isinstance(poetry_scripts, dict):
            scripts.update(poetry_scripts)
        return scripts

    # Regex fallback for 3.10 without tomli.
    return _regex_parse_toml_scripts(text)


def _regex_parse_toml_scripts(text: str) -> dict[str, str]:
    """Fallback regex parser for [project.scripts] / [tool.poetry.scripts]."""
    scripts: dict[str, str] = {}
    for table_name in ("project.scripts", "tool.poetry.scripts"):
        # Match the table header and capture lines until the next [table].
        pattern = rf'\[{re.escape(table_name)}\]\s*\n((?:[^\[]*))'
        m = re.search(pattern, text)
        if m:
            for line in m.group(1).splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    parts = line.split("=", 1)
                    key = parts[0].strip().strip('"\'')
                    val = parts[1].strip().strip('"\'')
                    if key and val:
                        scripts[key] = val
    return scripts


def _parse_setup_cfg_console_scripts(repo_path: Path) -> dict[str, str]:
    """Parse setup.cfg [options.entry_points] console_scripts."""
    setup_cfg = repo_path / "setup.cfg"
    if not setup_cfg.exists():
        return {}
    try:
        import configparser
        cp = configparser.ConfigParser()
        cp.read(setup_cfg)
        if "options.entry_points" not in cp:
            return {}
        ep_text = cp["options.entry_points"].get("console_scripts", "")
        scripts: dict[str, str] = {}
        for line in ep_text.strip().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                parts = line.split("=", 1)
                key = parts[0].strip()
                val = parts[1].strip()
                if key and val:
                    scripts[key] = val
        return scripts
    except Exception:
        return {}


def _parse_setup_py_console_scripts(repo_path: Path) -> dict[str, str]:
    """Regex-parse setup.py for console_scripts entry_points.

    setup.py is arbitrary Python, so we can't fully parse it. We regex
    for the common `console_scripts` list pattern. This is deliberately
    conservative — it only matches within a console_scripts context.
    """
    setup_py = repo_path / "setup.py"
    if not setup_py.exists():
        return {}
    try:
        text = setup_py.read_text()
    except OSError:
        return {}

    scripts: dict[str, str] = {}
    # Find console_scripts blocks and parse entries from them.
    # Matches: console_scripts=[...] or console_scripts: [...]
    cs_pattern = r'console_scripts["\']?\s*[=:]\s*\[([^\]]+)\]'
    for cs_match in re.finditer(cs_pattern, text):
        section = cs_match.group(1)
        entry_pattern = r'["\'](\w[\w-]*)\s*=\s*([\w.]+(?::[\w.]+)?)["\']'
        for m in re.finditer(entry_pattern, section):
            scripts[m.group(1)] = m.group(2)
    return scripts


def _detect_python_entrypoints(repo_path: Path) -> list[list[str]]:
    """Pick Python entrypoints by scanning for common boot files.

    Covers (in priority order):
      1. main.py / app.py / server.py / run.py at root  (scripts)
      2. manage.py at root                              (Django — run `check`)
      3. src/main.py / src/app.py                       (src-layout packages)
      4. __main__.py at root or in a top-level dir      (python -m <pkg>)
      5. [project.scripts] in pyproject.toml            (modern CLI entry points)
         [tool.poetry.scripts] in pyproject.toml          (Poetry)
         console_scripts in setup.cfg / setup.py          (legacy)

    Item 5 is the fix for the "modern CLI mislabeled as library" bug:
    a Typer/Click app that declares its entrypoint ONLY in
    [project.scripts] (no main.py) was coming back with empty candidates
    and getting the yellow library verdict. Now we parse the scripts
    table and resolve `pkg.mod:func` to a runnable `python -c` command.

    Django's `manage.py` with no args exits non-zero (prints usage), so
    for manage.py we run `manage.py check` which exits 0 if the Django
    project is correctly wired.
    """
    candidates: list[list[str]] = []

    # 1. Root-level scripts.
    for f in ("main.py", "app.py", "server.py", "run.py"):
        if (repo_path / f).exists():
            candidates.append(["python", f])

    # 2. Django — `manage.py check` verifies the project loads.
    if (repo_path / "manage.py").exists():
        candidates.append(["python", "manage.py", "check"])

    # 3. src-layout.
    for f in ("src/main.py", "src/app.py"):
        if (repo_path / f).exists():
            candidates.append(["python", f])

    # 4. python -m <pkg> via __main__.py.
    if (repo_path / "__main__.py").exists():
        candidates.append(["python", "__main__.py"])
    else:
        # Look for a top-level dir with __main__.py — that's `python -m <pkg>`.
        # Do NOT require __init__.py: PEP 420 namespace packages are valid.
        for entry in sorted((repo_path).iterdir()):
            if entry.is_dir() and not entry.name.startswith('.') \
                    and (entry / "__main__.py").exists():
                candidates.append(["python", "-m", entry.name])
                break  # one is enough; deterministic via sorted()

    # 5. Console scripts from pyproject.toml / setup.cfg / setup.py.
    # This is how modern Python CLIs declare their entrypoint — not via
    # main.py, but via [project.scripts] in pyproject.toml. Without this,
    # a real CLI (Typer/Click app with a console_scripts entry, no main.py)
    # would be mislabeled as a library (yellow NO RUNNABLE ENTRYPOINT).
    console_scripts: dict[str, str] = {}
    console_scripts.update(_parse_toml_console_scripts(repo_path))
    console_scripts.update(_parse_setup_cfg_console_scripts(repo_path))
    console_scripts.update(_parse_setup_py_console_scripts(repo_path))
    for name, target in sorted(console_scripts.items()):
        candidates.append(_resolve_console_script(name, target))

    # Dedup while preserving order.
    seen: set[tuple[str, ...]] = set()
    unique: list[list[str]] = []
    for c in candidates:
        t = tuple(c)
        if t not in seen:
            seen.add(t)
            unique.append(c)
    return unique


def detect_stack(repo_path: Path) -> Optional[StackProfile]:
    """
    Detect project stack by checking for marker files in the repo root.
    Returns None if no supported stack is found.

    SECURITY NOTE on install commands:
      The install phase runs with network ON (it has to, to fetch
      packages). That creates a supply-chain window: a malicious
      package.json can declare preinstall/postinstall scripts that
      execute arbitrary code with network access for up to 60 seconds.
      We close that window for npm with --ignore-scripts (lifecycle
      scripts are NOT executed; packages are still fetched and written
      to node_modules). For pip we use --prefer-binary to push toward
      wheels (no setup.py / PEP 517 build execution); sdist builds
      remain a residual risk documented in the README.
    """
    # Node.js
    if (repo_path / "package.json").exists():
        return StackProfile(
            name="Node.js",
            image="node:20-slim",
            # --ignore-scripts: do NOT run preinstall/postinstall/install
            # lifecycle scripts. They would execute with network ON for
            # up to 60s — the exact attack vector this tool exists to
            # catch. Packages are still fetched and unpacked.
            install_cmd=[
                "npm", "install", "--ignore-scripts",
                "--prefix", "/tmp/npm_cache",
            ],
            run_candidates=_detect_node_entrypoints(repo_path),
            env={"NODE_PATH": "/tmp/npm_cache/node_modules"},
            deps_mount="/tmp/npm_cache",
        )

    # Python — requirements.txt OR pyproject.toml OR setup.py OR any
    # recognized Python entrypoint file OR a top-level package with
    # __main__.py (python -m <pkg>).
    #
    # pyproject.toml is the dominant Python project format in 2026
    # (Poetry, Hatch, PDM, uv, modern setuptools). Without it, the tool
    # would miss the majority of real modern Python repos.
    py_entry_files = ("main.py", "app.py", "server.py", "run.py",
                      "manage.py", "__main__.py")
    has_python_entry = any((repo_path / f).exists() for f in py_entry_files) \
        or (repo_path / "src/main.py").exists() \
        or (repo_path / "src/app.py").exists()
    # Also detect: a top-level dir with __main__.py (python -m <pkg>).
    # Do NOT require __init__.py — PEP 420 namespace packages are valid.
    if not has_python_entry:
        for entry in sorted(repo_path.iterdir()):
            if entry.is_dir() and not entry.name.startswith('.') \
                    and (entry / "__main__.py").exists():
                has_python_entry = True
                break
    has_python_marker = (
        (repo_path / "requirements.txt").exists()
        or (repo_path / "pyproject.toml").exists()
        or (repo_path / "setup.py").exists()
        or (repo_path / "setup.cfg").exists()
        or has_python_entry
    )
    if has_python_marker:
        install_cmd: list[str] = []
        if (repo_path / "requirements.txt").exists():
            # --prefer-binary: prefer wheels over sdists. Wheels don't
            # execute setup.py / PEP 517 build backends, so this avoids
            # most arbitrary-code-during-install risk. sdist-only
            # packages still trigger a build (residual risk; see README).
            install_cmd = [
                "pip", "install", "--no-cache-dir", "--prefer-binary",
                "-r", "requirements.txt",
                "-t", "/tmp/pip_deps",
            ]
        return StackProfile(
            name="Python",
            image="python:3.11-slim",
            install_cmd=install_cmd,
            run_candidates=_detect_python_entrypoints(repo_path),
            env={
                "PYTHONPATH": "/tmp/pip_deps",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            deps_mount="/tmp/pip_deps" if install_cmd else None,
        )

    # Go — EXPERIMENTAL.
    # go run main.go under --network none can't fetch modules. Only
    # repos with a vendor/ directory or zero external deps will boot.
    # See README Limitations section.
    if (repo_path / "go.mod").exists():
        return StackProfile(
            name="Go (experimental)",
            image="golang:1.22-alpine",
            install_cmd=[],
            run_candidates=[["go", "run", "main.go"]],
            env={"GOFLAGS": "-mod=vendor", "GOPATH": "/tmp/go"},
            deps_mount=None,
        )

    # Rust — EXPERIMENTAL.
    # cargo run must compile offline under --network none within 30s at
    # 0.5 CPU. Only tiny zero-dep crates or pre-vendored projects boot.
    # See README Limitations section.
    if (repo_path / "Cargo.toml").exists():
        return StackProfile(
            name="Rust (experimental)",
            image="rust:1.75-slim",
            install_cmd=[],
            run_candidates=[["cargo", "run", "--offline"]],
            env={"CARGO_NET_OFFLINE": "true"},
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
    return _run_command(["docker", *args], timeout)


def _run_command(cmd: list[str], timeout: int) -> ExecutionResult:
    """Run an arbitrary command with timeout, capture stdout/stderr/exit_code.

    Shared by run_docker() and the native (bubblewrap) backend.
    """
    try:
        proc = subprocess.run(
            cmd,
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


# ----------------------------------------------------------------------
# Native sandbox backend (bubblewrap) — no Docker required
# ----------------------------------------------------------------------
#
# This is the adoption-tax fix. On Linux with bubblewrap installed,
# `repo-proofer <url>` runs in seconds with NO Docker daemon, NO image
# pulls, NO derived image builds. The sandbox is just as locked down:
#   --unshare-net       = no network (the moat)
#   --ro-bind /usr ...  = read-only host filesystem
#   --tmpfs /tmp        = writable in-memory /tmp
#   --tmpfs /home       = empty /home (SSH keys inaccessible)
#   --tmpfs /root       = empty /root (root's SSH keys inaccessible)
#
# strace runs natively on the host — no derived strace image needed.
#
# Limitations vs Docker:
#   - Linux only (bubblewrap doesn't exist on macOS/Windows)
#   - No memory/CPU limits (bubblewrap has no built-in cgroup controls)
#   - Uses host runtimes (not clean-room images)
# The security moat (network + filesystem isolation) is fully intact.

def check_bubblewrap() -> bool:
    """Check if bubblewrap (bwrap) is available on the host."""
    return shutil.which("bwrap") is not None


def check_strace() -> bool:
    """Check if strace is available on the host."""
    return shutil.which("strace") is not None


def check_host_runtime(stack: StackProfile) -> tuple[bool, str]:
    """Check if the host has the required runtime for the stack.

    Returns (ok, message). For native mode, we use the HOST's language
    runtimes instead of pulling Docker images.
    """
    if stack.name == "Python":
        if shutil.which("python3"):
            return True, "python3"
        return False, "python3 not found on PATH (install Python 3.10+)"
    elif stack.name == "Node.js":
        if shutil.which("node") and shutil.which("npm"):
            return True, "node"
        return False, "node/npm not found on PATH (install Node.js 18+)"
    elif "Go" in stack.name:
        if shutil.which("go"):
            return True, "go"
        return False, "go not found on PATH (install Go 1.22+)"
    elif "Rust" in stack.name:
        if shutil.which("cargo"):
            return True, "cargo"
        return False, "cargo not found on PATH (install Rust 1.75+)"
    return False, f"Unknown stack: {stack.name}"


def _native_adapt_cmd(cmd: list[str], stack_name: str) -> list[str]:
    """Adapt a Docker-mode command for native (host) execution.

    On the host, `python` is often `python3`, and `pip` should be
    `python3 -m pip` to avoid PATH issues. Node/Go/Rust commands
    pass through unchanged.
    """
    if not cmd:
        return cmd
    if stack_name == "Python":
        if cmd[0] == "python":
            return ["python3"] + cmd[1:]
        if cmd[0] == "pip":
            return ["python3", "-m", "pip"] + cmd[1:]
    return cmd


def _build_bwrap_args(
    repo_path: Path,
    stack: StackProfile,
    deps_dir: Optional[Path],
    trace_dir: Optional[Path],
    network: bool,
    deps_writable: bool,
) -> list[str]:
    """Build the common bubblewrap args for both install and execute.

    Security properties (identical to Docker sandbox):
      - Read-only host filesystem (--ro-bind /usr, /lib, /bin, /etc, ...)
      - Empty /home and /root (--tmpfs) so SSH keys are INACCESSIBLE
      - Writable /tmp via tmpfs (--tmpfs /tmp)
      - No network during execute (--unshare-net)
      - No capabilities (bubblewrap drops all by default)

    The repo is always mounted read-only at /app.
    Deps are mounted writable during install, read-only during execute.
    """
    args: list[str] = [
        "bwrap",
        # Read-only host filesystem — the app can READ system libs
        # but can't WRITE anywhere except /tmp and mounted dirs.
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/sbin", "/sbin",
        "--ro-bind", "/etc", "/etc",
    ]

    # lib64 may not exist on all architectures
    if Path("/lib64").exists():
        args += ["--ro-bind", "/lib64", "/lib64"]
    # /opt may not exist
    if Path("/opt").exists():
        args += ["--ro-bind", "/opt", "/opt"]

    args += [
        # Fresh /dev and /proc (don't expose host's)
        "--dev", "/dev",
        "--proc", "/proc",
        # Writable in-memory /tmp (like Docker's --tmpfs /tmp)
        "--tmpfs", "/tmp",
        # EMPTY /home and /root — SSH keys, .aws/credentials, .env etc.
        # are completely inaccessible. The app can't read them even if
        # strace is bypassed. Reads of ~/.ssh/id_rsa return ENOENT.
        # strace still catches the ATTEMPT (the openat syscall fires
        # before the ENOENT), so the sensitive-access detector works.
        "--tmpfs", "/home",
        "--tmpfs", "/root",
        "--tmpfs", "/run",
        # Cleanup + isolation
        "--die-with-parent",
        "--new-session",
        # Repo mounted read-only at /app
        "--ro-bind", str(repo_path), "/app",
        "--chdir", "/app",
    ]

    # Network isolation — ONLY during execute. Install needs network.
    if not network:
        args.append("--unshare-net")

    # Deps mount
    if stack.deps_mount and deps_dir is not None:
        if deps_writable:
            args += ["--bind", str(deps_dir), stack.deps_mount]
        else:
            args += ["--ro-bind", str(deps_dir), stack.deps_mount]

    # Trace mount (writable — strace writes trace files here)
    if trace_dir is not None:
        args += ["--bind", str(trace_dir), "/trace"]

    # Environment variables
    for key, value in stack.env.items():
        args += ["--setenv", key, value]

    return args


def native_install_deps(
    stack: StackProfile,
    repo_path: Path,
    deps_dir: Path,
) -> Optional[ExecutionResult]:
    """Run the install command in a bubblewrap sandbox with network ON.

    Same security model as Docker install_deps():
    - Read-only root filesystem
    - Repo mounted read-only
    - Deps dir mounted writable (persists to host for the exec phase)
    - Network ON (needed to fetch packages)
    - Empty /home and /root (no SSH keys exposed during install)
    """
    if not stack.install_cmd:
        return None

    args = _build_bwrap_args(
        repo_path, stack, deps_dir, trace_dir=None,
        network=True, deps_writable=True,
    )
    args.append("--")
    args.extend(_native_adapt_cmd(stack.install_cmd, stack.name))

    return _run_command(args, timeout=INSTALL_TIMEOUT_SEC)


def native_execute_entrypoint(
    stack: StackProfile,
    repo_path: Path,
    deps_dir: Optional[Path],
    trace_dir: Optional[Path] = None,
) -> ExecutionResult:
    """Run the project entrypoint in a bubblewrap sandbox.

    CRITICAL SECURITY CONSTRAINTS (same as Docker execute_entrypoint):
      --unshare-net         Absolutely no internet access.
      --ro-bind /usr ...    Read-only host filesystem.
      --tmpfs /home         Empty /home (SSH keys inaccessible).
      --tmpfs /root         Empty /root.
      --tmpfs /tmp          Writable in-memory /tmp.
      --ro-bind repo /app   Repo mounted READ-ONLY.

    No capabilities (bubblewrap drops all by default). No memory/CPU
    limits (bubblewrap has no built-in cgroup controls — see docs).

    If trace_dir is provided, strace wraps the entrypoint. strace runs
    natively on the host — no derived image needed (unlike Docker mode).
    """
    use_strace = trace_dir is not None

    # If the stack has NO runnable entrypoint, return immediately.
    if not stack.run_candidates:
        return ExecutionResult(
            stdout="",
            stderr="No runnable entrypoint found. This looks like a library.",
            exit_code=127,
            no_candidates=True,
        )

    base_args = _build_bwrap_args(
        repo_path, stack, deps_dir, trace_dir,
        network=False, deps_writable=False,
    )

    if use_strace:
        # strace runs on the host, wraps the entrypoint.
        # Same -ff (follow forks) and -e (syscall filter) as Docker mode.
        base_args += ["--"]
        strace_prefix = [
            "strace", "-ff",
            "-e", "trace=openat,open,openat2,creat,execve,execveat,connect,socket,unlink,unlinkat",
            "-o", "/trace/trace",
            "--",
        ]
    else:
        base_args += ["--"]
        strace_prefix = []

    # Try each run candidate (same fallback logic as Docker mode)
    last_result: Optional[ExecutionResult] = None
    for candidate in stack.run_candidates:
        native_cmd = _native_adapt_cmd(candidate, stack.name)
        full_args = base_args + strace_prefix + native_cmd
        result = _run_command(full_args, timeout=EXEC_TIMEOUT_SEC)

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
        no_candidates=True,
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
    # If the stack has NO runnable entrypoint candidates (e.g. a library
    # like `click` that ships pyproject.toml but no main.py/server.py/etc),
    # return immediately with no_candidates=True. analyze_result uses this
    # to produce a neutral yellow verdict instead of red — a library is
    # not slop, it just has nothing to run.
    if not stack.run_candidates:
        return ExecutionResult(
            stdout="",
            stderr="No runnable entrypoint found. This looks like a library.",
            exit_code=127,
            no_candidates=True,
        )

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
        no_candidates=True,
    )


# ----------------------------------------------------------------------
# Analysis — deterministic, regex-based
# ----------------------------------------------------------------------

def analyze_result(result: ExecutionResult) -> Verdict:
    """Produce a verdict from the execution result. 100% deterministic.

    BOOTS semantics (readiness-aware, not just exit-code-aware):

      no candidates (library)        -> NEUTRAL     ("no runnable entrypoint
                                                     (looks like a library)")
      exit 0 (clean exit)            -> BOOTS: YES  ("exited 0")
      timed out, no crash signature  -> BOOTS: YES  ("long-running process
                                                    (timed out at Ns,
                                                     no crash detected)")
      timed out, crash signature     -> BOOTS: NO   ("crashed before timeout")
      timed out + readiness signal   -> BOOTS: YES  ("server detected: <signal>")
      non-zero exit, not timeout     -> BOOTS: NO   ("exited <code> (crash)")

    The previous logic (`boots = exit_code == 0`) marked every server,
    daemon, and bot as BOOTS: NO because they don't exit on their own.
    That's a false negative on exactly the repos people most want to
    triage. A process that stays alive for the full timeout without
    crashing HAS booted — it's just long-running.

    A separate case: when the stack has NO runnable entrypoint at all
    (a library like `click` or `markupsafe` — pyproject.toml but no
    main.py), we produce a NEUTRAL verdict, not red. A library is not
    slop; showing it the same red as SSH-key-stealing malware erodes
    trust. The `no_entrypoint` flag drives a yellow display color and
    exit code 0 in main().

    Readiness signals ("listening on port 8080", "Uvicorn running",
    "server started", etc.) upgrade a timeout from "long-running" to
    "server detected" so the user gets more signal.
    """
    # ---- Library / no-entrypoint case ----
    # Short-circuit before any crash/network analysis. A library that
    # was detected but has nothing to run is not a failure.
    if result.no_candidates:
        return Verdict(
            boots=False,
            network_egress_blocked=True,
            filesystem_read_only=True,
            stdout_preview=result.stdout[:MAX_STDOUT_CHARS],
            stderr_preview=result.stderr[:MAX_STDERR_CHARS],
            warnings=[],
            detail="no runnable entrypoint (looks like a library)",
            no_entrypoint=True,
        )

    warnings: list[str] = []
    combined = result.stdout + "\n" + result.stderr
    combined_lower = combined.lower()

    # Network-error detection (unchanged — still deterministic regex).
    network_blocked = bool(NETWORK_ERROR_RE.search(combined))
    if network_blocked:
        warnings.append(
            "App crashed when network was blocked. "
            "May require external API to function."
        )

    # Readiness-signal detection — only meaningful for long-running procs.
    readiness_signal: Optional[str] = None
    for pat in READINESS_SIGNAL_PATTERNS:
        m = pat.search(combined)
        if m:
            readiness_signal = m.group(0).strip()
            break

    # Crash-signature detection — distinguishes a real crash from a
    # healthy long-running process that hit the timeout.
    crashed = any(sig in combined_lower for sig in CRASH_SIGNATURES)

    # ---- Determine boots + detail ----
    if result.exit_code == 0:
        boots = True
        detail = "exited 0"
    elif result.timed_out:
        # Timeout: the process didn't exit on its own.
        if crashed:
            # It crashed (traceback/panic/etc.) before the timeout fired.
            boots = False
            detail = f"crashed before {EXEC_TIMEOUT_SEC}s timeout"
            warnings.append(
                f"Process crashed within the {EXEC_TIMEOUT_SEC}s "
                f"execution window."
            )
        elif readiness_signal:
            # Stayed alive AND printed a readiness line -> strong server YES.
            boots = True
            detail = f"server detected: {readiness_signal}"
        else:
            # Stayed alive with no crash and no readiness signal.
            # This is the honest default for daemons/servers/bots.
            # Could also be a silent infinite loop, but a false positive
            # ("yes, it ran" for a hung loop) is less damaging than a
            # false negative ("no" for a real server), because the user
            # sees the timeout note and can investigate further.
            boots = True
            detail = (f"long-running process (timed out at "
                      f"{EXEC_TIMEOUT_SEC}s, no crash detected)")
            warnings.append(
                f"Process did not exit within {EXEC_TIMEOUT_SEC}s. "
                f"Treated as a healthy long-running process (server/daemon). "
                f"Use --keep-clone to inspect manually if unsure."
            )
    else:
        # Non-zero exit, not a timeout — genuine crash or arg-error.
        boots = False
        detail = f"exited {result.exit_code} (crash)"

    return Verdict(
        boots=boots,
        network_egress_blocked=True,    # We always block.
        filesystem_read_only=True,      # We always mount read-only.
        stdout_preview=result.stdout[:MAX_STDOUT_CHARS],
        stderr_preview=result.stderr[:MAX_STDERR_CHARS],
        warnings=warnings,
        detail=detail,
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
    # Three-color verdict system:
    #   GREEN  — BOOTS: YES (clean exit, long-running, or server detected)
    #   RED    — BOOTS: NO (crashed, network-blocked, sensitive access)
    #   YELLOW — NO RUNNABLE ENTRYPOINT (library, nothing to run)
    # The yellow state is critical for trust: without it, a library like
    # `click` shows the same red as SSH-key-stealing malware, and a
    # skeptical first user concludes the tool is broken.
    if verdict.no_entrypoint:
        boots_str = "[bold yellow]NO RUNNABLE ENTRYPOINT[/bold yellow]"
    elif verdict.boots:
        boots_str = "[bold green]YES[/bold green]"
    else:
        boots_str = "[bold red]NO[/bold red]"

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column()
    table.add_row("Repository", repo_url)
    table.add_row("Detected Stack", stack_name)
    table.add_row("BOOTS", boots_str)
    if verdict.detail:
        table.add_row("Detail", f"[dim]{verdict.detail}[/dim]")
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

def _select_backend(
    preference: str, stack: Optional[StackProfile]
) -> str:
    """Select the sandbox backend: 'native' (bubblewrap) or 'docker'.

    Preference can be 'auto', 'native', or 'docker'.
    In auto mode, prefer native (faster, no Docker) and fall back to
    Docker if bubblewrap or the required host runtime is unavailable.
    """
    if preference == "docker":
        return "docker"

    if preference == "native":
        if not check_bubblewrap():
            console.print(
                "[red]Error: --sandbox native requires bubblewrap (bwrap) "
                "on Linux. Use --sandbox docker instead.[/red]"
            )
            raise typer.Exit(code=3)
        if stack is not None:
            ok, msg = check_host_runtime(stack)
            if not ok:
                console.print(f"[red]Error: {msg}[/red]")
                raise typer.Exit(code=3)
        return "native"

    # auto: prefer native, fall back to Docker
    if check_bubblewrap():
        if stack is None:
            return "native"  # can't check runtime yet — will re-check later
        ok, msg = check_host_runtime(stack)
        if ok:
            return "native"
        console.print(
            f"[yellow]Host runtime for {stack.name} not found ({msg}). "
            f"Falling back to Docker.[/yellow]"
        )
    return "docker"


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
    sandbox: str = typer.Option(
        "auto",
        "--sandbox",
        help=(
            "Sandbox backend: 'auto' (default, prefer native bubblewrap), "
            "'native' (bubblewrap, no Docker needed, Linux only), or "
            "'docker' (full Docker isolation)."
        ),
    ),
) -> None:
    """Clone, sandbox, and execute a Git repo. Brutal honest verdict."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="repo-proofer-"))
    repo_dir = tmp_dir / "repo"
    deps_dir: Optional[Path] = None
    trace_dir: Optional[Path] = None
    backend: str = "docker"  # determined after stack detection

    try:
        # ---- Step 0: Quick backend availability check -------------
        # Full selection happens after stack detection (need to check
        # host runtime for native mode). But we can fail fast if the
        # user explicitly requested a backend that's clearly unavailable.
        if sandbox == "native" and not check_bubblewrap():
            console.print(
                "[red]Error: --sandbox native requires bubblewrap (bwrap) "
                "on Linux. Use --sandbox auto or --sandbox docker.[/red]"
            )
            raise typer.Exit(code=3)
        if sandbox == "docker":
            console.print("[dim]Checking Docker daemon...[/dim]")
            check_docker_running()

        # ---- Step 1: Clone (depth=1) --------------------------------
        # Note: errors are captured and printed AFTER the Progress
        # context exits. Printing inside an active Progress context
        # causes the spinner line and the error to interleave, which
        # looks broken to the user.
        clone_error: Optional[str] = None
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
                clone_error = e.stderr.strip() if e.stderr else str(e)
            except Exception as e:
                clone_error = str(e)

        if clone_error:
            console.print(f"[red]Clone failed: {clone_error}[/red]")
            raise typer.Exit(code=2)

        # ---- Step 2: Detect stack -----------------------------------
        stack = detect_stack(repo_dir)
        if stack is None:
            console.print(
                "[red]Error: Could not detect project stack.[/red]\n"
                "[dim]Supported markers: package.json, "
                "requirements.txt, pyproject.toml, setup.py, setup.cfg, "
                "main.py, go.mod, Cargo.toml[/dim]"
            )
            raise typer.Exit(code=4)

        # ---- Step 2b: Select sandbox backend -----------------------
        # Now that we know the stack, we can check if the host has the
        # required runtime for native mode.
        backend = _select_backend(sandbox, stack)

        if backend == "native":
            console.print(
                f"[cyan]Detected stack:[/cyan] [bold]{stack.name}[/bold] "
                f"| [green]Native sandbox (bubblewrap)[/green]"
            )
        else:
            console.print(
                f"[cyan]Detected stack:[/cyan] [bold]{stack.name}[/bold] "
                f"(image: {stack.image}) | [blue]Docker sandbox[/blue]"
            )

        # ---- Step 3: Prepare sandbox --------------------------------
        exec_image = stack.image  # only used for Docker backend
        if backend == "docker":
            ensure_image_pulled(stack.image)
            # Build strace-enabled derived image (cached on subsequent runs)
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
        else:
            # Native: strace runs on the host directly, no image build.
            if not no_behavior_report:
                if check_strace():
                    trace_dir = Path(tempfile.mkdtemp(prefix="repo-proofer-trace-"))
                else:
                    console.print(
                        "[yellow]strace not found on host — "
                        "Runtime Behavior Report disabled.[/yellow]"
                    )

        # ---- Step 4: Install deps (network ON) ---------------------
        install_result: Optional[ExecutionResult] = None
        if stack.install_cmd:
            deps_dir = Path(tempfile.mkdtemp(prefix="repo-proofer-deps-"))
            try:
                deps_dir.chmod(0o777)
            except PermissionError:
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
                if backend == "docker":
                    install_result = install_deps(stack, repo_dir, deps_dir)
                else:
                    install_result = native_install_deps(stack, repo_dir, deps_dir)

            if install_result.exit_code != 0:
                console.print(
                    f"[yellow]Install step exited {install_result.exit_code}. "
                    "Proceeding to execution anyway (no auto-repair).[/yellow]"
                )

        # ---- Step 5: Execute (network OFF, read-only FS) -----------
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
            if backend == "docker":
                exec_result = execute_entrypoint(
                    stack, exec_image, repo_dir, deps_dir, trace_dir,
                )
            else:
                exec_result = native_execute_entrypoint(
                    stack, repo_dir, deps_dir, trace_dir,
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

        # ---- Step 6b: Sensitive-access escalation ------------------
        # Sensitive file access is ALWAYS a hard fail, regardless of
        # whether the app crashed or exited cleanly. The previous logic
        # only escalated when boots=True, which meant a crashing repo
        # that read ~/.ssh/id_rsa would never trigger the escalation —
        # its sensitive access was buried under a crash verdict.
        #
        # Now: if strace caught ANY sensitive-path access, the exit
        # code is always 1, and the verdict is always NO. If the app
        # exited cleanly, we explicitly escalate. If it already crashed,
        # we foreground the sensitive access as the primary indicator.
        if behavior_report.sensitive_access:
            if verdict.boots:
                # Clean exit but touched secrets — escalate.
                console.print(
                    "[bold red][!] Escalating verdict to BOOTS: NO — "
                    "sensitive file access detected despite clean exit.[/bold red]"
                )
            else:
                # Already crashed, but sensitive access is the headline.
                console.print(
                    "[bold red][!] Sensitive file access detected — "
                    "primary indicator of malicious intent. "
                    f"Paths: {', '.join(behavior_report.sensitive_access)}[/bold red]"
                )
            raise typer.Exit(code=1)

        # A library (no runnable entrypoint) is not slop — exit 0 so CI
        # doesn't block on library repos. The verdict display is yellow,
        # not red, so the user sees it's a neutral result, not a failure.
        if verdict.no_entrypoint:
            raise typer.Exit(code=0)

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


def cli():
    """Entry point for the repo-proofer console script.

    This function is referenced by pyproject.toml's [project.scripts]
    section, enabling `uvx repo-proofer <url>` and `pipx run repo-proofer <url>`
    after the package is published to PyPI. For local development, use:
        uvx --from . repo-proofer <url>
        # or
        pipx install . && repo-proofer <url>
    """
    typer.run(main)


if __name__ == "__main__":
    cli()
