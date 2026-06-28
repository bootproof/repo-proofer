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

__version__ = "0.5.3"

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

INSTALL_TIMEOUT_SEC = 300   # 5 minutes — large repos (GitLab, Supabase) need this
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

# bind() — extract the port the app tried to listen on. Used by the
# claim-matching layer to verify "starts a server on port 3000" claims.
# strace format: bind(3, {sa_family=AF_INET, sin_port=htons(3000), ...}) = 0
STRACE_BIND_PORT_RE = re.compile(
    r'bind\(\d+,\s*\{sa_family=AF_INET[6]?,\s*'
    r'sin6?_port=htons\((\d+)\)'
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

# Sensitive paths are classified into two severity tiers.
#
# HIGH: paths that indicate credential/key theft if accessed. These are
#   the true exfil signals — SSH keys, .env files, AWS credentials,
#   /etc/shadow (password hashes), Docker/Kube config. Almost nothing
#   benign touches these. HIGH-tier access triggers the "malicious
#   intent" wording ONLY when correlated with a network attempt (the
#   smoking gun for exfiltration). HIGH read + 0 network = suspicious
#   but not confirmed exfil (softer wording).
#
# MEDIUM: paths routinely read by normal operation — package-manager
#   config (.npmrc, .pypirc, .netrc) AND /etc/passwd (read by libc on
#   every getpwnam() call — basically every program that resolves a
#   username or home directory touches it). Flagging these as "malicious
#   intent" was a false alarm that destroyed credibility on legitimate
#   repos like Supabase. MEDIUM-tier access is informational, NOT a fail.
SENSITIVE_PATH_PATTERNS_HIGH = [
    re.compile(r'^/root/\.ssh/'),
    re.compile(r'^/home/[^/]+/\.ssh/'),
    re.compile(r'^/etc/shadow$'),          # password hashes — almost never read benignly
    re.compile(r'^/etc/sudoers'),
    re.compile(r'\.aws/credentials'),
    re.compile(r'\.gnupg/'),
    re.compile(r'\.docker/config\.json'),
    re.compile(r'\.kube/config'),
    re.compile(r'\.git-credentials'),
    re.compile(r'\.env$'),
    re.compile(r'\.env\.'),
]

SENSITIVE_PATH_PATTERNS_MEDIUM = [
    re.compile(r'\.npmrc$'),
    re.compile(r'\.pypirc$'),
    re.compile(r'\.netrc$'),
    re.compile(r'pip\.conf$'),
    re.compile(r'cargo/credentials'),
    re.compile(r'^/etc/passwd$'),          # libc reads this on every getpwnam() — low signal
    re.compile(r'^/etc/nsswitch\.conf$'),  # libc name service config — routine
    re.compile(r'^/etc/hosts$'),           # libc resolver — routine
]

# Backward-compat alias (deprecated — use the tiered lists above)
SENSITIVE_PATH_PATTERNS = SENSITIVE_PATH_PATTERNS_HIGH + SENSITIVE_PATH_PATTERNS_MEDIUM

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


def _extract_missing_command(stderr: str) -> Optional[str]:
    """Extract the missing command name from a 'command not found' stderr.

    Handles common patterns across stacks:
      sh: 1: turbo: not found              (sh/dash — Node/turbo formbricks case)
      bash: turbo: command not found       (bash)
      bundler: command not found: rails    (bundler — Ruby/gitlab case)
      rails: command not found             (generic)
    Returns the command name (e.g. "turbo", "rails") or None.
    """
    # Pattern 1: <shell>: <line>: <cmd>: not found  (sh/dash)
    m = re.search(r'(?:sh|bash|/bin/sh|dash):\s*\d+:\s*([^:]+):\s*(?:not found|command not found)',
                  stderr, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # Pattern 2: bundler: command not found: <cmd>  (Ruby/bundler — the
    # command name comes AFTER "command not found", not before)
    m = re.search(r'bundler:\s*command not found:\s*(\S+)', stderr, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # Pattern 3: <cmd>: command not found  (generic, cmd at start of line)
    m = re.search(r'^([^:\s]+):\s*command not found', stderr, re.IGNORECASE | re.MULTILINE)
    if m:
        return m.group(1).strip()
    # Pattern 4: <cmd>: not found  (shorthand, no "command")
    m = re.search(r'^([^:\s]+):\s*not found', stderr, re.IGNORECASE | re.MULTILINE)
    if m:
        return m.group(1).strip()
    return None


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
    no_candidates: bool = False
    # True when the repo is a monorepo (npm workspaces) with no root
    # entrypoint. Distinguished from a crash: "npm error Missing script:
    # start" on a workspace repo is NOT a crash, it's a missing root
    # entrypoint. Produces a yellow verdict, not red.
    monorepo_no_root_entry: bool = False


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
    # True when the repo is a monorepo (npm workspaces) with no root
    # entrypoint. Same yellow treatment as no_entrypoint — a monorepo
    # isn't slop, it just has no root start script.
    monorepo: bool = False


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
    # Write attempts that were BLOCKED by the read-only filesystem (open
    # returned -1 EROFS/EACCES). Reported honestly as "blocked" not
    # "written" — the Supabase bug counted npm's rejected log write as a
    # successful write, which is dishonest.
    writes_blocked: list[str] = field(default_factory=list)
    processes_spawned: list[str] = field(default_factory=list)
    network_attempts: list[str] = field(default_factory=list)
    # Ports the app tried to bind() — used by claim matching to verify
    # "starts a server on port 3000" type README claims.
    ports_bound: list[str] = field(default_factory=list)
    # HIGH-severity sensitive access: SSH keys, .env, /etc/shadow, AWS
    # creds. Triggers "malicious intent" ONLY when correlated with a
    # network attempt (the exfil smoking gun).
    sensitive_access: list[str] = field(default_factory=list)
    # MEDIUM-severity: package-manager config (.npmrc, .pypirc, .netrc)
    # AND /etc/passwd (read by libc on every getpwnam). Informational.
    medium_sensitive_access: list[str] = field(default_factory=list)
    strace_enabled: bool = False

    @property
    def has_data(self) -> bool:
        return any([
            self.files_read, self.files_written, self.writes_blocked,
            self.processes_spawned, self.network_attempts,
            self.ports_bound,
            self.sensitive_access, self.medium_sensitive_access,
        ])


# ----------------------------------------------------------------------
# Claim extraction — deterministic, regex-based, NO LLMs
# ----------------------------------------------------------------------
#
# The original vision asked for "N of M README claims observed to
# execute." This is the layer that delivers it — without any AI.
#
# We extract TESTABLE assertions from the README using regex patterns:
# port numbers, database services, API integrations, install/run
# commands, file types, frameworks. Each claim is then matched against
# the runtime evidence (strace trace, stdout, exit code).
#
# Three possible verdicts per claim:
#   VERIFIED     — runtime evidence supports the claim
#   UNVERIFIED   — no evidence found (claim might be true under
#                  different conditions, but we didn't observe it)
#   UNVERIFIABLE — we can't check this claim type with our tools

# Regex patterns for claim extraction. Each is (pattern, claim_type).
# The claim_type determines how we match against runtime evidence.
CLAIM_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Port claims: "listening on port 3000", "runs on :8080", "port 5000",
    # "http://localhost:8000", "http://127.0.0.1:3000"
    (re.compile(
        r'(?:listening|runs?|starts?|serves?|binds?)\s+(?:on\s+)?(?:port\s+)?[:]?(\d{4,5})',
        re.IGNORECASE), "port"),
    # URL-based port: http://localhost:8000, http://127.0.0.1:3000
    (re.compile(
        r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):(\d{4,5})',
        re.IGNORECASE), "port"),

    # Database/service claims: "connects to PostgreSQL", "requires Redis"
    (re.compile(
        r'(?:connects?\s+to|requires?|uses?|powered\s+by|stores?\s+(?:in|to|data\s+in))\s+'
        r'(postgresql|postgres|mysql|redis|mongodb|mongo|elasticsearch|sqlite|supabase)',
        re.IGNORECASE), "service"),

    # API claims: "uses the OpenAI API", "integrates with Stripe"
    (re.compile(
        r'(?:uses?|requires?|integrates?\s+with|calls?)\s+(?:the\s+)?'
        r'(openai|anthropic|stripe|github|twitter|slack|aws)\s*(?:api)?',
        re.IGNORECASE), "api"),

    # Install commands from README code blocks — broadened to catch
    # real-world patterns like "pip install fastapi", "npm install",
    # "pip install -r requirements.txt", etc.
    (re.compile(r'pip\s+install\s+(?:-r\s+)?(?:requirements\.txt|\S+)'), "install_python"),
    (re.compile(r'npm\s+install'), "install_node"),
    (re.compile(r'cargo\s+(?:build|install)'), "install_rust"),
    (re.compile(r'go\s+mod\s+(?:download|vendor)'), "install_go"),
    (re.compile(r'bundle\s+install'), "install_ruby"),

    # Run commands from README code blocks
    (re.compile(r'python\s+(main|app|server|run|manage)\.py'), "run_python"),
    (re.compile(r'node\s+(index|app|server|main)\.js'), "run_node"),
    (re.compile(r'npm\s+start'), "run_npm_start"),
    (re.compile(r'cargo\s+run'), "run_cargo"),
    (re.compile(r'go\s+run\s+(?:main\.go)?'), "run_go"),

    # File processing: "processes CSV files", "reads JSON"
    (re.compile(
        r'(?:processes?|reads?|writes?|parses?|handles?|imports?|exports?)\s+'
        r'\.?(csv|json|xml|yaml|yml|toml|excel|xlsx)\s+files?',
        re.IGNORECASE), "file_type"),

    # Framework: "built with Flask", "uses Express", "FastAPI framework"
    (re.compile(
        r'(?:built\s+with|uses?|powered\s+by|written\s+in|based\s+on|is\s+a)\s+'
        r'(flask|django|fastapi|starlette|express|nextjs|next\.js|react|vue|angular|spring|rails|starlette|uvicorn|gunicorn|pydantic)',
        re.IGNORECASE), "framework"),
]

# Known service → port mapping for database/service claim matching
SERVICE_PORTS = {
    "postgresql": "5432", "postgres": "5432",
    "mysql": "3306", "redis": "6379",
    "mongodb": "27017", "mongo": "27017",
    "elasticsearch": "9200", "sqlite": None,  # SQLite is local file, no port
    "supabase": "5432",  # Supabase uses Postgres
}

# Buzzword patterns — common AI-slop claims that can't be verified by
# execution. These are flagged as UNVERIFIABLE so the report doesn't
# silently ignore them (which would make "2 of 2 verified" misleading
# when the README also claims "quantum-enhanced" and "blockchain-secured").
#
# Each entry is (pattern, label) — the label is displayed to the user.
SLOP_BUZZWORDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'quantum[- ]?(?:enhanced|powered|computing|scheduler|ready)', re.IGNORECASE), "quantum"),
    (re.compile(r'blockchain[- ]?(?:secured|audit|powered|based|trail|ledger)', re.IGNORECASE), "blockchain"),
    (re.compile(r'ai[- ]?(?:powered|driven|enhanced|assisted)', re.IGNORECASE), "ai-powered"),
    (re.compile(r'(?:next[- ]?gen|next[- ]?generation|cutting[- ]?edge|revolutionary|game[- ]?changing)', re.IGNORECASE), "marketing-speak"),
    (re.compile(r'(?:predictive|proactive)\s+(?:auto[- ]?scal|schedul|analy|insight)', re.IGNORECASE), "predictive-ai"),
    (re.compile(r'(?:zero[- ]?trust|military[- ]?grade|enterprise[- ]?grade)\s+security', re.IGNORECASE), "security-buzzword"),
    (re.compile(r'(?:carbon[- ]?aware|green\s+computing|eco[- ]?friendly)', re.IGNORECASE), "eco-buzzword"),
    (re.compile(r'(?:self[- ]?healing|auto[- ]?healing|self[- ]?repair)', re.IGNORECASE), "self-healing"),
    (re.compile(r'(?:edge[- ]?native|edge[- ]?computing|247\s+edge\s+regions)', re.IGNORECASE), "edge-buzzword"),
    (re.compile(r'(?:5g[- ]?optimized|5g[- ]?ready)', re.IGNORECASE), "5g-buzzword"),
    (re.compile(r'(?:neural|deep\s+learning|machine\s+learning)\s+(?:powered|driven|engine|scheduler)', re.IGNORECASE), "ml-buzzword"),
    (re.compile(r'(?:sentiment[- ]?aware|emotion[- ]?aware|cognitive)', re.IGNORECASE), "cognitive-buzzword"),
]


@dataclass
class Claim:
    """A testable assertion extracted from the README."""
    text: str           # The original claim text from the README
    claim_type: str     # "port", "service", "api", "install_python", etc.
    expected: str       # What we expect to see (e.g., "3000" for port)
    source_line: int    # Line number in the README


@dataclass
class ClaimMatch:
    """The result of matching a claim against runtime evidence."""
    claim: Claim
    status: str         # "VERIFIED", "UNVERIFIED", "UNVERIFIABLE"
    evidence: str       # What we observed (or why we couldn't verify)


def extract_claims(repo_path: Path) -> list[Claim]:
    """Extract testable claims AND buzzword claims from the README.

    100% deterministic — no LLMs, no AI. Two categories of claim are
    extracted:

    1. TESTABLE claims (ports, services, frameworks, install commands,
       file types) — these can be matched against runtime evidence.

    2. BUZZWORD claims (quantum, blockchain, AI-powered, etc.) — these
       are common AI-slop marketing terms that CANNOT be verified by
       execution. They're extracted and marked UNVERIFIABLE so the
       report doesn't silently ignore them. Without this, a README that
       says "quantum-enhanced blockchain platform" with "pip install"
       would show "1 of 1 claims verified" — misleadingly clean.

    Also tracks README coverage: how many of the README's lines contain
    claims we can check, so the user knows whether "all verified" means
    "the README was thorough and we checked everything" or "the README
    was 500 lines but we only found 2 checkable claims."
    """
    # Find the README file
    readme_path: Optional[Path] = None
    for name in ("README.md", "README.rst", "README.txt", "README",
                 "readme.md", "readme"):
        candidate = repo_path / name
        if candidate.exists():
            readme_path = candidate
            break

    if readme_path is None:
        return []

    try:
        text = readme_path.read_text(errors="replace")
    except OSError:
        return []

    claims: list[Claim] = []
    seen: set[tuple[str, str]] = set()  # Dedup by (claim_type, expected)

    for line_num, line in enumerate(text.splitlines(), 1):
        # --- Testable claims (ports, services, frameworks, etc.) ---
        for pattern, claim_type in CLAIM_PATTERNS:
            for m in pattern.finditer(line):
                try:
                    expected = m.group(1).lower().rstrip(".")
                except IndexError:
                    expected = claim_type
                key = (claim_type, expected)
                if key in seen:
                    continue
                seen.add(key)
                claim_text = line.strip()[:120]
                claims.append(Claim(
                    text=claim_text,
                    claim_type=claim_type,
                    expected=expected,
                    source_line=line_num,
                ))

        # --- Buzzword claims (quantum, blockchain, AI-powered, etc.) ---
        # These are extracted as "buzzword" type and always match as
        # UNVERIFIABLE — they're marketing terms, not testable assertions.
        for pattern, label in SLOP_BUZZWORDS:
            m = pattern.search(line)
            if m:
                key = ("buzzword", label)
                if key in seen:
                    continue
                seen.add(key)
                claim_text = line.strip()[:120]
                claims.append(Claim(
                    text=claim_text,
                    claim_type="buzzword",
                    expected=label,
                    source_line=line_num,
                ))

    return claims


def match_claims(
    claims: list[Claim],
    behavior_report: BehaviorReport,
    exec_result: ExecutionResult,
    stack: StackProfile,
    repo_path: Path,
) -> list[ClaimMatch]:
    """Match each claim against runtime evidence.

    Deterministic — no AI, no fuzzy matching. Each claim type has its
    own matching logic that checks specific runtime evidence.
    """
    matches: list[ClaimMatch] = []

    for claim in claims:
        match = _match_single_claim(
            claim, behavior_report, exec_result, stack, repo_path
        )
        matches.append(match)

    return matches


def _match_single_claim(
    claim: Claim,
    report: BehaviorReport,
    exec_result: ExecutionResult,
    stack: StackProfile,
    repo_path: Path,
) -> ClaimMatch:
    """Match a single claim against runtime evidence."""

    if claim.claim_type == "port":
        port = claim.expected
        # Check if the app bound to this port
        if port in report.ports_bound:
            return ClaimMatch(claim, "VERIFIED",
                              f"App bound to port {port} (strace bind() observed)")
        # Check if stdout mentioned the port (readiness signal)
        combined = exec_result.stdout + exec_result.stderr
        if port in combined:
            return ClaimMatch(claim, "VERIFIED",
                              f"Port {port} mentioned in output")
        return ClaimMatch(claim, "UNVERIFIED",
                          f"No bind() or output mentioning port {port}")

    elif claim.claim_type == "service":
        service = claim.expected
        port = SERVICE_PORTS.get(service)
        if port is None:
            # SQLite is local — check if any .db/.sqlite file was opened
            if service == "sqlite":
                for f in report.files_read + report.files_written:
                    if f.endswith((".db", ".sqlite", ".sqlite3")):
                        return ClaimMatch(claim, "VERIFIED",
                                          f"SQLite database file accessed: {f}")
                return ClaimMatch(claim, "UNVERIFIED",
                                  "No SQLite database file accessed")
            return ClaimMatch(claim, "UNVERIFIABLE",
                              f"Unknown service: {service}")
        # Check if the app tried to connect to the service port
        for net in report.network_attempts:
            if f":{port}" in net:
                return ClaimMatch(claim, "VERIFIED",
                                  f"Network connect to port {port} ({service}) observed")
        # Check if stderr mentions connection refused on this port
        combined = (exec_result.stdout + exec_result.stderr).lower()
        if port in combined and ("refused" in combined or "connection" in combined):
            return ClaimMatch(claim, "VERIFIED",
                              f"Connection attempt to {service} (port {port}) in stderr")
        return ClaimMatch(claim, "UNVERIFIED",
                          f"No connect() to port {port} ({service}) observed")

    elif claim.claim_type == "api":
        api = claim.expected
        # Under --network none, the app can't reach the API, but it may
        # try. Check if any network attempt was made (the app tried to
        # phone home to SOME API).
        if report.network_attempts:
            return ClaimMatch(claim, "VERIFIED",
                              f"Network attempt(s) observed (API call blocked by sandbox): "
                              f"{', '.join(report.network_attempts[:3])}")
        # Check if the app read credentials (.env, API key files)
        if report.sensitive_access:
            return ClaimMatch(claim, "VERIFIED",
                              "Credential file access observed (API key read)")
        return ClaimMatch(claim, "UNVERIFIED",
                          f"No network attempts or credential reads for {api} API")

    elif claim.claim_type.startswith("install_"):
        # Check if the install command matches what we actually ran
        install_str = " ".join(stack.install_cmd) if stack.install_cmd else ""
        if claim.claim_type == "install_python" and "pip install" in install_str:
            return ClaimMatch(claim, "VERIFIED",
                              f"Install used: {install_str}")
        if claim.claim_type == "install_node" and "npm install" in install_str:
            return ClaimMatch(claim, "VERIFIED",
                              f"Install used: {install_str}")
        if claim.claim_type == "install_rust" and "cargo" in install_str:
            return ClaimMatch(claim, "VERIFIED",
                              f"Install used: {install_str}")
        if claim.claim_type == "install_go" and "go mod" in install_str:
            return ClaimMatch(claim, "VERIFIED",
                              f"Install used: {install_str}")
        if claim.claim_type == "install_ruby" and "bundle" in install_str:
            return ClaimMatch(claim, "VERIFIED",
                              f"Install used: {install_str}")
        return ClaimMatch(claim, "UNVERIFIED",
                          f"Install command was: {install_str or '(none)'}")

    elif claim.claim_type.startswith("run_"):
        # Check if the run command matches what we actually tried
        candidates_str = " ".join(
            " ".join(c) for c in stack.run_candidates
        )
        if claim.expected in candidates_str or claim.text.split()[0:2] == \
                stack.run_candidates[0][0:2] if stack.run_candidates else False:
            return ClaimMatch(claim, "VERIFIED",
                              f"Entrypoint tried: {candidates_str}")
        # More flexible: check if the expected file/command appears
        for candidate in stack.run_candidates:
            if claim.expected in " ".join(candidate):
                return ClaimMatch(claim, "VERIFIED",
                                  f"Entrypoint tried: {' '.join(candidate)}")
        return ClaimMatch(claim, "UNVERIFIED",
                          f"Entrypoint(s) tried: {candidates_str}")

    elif claim.claim_type == "file_type":
        ext = claim.expected
        # Check if any file with this extension was opened
        for f in report.files_read + report.files_written:
            if f.endswith(f".{ext}"):
                return ClaimMatch(claim, "VERIFIED",
                                  f" .{ext} file accessed: {f}")
        return ClaimMatch(claim, "UNVERIFIED",
                          f"No .{ext} files accessed during execution")

    elif claim.claim_type == "framework":
        framework = claim.expected
        # Check if framework modules were read from strace
        for f in report.files_read:
            if framework in f.lower():
                return ClaimMatch(claim, "VERIFIED",
                                  f"Framework module read: {f}")
        # Check if framework appears in requirements.txt/package.json
        deps_file = repo_path / "requirements.txt"
        if deps_file.exists():
            try:
                deps_text = deps_file.read_text().lower()
                if framework in deps_text:
                    return ClaimMatch(claim, "VERIFIED",
                                      f"Framework in requirements.txt")
            except OSError:
                pass
        pkg_file = repo_path / "package.json"
        if pkg_file.exists():
            try:
                import json
                pkg = json.loads(pkg_file.read_text())
                deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                for dep_name in deps:
                    if framework in dep_name.lower():
                        return ClaimMatch(claim, "VERIFIED",
                                          f"Framework in package.json: {dep_name}")
            except (OSError, ValueError):
                pass
        return ClaimMatch(claim, "UNVERIFIED",
                          f"No evidence of {framework} in strace or deps")

    elif claim.claim_type == "buzzword":
        # Buzzword claims (quantum, blockchain, AI-powered, etc.) are
        # ALWAYS unverifiable — they're marketing terms with no
        # testable runtime behavior. Flag them so the report shows
        # the gap honestly, e.g. "2 of 2 testable claims verified,
        # 5 buzzword claims not machine-verifiable."
        return ClaimMatch(claim, "UNVERIFIABLE",
                          f"'{claim.expected}' is a marketing claim — "
                          f"cannot be verified by execution")

    return ClaimMatch(claim, "UNVERIFIABLE",
                      f"Unknown claim type: {claim.claim_type}")


# ----------------------------------------------------------------------
# Stack detection — deterministic, file-existence based
# ----------------------------------------------------------------------

def _detect_node_workspaces(repo_path: Path) -> Optional[list[str]]:
    """Detect npm/pnpm workspaces in package.json.

    Returns the list of workspace glob patterns if present, or None.
    Used to distinguish "monorepo with no root start script" (yellow,
    not slop) from "app that crashed" (red). Supabase, turborepo, etc.
    declare workspaces but have no root entrypoint — reporting them as
    a crash was a false alarm.
    """
    import json
    try:
        pkg = json.loads((repo_path / "package.json").read_text())
    except (OSError, ValueError):
        return None
    workspaces = pkg.get("workspaces")
    if isinstance(workspaces, list):
        return workspaces
    if isinstance(workspaces, dict) and "packages" in workspaces:
        return workspaces["packages"]
    return None


def _extract_pyproject_deps(pyproject_path: Path) -> list[str]:
    """Extract the dependency list from pyproject.toml. Runs on the HOST
    (not inside Docker) to avoid inline Python quoting issues.

    Handles:
      - PEP 621: [project.dependencies]
      - Poetry: [tool.poetry.dependencies] (filters out 'python' key)
      - Optional deps: [project.optional-dependencies]

    Returns a list of pip-installable requirement strings.
    """
    try:
        text = pyproject_path.read_text()
    except OSError:
        return []

    # Try tomllib (3.11+) or tomli (3.10)
    data = None
    try:
        import tomllib
        data = tomllib.loads(text)
    except ImportError:
        try:
            import tomli
            data = tomli.loads(text)
        except ImportError:
            pass

    if data is None:
        # Regex fallback — extract lines that look like deps
        # from [project.dependencies] section
        deps: list[str] = []
        in_deps = False
        for line in text.splitlines():
            if line.strip() == "[project.dependencies]":
                in_deps = True
                continue
            if line.strip().startswith("[") and in_deps:
                break  # Next section
            if in_deps and line.strip() and not line.strip().startswith("#"):
                # Strip quotes and whitespace
                dep = line.strip().strip('"').strip("'")
                if dep:
                    deps.append(dep)
        return deps

    deps = []

    # PEP 621: [project.dependencies]
    project_deps = data.get("project", {}).get("dependencies", [])
    if isinstance(project_deps, list):
        deps.extend(project_deps)

    # Poetry: [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry_deps, dict):
        for name, version in poetry_deps.items():
            if name.lower() == "python":
                continue  # Skip the python version constraint
            if isinstance(version, str):
                deps.append(f"{name}{version}")
            elif isinstance(version, dict):
                # Poetry table format — just use the name
                deps.append(name)

    return deps


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

    DETECTION PRIORITY (matters for polyglot repos):
      Many real-world repos are polyglot — a Rails app with a package.json
      for frontend assets (GitLab), a Django app with a package.json for
      webpack, etc. The primary app language must win over a secondary
      package.json. We check in priority order:
        1. Rails (Gemfile + config.ru) — Ruby, the actual app
        2. Python (requirements.txt/pyproject.toml/setup.py/manage.py/etc)
        3. Node.js (package.json) — often just frontend assets
        4. Go (go.mod)
        5. Rust (Cargo.toml)

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
    # ---- Rails (Ruby) — check BEFORE Node.js ----
    # A repo with both Gemfile+config.ru AND package.json is a Rails app
    # with frontend assets (GitLab, GitLab, Discourse, Mastodon, etc).
    # The Ruby app is the primary; package.json is secondary. Without
    # this priority check, repo-proofer would detect Node.js, run
    # `npm start`, and report "Missing script: start" as a crash —
    # missing the actual Ruby app entirely.
    if (repo_path / "Gemfile").exists() and (repo_path / "config.ru").exists():
        return StackProfile(
            name="Ruby (Rails)",
            image="ruby:3.3-slim",
            install_cmd=[
                "sh", "-c",
                "bundle config set path /tmp/bundle && bundle install",
            ],
            run_candidates=[
                # Try the Rails server entrypoint.
                ["bundle", "exec", "rails", "server", "-b", "0.0.0.0"],
                # Fall back to rackup if rails command isn't available.
                ["bundle", "exec", "rackup", "--host", "0.0.0.0"],
            ],
            env={"BUNDLE_GEMFILE": "/app/Gemfile"},
            deps_mount="/tmp/bundle",
        )

    # ---- Python — check BEFORE Node.js ----
    # A repo with both manage.py/pyproject.toml AND package.json is a
    # Django/Flask app with frontend assets. The Python app is primary.
    py_entry_files = ("main.py", "app.py", "server.py", "run.py",
                      "manage.py", "__main__.py")
    has_python_entry = any((repo_path / f).exists() for f in py_entry_files) \
        or (repo_path / "src/main.py").exists() \
        or (repo_path / "src/app.py").exists()
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
            install_cmd = [
                "pip", "install", "--no-cache-dir", "--prefer-binary",
                "-r", "requirements.txt",
                "-t", "/tmp/pip_deps",
            ]
        elif (repo_path / "pyproject.toml").exists():
            # Extract dependencies from pyproject.toml ON THE HOST (not
            # inside Docker — avoids inline Python quoting hell). Write
            # them to a requirements-style file in the repo dir so Docker
            # can read it. Then install ONLY the deps, not the package
            # itself, to avoid the source-vs-installed shadowing conflict
            # (the FastAPI RuntimeError fix).
            deps = _extract_pyproject_deps(repo_path / "pyproject.toml")
            if deps:
                # Write deps to a temp file in the repo (mounted :ro in
                # Docker, but we write it BEFORE Docker runs — the mount
                # picks it up).
                deps_file = repo_path / ".repo-proofer-deps.txt"
                try:
                    deps_file.write_text("\n".join(deps) + "\n")
                except OSError:
                    deps_file = None

                if deps_file:
                    install_cmd = [
                        "pip", "install", "--no-cache-dir", "--prefer-binary",
                        "-r", ".repo-proofer-deps.txt",
                        "-t", "/tmp/pip_deps",
                    ]
                else:
                    # Couldn't write the file — fall back
                    install_cmd = [
                        "sh", "-c",
                        "pip install --no-cache-dir --prefer-binary "
                        "-t /tmp/pip_deps .",
                    ]
            else:
                # No deps extracted — fall back to installing the package
                install_cmd = [
                    "sh", "-c",
                    "pip install --no-cache-dir --prefer-binary "
                    "-t /tmp/pip_deps .",
                ]
        elif (repo_path / "setup.py").exists() or (repo_path / "setup.cfg").exists():
            # Legacy setup.py/setup.cfg — install the project which reads
            # install_requires from setup.py/setup.cfg.
            install_cmd = [
                "sh", "-c",
                "pip install --no-cache-dir --prefer-binary "
                "-t /tmp/pip_deps .",
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

    # ---- Node.js ----
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
            "-e", "trace=openat,open,openat2,creat,execve,execveat,connect,socket,bind,unlink,unlinkat",
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

        # Monorepo detection (same logic as Docker execute_entrypoint).
        # Check BEFORE the NOT_FOUND marker check — "Missing script"
        # doesn't match any NOT_FOUND marker, so without this the result
        # would be returned as a crash.
        if stack.name == "Node.js" and "missing script" in combined:
            workspaces = _detect_node_workspaces(repo_path)
            if workspaces:
                result.monorepo_no_root_entry = True
                return result

        if any(marker in combined for marker in NOT_FOUND_MARKERS):
            last_result = result
            continue

        return result

    if last_result is not None:
        # Fallback monorepo check for the NOT_FOUND path.
        if stack.name == "Node.js":
            workspaces = _detect_node_workspaces(repo_path)
            if workspaces:
                combined = (last_result.stdout + "\n" + last_result.stderr).lower()
                if "missing script" in combined or "no such file" in combined:
                    last_result.monorepo_no_root_entry = True
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
                "-e", "trace=openat,open,openat2,creat,execve,execveat,connect,socket,bind,unlink,unlinkat",
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

        # Monorepo detection: "npm error Missing script: start" on a
        # workspace repo is NOT a crash — it's a missing root entrypoint.
        # Check this BEFORE the NOT_FOUND marker check, because "Missing
        # script" doesn't match any NOT_FOUND marker (which look for
        # "no such file or directory", "cannot find module", etc), so
        # the old code returned the result as a crash without ever
        # reaching the monorepo check. (The Supabase/GitLab fix.)
        if stack.name == "Node.js" and "missing script" in combined:
            workspaces = _detect_node_workspaces(repo_path)
            if workspaces:
                result.monorepo_no_root_entry = True
                return result

        if any(marker in combined for marker in NOT_FOUND_MARKERS):
            last_result = result
            continue

        return result

    if last_result is not None:
        # Fallback monorepo check for the NOT_FOUND path (e.g. index.js
        # doesn't exist AND workspaces are declared).
        if stack.name == "Node.js":
            workspaces = _detect_node_workspaces(repo_path)
            if workspaces:
                combined = (last_result.stdout + "\n" + last_result.stderr).lower()
                if "missing script" in combined or "no such file" in combined:
                    last_result.monorepo_no_root_entry = True
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

def analyze_result(
    result: ExecutionResult,
    install_result: Optional[ExecutionResult] = None,
) -> Verdict:
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
      install failed + 127 exec      -> BOOTS: NO   ("could not start: install
                                                    failed (exit N), <cmd>
                                                    unavailable")
      exit 127 (command not found)   -> BOOTS: NO   ("failed to start: <cmd>
                                                    not found (missing dep)")
      missing script                 -> BOOTS: NO   ("no runnable entrypoint")
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

    # ---- Monorepo case ----
    # A workspace repo (npm workspaces) with no root start script is NOT
    # a crash. "npm error Missing script: start" on a monorepo is the
    # expected behavior — the entrypoints live in sub-packages. Reporting
    # this as "exited 1 (crash)" was a false alarm on repos like Supabase.
    if result.monorepo_no_root_entry:
        return Verdict(
            boots=False,
            network_egress_blocked=True,
            filesystem_read_only=True,
            stdout_preview=result.stdout[:MAX_STDOUT_CHARS],
            stderr_preview=result.stderr[:MAX_STDERR_CHARS],
            warnings=[],
            detail="monorepo: no root entrypoint (workspaces detected — try a sub-package)",
            no_entrypoint=True,
            monorepo=True,
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
        # Non-zero exit, not a timeout. Distinguish three distinct cases
        # that all used to be flattened into "crash" — each means
        # something different and deserves its own label:
        #
        #   127 = "command not found" — the launcher couldn't find a
        #         build tool or binary (e.g. `turbo: not found` when
        #         deps weren't fully installed). This is an environment
        #         failure, not an application crash. The app never ran.
        #
        #   "Missing script" in stderr = npm couldn't find a start
        #         script. Already handled by the monorepo detection
        #         above, but if it slips through, label it honestly.
        #
        #   Any other non-zero = genuine application crash (traceback,
        #         segfault, panic, exit 1 from running code).
        boots = False
        # ---- Install-failure-first check ----
        # When install failed AND execution fails, the install failure is
        # the ROOT CAUSE — the exec failure is just its shadow. The
        # command wasn't found (or crashed) because deps were never
        # installed. Lead with the install failure, not the downstream
        # exit code. (The GitLab case: bundle install failed → rails
        # never installed → bundler exits non-zero. The honest verdict
        # leads with "install failed", not "crash" or "command not found".)
        #
        # This fires on ANY non-zero exec exit when install failed — not
        # just 127 — because bundler/ruby may exit with different codes
        # than sh/bash. The key signal is "install failed + exec failed"
        # = environment failure, not app crash.
        if (install_result is not None
                and install_result.exit_code != 0
                and result.exit_code != 0):
            missing_cmd = _extract_missing_command(result.stderr)
            cmd_part = f", '{missing_cmd}' unavailable" if missing_cmd else ""
            detail = (
                f"could not start: install failed (exit {install_result.exit_code})"
                f"{cmd_part}"
            )
            warnings.append(
                "The install step failed, so required tools were never "
                "installed. This is an environment failure — the repo's "
                "code never ran. Check the Install Warning panel for the "
                "install error."
            )
        # ---- 127 without install failure ----
        elif result.exit_code == 127:
            # Command not found — environment/dependency failure.
            # Try to extract the missing command from stderr for detail.
            missing_cmd = _extract_missing_command(result.stderr)
            if missing_cmd:
                detail = f"failed to start: '{missing_cmd}' not found (exit 127 — missing dependency or build tool)"
            else:
                detail = f"failed to start (exit 127 — command not found, likely missing dependency)"
            warnings.append(
                "The entrypoint couldn't start because a required tool "
                "or dependency is missing from the sandbox. This is an "
                "environment failure, not an application crash."
            )
        elif "missing script" in combined_lower:
            # npm "Missing script: start" — no root entrypoint.
            detail = "no runnable entrypoint (missing start script)"
            warnings.append(
                "No root entrypoint found. If this is a monorepo, "
                "the entrypoint may live in a sub-package."
            )
        else:
            # Genuine non-zero exit from running code.
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
    seen_writes_blocked: set[str] = set()
    seen_procs: set[str] = set()
    seen_net: set[str] = set()
    seen_sensitive_high: set[str] = set()
    seen_sensitive_medium: set[str] = set()
    seen_ports_bound: set[str] = set()

    # strace -ff creates files named trace.<pid> and trace.<pid>.<pid>.
    # Use 'trace.*' (not 'trace*') to avoid matching a bare 'trace' file
    # if one exists — a bare 'trace' file would be combined output that
    # double-counts every syscall across the per-pid files and the
    # combined file, causing the duplicated report rendering bug.
    trace_files = sorted(trace_dir.glob("trace.*"))
    if not trace_files:
        # Fallback: some strace versions write a bare 'trace' file.
        # Only use it if no per-pid files exist.
        bare = trace_dir / "trace"
        if bare.exists():
            trace_files = [bare]
        else:
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
                # Classify sensitive paths into HIGH and MEDIUM tiers.
                # HIGH = credential/key theft (SSH, .env, /etc/passwd, AWS).
                # MEDIUM = package-manager config (.npmrc, .pypirc, .netrc)
                #   — routinely read by npm/pip during normal operation.
                is_high = any(
                    p.search(path) for p in SENSITIVE_PATH_PATTERNS_HIGH
                )
                is_medium = any(
                    p.search(path) for p in SENSITIVE_PATH_PATTERNS_MEDIUM
                )
                # Sensitive paths are ALWAYS recorded, even if they
                # also match a runtime-noise prefix (paranoid by design).
                if is_high and path not in seen_sensitive_high:
                    seen_sensitive_high.add(path)
                elif is_medium and path not in seen_sensitive_medium:
                    seen_sensitive_medium.add(path)

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

                # Check the syscall return value. A negative return (e.g.
                # -1 EROFS, -1 EACCES) means the open was REJECTED —
                # typically by the read-only filesystem. Counting these
                # as successful writes is dishonest (the Supabase bug:
                # npm's log write was blocked but the report said
                # "Files Written 1"). Split into successful writes vs
                # blocked write attempts.
                retval = int(m.group(2))
                write_blocked = (retval < 0)

                if is_write:
                    if write_blocked:
                        if path not in seen_writes_blocked:
                            seen_writes_blocked.add(path)
                    else:
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
            # Only count INTERNET (AF_INET/AF_INET6) connects as network
            # egress attempts. AF_UNIX connects are local sockets (nscd,
            # Docker daemon, etc) — not network egress. Counting them as
            # "network calls" over-reports and undercuts trust in the count.
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
            # AF_UNIX connects are NOT network egress — skip them.
            # (Old behavior counted them as "connect unix:/path" which
            # inflated the network count with local socket activity.)
            # Bare connect call we couldn't parse — still record as attempt.
            if line.startswith("connect(") and "AF_UNIX" not in line:
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

            # --- bind() — port the app tried to listen on ---
            # Used by the claim-matching layer to verify "starts a server
            # on port 3000" type README claims.
            m_bind = STRACE_BIND_PORT_RE.search(line)
            if m_bind:
                port = m_bind.group(1)
                if port not in seen_ports_bound:
                    seen_ports_bound.add(port)
                continue

    report.files_read = sorted(set(seen_reads))
    report.files_written = sorted(set(seen_writes))
    report.writes_blocked = sorted(set(seen_writes_blocked))
    report.processes_spawned = sorted(set(seen_procs))
    report.network_attempts = sorted(set(seen_net))
    report.ports_bound = sorted(set(seen_ports_bound))
    report.sensitive_access = sorted(set(seen_sensitive_high))
    report.medium_sensitive_access = sorted(set(seen_sensitive_medium))
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
    if report.writes_blocked:
        table.add_row(
            "Write Attempts Blocked",
            f"[yellow]{len(report.writes_blocked)}[/yellow] "
            f"(by read-only FS)",
        )
    table.add_row("Processes Spawned", str(len(report.processes_spawned)))
    table.add_row("Network Calls Attempted", str(len(report.network_attempts)))
    # HIGH-severity: SSH keys, .env, /etc/shadow, AWS creds — the exfil signal
    if report.sensitive_access:
        table.add_row(
            "Sensitive File Access (HIGH)",
            f"[bold red]{len(report.sensitive_access)}[/bold red] "
            f"(see below)",
        )
    else:
        table.add_row("Sensitive File Access (HIGH)", "[green]0[/green]")
    # MEDIUM-severity: .npmrc, .pypirc, .netrc, /etc/passwd — routine reads
    if report.medium_sensitive_access:
        table.add_row(
            "Config File Access (MEDIUM)",
            f"[yellow]{len(report.medium_sensitive_access)}[/yellow] "
            f"(informational)",
        )

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

    # Blocked writes — the read-only FS rejected these. Honest reporting:
    # don't count rejected writes as successful (the Supabase bug).
    if report.writes_blocked:
        console.print(Panel(
            "\n".join(f"- {p}" for p in report.writes_blocked),
            title=(
                f"[yellow]Write Attempts Blocked "
                f"({len(report.writes_blocked)})[/yellow]\n"
                "[dim]Rejected by read-only filesystem — nothing was "
                "actually written.[/dim]"
            ),
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

    # HIGH-severity panel — the exfil signal. Red, bold, alarming.
    if report.sensitive_access:
        console.print(Panel(
            "\n".join(f"- {p}" for p in report.sensitive_access),
            title=(
                f"[bold red]Sensitive File Access — HIGH "
                f"({len(report.sensitive_access)})[/bold red]"
            ),
            border_style="red",
        ))

    # MEDIUM-severity panel — informational, not alarming. Yellow, dim.
    # .npmrc/.pypirc reads are normal package-manager behavior; flagging
    # them as "primary indicator of malicious intent" was a false alarm
    # that destroyed credibility on legitimate repos like Supabase.
    if report.medium_sensitive_access:
        console.print(Panel(
            "\n".join(f"- {p}" for p in report.medium_sensitive_access),
            title=(
                f"[yellow]System/Config File Access — MEDIUM "
                f"({len(report.medium_sensitive_access)})[/yellow]\n"
                "[dim]Informational only — routine reads by npm/pip/libc. "
                "Review if unexpected.[/dim]"
            ),
            border_style="yellow",
        ))


def print_claim_report(matches: list[ClaimMatch]) -> None:
    """Print the README Claim Verification report.

    This is the layer that turns 'did it boot' into 'is it slop'.
    Extracts testable claims from the README and maps each to runtime
    evidence. A repo that boots cleanly but has 0 of 5 claims verified
    is likely slop — its README promises things the code doesn't do.
    """
    if not matches:
        # No claims extracted (no README, or README had no testable claims)
        console.print(Panel(
            "[dim]No testable claims found in README.[/dim]\n"
            "[dim]Claim verification requires a README with specific, "
            "checkable assertions (ports, services, frameworks, "
            "install/run commands, file types).[/dim]",
            title="[bold blue]README Claim Verification[/bold blue]",
            border_style="blue",
        ))
        return

    verified = [m for m in matches if m.status == "VERIFIED"]
    unverified = [m for m in matches if m.status == "UNVERIFIED"]
    unverifiable = [m for m in matches if m.status == "UNVERIFIABLE"]

    # Split unverifiable into buzzword claims vs genuinely-unverifiable
    # testable claims. Buzzword claims (quantum, blockchain, AI-powered)
    # get their own section so they don't inflate the "testable" count.
    buzzword_matches = [m for m in unverifiable if m.claim.claim_type == "buzzword"]
    genuinely_unverifiable = [m for m in unverifiable if m.claim.claim_type != "buzzword"]

    # Testable claims = verified + unverified + genuinely_unverifiable
    # (buzzword claims are NOT testable — they're marketing terms)
    testable = verified + unverified + genuinely_unverifiable
    testable_total = len(testable)
    total = len(matches)

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column()
    if testable_total > 0:
        table.add_row("Claims Verified",
                      f"[bold green]{len(verified)}[/bold green] of {testable_total} testable")
    else:
        table.add_row("Claims Verified", "[dim]0 (no testable claims found)[/dim]")
    if unverified:
        table.add_row("Claims Unverified", f"[yellow]{len(unverified)}[/yellow]")
    if buzzword_matches:
        table.add_row("Buzzword Claims",
                      f"[magenta]{len(buzzword_matches)}[/magenta] (not machine-verifiable)")
    if genuinely_unverifiable:
        table.add_row("Claims Unverifiable", f"[dim]{len(genuinely_unverifiable)}[/dim]")

    # The headline: honest about coverage. "2 of 2 testable verified"
    # is different from "2 of 2 verified" when there are also 5 buzzwords.
    if testable_total == 0 and buzzword_matches:
        verdict_line = (
            f"[bold red]0 testable claims found, {len(buzzword_matches)} "
            f"buzzword claims detected. README makes marketing claims "
            f"with no verifiable technical assertions. Likely slop.[/bold red]"
        )
    elif testable_total > 0:
        pct = (len(verified) / testable_total * 100) if testable_total > 0 else 0
        buzzword_note = ""
        if buzzword_matches:
            buzzword_note = (f" ({len(buzzword_matches)} buzzword claim"
                             f"{'s' if len(buzzword_matches) != 1 else ''} "
                             f"not machine-verifiable)")

        if pct == 100:
            verdict_line = (f"[bold green]All {testable_total} testable README "
                            f"claims verified by execution.{buzzword_note}[/bold green]")
        elif pct >= 50:
            verdict_line = (f"[yellow]{len(verified)} of {testable_total} testable "
                            f"claims verified — some not observed.{buzzword_note}[/yellow]")
        elif pct > 0:
            verdict_line = (f"[bold red]{len(verified)} of {testable_total} testable "
                            f"claims verified — most NOT observed. Possible slop.{buzzword_note}[/bold red]")
        else:
            verdict_line = (f"[bold red]0 of {testable_total} testable claims verified — "
                            f"README does not match execution. Likely slop.{buzzword_note}[/bold red]")
    else:
        verdict_line = "[dim]No testable claims found in README.[/dim]"

    console.print(Panel(
        table,
        title="[bold blue]README Claim Verification[/bold blue]",
        border_style="blue",
        subtitle=f"[dim]{verdict_line}[/dim]",
    ))

    # Verified claims
    if verified:
        console.print(Panel(
            "\n".join(
                f"[green]\u2713[/green] {m.claim.text}\n"
                f"  [dim]{m.evidence}[/dim]"
                for m in verified
            ),
            title=f"[green]Verified ({len(verified)})[/green]",
            border_style="green",
        ))

    # Unverified claims — the "confident-looking garbage" section
    if unverified:
        console.print(Panel(
            "\n".join(
                f"[yellow]\u26a0[/yellow] {m.claim.text}\n"
                f"  [dim]{m.evidence}[/dim]"
                for m in unverified
            ),
            title=f"[yellow]Unverified ({len(unverified)})[/yellow]",
            border_style="yellow",
        ))

    # Buzzword claims — marketing terms that can't be verified.
    # This is the section that catches "quantum-enhanced blockchain" slop.
    if buzzword_matches:
        console.print(Panel(
            "\n".join(
                f"[magenta]~ {m.claim.text}\n"
                f"  [dim]{m.evidence}[/dim]"
                for m in buzzword_matches
            ),
            title=(
                f"[magenta]Buzzword Claims ({len(buzzword_matches)})[/magenta]\n"
                "[dim]Marketing terms — cannot be verified by execution. "
                "High concentration of these is a slop signal.[/dim]"
            ),
            border_style="magenta",
        ))

    # Genuinely unverifiable claims (not buzzwords)
    if genuinely_unverifiable:
        console.print(Panel(
            "\n".join(
                f"[dim]? {m.claim.text}\n  {m.evidence}[/dim]"
                for m in genuinely_unverifiable
            ),
            title=f"[dim]Unverifiable ({len(genuinely_unverifiable)})[/dim]",
            border_style="dim",
        ))

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
        verdict = analyze_result(exec_result, install_result)

        # ---- Step 5b: Parse strace trace (if enabled) --------------
        behavior_report = BehaviorReport()
        if trace_dir is not None and trace_dir.exists():
            behavior_report = parse_strace_output(trace_dir)

        # ---- Step 6: Print verdict ----------------------------------
        print_verdict(verdict, repo_url, stack.name, install_result)
        print_behavior_report(behavior_report)

        # ---- Step 6a: README Claim Verification --------------------
        # This is the layer that turns "did it boot" into "is it slop".
        # Extracts testable claims from the README and matches each
        # against runtime evidence. A repo that boots cleanly but has
        # 0 of 5 claims verified is likely slop.
        claims = extract_claims(repo_dir)
        if claims:
            claim_matches = match_claims(
                claims, behavior_report, exec_result, stack, repo_dir,
            )
            print_claim_report(claim_matches)

        # ---- Step 6b: Sensitive-access escalation (correlation-gated) -----
        # The smoking gun for exfiltration is "read a secret AND THEN
        # reached for the network." A HIGH-severity read with 0 network
        # attempts is suspicious but not confirmed exfil — the secret
        # may have been read by a dependency's init code, a health check,
        # or a misconfigured loader. We reserve "primary indicator of
        # malicious intent" for the correlated case.
        #
        # MEDIUM-severity (.npmrc, .pypirc, /etc/passwd) is never a hard
        # fail — these are routinely read by npm/pip/libc.
        if behavior_report.sensitive_access:
            has_network = bool(behavior_report.network_attempts)
            if has_network:
                # HIGH secret read + network attempt = exfiltration signal.
                # This is the "primary indicator of malicious intent" —
                # the line that earns the red wording.
                console.print(
                    "[bold red][!] EXFILTRATION DETECTED — high-risk "
                    "sensitive file access correlated with network "
                    f"attempt(s). Secret paths: "
                    f"{', '.join(behavior_report.sensitive_access)}. "
                    f"Network: {', '.join(behavior_report.network_attempts)}. "
                    "Primary indicator of malicious intent.[/bold red]"
                )
                raise typer.Exit(code=1)
            else:
                # HIGH secret read + 0 network = suspicious but no exfil
                # attempted. Warn loudly but don't accuse. The read is
                # real and worth investigating, but "malicious intent"
                # is overclaiming when nothing tried to leave the box.
                console.print(
                    f"[yellow][!] Sensitive file access detected (no "
                    f"exfiltration attempted — network blocked, 0 calls). "
                    f"Paths: {', '.join(behavior_report.sensitive_access)}. "
                    f"Review whether the app should be reading these.[/yellow]"
                )
                # Don't hard-fail — the app may legitimately read .env for
                # config. The warning is visible; the user decides.

        # MEDIUM-severity: informational note, NOT a hard fail.
        if behavior_report.medium_sensitive_access:
            console.print(
                f"[yellow][i] System/config file access observed (routine): "
                f"{', '.join(behavior_report.medium_sensitive_access)}[/yellow]"
            )

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
