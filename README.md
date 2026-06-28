# repo-proofer

**Brutally honest verdicts for AI-generated GitHub repos. 100% deterministic. No LLMs.**

GitHub is flooded with AI-generated "slop" — repositories that have impressive READMEs but don't actually run, or worse, quietly phone home to a C2 server the moment you `npm install` them. Developers waste 30+ minutes cloning, debugging, and disinfecting these repos.

`repo-proofer` is a consumer-side triage tool. Point it at any public Git URL. It clones the repo, drops it into a hardened Docker sandbox with the network disabled and the filesystem read-only, executes the entrypoint, and prints a brutal honest verdict:

```
BOOTS: NO. Network Egress: BLOCKED. Filesystem: READ-ONLY.
[!] App crashed when network was blocked. May require external API to function.
```

If a repo can't boot without internet, that's not a tool failure — that's a successful detection of a hidden dependency. **You cannot bypass physics.**

---

## The Solution

`--network none` and `--read-only` are mandatory on every execution. Static analysis (Snyk, Socket, GitHub Advanced Security) reads code to see if it *looks* malicious. `repo-proofer` actually runs it in a locked box and watches what it *does*. Obfuscation can fool a linter. It cannot fool a kernel that refuses to open a socket.

If the app tries to read `~/.ssh/id_rsa` while the network is blocked, the verdict escalates to `BOOTS: NO` even if the process exited cleanly. 

---

## Features

- **Zero AI.** Pure subprocess + filesystem + strace. Deterministic, fast, free to run forever.
- **Hardened sandbox.** `--rm --read-only --network none --cap-drop ALL --memory 512m --cpus 0.5 --tmpfs /tmp` (Docker mode) or `--unshare-net --ro-bind --tmpfs /home --tmpfs /root` (native bubblewrap mode). The repo is always mounted `:ro`. No exceptions.
- **Stack auto-detection.** Node.js, Python, Go (experimental), Rust (experimental) — picked by file-existence (`package.json`, `requirements.txt`/`pyproject.toml`/`setup.py`/`setup.cfg`/`main.py`, `go.mod`, `Cargo.toml`). Python entrypoints are resolved from `[project.scripts]` / `console_scripts` (modern CLI apps), `manage.py`, `src/` layouts, `__main__.py`, and conventional files — so a real Typer/Click CLI that declares its entrypoint only in `pyproject.toml` is correctly detected as runnable, not mislabeled as a library.
- **Runtime Behavior Report.** When enabled (default), the entrypoint is wrapped in `strace -ff` inside the sandbox. After execution you get an SBOM-style report based on *actual execution, not static guessing*:
  - Files Read
  - Files Written
  - Processes Spawned
  - Network Calls Attempted (with target IP:port for hardcoded-IP malware; hostname-based C2 may appear as DNS resolver queries under `--network none`)
  - Sensitive File Access (`~/.ssh/`, `.aws/credentials`, `.env`, `/etc/passwd`, ...) — the strongest and most unambiguous signal
- **Graceful fallback.** No Docker? Errors cleanly. No strace image? Falls back to a non-traced run. Install step fails? Proceeds to execution anyway (no auto-repair). Missing Python deps? Prints a guided `pip install` message instead of a traceback.

---

## Install

### Option 1: One-command install (recommended)

Once published to PyPI:

```bash
# Using uv (fastest — no install needed, runs from cache):
uvx repo-proofer https://github.com/owner/repo.git

# Or install permanently with pipx:
pipx install repo-proofer
repo-proofer https://github.com/owner/repo.git

# Or with uv tool install:
uv tool install repo-proofer
repo-proofer https://github.com/owner/repo.git
```

### Option 2: From source (for development)

```bash
git clone https://github.com/bootproof/repo-proofer.git
cd repo-proofer

# Create a venv first (avoids 'externally-managed-environment' on macOS/Linux):
python3 -m venv .venv
source .venv/bin/activate

pip install -e .          # installs proofer.py + deps + `repo-proofer` command
# or just:
pip install -r requirements.txt
```

Requires:
- Python 3.10+
- Docker (running locally)

Supported stacks and their base images:

| Marker file                          | Stack                | Image                | Status       |
|--------------------------------------|----------------------|----------------------|--------------|
| `package.json`                       | Node.js              | `node:20-slim`       | Supported    |
| `requirements.txt` / `pyproject.toml` / `setup.py` / `setup.cfg` / `main.py` / `server.py` / `manage.py` / `[project.scripts]` | Python | `python:3.11-slim` | Supported |
| `go.mod`                             | Go                   | `golang:1.22-alpine` | Experimental |
| `Cargo.toml`                         | Rust                 | `rust:1.75-slim`     | Experimental |

> **Why Go/Rust are experimental:** both run under `--network none` with no install step, so any project with external dependencies can't fetch them at runtime. Only zero-dependency or pre-vendored Go/Rust projects will boot. See [Limitations](#limitations) below.

---

## Usage

```bash
python proofer.py https://github.com/owner/repo.git
python proofer.py https://github.com/owner/repo.git --keep-clone
python proofer.py https://github.com/owner/repo.git --no-behavior-report
```

### Options

| Flag                     | Description                                                                       |
|--------------------------|-----------------------------------------------------------------------------------|
| `--keep-clone`           | Keep the cloned repo, deps cache, and strace trace on disk for debugging.         |
| `--no-behavior-report`   | Skip strace wrapping. Faster, but no file/process/network tracking.               |
| `--help`                 | Show help.                                                                        |

### Exit codes

| Code | Meaning                                              |
|------|------------------------------------------------------|
| 0    | Repo boots cleanly, OR is a library (no entrypoint).|
| 1    | Repo does NOT boot (non-zero exit, sensitive access).|
| 2    | Clone failed.                                        |
| 3    | Docker not installed / daemon not running.           |
| 4    | Could not detect project stack.                      |
| 5    | Failed to pull Docker image.                         |

> **Note on exit code 0 for libraries:** A repo detected as a known stack but with no runnable entrypoint (e.g. `click`, `markupsafe` — a library, not an app) exits 0 with a yellow `NO RUNNABLE ENTRYPOINT` verdict. This is NOT the same red as a crashed/slop repo. Libraries are not slop; they just have nothing to run. CI pipelines won't block on library repos.

The exit code is CI-friendly: wire it into a GitHub Actions workflow and any repo that crashes or attempts sensitive access blocks the PR.

---

## Quick start

```bash
# Test against the built-in clean fixture (should BOOTS: YES, exit 0)
python proofer.py file://$(pwd)/tests/fixtures/clean-repo

# Test against the built-in slop fixture (should BOOTS: NO, exit 1)
python proofer.py file://$(pwd)/tests/fixtures/slop-repo
```

Or point it at any public GitHub URL:

```bash
# A Python library — will return NO RUNNABLE ENTRYPOINT (yellow, exit 0).
# This is the correct verdict for a library: it's not slop, just nothing to run.
python proofer.py https://github.com/pallets/markupsafe.git

# Or use the installed command:
repo-proofer https://github.com/pallets/markupsafe.git
```

> **Three-color verdict system:**
> - **GREEN `BOOTS: YES`** — the repo ran successfully (clean exit, long-running server, or readiness signal detected).
> - **RED `BOOTS: NO`** — the repo crashed or attempted sensitive file access. This is the slop signal.
> - **YELLOW `NO RUNNABLE ENTRYPOINT`** — the repo was detected as a known stack but has nothing to run (a library). Not slop, just not runnable. Exits 0 so CI doesn't block.

### Run the full test suite

```bash
# Deterministic tests (no Docker needed, ~1 second)
python scripts/smoke_test.py

# Docker integration tests (requires Docker, ~2 minutes first run)
python tests/integration_test.py
```

---

## Example output

```
Checking Docker daemon...
Cloning https://github.com/owner/repo.git (depth=1)...
Detected stack: Python (image: python:3.11-slim)
Building strace-enabled image (one-time setup for python:3.11-slim)...
Installing dependencies (network ON, timeout 60s)...
Executing entrypoint (network OFF, read-only FS, timeout 30s)...

╭─ repo-proofer verdict ──────────────────────────────╮
│ Repository          https://github.com/owner/repo.git│
│ Detected Stack      Python                            │
│ BOOTS               NO                                │
│ Network Egress      BLOCKED                           │
│ Filesystem          READ-ONLY                         │
│ Warnings            [!] App crashed when network was  │
│                     blocked. May require external API │
│                     to function.                      │
╰──────────────────────────────────────────────────────╯

╭─ Runtime Behavior Report ────────────────────────────╮
│ Files Read              3                             │
│ Files Written           2                             │
│ Processes Spawned       1                             │
│ Network Calls Attempted 1                             │
│ Sensitive File Access   1 (see below)                 │
│                                                       │
│ Generated via strace inside the zero-network sandbox  │
╰──────────────────────────────────────────────────────╯

╭─ Network Calls Attempted (1) ────────────────────────╮
│ - connect 93.184.216.34:443                          │
╰──────────────────────────────────────────────────────╯

╭─ Sensitive File Access (1) ──────────────────────────╮
│ - /root/.ssh/id_rsa                                  │
╰──────────────────────────────────────────────────────╯

[!] Escalating verdict to BOOTS: NO — sensitive file access detected despite clean exit.
```

---

## How it works

```
1. Clone         git clone --depth=1                          (network ON)
2. Detect        filesystem checks for marker files           (deterministic)
3. Install       docker run ... <install_cmd>                 (network ON, 60s)
4. Execute       docker run --rm --read-only --network none   (network OFF)
                          --cap-drop ALL --memory 512m --cpus 0.5
                          --tmpfs /tmp -v repo:/app:ro
                          --entrypoint /usr/bin/strace        (when behavior report on)
                          -ff -e trace=openat,open,creat,execve,connect,socket,...
5. Analyze       regex on stdout/stderr + strace trace files  (deterministic)
6. Verdict       rich panel + exit code
```

### Security constraints (do not weaken)

The execution phase **always** includes every one of these flags. Removing any of them breaks the moat:

| Flag                  | Why                                                        |
|-----------------------|------------------------------------------------------------|
| `--rm`                | Container is removed after run.                            |
| `--read-only`         | Root filesystem is read-only.                              |
| `--network none`      | Absolutely no internet access.                             |
| `--cap-drop ALL`      | No Linux capabilities (SYS_PTRACE added only for strace). |
| `--memory 512m`       | Memory cap.                                                |
| `--cpus 0.5`          | CPU cap.                                                   |
| `--tmpfs /tmp`        | Writable in-memory `/tmp`.                                 |
| `-v repo:/app:ro`     | Repo mounted **read-only**.                                |

If the app crashes because it can't reach the network, **that is a successful detection of a hidden dependency, not a tool failure.**

---

## Why no LLMs?

Speed, reliability, and zero cost. A deterministic engine runs in seconds (warm cache, fast-exiting scripts), costs nothing per invocation, and gives the same answer every time. An LLM-based analyzer would be slower, more expensive, and gameable via prompt injection in the repo's own README. Pure determinism is the core feature.

---

## Limitations

This tool is honest about what it can and can't do. The gaps below are real; workarounds are noted where they exist.

- **First run is minutes, not seconds — in Docker mode.** The Docker backend pulls base images (hundreds of MB) and builds a strace image. The native backend (bubblewrap, default on Linux) has no image pulls — it uses the host's runtimes directly and starts in milliseconds.
- **Go and Rust are experimental.** Both run under `--network none` with no install step, so any project with external dependencies can't fetch them at runtime. Only zero-dependency or pre-vendored Go/Rust projects will boot. A future release may add a `go mod vendor` / `cargo vendor` install phase.
- **Hostname-based C2 detection is indirect.** Under `--network none`, DNS resolution fails *before* `connect()`, so a hostname-based egress target shows up in the strace report as a DNS query to the resolver (e.g. `connect 192.168.65.7:53`), not as the actual hostname. Hardcoded-IP malware produces the clean `connect <IP>:<port>` line shown in the example above. The **Sensitive File Access** list is the strong, unambiguous signal regardless of how the app phones home.
- **Install-phase residual risk.** The install phase runs with network ON (it has to, to fetch packages). We close the npm supply-chain window with `--ignore-scripts` (lifecycle scripts are NOT executed), and push pip toward wheels with `--prefer-binary`. However, pip packages that only ship as sdists will still trigger a PEP 517 build backend during install. This is a known residual risk; a future release may run the install phase under `--network none` with a pre-populated package cache.
- **Native sandbox is Linux-only.** Bubblewrap doesn't exist on macOS/Windows. On those platforms, `--sandbox auto` falls back to Docker. The native sandbox also has no memory/CPU limits (bubblewrap has no built-in cgroup controls) — the network + filesystem moat is fully intact, but a resource-exhaustion DoS isn't prevented. Use `--sandbox docker` for the full isolation profile.
- **Docker is now optional.** The default `--sandbox auto` prefers the native bubblewrap sandbox (no Docker, no image pulls, millisecond startup). Docker is used as a fallback when bubblewrap isn't available (macOS/Windows) or when explicitly requested via `--sandbox docker`.

---

## Roadmap

- [x] Phase 1: Open-source CLI (this repo)
- [x] `uvx` / `pipx` packaging (`pyproject.toml` + console script)
- [x] Three-color verdict system (green/red/yellow — libraries are not slop)
- [x] Console-script entrypoint detection (`[project.scripts]` / `console_scripts`)
- [x] Docker-optional native sandbox (bubblewrap — `--sandbox auto/native/docker`)
- [ ] Publish to PyPI (see [PUBLISH.md](PUBLISH.md) — package builds, publish is one command)
- [ ] Phase 2: Cloud API + runtime-behavior database
- [ ] Phase 3: Enterprise CI/CD gate (GitHub Actions / GitLab CI plugin)

---

## License

MIT
