# repo-proofer

**Brutally honest verdicts for AI-generated GitHub repos. 100% deterministic. No LLMs.**

GitHub is flooded with AI-generated "slop" — repositories that have impressive READMEs but don't actually run, or worse, quietly phone home to a C2 server the moment you `npm install` them. Developers waste 30+ minutes cloning, debugging, and disinfecting these repos.

`repo-proofer` is a consumer-side triage tool. Point it at any public Git URL. In under 5 seconds it clones the repo, drops it into a hardened Docker sandbox with the network disabled and the filesystem read-only, executes the entrypoint, and prints a brutal honest verdict:

```
BOOTS: NO. Network Egress: BLOCKED. Filesystem: READ-ONLY.
[!] App crashed when network was blocked. May require external API to function.
```

If a repo can't boot without internet, that's not a tool failure — that's a successful detection of a hidden dependency. **You cannot bypass physics.**

---

## The moat

`--network none` and `--read-only` are mandatory on every execution. Static analysis (Snyk, Socket, GitHub Advanced Security) reads code to see if it *looks* malicious. `repo-proofer` actually runs it in a locked box and watches what it *does*. Obfuscation can fool a linter. It cannot fool a kernel that refuses to open a socket.

If the app tries to read `~/.ssh/id_rsa` while the network is blocked, the verdict escalates to `BOOTS: NO` even if the process exited cleanly. **That's the enterprise hook.**

---

## Features

- **Zero AI.** Pure subprocess + filesystem + strace. Deterministic, fast, free to run forever.
- **Hardened sandbox.** `--rm --read-only --network none --cap-drop ALL --memory 512m --cpus 0.5 --tmpfs /tmp`. The repo is mounted `:ro`. No exceptions.
- **Stack auto-detection.** Node.js, Python, Go, Rust — picked by file-existence (`package.json`, `requirements.txt`/`main.py`, `go.mod`, `Cargo.toml`).
- **Runtime Behavior Report.** When enabled (default), the entrypoint is wrapped in `strace -ff` inside the sandbox. After execution you get an SBOM-style report based on *actual execution, not static guessing*:
  - Files Read
  - Files Written
  - Processes Spawned
  - Network Calls Attempted (with target IP/port, even when blocked)
  - Sensitive File Access (`~/.ssh/`, `.aws/credentials`, `.env`, `/etc/passwd`, ...)
- **Graceful fallback.** No Docker? Errors cleanly. No strace image? Falls back to a non-traced run. Install step fails? Proceeds to execution anyway (no auto-repair).

---

## Install

```bash
pip install -r requirements.txt
```

Requires:
- Python 3.10+
- Docker (running locally)

Supported stacks and their base images:

| Marker file        | Stack    | Image                |
|--------------------|----------|----------------------|
| `package.json`     | Node.js  | `node:20-slim`       |
| `requirements.txt` / `main.py` | Python | `python:3.11-slim` |
| `go.mod`           | Go       | `golang:1.22-alpine` |
| `Cargo.toml`       | Rust     | `rust:1.75-slim`     |

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
| 0    | Repo boots cleanly under sandboxed execution.        |
| 1    | Repo does NOT boot (non-zero exit, sensitive access).|
| 2    | Clone failed.                                        |
| 3    | Docker not installed / daemon not running.           |
| 4    | Could not detect project stack.                      |
| 5    | Failed to pull Docker image.                         |

The exit code is CI-friendly: wire it into a GitHub Actions workflow and any repo that can't boot offline blocks the PR.

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

Speed, reliability, and zero cost. A deterministic engine runs in 4 seconds, costs nothing per invocation, and gives the same answer every time. An LLM-based analyzer would be slower, more expensive, and gameable via prompt injection in the repo's own README. Pure determinism is the core feature.

---

## Roadmap

- [x] Phase 1: Open-source CLI (this repo)
- [ ] Phase 2: Cloud API + runtime-behavior database
- [ ] Phase 3: Enterprise CI/CD gate (GitHub Actions / GitLab CI plugin)

---

## License

MIT
