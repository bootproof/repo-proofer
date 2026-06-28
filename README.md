# repo-proofer

[![CI](https://github.com/bootproof/repo-proofer/actions/workflows/ci.yml/badge.svg)](https://github.com/bootproof/repo-proofer/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/repo-proofer.svg)](https://pypi.org/project/repo-proofer/)

Find out if a repo will steal your keys before you run it.

GitHub is flooded with AI-generated "slop" — repositories with impressive READMEs that don't actually run, or worse, quietly phone home to a C2 server the moment you `npm install` them. `repo-proofer` clones a repo, drops it into a zero-network, read-only sandbox, executes it, and tells you — deterministically, no AI — whether it booted and whether it tried to read your SSH keys.

<p align="center">
<i>The slop-repo fixture being caught red-handed.</i>
</p>

```
$ repo-proofer file://$(pwd)/tests/fixtures/slop-repo

╭─ repo-proofer verdict ──────────────────────────────╮
│ Repository          file://.../slop-repo             │
│ Detected Stack      Python                            │
│ BOOTS               NO                                │
│ Detail              exited 1 (crash)                  │
│ Network Egress      BLOCKED                           │
│ Filesystem          READ-ONLY                         │
│ Warnings            [!] App crashed when network was  │
│                     blocked. May require external API │
│                     to function.                      │
╰──────────────────────────────────────────────────────╯

╭─ Sensitive File Access (3) ──────────────────────────╮
│ - /etc/passwd                                        │
│ - /root/.ssh/id_ed25519                              │
│ - /root/.ssh/id_rsa                                  │
╰──────────────────────────────────────────────────────╯

[!] Sensitive file access detected — primary indicator of malicious intent.
```

## Highlights

- **Runs untrusted code safely.** Every execution is sandboxed with the network disabled and the filesystem read-only. The repo can't phone home. It can't write outside `/tmp`. It can't read `~/.ssh`.
- **Catches what static analysis can't.** Snyk, Socket, and GitHub Advanced Security read code to see if it *looks* malicious. `repo-proofer` runs it and watches what it *does*. Obfuscation can fool a linter. It cannot fool a kernel that refuses to open a socket.
- **100% deterministic, zero AI.** Pure subprocess + filesystem + strace. No LLMs, no API calls, no prompt-injection surface. Same answer every time, free to run forever.
- **No Docker required.** The default `--sandbox auto` uses a native bubblewrap sandbox on Linux — millisecond startup, no image pulls. Docker is the fallback for macOS/Windows or `--sandbox docker` for full clean-room isolation.
- **Three-color verdicts.** Green `BOOTS: YES` (it ran), red `BOOTS: NO` (it crashed or tried to steal secrets), yellow `NO RUNNABLE ENTRYPOINT` (it's a library, not slop). Libraries don't get the same red as malware.
- **Runtime Behavior Report.** strace traces every syscall inside the sandbox. You get an SBOM-style report based on *actual execution*: files read, files written, processes spawned, network calls attempted, sensitive paths touched.
- **Installable in one command.** `uvx repo-proofer <url>` — no clone, no venv, no setup. Published on [PyPI](https://pypi.org/project/repo-proofer/).

## Installation

Run `repo-proofer` instantly with `uvx` — no clone, no venv, no setup:

```bash
uvx repo-proofer https://github.com/owner/repo.git
```

That's it. `uvx` creates an ephemeral isolated environment, installs `typer`/`rich`/`GitPython`, clones the target repo, spins up the sandbox, runs the strace, prints the verdict, and cleans up after itself.

Other install methods:

```bash
# Install permanently with pipx:
pipx install repo-proofer
repo-proofer https://github.com/owner/repo.git

# Or with pip:
pip install repo-proofer

# Or from source (for development):
git clone https://github.com/bootproof/repo-proofer.git
cd repo-proofer
pip install -e .
```

Requires Python 3.10+.

**On Linux (zero-setup, instant):** install `bubblewrap` and `strace` — both are required for the native sandbox and exfil detection:

```bash
sudo apt install bubblewrap strace   # Debian/Ubuntu
sudo dnf install bubblewrap strace   # Fedora
```

Then `uvx repo-proofer <url>` runs in ~1.5 seconds with no Docker daemon, no image pulls. This is the recommended path.

**On macOS / Windows:** the native sandbox isn't available (bubblewrap is Linux-only). `--sandbox auto` falls back to Docker — run `repo-proofer <url>` with Docker Desktop running. First run pulls images (~minutes); subsequent runs are fast.

## Documentation

See the [Limitations](#limitations) section for honest gaps, and the [FAQ](#faq) for common questions. The command-line reference is available with `repo-proofer --help`.

## Features

### Triage a repo

Point `repo-proofer` at any Git URL. It clones, detects the stack, installs deps, executes the entrypoint in a locked sandbox, and prints a verdict.

```console
$ repo-proofer https://github.com/pallets/markupsafe.git
Cloning https://github.com/pallets/markupsafe.git (depth=1)...
Detected stack: Python | Native sandbox (bubblewrap)
Installing dependencies (network ON, timeout 60s)...
Executing entrypoint (network OFF, read-only FS, timeout 30s)...

╭─ repo-proofer verdict ──────────────────────────────╮
│ Repository          https://github.com/pallets/mar…  │
│ Detected Stack      Python                            │
│ BOOTS               NO RUNNABLE ENTRYPOINT            │
│ Detail              no runnable entrypoint            │
│                     (looks like a library)            │
│ Network Egress      BLOCKED                           │
│ Filesystem          READ-ONLY                         │
╰──────────────────────────────────────────────────────╯
```

`markupsafe` is a library — no `main.py`, nothing to run. The yellow verdict is correct: it's not slop, it just has no entrypoint. CI exits 0.

### Catch a malicious repo

The `slop-repo` fixture impersonates an AI startup while quietly reading `~/.ssh/id_rsa` and `/etc/passwd`, then phoning home to a C2 server. Under `repo-proofer`'s `--network none` sandbox, the phone-home fails and strace catches the secret reads:

```console
$ repo-proofer file://$(pwd)/tests/fixtures/slop-repo

╭─ repo-proofer verdict ──────────────────────────────╮
│ BOOTS               NO                                │
│ Detail              exited 1 (crash)                  │
│ Warnings            [!] App crashed when network was  │
│                     blocked.                          │
╰──────────────────────────────────────────────────────╯

╭─ Runtime Behavior Report ────────────────────────────╮
│ Files Read              2                             │
│ Network Calls Attempted 1                             │
│ Sensitive File Access   3 (see below)                 │
╰──────────────────────────────────────────────────────╯

╭─ Network Calls Attempted (1) ────────────────────────╮
│ - connect 203.0.113.42:443                           │
╰──────────────────────────────────────────────────────╯

╭─ Sensitive File Access (3) ──────────────────────────╮
│ - /etc/passwd                                        │
│ - /root/.ssh/id_ed25519                              │
│ - /root/.ssh/id_rsa                                  │
╰──────────────────────────────────────────────────────╯

[!] Sensitive file access detected — primary indicator of malicious intent.
```

Exit code 1. The verdict is unambiguous: this repo tried to steal your keys.

### The sandbox

Two backends, same moat:

```console
$ repo-proofer <url> --sandbox native    # bubblewrap (Linux, no Docker, milliseconds)
$ repo-proofer <url> --sandbox docker    # Docker (clean-room images, memory/CPU limits)
$ repo-proofer <url> --sandbox auto      # default: prefer native, fall back to Docker
```

Both backends enforce the same security constraints:

| Constraint | Docker mode | Native mode |
|---|---|---|
| Network | `--network none` | `--unshare-net` |
| Filesystem | `--read-only` + `--tmpfs /tmp` | `--ro-bind /usr` + `--tmpfs /tmp` |
| SSH keys | not mounted | `--tmpfs /home` + `--tmpfs /root` (empty) |
| Capabilities | `--cap-drop ALL` | bubblewrap drops all by default |
| Repo | `-v repo:/app:ro` | `--ro-bind repo /app` |

If the app crashes because it can't reach the network, **that is a successful detection of a hidden dependency, not a tool failure.**

### Stack detection

`repo-proofer` detects the stack from marker files and resolves the entrypoint:

```console
$ repo-proofer https://github.com/owner/my-cli.git
Detected stack: Python | Native sandbox (bubblewrap)
Executing entrypoint (network OFF, read-only FS, timeout 30s)...
```

| Marker | Stack | Entrypoint resolution |
|---|---|---|
| `package.json` | Node.js | `scripts.start`, `main`, `bin`, then `index.js`/`app.js`/`server.js` |
| `requirements.txt` / `pyproject.toml` / `setup.py` / `setup.cfg` | Python | `[project.scripts]`, `console_scripts`, `main.py`/`app.py`/`server.py`/`run.py`, `manage.py check`, `src/` layout, `python -m <pkg>` |
| `go.mod` | Go (experimental) | `go run main.go` |
| `Cargo.toml` | Rust (experimental) | `cargo run --offline` |

A modern CLI that declares its entrypoint only in `[project.scripts]` (no `main.py`) is correctly detected as runnable — not mislabeled as a library.

### Exit codes

```console
$ repo-proofer <url>; echo "exit: $?"
exit: 0    # boots cleanly, OR is a library (yellow)
exit: 1    # crashed, or attempted sensitive file access (red)
exit: 2    # clone failed
exit: 3    # sandbox unavailable (no Docker / no bubblewrap)
exit: 4    # could not detect project stack
exit: 5    # failed to pull Docker image
```

The exit code is CI-friendly: wire it into a GitHub Actions workflow and any repo that crashes or touches secrets blocks the PR.

## How it works

```
1. Clone      git clone --depth=1                          (network ON)
2. Detect     filesystem checks for marker files           (deterministic)
3. Install    sandbox ... <install_cmd>                    (network ON, 60s)
4. Execute    sandbox --network=none --read-only ...       (network OFF)
              └─ strace -ff -e trace=openat,connect,...    (behavior report)
5. Analyze    regex on stdout/stderr + strace trace        (deterministic)
6. Verdict    three-color panel + exit code
```

No LLMs. No AI APIs. Pure subprocess + filesystem + strace. An LLM-based analyzer would be slower, more expensive, and gameable via prompt injection in the repo's own README. Pure determinism is the core feature.

## Limitations

This tool is honest about what it can and can't do.

- **First run is minutes in Docker mode.** The Docker backend pulls base images and builds a strace image. The native backend (default on Linux) has no image pulls — it uses the host's runtimes and starts in milliseconds.
- **Go and Rust are experimental.** Both run under `--network none` with no install step, so projects with external dependencies can't fetch them at runtime. Only zero-dependency or pre-vendored Go/Rust projects boot.
- **Hostname-based C2 detection is indirect.** Under `--network none`, DNS resolution fails *before* `connect()`, so a hostname-based egress target shows up as a DNS query to the resolver, not the actual hostname. Hardcoded-IP malware produces a clean `connect <IP>:<port>` line. The **Sensitive File Access** list is the strong, unambiguous signal regardless.
- **Install-phase residual risk.** The install phase runs with network ON (it has to, to fetch packages). npm's supply-chain window is closed with `--ignore-scripts`; pip is pushed toward wheels with `--prefer-binary`. sdist-only packages still trigger a PEP 517 build — a known residual risk.
- **Native sandbox is Linux-only.** Bubblewrap doesn't exist on macOS/Windows. On those platforms, `--sandbox auto` falls back to Docker. The native sandbox also has no memory/CPU limits — use `--sandbox docker` for the full isolation profile.
- **Speed vs. isolation tradeoff.** The default `--sandbox auto` prefers the native bubblewrap sandbox (fast, no Docker) over Docker (clean-room isolation, cgroup limits). For "is this slop / does it phone home," native is a reasonable trade. For "this might be targeted malware aimed at me," use `--sandbox docker` for full container isolation with a separate kernel namespace and seccomp profile.

## FAQ

#### Why not just read the code myself?

You can — and you should, for repos you trust. But for the 95% case ("a stranger's repo with a flashy README"), reading every line of `setup.py` and `postinstall.sh` takes longer than running `repo-proofer`, and obfuscation can hide intent from a human reader. `repo-proofer` watches physics: if the app opens a socket, the kernel tells us. You can't obfuscate a syscall.

#### How is this different from Snyk / Socket / GitHub Advanced Security?

Those tools do *static analysis* — they read code to see if it looks malicious. `repo-proofer` does *dynamic execution* — it runs the code in a locked box and watches what it actually does. Static analysis is bypassable (obfuscated code, environment-triggered payloads). Dynamic execution is not: if a malicious repo needs to phone home to download its payload, it physically cannot do that inside `--network none`.

#### What does "BOOTS: YES" mean for a server that never exits?

A process that times out without crashing is a healthy long-running process (server, daemon, bot). The verdict is `BOOTS: YES (long-running)`. If it also printed a readiness signal (`"listening on port 8080"`, `"Uvicorn running"`), the verdict upgrades to `BOOTS: YES (server detected)` with the matched signal shown.

#### Can it run on macOS?

Yes, with Docker. `--sandbox auto` falls back to Docker on macOS (bubblewrap is Linux-only). `uvx repo-proofer <url>` works — it just needs Docker Desktop running.

#### Is it ready for production?

The engine is stable and the deterministic test suite (56 tests) passes on every commit. The native bubblewrap sandbox is new and should be considered beta — the Docker sandbox is the production-grade path. See the [CI badge](https://github.com/bootproof/repo-proofer/actions) for current status.

## Contributing

Contributions are welcome. See the [test suite](scripts/smoke_test.py) for the deterministic core, and [tests/integration_test.py](tests/integration_test.py) for the Docker integration tests. Run `python scripts/smoke_test.py` to verify before submitting a PR.

## License

[MIT](LICENSE)
