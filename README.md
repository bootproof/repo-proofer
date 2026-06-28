# repo-proofer

<p align="center">
  <strong>Find out if a repo will steal your keys — or lie to your face — before you run it.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/repo-proofer/"><img src="https://img.shields.io/pypi/v/repo-proofer.svg?color=blue&label=PyPI&cacheSeconds=0" alt="PyPI"></a>
  <a href="https://pypi.org/project/repo-proofer/"><img src="https://img.shields.io/pypi/dm/repo-proofer.svg?color=blue&label=downloads&cacheSeconds=0" alt="PyPI downloads"></a>
  <a href="https://pypi.org/project/repo-proofer/"><img src="https://img.shields.io/pypi/pyversions/repo-proofer.svg?color=blue&cacheSeconds=0" alt="Python versions"></a>
  <a href="https://github.com/bootproof/repo-proofer/actions"><img src="https://github.com/bootproof/repo-proofer/actions/workflows/ci.yml/badge.svg?cacheSeconds=0" alt="CI"></a>
  <a href="https://github.com/bootproof/repo-proofer/actions"><img src="https://github.com/bootproof/repo-proofer/actions/workflows/proofer.yml/badge.svg?cacheSeconds=0" alt="repo-proofer"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?cacheSeconds=0" alt="License"></a>
  <a href="https://github.com/bootproof/repo-proofer"><img src="https://img.shields.io/github/stars/bootproof/repo-proofer.svg?style=social&cacheSeconds=0" alt="GitHub stars"></a>
</p>

---

GitHub is flooded with AI-generated "slop" — repositories with impressive READMEs that don't actually run, or worse, quietly phone home to a C2 server the moment you `npm install` them. `repo-proofer` clones a repo, drops it into a zero-network, read-only sandbox, executes it, and tells you three things — **deterministically, no AI**:

1. **Does it boot?** — three-color verdict (green/red/yellow)
2. **Will it steal your keys?** — strace-based exfiltration detection
3. **Does its README tell the truth?** — claim verification with buzzword detection

<p align="center">
<i>The slop-repo fixture caught red-handed: SSH key theft, network egress, and 11 buzzword lies.</i>
</p>

```
$ uvx repo-proofer file://$(pwd)/tests/fixtures/slop-repo

╭─ repo-proofer verdict ──────────────────────────────╮
│ BOOTS               NO                                │
│ Detail              exited 1 (crash)                  │
│ Network Egress      BLOCKED                           │
│ Filesystem          READ-ONLY                         │
│ Warnings            [!] App crashed when network was  │
│                     blocked.                          │
╰──────────────────────────────────────────────────────╯

╭─ Sensitive File Access — HIGH (2) ───────────────────╮
│ - /root/.ssh/id_ed25519                              │
│ - /root/.ssh/id_rsa                                  │
╰──────────────────────────────────────────────────────╯

╭─ README Claim Verification ──────────────────────────╮
│ Claims Verified    2 of 2 testable                   │
│ Buzzword Claims    11 (not machine-verifiable)       │
│                                                      │
│ All 2 testable claims verified (11 buzzword claims   │
│ not machine-verifiable)                              │
╰──────────────────────────────────────────────────────╯

╭─ Buzzword Claims (11) ───────────────────────────────╮
│ Marketing terms — cannot be verified by execution.   │
│ High concentration of these is a slop signal.        │
│ ~ Quantum-Enhanced GPT-5 + Blockchain Audit Trail    │
│ ~ AI-Powered code review                             │
│ ~ Predictive Auto-Scaling                            │
│ ~ Zero-Trust Security                                │
│ ~ Carbon-Aware                                       │
│ ~ Self-Healing                                       │
│ ... (5 more)                                         │
╰──────────────────────────────────────────────────────╯

[!] EXFILTRATION DETECTED — high-risk sensitive file access correlated
with network attempt(s). Secret paths: /root/.ssh/id_ed25519,
/root/.ssh/id_rsa. Primary indicator of malicious intent.
```

One command. Three answers. Zero AI.

## Highlights

- **Runs untrusted code safely.** Every execution is sandboxed with `--network none` and `--read-only`. The repo can't phone home. It can't write outside `/tmp`. It can't read `~/.ssh`.
- **Catches what static analysis can't.** Snyk, Socket, and GitHub Advanced Security read code to see if it *looks* malicious. `repo-proofer` runs it and watches what it *does*. Obfuscation can fool a linter. It cannot fool a kernel that refuses to open a socket.
- **Detects exfiltration, not just access.** Reading `~/.ssh/id_rsa` is flagged as `EXFILTRATION DETECTED` only when correlated with a network attempt — the smoking gun. A config file read with zero network calls stays yellow, not red. No false accusations.
- **Verifies README claims against execution.** Extracts testable assertions from the README (ports, services, frameworks, install commands) and maps each to runtime evidence. "Starts on port 3000" is VERIFIED when strace shows a `bind()` on port 3000. Claims that can't be checked are labeled UNVERIFIABLE — never silently ignored.
- **Catches buzzword slop.** 12 regex patterns detect marketing claims ("quantum-enhanced," "blockchain-secured," "AI-powered," "zero-trust security") that can't be verified by execution. A README with 11 buzzwords and 2 testable claims is flagged as slop — even if the 2 testable claims pass.
- **100% deterministic, zero AI.** Pure subprocess + filesystem + strace. No LLMs, no API calls, no prompt-injection surface. Same answer every time, free to run forever.
- **No Docker required on Linux.** The default `--sandbox auto` uses a native bubblewrap sandbox — millisecond startup, no image pulls. Docker is the fallback for macOS/Windows or `--sandbox docker` for full clean-room isolation.
- **Three-color verdicts.** Green `BOOTS: YES` (it ran), red `BOOTS: NO` (it crashed or tried to steal secrets), yellow `NO RUNNABLE ENTRYPOINT` (it's a library, not slop). Libraries don't get the same red as malware.
- **Installable in one command.** `uvx repo-proofer <url>` — no clone, no venv, no setup. Published on [PyPI](https://pypi.org/project/repo-proofer/).

## Installation

Run `repo-proofer` instantly with `uvx` — no clone, no venv, no setup:

```bash
uvx repo-proofer https://github.com/owner/repo.git
```

That's it. `uvx` creates an ephemeral isolated environment, installs the dependencies, clones the target repo, spins up the sandbox, runs the strace, prints the verdict, and cleans up after itself.

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

## Features

### Triage a repo

Point `repo-proofer` at any Git URL. It clones, detects the stack, installs deps, executes the entrypoint in a locked sandbox, and prints a verdict.

```console
$ uvx repo-proofer https://github.com/pallets/markupsafe.git

╭─ repo-proofer verdict ──────────────────────────────╮
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

The `slop-repo` fixture impersonates an AI startup while quietly reading `~/.ssh/id_rsa`, then phoning home to a C2 server. Under `repo-proofer`'s `--network none` sandbox, the phone-home fails and strace catches the secret reads:

```console
$ uvx repo-proofer file://$(pwd)/tests/fixtures/slop-repo

╭─ repo-proofer verdict ──────────────────────────────╮
│ BOOTS               NO                                │
│ Detail              exited 1 (crash)                  │
│ Warnings            [!] App crashed when network was  │
│                     blocked.                          │
╰──────────────────────────────────────────────────────╯

╭─ Sensitive File Access — HIGH (2) ───────────────────╮
│ - /root/.ssh/id_ed25519                              │
│ - /root/.ssh/id_rsa                                  │
╰──────────────────────────────────────────────────────╯

[!] EXFILTRATION DETECTED — high-risk sensitive file access
correlated with network attempt(s). Secret paths:
/root/.ssh/id_ed25519, /root/.ssh/id_rsa.
Primary indicator of malicious intent.
```

Exit code 1. The "malicious intent" wording is **earned** — it only fires when a HIGH-severity secret read (SSH keys, `.env`, AWS credentials) is correlated with a network attempt. A repo that reads `.npmrc` with zero network calls stays yellow, not red. No false accusations.

### Verify README claims

`repo-proofer` reads the README, extracts testable claims, and maps each to runtime evidence:

```console
╭─ README Claim Verification ──────────────────────────╮
│ Claims Verified    3 of 3 testable                   │
│                                                      │
│ All 3 testable README claims verified by execution.  │
╰──────────────────────────────────────────────────────╯

╭─ Verified (3) ───────────────────────────────────────╮
│ ✓ Server starts on port 3000                         │
│   App bound to port 3000 (strace bind() observed)    │
│ ✓ pip install -r requirements.txt                    │
│   Install used: pip install -r requirements.txt      │
│ ✓ Built with Flask                                   │
│   Framework in requirements.txt                      │
╰──────────────────────────────────────────────────────╯
```

A repo that boots cleanly but has 0 of 5 claims verified is flagged as **likely slop** — its README promises things the code doesn't do.

### Catch buzzword slop

12 regex patterns detect marketing claims that can't be verified by execution:

```console
╭─ Buzzword Claims (11) ───────────────────────────────╮
│ Marketing terms — cannot be verified by execution.   │
│ High concentration of these is a slop signal.        │
│                                                      │
│ ~ Quantum-Enhanced GPT-5 + Blockchain Audit Trail    │
│ ~ AI-Powered code review                             │
│ ~ Predictive Auto-Scaling                            │
│ ~ Zero-Trust Security                                │
│ ~ Carbon-Aware                                       │
│ ~ Self-Healing                                       │
│ ~ Edge-Native Architecture                           │
│ ... (4 more)                                         │
╰──────────────────────────────────────────────────────╯
```

A README with 11 buzzwords and 2 testable claims is flagged as slop — even if the 2 testable claims pass. The buzzword count is the slop signal that's visible at a glance.

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

| Marker | Stack | Entrypoint resolution |
|---|---|---|
| `package.json` | Node.js | `scripts.start`, `main`, `bin`, then `index.js`/`app.js`/`server.js` |
| `requirements.txt` / `pyproject.toml` / `setup.py` / `setup.cfg` | Python | `[project.scripts]`, `console_scripts`, `main.py`/`app.py`/`server.py`/`run.py`, `manage.py check`, `src/` layout, `python -m <pkg>` |
| `Gemfile` + `config.ru` | Ruby (Rails) | `bundle exec rails server` |
| `go.mod` | Go (experimental) | `go run main.go` |
| `Cargo.toml` | Rust (experimental) | `cargo run --offline` |

Polyglot repos (Rails + frontend `package.json`, Django + webpack) correctly resolve to their primary app language — a secondary `package.json` doesn't mask a Rails or Django app.

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
              └─ strace -ff -e trace=openat,connect,bind   (behavior report)
5. Analyze    regex on stdout/stderr + strace trace        (deterministic)
6. Claims     extract README claims → match to evidence    (deterministic)
7. Verdict    three-color panel + exit code
```

No LLMs. No AI APIs. Pure subprocess + filesystem + strace. An LLM-based analyzer would be slower, more expensive, and gameable via prompt injection in the repo's own README. Pure determinism is the core feature.

## Limitations

This tool is honest about what it can and can't do.

- **First run is minutes in Docker mode.** The Docker backend pulls base images and builds a strace image. The native backend (default on Linux) has no image pulls — it uses the host's runtimes and starts in milliseconds.
- **Go and Rust are experimental.** Both run under `--network none` with no install step, so projects with external dependencies can't fetch them at runtime. Only zero-dependency or pre-vendored Go/Rust projects boot.
- **Claim verification is regex-based, not semantic.** We extract testable assertions (ports, services, frameworks, install commands, file types) using regex patterns — not LLMs. This means we'll miss nuanced claims, but every claim we extract is checkable and the extraction is reproducible. Buzzword detection catches the marketing terms that can't be verified.
- **Hostname-based C2 detection is indirect.** Under `--network none`, DNS resolution fails *before* `connect()`, so a hostname-based egress target shows up as a DNS query to the resolver, not the actual hostname. The **Sensitive File Access** list is the strong, unambiguous signal regardless.
- **Install-phase residual risk.** The install phase runs with network ON (it has to, to fetch packages). npm's supply-chain window is closed with `--ignore-scripts`; pip is pushed toward wheels with `--prefer-binary`. sdist-only packages still trigger a PEP 517 build — a known residual risk.
- **Native sandbox is Linux-only.** Bubblewrap doesn't exist on macOS/Windows. On those platforms, `--sandbox auto` falls back to Docker. The native sandbox also has no memory/CPU limits — use `--sandbox docker` for the full isolation profile.
- **Speed vs. isolation tradeoff.** The default `--sandbox auto` prefers the native bubblewrap sandbox (fast, no Docker) over Docker (clean-room isolation, cgroup limits). For "is this slop / does it phone home," native is a reasonable trade. For "this might be targeted malware aimed at me," use `--sandbox docker` for full container isolation.

## FAQ

#### Why not just read the code myself?

You can — and you should, for repos you trust. But for the 95% case ("a stranger's repo with a flashy README"), reading every line of `setup.py` and `postinstall.sh` takes longer than running `repo-proofer`, and obfuscation can hide intent from a human reader. `repo-proofer` watches physics: if the app opens a socket, the kernel tells us. You can't obfuscate a syscall.

#### How is this different from Snyk / Socket / GitHub Advanced Security?

Those tools do *static analysis* — they read code to see if it looks malicious. `repo-proofer` does *dynamic execution* — it runs the code in a locked box and watches what it actually does. Static analysis is bypassable (obfuscated code, environment-triggered payloads). Dynamic execution is not: if a malicious repo needs to phone home to download its payload, it physically cannot do that inside `--network none`.

#### What does "BOOTS: YES" mean for a server that never exits?

A process that times out without crashing is a healthy long-running process (server, daemon, bot). The verdict is `BOOTS: YES (long-running)`. If it also printed a readiness signal (`"listening on port 8080"`, `"Uvicorn running"`), the verdict upgrades to `BOOTS: YES (server detected)` with the matched signal shown.

#### How does the claim verification work?

`repo-proofer` reads the README and applies 15 regex patterns to extract testable assertions: port numbers, database services, API integrations, install commands, run commands, file types, and frameworks. Each claim is then matched against the strace trace and execution output. A "starts on port 3000" claim is VERIFIED when strace shows a `bind()` on port 3000. Claims that can't be checked are labeled UNVERIFIABLE — never silently ignored.

#### How does buzzword detection work?

12 regex patterns detect common AI-slop marketing terms: "quantum-enhanced," "blockchain-secured," "AI-powered," "zero-trust security," "predictive auto-scaling," "self-healing," "carbon-aware," "edge-native," "5G-optimized," and more. These are always UNVERIFIABLE — they're marketing terms with no testable runtime behavior. A high buzzword count is a slop signal visible at a glance.

#### Can it run on macOS?

Yes, with Docker. `--sandbox auto` falls back to Docker on macOS (bubblewrap is Linux-only). `uvx repo-proofer <url>` works — it just needs Docker Desktop running.

#### Is it ready for production?

The engine is stable and the deterministic test suite (91 tests) passes on every commit. The native bubblewrap sandbox is newer than the Docker path — use `--sandbox docker` for the full isolation profile. See the [CI badge](https://github.com/bootproof/repo-proofer/actions) for current status.

## Contributing

Contributions are welcome. See the [test suite](scripts/smoke_test.py) for the deterministic core, and [tests/integration_test.py](tests/integration_test.py) for the Docker integration tests. Run `python scripts/smoke_test.py` to verify before submitting a PR.

## License

[MIT](LICENSE)
