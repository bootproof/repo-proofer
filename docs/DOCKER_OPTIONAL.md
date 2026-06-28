# Design: Docker-Optional Sandbox (The Adoption Tax Fix)

## Status: Design spec — not yet implemented

## Problem

`repo-proofer` requires Docker. This is the single biggest barrier to the
"used instantly" adoption thesis. Specifically:

1. **Docker isn't universally available.** A large fraction of developers
   who'd triage a random repo don't have a Docker daemon running. On macOS,
   Docker Desktop is a 4GB install that many people don't keep running.
   On Linux, Docker requires root or docker group membership. On CI runners
   without Docker, the tool can't run at all.

2. **First run is minutes, not seconds.** Even with Docker installed, the
   first run pulls hundreds of MB of base images (`node:20-slim`,
   `python:3.11-slim`, etc.) and builds a derived strace image. This
   kills the "instant payoff" that drives adoption.

3. **`uvx repo-proofer <url>` stalls.** The one-command install works
   (the package is on PyPI), but the first invocation hits the Docker
   pull wall. A stranger who runs `uvx repo-proofer <url>` on a Friday
   and waits 3 minutes for image pulls may not come back.

## Proposal: Two-tier sandbox with `--sandbox` flag

```
repo-proofer <url>                     # default: native (no Docker)
repo-proofer <url> --sandbox docker    # full Docker isolation
repo-proofer <url> --sandbox native    # explicit native (bubblewrap)
```

### Tier 1: Native sandbox (default, no Docker)

**What it is:** A lightweight Linux namespace sandbox using
[bubblewrap](https://github.com/containers/bubblewrap) (or
[nsjail](https://github.com/google/nsjail) as an alternative).
No Docker daemon required. No image pulls. Starts in milliseconds.

**What it provides:**
- Network isolation (`--unshare-net`)
- Read-only root filesystem (`--ro-bind / /`)
- Writable `/tmp` via tmpfs (`--tmpfs /tmp`)
- Process isolation (`--unshare-pid`)
- No capabilities (bubblewrap drops all by default)
- strace support (strace runs natively on the host — no derived image needed)

**What it does NOT provide (vs Docker):**
- No language-runtime isolation (the host's Python/Node/Go is used,
  not a clean `python:3.11-slim` image)
- No image-based reproducibility (two hosts with different Python
  versions may produce different results)
- No protection against host kernel exploits (Docker's seccomp profile
  adds an extra layer)

**When to use:** Consumer triage. The 95% case. "Is this repo slop?"
on a Friday afternoon with no Docker running.

### Tier 2: Docker sandbox (the current engine, `--sandbox docker`)

**What it is:** The current engine. Full Docker isolation with
`--network none --read-only --cap-drop ALL`. Clean language runtimes
from official images. Derived strace images.

**What it provides:**
- Everything Tier 1 provides, plus:
- Clean-room language runtimes (deterministic across hosts)
- Seccomp profile (extra kernel-attack surface reduction)
- Image-based reproducibility (two hosts produce the same verdict)

**When to use:** Enterprise CI gates. Security-sensitive triage where
you need the clean-room guarantee. The `--strict` mode.

### Tier 3 (future): Cloud API

**What it is:** `repo-proofer <url>` hits `api.repoproofer.com` which
runs the Docker sandbox server-side. No local sandbox at all.

**When to use:** When the user has neither Docker nor bubblewrap
(e.g., on a restricted corporate laptop). Also the monetization path.

## Implementation plan

### Phase 1: Refactor the execution layer (no behavior change)

Extract the Docker execution logic into a `SandboxBackend` protocol:

```python
class SandboxBackend(Protocol):
    def install(
        self, stack: StackProfile, repo_path: Path, deps_dir: Path
    ) -> ExecutionResult: ...

    def execute(
        self, stack: StackProfile, repo_path: Path, deps_dir: Path,
        trace_dir: Optional[Path] = None,
    ) -> ExecutionResult: ...
```

Existing Docker logic moves into `DockerBackend`. This is a pure
refactor — no behavior change, just extracting the interface.

### Phase 2: Implement `NativeBackend` (bubblewrap)

```python
class NativeBackend:
    """Bubblewrap-based sandbox. No Docker required."""

    def execute(self, stack, repo_path, deps_dir, trace_dir=None):
        args = [
            "bwrap",
            "--ro-bind", "/", "/",           # read-only root
            "--tmpfs", "/tmp",                # writable /tmp
            "--unshare-net",                  # no network
            "--unshare-pid",                  # process isolation
            "--die-with-parent",              # cleanup on exit
            "--bind", str(repo_path), "/app", # repo (read-write for now;
                                               # bubblewrap can't do :ro
                                               # on bind mounts the same way)
        ]
        if deps_dir:
            args += ["--bind", str(deps_dir), stack.deps_mount]
        if trace_dir:
            args += ["--bind", str(trace_dir), "/trace"]
            # Wrap in strace (available on host, no derived image needed)
            args += ["--", "strace", "-ff", "-o", "/trace/trace", "--",
                     *stack.run_candidates[0]]
        else:
            args += ["--", *stack.run_candidates[0]]
        # ... run via subprocess, same timeout/capture logic
```

**Key advantages over Docker:**
- No image pull (uses host's Python/Node/Go)
- No derived image build (strace is on the host)
- Millisecond startup (no container creation overhead)
- Works on any Linux with bubblewrap installed (most distros ship it)

**Key limitation:**
- macOS/Windows don't have bubblewrap. On those platforms, the native
  backend would fall back to a `seccomp` + `unshare` approach (Linux VM
  required) or prompt the user to install Docker. This is the honest
  tradeoff: the instant payoff is Linux-only; macOS users still need
  Docker (or the future Cloud API tier).

### Phase 3: Stack detection for native (host runtimes)

The native backend uses the HOST's language runtimes, not Docker images.
So stack detection needs a "native" mode that:
- Checks `python3 --version` instead of `python:3.11-slim`
- Checks `node --version` instead of `node:20-slim`
- Checks `go version` instead of `golang:1.22-alpine`
- Checks `cargo --version` instead of `rust:1.75-slim`

If the host doesn't have the required runtime, the tool prints:
```
[!] Native sandbox requires Python 3.10+ on the host.
    Install it or use --sandbox docker for containerized execution.
```

### Phase 4: Auto-detection and graceful fallback

```python
def pick_backend(preferred: str = "auto") -> SandboxBackend:
    if preferred == "docker":
        return DockerBackend()
    if preferred == "native":
        return NativeBackend()
    # auto: prefer native (faster, no Docker), fall back to Docker
    if NativeBackend.is_available():
        return NativeBackend()
    if DockerBackend.is_available():
        return DockerBackend()
    raise RuntimeError(
        "No sandbox available. Install bubblewrap (Linux) or Docker."
    )
```

### Phase 5: Update README + CLI help

```
repo-proofer <url>                      # native sandbox (default, no Docker)
repo-proofer <url> --sandbox docker     # full Docker isolation
repo-proofer <url> --sandbox native     # explicit native
```

## Security tradeoffs (honest)

The native sandbox is **slightly weaker** than Docker for one specific
threat model: if the repo-proofer process itself is compromised (not
just the sandboxed app), the native sandbox offers less protection
because it shares the host kernel and filesystem more directly.

However, for the consumer-triage use case ("is this repo slop?"), this
is the right tradeoff:
- The sandboxed app still can't reach the network.
- The sandboxed app still can't write outside `/tmp`.
- The sandboxed app still can't read `~/.ssh` (bubblewrap bind-mounts
  only `/app`, not the home directory).
- The strace-based behavior report works identically.

The Docker tier remains available for `--strict` / enterprise use where
the clean-room guarantee matters.

## What this unlocks

After this lands, the adoption curve becomes:
```
uvx repo-proofer <url>     # works on any Linux with bubblewrap, ~2 seconds
```

No Docker. No image pulls. No build step. Just run the repo in a locked
box and print the verdict. That's the "run it in one line on a Friday"
experience from the original thesis.

## Effort estimate

- Phase 1 (refactor): 2-3 hours
- Phase 2 (bubblewrap backend): 4-6 hours
- Phase 3 (host runtime detection): 1-2 hours
- Phase 4 (auto-detection): 1 hour
- Phase 5 (docs): 1 hour

Total: ~1-2 days of focused work. The hardest part is Phase 2 — getting
the bubblewrap bind-mount flags right for all the edge cases (deps dir,
trace dir, read-only repo mount).
