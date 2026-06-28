# repo-proofer test evidence

## Integration test
repo-proofer integration test
Repo root: /Users/ross/repo-proofer
Fixtures:  /Users/ross/repo-proofer/tests/fixtures

[1/4] Ensuring fixture repos are git-initialized...
      Done.

[2/4] Checking Python dependencies...
      Dependencies OK.

[3/4] Checking Docker daemon...
      Docker is running.

[4/4] Running proofer.py against each fixture...

======================================================================
  FIXTURE: clean-repo
  A well-behaved Python repo. Should BOOTS:YES, exit 0, no warnings, no sensitive access.
======================================================================

--- proofer stdout ---
Checking Docker daemon...
⠋ Cloning file:///Users/ross/repo-proofer/tests/fixtures/clean-repo (depth=1)... 0:00:00
Detected stack: Python (image: python:3.11-slim)
⠴ Installing dependencies (network ON, timeout 60s)... 0:00:02
⠴ Executing entrypoint (network OFF, read-only FS, timeout 30s)... 0:00:00
╭───────────────────────────── repo-proofer verdict ──────────────────────────────╮
│   Repository        file:///Users/ross/repo-proofer/tests/fixtures/clean-repo   │
│   Detected Stack    Python                                                      │
│   BOOTS             YES                                                         │
│   Detail            exited 0                                                    │
│   Network Egress    BLOCKED                                                     │
│   Filesystem        READ-ONLY                                                   │
╰─────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── stdout (first 500 chars) ──────────────────────────────────────────────╮
│ Hello from clean-repo!                                                                                               │
│ This repo runs entirely offline and exits cleanly.                                                                   │
│ README title: # clean-repo                                                                                           │
│ Wrote result to /tmp/clean-repo-result.json                                                                          │
│ Done. Exiting 0.                                                                                                     │
│                                                                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── Runtime Behavior Report ───────────────────────────────────────────────╮
│   Files Read                 11                                                                                      │
│   Files Written              2                                                                                       │
│   Processes Spawned          1                                                                                       │
│   Network Calls Attempted    0                                                                                       │
│   Sensitive File Access      0                                                                                       │
╰──────────────────────────────── Generated via strace inside the zero-network sandbox ────────────────────────────────╯
╭───────────────────────────────────────────────── Files Written (2) ──────────────────────────────────────────────────╮
│ - /tmp/clean-repo-result.json                                                                                        │
│ - /tmp/ghvl2a5s                                                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────────────────── Processes Spawned (1) ────────────────────────────────────────────────╮
│ - /usr/local/bin/python                                                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯


[PASS] clean-repo — exit 0, all assertions passed.

======================================================================
  FIXTURE: slop-repo
  A malicious repo disguised as an AI startup. Should BOOTS:NO, exit 1, with network-attempt + sensitive-access detection.
======================================================================

--- proofer stdout ---
Checking Docker daemon...
⠋ Cloning file:///Users/ross/repo-proofer/tests/fixtures/slop-repo (depth=1)... 0:00:00
Detected stack: Python (image: python:3.11-slim)
⠧ Installing dependencies (network ON, timeout 60s)... 0:00:02
⠸ Executing entrypoint (network OFF, read-only FS, timeout 30s)... 0:00:00
╭──────────────────────────────────────── repo-proofer verdict ─────────────────────────────────────────╮
│   Repository        file:///Users/ross/repo-proofer/tests/fixtures/slop-repo                          │
│   Detected Stack    Python                                                                            │
│   BOOTS             NO                                                                                │
│   Detail            exited 1 (crash)                                                                  │
│   Network Egress    BLOCKED                                                                           │
│   Filesystem        READ-ONLY                                                                         │
│   Warnings          [!] App crashed when network was blocked. May require external API to function.   │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── stdout (first 500 chars) ──────────────────────────────────────────────╮
│ ============================================================                                                         │
│   QuantumGPT-Neo v4.7.2 — Next-Gen DevOps Orchestration                                                              │
│   Powered by Quantum-Enhanced GPT-5 + Blockchain Audit Trail                                                         │
│ ============================================================                                                         │
│                                                                                                                      │
│ [*] Initializing quantum scheduler.............. OK                                                                  │
│ [*] Loading pre-trained neural weights.......... OK                                                                  │
│ [*] Calibrating blockchain audit ledger......... OK                                                                  │
│ [*] Connecting to 247 edge regions.............. CONNECTING                                                          │
│ [!] Network error: [Errno -3] Temporary fail                                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── Runtime Behavior Report ───────────────────────────────────────────────╮
│   Files Read                 14                                                                                      │
│   Files Written              0                                                                                       │
│   Processes Spawned          1                                                                                       │
│   Network Calls Attempted    3                                                                                       │
│   Sensitive File Access      3 (see below)                                                                           │
╰──────────────────────────────── Generated via strace inside the zero-network sandbox ────────────────────────────────╯
╭─────────────────────────────────────────────── Processes Spawned (1) ────────────────────────────────────────────────╮
│ - /usr/local/bin/python                                                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────── Network Calls Attempted (3) ─────────────────────────────────────────────╮
│ - connect 192.168.65.7:53                                                                                            │
│ - connect unix:/var/run/nscd/socket                                                                                  │
│ - socket(AF_INET*)                                                                                                   │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────────────────────── Sensitive File Access (3) ──────────────────────────────────────────────╮
│ - /etc/passwd                                                                                                        │
│ - /root/.ssh/id_ed25519                                                                                              │
│ - /root/.ssh/id_rsa                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
[!] Sensitive file access detected — primary indicator of malicious intent. Paths: /etc/passwd, /root/.ssh/id_ed25519, 
/root/.ssh/id_rsa


[PASS] slop-repo — exit 1, all assertions passed.

======================================================================
  RESULT: 2/2 fixtures passed
======================================================================

## clean-repo direct proof
Checking Docker daemon...
⠋ Cloning file:///Users/ross/repo-proofer/tests/fixtures/clean-repo (depth=1)... 0:00:00
Detected stack: Python (image: python:3.11-slim)
⠹ Installing dependencies (network ON, timeout 60s)... 0:00:01
⠼ Executing entrypoint (network OFF, read-only FS, timeout 30s)... 0:00:00
╭───────────────────────────── repo-proofer verdict ──────────────────────────────╮
│   Repository        file:///Users/ross/repo-proofer/tests/fixtures/clean-repo   │
│   Detected Stack    Python                                                      │
│   BOOTS             YES                                                         │
│   Detail            exited 0                                                    │
│   Network Egress    BLOCKED                                                     │
│   Filesystem        READ-ONLY                                                   │
╰─────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── stdout (first 500 chars) ──────────────────────────────────────────────╮
│ Hello from clean-repo!                                                                                               │
│ This repo runs entirely offline and exits cleanly.                                                                   │
│ README title: # clean-repo                                                                                           │
│ Wrote result to /tmp/clean-repo-result.json                                                                          │
│ Done. Exiting 0.                                                                                                     │
│                                                                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── Runtime Behavior Report ───────────────────────────────────────────────╮
│   Files Read                 11                                                                                      │
│   Files Written              2                                                                                       │
│   Processes Spawned          1                                                                                       │
│   Network Calls Attempted    0                                                                                       │
│   Sensitive File Access      0                                                                                       │
╰──────────────────────────────── Generated via strace inside the zero-network sandbox ────────────────────────────────╯
╭───────────────────────────────────────────────── Files Written (2) ──────────────────────────────────────────────────╮
│ - /tmp/clean-repo-result.json                                                                                        │
│ - /tmp/ok_agutu                                                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────────────────── Processes Spawned (1) ────────────────────────────────────────────────╮
│ - /usr/local/bin/python                                                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

## slop-repo direct proof
Checking Docker daemon...
⠋ Cloning file:///Users/ross/repo-proofer/tests/fixtures/slop-repo (depth=1)... 0:00:00
Detected stack: Python (image: python:3.11-slim)
⠙ Installing dependencies (network ON, timeout 60s)... 0:00:01
⠹ Executing entrypoint (network OFF, read-only FS, timeout 30s)... 0:00:00
╭──────────────────────────────────────── repo-proofer verdict ─────────────────────────────────────────╮
│   Repository        file:///Users/ross/repo-proofer/tests/fixtures/slop-repo                          │
│   Detected Stack    Python                                                                            │
│   BOOTS             NO                                                                                │
│   Detail            exited 1 (crash)                                                                  │
│   Network Egress    BLOCKED                                                                           │
│   Filesystem        READ-ONLY                                                                         │
│   Warnings          [!] App crashed when network was blocked. May require external API to function.   │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── stdout (first 500 chars) ──────────────────────────────────────────────╮
│ ============================================================                                                         │
│   QuantumGPT-Neo v4.7.2 — Next-Gen DevOps Orchestration                                                              │
│   Powered by Quantum-Enhanced GPT-5 + Blockchain Audit Trail                                                         │
│ ============================================================                                                         │
│                                                                                                                      │
│ [*] Initializing quantum scheduler.............. OK                                                                  │
│ [*] Loading pre-trained neural weights.......... OK                                                                  │
│ [*] Calibrating blockchain audit ledger......... OK                                                                  │
│ [*] Connecting to 247 edge regions.............. CONNECTING                                                          │
│ [!] Network error: [Errno -3] Temporary fail                                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── Runtime Behavior Report ───────────────────────────────────────────────╮
│   Files Read                 14                                                                                      │
│   Files Written              0                                                                                       │
│   Processes Spawned          1                                                                                       │
│   Network Calls Attempted    3                                                                                       │
│   Sensitive File Access      3 (see below)                                                                           │
╰──────────────────────────────── Generated via strace inside the zero-network sandbox ────────────────────────────────╯
╭─────────────────────────────────────────────── Processes Spawned (1) ────────────────────────────────────────────────╮
│ - /usr/local/bin/python                                                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────── Network Calls Attempted (3) ─────────────────────────────────────────────╮
│ - connect 192.168.65.7:53                                                                                            │
│ - connect unix:/var/run/nscd/socket                                                                                  │
│ - socket(AF_INET*)                                                                                                   │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────────────────────── Sensitive File Access (3) ──────────────────────────────────────────────╮
│ - /etc/passwd                                                                                                        │
│ - /root/.ssh/id_ed25519                                                                                              │
│ - /root/.ssh/id_rsa                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
[!] Sensitive file access detected — primary indicator of malicious intent. Paths: /etc/passwd, /root/.ssh/id_ed25519, 
/root/.ssh/id_rsa

## external repo proof: http-party/http-server
Checking Docker daemon...
⠏ Cloning https://github.com/http-party/http-server.git (depth=1)... 0:00:00
Detected stack: Node.js (image: node:20-slim)
⠇ Installing dependencies (network ON, timeout 60s)... 0:00:00
⠦ Executing entrypoint (network OFF, read-only FS, timeout 30s)... 0:00:01
╭─────────────────────── repo-proofer verdict ────────────────────────╮
│   Repository        https://github.com/http-party/http-server.git   │
│   Detected Stack    Node.js                                         │
│   BOOTS             NO                                              │
│   Detail            exited 1 (crash)                                │
│   Network Egress    BLOCKED                                         │
│   Filesystem        READ-ONLY                                       │
╰─────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── stderr (first 500 chars) ──────────────────────────────────────────────╮
│ node:internal/modules/cjs/loader:1210                                                                                │
│   throw err;                                                                                                         │
│   ^                                                                                                                  │
│                                                                                                                      │
│ Error: Cannot find module 'chalk'                                                                                    │
│ Require stack:                                                                                                       │
│ - /app/bin/http-server                                                                                               │
│     at Module._resolveFilename (node:internal/modules/cjs/loader:1207:15)                                            │
│     at Module._load (node:internal/modules/cjs/loader:1038:27)                                                       │
│     at Module.require (node:internal/modules/cjs/loader:1289:19)                                                     │
│     at require (node:internal/modules/helpers:182:18)                                                                │
│     at Object.<anonymous> (/app/bin/http-server:5:17)                                                                │
│     at Module._compile (node:internal/modules/cjs/loader:1521:                                                       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────── Runtime Behavior Report ───────────────────────────────────────────────╮
│   Files Read                 9                                                                                       │
│   Files Written              1                                                                                       │
│   Processes Spawned          8                                                                                       │
│   Network Calls Attempted    3                                                                                       │
│   Sensitive File Access      2 (see below)                                                                           │
╰──────────────────────────────── Generated via strace inside the zero-network sandbox ────────────────────────────────╯
╭───────────────────────────────────────────────── Files Written (1) ──────────────────────────────────────────────────╮
│ - /root/.npm/_update-notifier-last-checked                                                                           │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────────────────── Processes Spawned (8) ────────────────────────────────────────────────╮
│ - /app/node_modules/.bin/sh                                                                                          │
│ - /node_modules/.bin/sh                                                                                              │
│ - /usr/bin/sh                                                                                                        │
│ - /usr/local/bin/node                                                                                                │
│ - /usr/local/bin/sh                                                                                                  │
│ - /usr/local/lib/node_modules/npm/node_modules/@npmcli/run-script/lib/node-gyp-bin/sh                                │
│ - /usr/local/sbin/sh                                                                                                 │
│ - /usr/sbin/sh                                                                                                       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────── Network Calls Attempted (3) ─────────────────────────────────────────────╮
│ - connect 192.168.65.7:53                                                                                            │
│ - connect unix:/var/run/nscd/socket                                                                                  │
│ - socket(AF_INET*)                                                                                                   │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────────────────────── Sensitive File Access (2) ──────────────────────────────────────────────╮
│ - /app/.npmrc                                                                                                        │
│ - /root/.npmrc                                                                                                       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
[!] Sensitive file access detected — primary indicator of malicious intent. Paths: /app/.npmrc, /root/.npmrc
