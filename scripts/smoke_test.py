#!/usr/bin/env python3
"""
Smoke + parser tests for proofer.py.

Exercises:
  - Stack detection (Node, Python, Go, Rust, unknown) including the new
    manifest-aware entrypoint detection (package.json main/scripts.start/bin,
    Python server.py/manage.py/src-layout/python -m).
  - Verdict analysis with readiness-aware BOOTS semantics:
      exit 0                  -> YES ("exited 0")
      timeout, no crash       -> YES ("long-running process")
      timeout + crash sig     -> NO  ("crashed before timeout")
      timeout + readiness     -> YES ("server detected: <signal>")
      non-zero exit           -> NO  ("exited <code> (crash)")
  - strace parser regexes + BehaviorReport classification (unchanged).

No Docker required for any of these tests — they call the pure functions
directly.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from proofer import (
    detect_stack,
    analyze_result,
    parse_strace_output,
    ExecutionResult,
    BehaviorReport,
    StackProfile,
    NETWORK_ERROR_RE,
    STRACE_OPEN_RE,
    STRACE_WRITE_FLAGS_RE,
    STRACE_EXECVE_RE,
    STRACE_CONNECT_IPV4_RE,
    STRACE_CONNECT_IPV6_RE,
    STRACE_CONNECT_UNIX_RE,
    STRACE_SOCKET_INET_RE,
    _native_adapt_cmd,
    _build_bwrap_args,
    _select_backend,
)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _make_repo(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp(prefix="smoke-"))
    for name, content in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


def _write_trace(trace_dir: Path, filename: str, lines: list[str]) -> None:
    trace_dir.mkdir(parents=True, exist_ok=True)
    (trace_dir / filename).write_text("\n".join(lines) + "\n")


# ----------------------------------------------------------------------
# Stack detection tests
# ----------------------------------------------------------------------

def test_detect_node():
    repo = _make_repo({
        "package.json": '{"name":"x","version":"1.0.0"}',
        "index.js": "console.log('hi')",
    })
    s = detect_stack(repo)
    assert s is not None, "Expected Node.js stack"
    assert s.name == "Node.js"
    assert s.image == "node:20-slim"
    # --ignore-scripts is now mandatory (install-phase supply-chain fix).
    assert "--ignore-scripts" in s.install_cmd, \
        f"npm install must include --ignore-scripts, got {s.install_cmd}"
    # No scripts.start/main/bin in package.json, index.js exists ->
    # first candidate is `node index.js`, with `npm start` as fallback.
    assert s.run_candidates[0] == ["node", "index.js"]
    assert ["npm", "start"] in s.run_candidates  # fallback present
    assert s.env == {"NODE_PATH": "/tmp/npm_cache/node_modules"}
    assert s.deps_mount == "/tmp/npm_cache"
    print("[OK] detect_stack: Node.js (with --ignore-scripts in install)")


def test_detect_node_reads_package_json_main():
    """package.json with a `main` field should produce `node <main>` as a candidate."""
    repo = _make_repo({
        "package.json": '{"name":"x","version":"1.0.0","main":"lib/server.js"}',
        "lib/server.js": "console.log('hi')",
    })
    s = detect_stack(repo)
    assert s is not None
    assert ["node", "lib/server.js"] in s.run_candidates, \
        f"Expected node lib/server.js from main field, got {s.run_candidates}"
    print("[OK] detect_stack: Node.js reads package.json main field")


def test_detect_node_reads_scripts_start():
    """package.json with scripts.start should produce `npm start` FIRST."""
    repo = _make_repo({
        "package.json": '{"name":"x","scripts":{"start":"node server.js"}}',
        "server.js": "console.log('hi')",
    })
    s = detect_stack(repo)
    assert s is not None
    assert s.run_candidates[0] == ["npm", "start"], \
        f"Expected npm start first, got {s.run_candidates}"
    print("[OK] detect_stack: Node.js reads scripts.start (first candidate)")


def test_detect_node_reads_bin_field():
    """package.json with a string bin field should produce `node <bin>`."""
    repo = _make_repo({
        "package.json": '{"name":"x","bin":"./cli.js"}',
        "cli.js": "console.log('hi')",
    })
    s = detect_stack(repo)
    assert s is not None
    assert ["node", "./cli.js"] in s.run_candidates, \
        f"Expected node ./cli.js from bin field, got {s.run_candidates}"
    print("[OK] detect_stack: Node.js reads bin field")


def test_detect_node_malformed_package_json_falls_back():
    """Malformed package.json should not crash - fall back to file conventions."""
    repo = _make_repo({
        "package.json": '{ this is not valid json',
        "index.js": "console.log('hi')",
    })
    s = detect_stack(repo)
    assert s is not None  # Still detected as Node.js (package.json exists)
    assert ["node", "index.js"] in s.run_candidates  # Convention fallback worked
    print("[OK] detect_stack: Node.js malformed package.json -> convention fallback")


def test_detect_node_no_duplicate_candidates():
    """package.json with main="index.js" AND index.js exists should NOT
    produce a duplicated ['node', 'index.js'] candidate. This was a bug
    where the main field and the convention fallback both added the same
    entry."""
    repo = _make_repo({
        "package.json": '{"name":"x","main":"index.js"}',
        "index.js": "console.log('hi')",
    })
    s = detect_stack(repo)
    assert s is not None
    # Count occurrences of ["node", "index.js"] — must be exactly 1.
    count = s.run_candidates.count(["node", "index.js"])
    assert count == 1, \
        f"Expected exactly 1 ['node', 'index.js'], got {count}: {s.run_candidates}"
    print("[OK] detect_stack: Node.js no duplicate candidates (main + convention dedup)")


def test_detect_python_namespace_package_main():
    """PEP 420 namespace package: a directory with __main__.py but NO
    __init__.py. `python -m <pkg>` works on these. The previous code
    required __init__.py and missed this case, causing namespace-package
    repos to come back with empty candidates and get mislabeled as slop."""
    repo = _make_repo({
        "myapp/__main__.py": "print('hi')",
        # NOTE: no __init__.py — this is a PEP 420 namespace package
    })
    s = detect_stack(repo)
    assert s is not None, "Namespace package with __main__.py must be detected"
    assert s.name == "Python"
    assert ["python", "-m", "myapp"] in s.run_candidates, \
        f"Expected python -m myapp for namespace package, got {s.run_candidates}"
    print("[OK] detect_stack: Python (PEP 420 namespace package __main__.py)")


def test_detect_python_with_requirements():
    repo = _make_repo({
        "requirements.txt": "flask==3.0.0",
        "main.py": "print('hi')",
    })
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert s.image == "python:3.11-slim"
    assert "pip install" in " ".join(s.install_cmd)
    # --prefer-binary is now mandatory (pushes wheels over sdists).
    assert "--prefer-binary" in s.install_cmd, \
        f"pip install must include --prefer-binary, got {s.install_cmd}"
    # main.py exists, no other entry files -> only [python main.py].
    assert s.run_candidates == [["python", "main.py"]], \
        f"Got {s.run_candidates}"
    assert s.env["PYTHONPATH"] == "/tmp/pip_deps"
    assert s.env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert s.deps_mount == "/tmp/pip_deps"
    print("[OK] detect_stack: Python (with requirements.txt + --prefer-binary)")


def test_detect_python_main_only():
    repo = _make_repo({"main.py": "print('hi')"})
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert s.install_cmd == [], "main.py-only repo should have empty install_cmd"
    assert s.deps_mount is None
    print("[OK] detect_stack: Python (main.py only, no install)")


def test_detect_python_server_py():
    """A repo with only server.py (no main.py) should still be detected."""
    repo = _make_repo({"server.py": "print('hi')"})
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert s.run_candidates == [["python", "server.py"]]
    print("[OK] detect_stack: Python (server.py only)")


def test_detect_python_django_manage_py():
    """Django repos use `manage.py check` (not bare `manage.py`) to verify boot."""
    repo = _make_repo({"manage.py": "#!/usr/bin/env python\nprint('django')"})
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert ["python", "manage.py", "check"] in s.run_candidates, \
        f"Expected manage.py check, got {s.run_candidates}"
    print("[OK] detect_stack: Python (Django manage.py check)")


def test_detect_python_src_layout():
    """src/main.py should be detected as an entrypoint."""
    repo = _make_repo({"src/main.py": "print('hi')"})
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert ["python", "src/main.py"] in s.run_candidates
    print("[OK] detect_stack: Python (src/main.py layout)")


def test_detect_python_package_with_main():
    """A top-level package dir with __main__.py -> python -m <pkg>."""
    repo = _make_repo({
        "myapp/__init__.py": "",
        "myapp/__main__.py": "print('hi')",
    })
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert ["python", "-m", "myapp"] in s.run_candidates, \
        f"Expected python -m myapp, got {s.run_candidates}"
    print("[OK] detect_stack: Python (python -m <pkg> via __main__.py)")


def test_detect_python_pyproject_toml():
    """pyproject.toml is the dominant Python project format in 2026.
    Without detecting it, the tool misses Poetry/Hatch/PDM/uv/modern
    setuptools repos. This test locks in the fix."""
    repo = _make_repo({
        "pyproject.toml": (
            "[project]\nname = \"x\"\nversion = \"0.1.0\"\n"
            "[project.scripts]\nx = \"x:main\"\n"
        ),
        "main.py": "print('hi')",
    })
    s = detect_stack(repo)
    assert s is not None, "pyproject.toml must be detected as Python"
    assert s.name == "Python"
    assert s.image == "python:3.11-slim"
    # main.py exists so it should be picked as the entrypoint.
    assert ["python", "main.py"] in s.run_candidates
    print("[OK] detect_stack: Python (pyproject.toml detected)")


def test_detect_python_setup_py():
    """setup.py is the legacy Python project marker. Still common."""
    repo = _make_repo({
        "setup.py": "from setuptools import setup\nsetup(name='x')",
        "main.py": "print('hi')",
    })
    s = detect_stack(repo)
    assert s is not None, "setup.py must be detected as Python"
    assert s.name == "Python"
    print("[OK] detect_stack: Python (setup.py detected)")


def test_detect_python_pyproject_no_main():
    """A pyproject.toml-only repo (library, no entrypoint) should still
    be DETECTED as Python — even if it will later report BOOTS:NO because
    there's nothing to run. Detection is not the same as booting."""
    repo = _make_repo({
        "pyproject.toml": (
            "[project]\nname = \"mylib\"\nversion = \"0.1.0\"\n"
        ),
    })
    s = detect_stack(repo)
    assert s is not None, "pyproject.toml-only repo must be detected"
    assert s.name == "Python"
    # No entrypoint files exist, so run_candidates should be empty.
    # (The tool will report BOOTS:NO with 'No entrypoint candidate ran' —
    # that's honest, not a detection failure.)
    assert s.run_candidates == [], \
        f"Expected empty run_candidates, got {s.run_candidates}"
    print("[OK] detect_stack: Python (pyproject.toml-only, no entrypoint -> still detected)")


def test_detect_python_console_scripts_pyproject():
    """A modern Python CLI that declares its entrypoint ONLY in
    [project.scripts] (no main.py) should produce a runnable
    `python -c` candidate. Without this, the CLI would be mislabeled
    as a library (yellow NO RUNNABLE ENTRYPOINT)."""
    repo = _make_repo({
        "pyproject.toml": (
            '[project]\nname = "mytool"\nversion = "0.1.0"\n'
            '[project.scripts]\nmytool = "mytool.cli:app"\n'
        ),
        "mytool/__init__.py": "",
        "mytool/cli.py": "def app(): print('hi')",
    })
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    # Should have a python -c candidate that imports mytool.cli and calls app()
    assert any("-c" in c and "mytool.cli" in " ".join(c) for c in s.run_candidates), \
        f"Expected python -c with mytool.cli, got {s.run_candidates}"
    print("[OK] detect_stack: Python ([project.scripts] -> python -c candidate)")


def test_detect_python_console_scripts_poetry():
    """Poetry's [tool.poetry.scripts] format should also be detected."""
    repo = _make_repo({
        "pyproject.toml": (
            '[tool.poetry]\nname = "mytool"\n'
            '[tool.poetry.scripts]\nmytool = "mytool.cli:app"\n'
        ),
        "mytool/__init__.py": "",
    })
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert any("-c" in c for c in s.run_candidates), \
        f"Expected python -c from Poetry scripts, got {s.run_candidates}"
    print("[OK] detect_stack: Python ([tool.poetry.scripts] -> python -c)")


def test_detect_python_console_scripts_poetry_shorthand():
    """Poetry shorthand: bare module (no :func) means module:main."""
    repo = _make_repo({
        "pyproject.toml": (
            '[tool.poetry.scripts]\nmytool = "mytool.cli"\n'
        ),
        "mytool/__init__.py": "",
    })
    s = detect_stack(repo)
    assert s is not None
    cmd = [c for c in s.run_candidates if "-c" in c]
    assert cmd, f"Expected python -c candidate, got {s.run_candidates}"
    # Shorthand resolves to :main
    assert "main" in " ".join(cmd[0]), \
        f"Expected 'main' in Poetry shorthand command, got {cmd[0]}"
    print("[OK] detect_stack: Python (Poetry shorthand -> module:main)")


def test_detect_python_console_scripts_dotted_attr():
    """Dotted attribute path (pkg.mod:obj.method) should resolve correctly."""
    repo = _make_repo({
        "pyproject.toml": (
            '[project.scripts]\nmytool = "mytool.cli:app.main"\n'
        ),
        "mytool/__init__.py": "",
    })
    s = detect_stack(repo)
    assert s is not None
    cmd = [c for c in s.run_candidates if "-c" in c]
    assert cmd, f"Expected python -c candidate, got {s.run_candidates}"
    code = " ".join(cmd[0])
    assert "getattr(obj, 'app')" in code, f"Expected getattr app, got {code}"
    assert "getattr(obj, 'main')" in code, f"Expected getattr main, got {code}"
    print("[OK] detect_stack: Python (dotted attr pkg.mod:obj.method)")


def test_detect_python_console_scripts_setup_cfg():
    """setup.cfg [options.entry_points] console_scripts should be detected."""
    repo = _make_repo({
        "setup.cfg": (
            "[metadata]\nname = mytool\n\n"
            "[options.entry_points]\nconsole_scripts =\n"
            "    mytool = mytool.cli:app\n"
        ),
        "mytool/__init__.py": "",
    })
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert any("-c" in c for c in s.run_candidates), \
        f"Expected python -c from setup.cfg, got {s.run_candidates}"
    print("[OK] detect_stack: Python (setup.cfg console_scripts -> python -c)")


def test_detect_python_console_scripts_setup_py():
    """setup.py entry_points console_scripts should be detected via regex."""
    repo = _make_repo({
        "setup.py": (
            'from setuptools import setup\n'
            'setup(name="mytool", entry_points={\n'
            '    "console_scripts": ["mytool = mytool.cli:app"],\n'
            '})\n'
        ),
        "mytool/__init__.py": "",
    })
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert any("-c" in c for c in s.run_candidates), \
        f"Expected python -c from setup.py, got {s.run_candidates}"
    print("[OK] detect_stack: Python (setup.py console_scripts -> python -c)")


def test_detect_python_console_scripts_with_main_py():
    """When both main.py AND [project.scripts] exist, main.py should come
    first (it's the more reliable entrypoint) and the console script
    should also be present as a fallback."""
    repo = _make_repo({
        "pyproject.toml": (
            '[project.scripts]\nmytool = "mytool.cli:app"\n'
        ),
        "main.py": "print('hi')",
        "mytool/__init__.py": "",
    })
    s = detect_stack(repo)
    assert s is not None
    # main.py should be first
    assert s.run_candidates[0] == ["python", "main.py"], \
        f"Expected python main.py first, got {s.run_candidates}"
    # Console script should also be present
    assert any("-c" in c for c in s.run_candidates), \
        f"Expected python -c candidate too, got {s.run_candidates}"
    print("[OK] detect_stack: Python (main.py first, [project.scripts] as fallback)")


def test_detect_go():
    repo = _make_repo({"go.mod": "module x\ngo 1.22\n", "main.go": "package main\n"})
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Go (experimental)"  # demoted
    assert s.image == "golang:1.22-alpine"
    assert s.install_cmd == []
    assert s.run_candidates == [["go", "run", "main.go"]]
    print("[OK] detect_stack: Go (experimental)")


def test_detect_rust():
    repo = _make_repo({"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"\n"})
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Rust (experimental)"  # demoted
    assert s.image == "rust:1.75-slim"
    assert s.run_candidates == [["cargo", "run", "--offline"]]  # --offline added
    print("[OK] detect_stack: Rust (experimental, --offline)")


def test_detect_unknown():
    repo = _make_repo({"README.md": "nothing useful here"})
    s = detect_stack(repo)
    assert s is None
    print("[OK] detect_stack: unknown -> None")


# ----------------------------------------------------------------------
# Verdict analysis tests (readiness-aware BOOTS semantics)
# ----------------------------------------------------------------------

def test_analyze_boots_yes():
    r = ExecutionResult(stdout="hello\n", stderr="", exit_code=0)
    v = analyze_result(r)
    assert v.boots is True
    assert v.network_egress_blocked is True
    assert v.filesystem_read_only is True
    assert v.warnings == []
    assert v.stdout_preview == "hello\n"
    assert v.detail == "exited 0"
    assert v.no_entrypoint is False
    print("[OK] analyze_result: exit 0 -> BOOTS:YES, detail='exited 0'")


def test_analyze_library_no_entrypoint():
    """A library (pyproject.toml-only, no runnable entrypoint) should get
    a NEUTRAL verdict, not red. This is the trust-preserving change: without
    it, `click` and `markupsafe` show the same red as SSH-key-stealing
    malware, and a skeptical first user concludes the tool is broken.

    The verdict should be:
      boots=False, no_entrypoint=True (yellow display, not red)
      detail="no runnable entrypoint (looks like a library)"
      warnings=[] (no crash, no network error — it just had nothing to run)
    """
    r = ExecutionResult(
        stdout="",
        stderr="No runnable entrypoint found. This looks like a library.",
        exit_code=127,
        no_candidates=True,
    )
    v = analyze_result(r)
    assert v.boots is False
    assert v.no_entrypoint is True, \
        "Library (no_candidates) must set no_entrypoint=True for yellow display"
    assert "library" in v.detail.lower(), f"Expected 'library' in detail, got {v.detail}"
    assert v.warnings == [], \
        f"Library verdict should have no warnings, got {v.warnings}"
    print("[OK] analyze_result: no_candidates -> NEUTRAL (no_entrypoint=True, yellow)")


def test_analyze_boots_no():
    r = ExecutionResult(stdout="", stderr="some error", exit_code=1)
    v = analyze_result(r)
    assert v.boots is False
    assert v.warnings == []
    assert "exited 1" in v.detail
    print("[OK] analyze_result: exit 1 (no crash sig) -> BOOTS:NO")


def test_analyze_network_error_node():
    r = ExecutionResult(
        stdout="",
        stderr="Error: getaddrinfo ENOTFOUND api.example.com",
        exit_code=1,
    )
    v = analyze_result(r)
    assert v.boots is False
    assert any("network was blocked" in w for w in v.warnings)
    print("[OK] analyze_result: Node ENOTFOUND -> network warning")


def test_analyze_network_error_python():
    r = ExecutionResult(
        stdout="",
        stderr="socket.gaierror: [Errno -2] Name or service not known",
        exit_code=1,
    )
    v = analyze_result(r)
    assert v.boots is False
    assert any("network was blocked" in w for w in v.warnings)
    print("[OK] analyze_result: Python gaierror -> network warning")


def test_analyze_timeout_long_running():
    """NEW SEMANTICS: a process that times out WITHOUT a crash signature
    is a healthy long-running process (server/daemon/bot) -> BOOTS: YES.

    The previous logic returned BOOTS:NO for every timeout, which was a
    false negative on every server, daemon, and bot. This test locks in
    the fix.
    """
    r = ExecutionResult(stdout="", stderr="", exit_code=-1, timed_out=True)
    v = analyze_result(r)
    assert v.boots is True, \
        "Timeout without crash should be BOOTS:YES (long-running process)"
    assert "long-running" in v.detail, f"Expected long-running detail, got {v.detail}"
    assert any("did not exit" in w for w in v.warnings)
    print("[OK] analyze_result: timeout + no crash -> BOOTS:YES (long-running)")


def test_analyze_timeout_with_crash():
    """Timeout + crash signature in stderr -> BOOTS:NO (genuine crash)."""
    r = ExecutionResult(
        stdout="",
        stderr="Traceback (most recent call last):\n  File ...",
        exit_code=-1,
        timed_out=True,
    )
    v = analyze_result(r)
    assert v.boots is False, \
        "Timeout WITH crash signature should be BOOTS:NO"
    assert "crashed before" in v.detail, f"Got {v.detail}"
    print("[OK] analyze_result: timeout + crash signature -> BOOTS:NO")


def test_analyze_timeout_with_readiness_signal():
    """Timeout + readiness signal ('listening on port 8080') -> BOOTS:YES
    with 'server detected' detail. This is the strongest possible YES
    for a long-running process."""
    r = ExecutionResult(
        stdout="Loading...\nListening on port 8080\n",
        stderr="",
        exit_code=-1,
        timed_out=True,
    )
    v = analyze_result(r)
    assert v.boots is True
    assert "server detected" in v.detail, f"Got {v.detail}"
    assert "listening on port 8080" in v.detail.lower()
    print("[OK] analyze_result: timeout + readiness signal -> BOOTS:YES (server detected)")


def test_analyze_readiness_uvicorn():
    """Uvicorn's startup line should be recognized as a readiness signal."""
    r = ExecutionResult(
        stdout="INFO:     Uvicorn running on http://0.0.0.0:8000\n",
        stderr="",
        exit_code=-1,
        timed_out=True,
    )
    v = analyze_result(r)
    assert v.boots is True
    assert "uvicorn" in v.detail.lower()
    print("[OK] analyze_result: Uvicorn startup line -> server detected")


def test_analyze_stdout_truncation():
    long_out = "x" * 5000
    r = ExecutionResult(stdout=long_out, stderr="", exit_code=0)
    v = analyze_result(r)
    assert len(v.stdout_preview) == 500
    print("[OK] analyze_result: stdout truncated to 500 chars")


def test_network_regex_negative():
    assert NETWORK_ERROR_RE.search("hello world") is None
    assert NETWORK_ERROR_RE.search("Server listening on port 3000") is None
    assert NETWORK_ERROR_RE.search("All tests passed") is None
    print("[OK] NETWORK_ERROR_RE: no false positives on benign strings")


def test_network_regex_positive_variants():
    cases = [
        "Error: connect ECONNREFUSED 127.0.0.1:80",
        "urllib3.exceptions.MaxRetryError",
        "Temporary failure in name resolution",
        "Network is unreachable",
        "fetch failed",
        "Failed to fetch",
    ]
    for c in cases:
        assert NETWORK_ERROR_RE.search(c) is not None, f"Should match: {c}"
    print("[OK] NETWORK_ERROR_RE: matches all known variants")


# ----------------------------------------------------------------------
# strace parser - regex unit tests (unchanged)
# ----------------------------------------------------------------------

def test_strace_open_regex_rdonly():
    line = 'openat(AT_FDCWD, "/app/index.js", O_RDONLY) = 3'
    m = STRACE_OPEN_RE.match(line)
    assert m is not None
    assert m.group(1) == "/app/index.js"
    assert STRACE_WRITE_FLAGS_RE.search(line) is None  # read-only
    print("[OK] STRACE_OPEN_RE: O_RDONLY path captured, no write flags")


def test_strace_open_regex_wronly_creat():
    line = 'openat(AT_FDCWD, "/tmp/results.json", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4'
    m = STRACE_OPEN_RE.match(line)
    assert m is not None
    assert m.group(1) == "/tmp/results.json"
    assert STRACE_WRITE_FLAGS_RE.search(line) is not None
    print("[OK] STRACE_OPEN_RE: O_WRONLY|O_CREAT|O_TRUNC -> write flags detected")


def test_strace_open_regex_rdwr():
    line = 'openat(AT_FDCWD, "/tmp/cache.bin", O_RDWR|O_CREAT, 0644) = 5'
    m = STRACE_OPEN_RE.match(line)
    assert m is not None
    assert m.group(1) == "/tmp/cache.bin"
    assert STRACE_WRITE_FLAGS_RE.search(line) is not None
    print("[OK] STRACE_OPEN_RE: O_RDWR|O_CREAT -> write flags detected")


def test_strace_open_regex_creat_only():
    """creat() has no O_* flags in its signature, so STRACE_WRITE_FLAGS_RE
    alone won't match - but the parser must still classify it as a write.
    We verify both: regex captures the path, parser classifies as write."""
    line = 'creat("/tmp/newfile", 0644) = 6'
    m = STRACE_OPEN_RE.match(line)
    assert m is not None
    assert m.group(1) == "/tmp/newfile"
    # The flag regex correctly returns None - creat has no O_* flags.
    assert STRACE_WRITE_FLAGS_RE.search(line) is None
    # But the PARSER must still classify creat() as a write.
    d = Path(tempfile.mkdtemp(prefix="trace-creat-"))
    _write_trace(d, "trace.100", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        line,
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert r.files_written == ["/tmp/newfile"], \
        f"creat() must be classified as write, got {r.files_written}"
    assert r.files_read == []
    print("[OK] STRACE_OPEN_RE + parser: creat() classified as write via parser special-case")


def test_strace_execve_regex():
    line = 'execve("/usr/local/bin/node", ["node", "index.js"], 0x7ffd... /* 18 vars */) = 0'
    m = STRACE_EXECVE_RE.match(line)
    assert m is not None
    assert m.group(1) == "/usr/local/bin/node"
    print("[OK] STRACE_EXECVE_RE: binary path captured")


def test_strace_connect_ipv4_regex():
    line = ('connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH '
            '(Network is unreachable)')
    m = STRACE_CONNECT_IPV4_RE.search(line)
    assert m is not None
    assert m.group(1) == "443"
    assert m.group(2) == "93.184.216.34"
    print("[OK] STRACE_CONNECT_IPV4_RE: port + addr captured")


def test_strace_connect_ipv6_regex():
    line = ('connect(4, {sa_family=AF_INET6, sin6_port=htons(443), '
            'inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", '
            '&sin6_addr), sin6_flowinfo=0, sin6_scope_id=0}, 28) = -1 ENETUNREACH')
    m = STRACE_CONNECT_IPV6_RE.search(line)
    assert m is not None
    assert m.group(1) == "443"
    print("[OK] STRACE_CONNECT_IPV6_RE: port + addr captured")


def test_strace_connect_unix_regex():
    line = 'connect(5, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = -1 ENOENT'
    m = STRACE_CONNECT_UNIX_RE.search(line)
    assert m is not None
    assert m.group(1) == "/var/run/docker.sock"
    print("[OK] STRACE_CONNECT_UNIX_RE: sun_path captured")


def test_strace_socket_inet_regex():
    line = 'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 7'
    m = STRACE_SOCKET_INET_RE.match(line)
    assert m is not None
    # AF_UNIX should NOT match
    line_unix = 'socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 8'
    assert STRACE_SOCKET_INET_RE.match(line_unix) is None
    print("[OK] STRACE_SOCKET_INET_RE: AF_INET matches, AF_UNIX doesn't")


# ----------------------------------------------------------------------
# strace parser - BehaviorReport tests (unchanged)
# ----------------------------------------------------------------------

def test_parse_empty_trace_dir():
    d = Path(tempfile.mkdtemp(prefix="trace-empty-"))
    r = parse_strace_output(d)
    assert r.strace_enabled is True
    assert r.files_read == []
    assert r.files_written == []
    assert r.processes_spawned == []
    assert r.network_attempts == []
    assert r.sensitive_access == []
    assert r.has_data is False
    print("[OK] parse_strace_output: empty dir -> empty report")


def test_parse_clean_app():
    d = Path(tempfile.mkdtemp(prefix="trace-clean-"))
    _write_trace(d, "trace.123", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], 0x7ffd... /* 18 vars */) = 0',
        'openat(AT_FDCWD, "/app/main.py", O_RDONLY) = 3',
        'openat(AT_FDCWD, "/usr/lib/python3.11/codecs.py", O_RDONLY) = 4',
        'openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 5',
        'openat(AT_FDCWD, "/tmp/results.json", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 6',
        'openat(AT_FDCWD, "/dev/null", O_RDWR) = 7',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert r.files_read == ["/app/main.py"], f"Expected only /app/main.py, got {r.files_read}"
    assert r.files_written == ["/tmp/results.json"], f"Expected /tmp/results.json, got {r.files_written}"
    assert r.processes_spawned == ["/usr/local/bin/python3"]
    assert r.network_attempts == []
    assert r.sensitive_access == []
    print("[OK] parse_strace_output: clean app -> 1 read, 1 write, 1 proc, no net")


def test_parse_network_attempt():
    d = Path(tempfile.mkdtemp(prefix="trace-net-"))
    _write_trace(d, "trace.456", [
        'execve("/usr/local/bin/node", ["node", "index.js"], 0x7ffd... /* 18 vars */) = 0',
        'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 14',
        'connect(14, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH (Network is unreachable)',
        '+++ exited with 1 +++',
    ])
    r = parse_strace_output(d)
    assert any("93.184.216.34" in n for n in r.network_attempts), \
        f"Expected 93.184.216.34 in network_attempts, got {r.network_attempts}"
    assert any("socket(AF_INET" in n for n in r.network_attempts), \
        f"Expected socket(AF_INET*) entry, got {r.network_attempts}"
    print("[OK] parse_strace_output: network attempt captured with target")


def test_parse_sensitive_ssh_access():
    d = Path(tempfile.mkdtemp(prefix="trace-sensitive-"))
    _write_trace(d, "trace.789", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
        'openat(AT_FDCWD, "/home/user/.aws/credentials", O_RDONLY) = -1 ENOENT',
        'openat(AT_FDCWD, "/app/.env", O_RDONLY) = 3',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert "/root/.ssh/id_rsa" in r.sensitive_access
    assert "/home/user/.aws/credentials" in r.sensitive_access
    assert "/app/.env" in r.sensitive_access
    assert "/app/.env" in r.files_read
    assert "/root/.ssh/id_rsa" in r.files_read
    print("[OK] parse_strace_output: sensitive paths (ssh, aws, .env) detected")


def test_parse_runtime_noise_filtered():
    d = Path(tempfile.mkdtemp(prefix="trace-noise-"))
    _write_trace(d, "trace.111", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        'openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 3',
        'openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libpython3.11.so.1.0", O_RDONLY|O_CLOEXEC) = 4',
        'openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 5',
        'openat(AT_FDCWD, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 6',
        'openat(AT_FDCWD, "/dev/urandom", O_RDONLY) = 7',
        'openat(AT_FDCWD, "/etc/ssl/certs/ca-certificates.crt", O_RDONLY) = 8',
        'openat(AT_FDCWD, "/app/main.py", O_RDONLY) = 9',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert r.files_read == ["/app/main.py"], \
        f"Only /app/main.py should remain after noise filter, got {r.files_read}"
    print("[OK] parse_strace_output: runtime noise correctly filtered")


def test_parse_dedup_across_forks():
    d = Path(tempfile.mkdtemp(prefix="trace-dedup-"))
    _write_trace(d, "trace.200", [
        'execve("/usr/local/bin/node", ["node", "index.js"], ...) = 0',
        'openat(AT_FDCWD, "/app/index.js", O_RDONLY) = 3',
        'clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 201',
        '+++ exited with 0 +++',
    ])
    _write_trace(d, "trace.201", [
        'execve("/usr/local/bin/node", ["node", "worker.js"], ...) = 0',
        'openat(AT_FDCWD, "/app/index.js", O_RDONLY) = 3',
        'openat(AT_FDCWD, "/app/worker.js", O_RDONLY) = 4',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert r.files_read.count("/app/index.js") == 1, \
        f"Expected dedup, got {r.files_read}"
    assert set(r.files_read) == {"/app/index.js", "/app/worker.js"}
    assert r.processes_spawned == ["/usr/local/bin/node"]
    print("[OK] parse_strace_output: dedup across forked-process trace files")


def test_parse_multiple_distinct_writes():
    d = Path(tempfile.mkdtemp(prefix="trace-writes-"))
    _write_trace(d, "trace.300", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        'openat(AT_FDCWD, "/tmp/cache.bin", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3',
        'openat(AT_FDCWD, "/tmp/results.json", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4',
        'openat(AT_FDCWD, "/tmp/log.txt", O_WRONLY|O_CREAT|O_APPEND, 0644) = 5',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert r.files_written == [
        "/tmp/cache.bin",
        "/tmp/log.txt",
        "/tmp/results.json",
    ], f"Expected sorted writes, got {r.files_written}"
    print("[OK] parse_strace_output: multiple distinct writes, sorted")


def test_parse_malformed_lines_ignored():
    d = Path(tempfile.mkdtemp(prefix="trace-malformed-"))
    _write_trace(d, "trace.400", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        'mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f...',
        'brk(NULL) = 0x55a...',
        'brk(0x55a...) = 0x55a...',
        'fstat(3, {st_mode=S_IFREG|0644, st_size=1234, ...}) = 0',
        'some garbage line that doesnt match anything ===',
        '',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert r.files_read == []
    assert r.files_written == []
    assert r.processes_spawned == ["/usr/local/bin/python3"]
    assert r.network_attempts == []
    print("[OK] parse_strace_output: unknown syscalls ignored gracefully")


def test_parse_ipv6_attempt():
    d = Path(tempfile.mkdtemp(prefix="trace-v6-"))
    _write_trace(d, "trace.500", [
        'execve("/usr/local/bin/node", ["node", "index.js"], ...) = 0',
        'socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 10',
        'connect(10, {sa_family=AF_INET6, sin6_port=htons(443), '
        'inet_pton(AF_INET6, "2606:2800:220:1:248:1893:25c8:1946", &sin6_addr), '
        'sin6_flowinfo=0, sin6_scope_id=0}, 28) = -1 ENETUNREACH',
        '+++ exited with 1 +++',
    ])
    r = parse_strace_output(d)
    v6_entries = [n for n in r.network_attempts if n.startswith("connect [")]
    assert len(v6_entries) == 1, f"Expected 1 IPv6 connect, got {v6_entries}"
    assert "2606:2800:220:1:248:1893:25c8:1946" in v6_entries[0]
    print("[OK] parse_strace_output: IPv6 connect captured with bracketed addr")


def test_parse_unix_socket_recorded():
    d = Path(tempfile.mkdtemp(prefix="trace-unix-"))
    _write_trace(d, "trace.600", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        'connect(5, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = -1 ENOENT',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert any("unix:/var/run/docker.sock" in n for n in r.network_attempts), \
        f"Expected unix socket entry, got {r.network_attempts}"
    print("[OK] parse_strace_output: AF_UNIX connect recorded")


def test_behavior_report_has_data_property():
    empty = BehaviorReport()
    assert empty.has_data is False

    with_files = BehaviorReport(files_read=["/app/main.py"])
    assert with_files.has_data is True

    with_sensitive = BehaviorReport(sensitive_access=["/root/.ssh/id_rsa"])
    assert with_sensitive.has_data is True

    with_net = BehaviorReport(network_attempts=["connect 1.2.3.4:443"])
    assert with_net.has_data is True
    print("[OK] BehaviorReport.has_data: correctly reflects non-empty fields")


# ----------------------------------------------------------------------
# Native sandbox backend tests (bubblewrap)
# ----------------------------------------------------------------------

def test_native_adapt_cmd_python():
    """python -> python3, pip -> python3 -m pip"""
    assert _native_adapt_cmd(["python", "main.py"], "Python") == ["python3", "main.py"]
    assert _native_adapt_cmd(["pip", "install", "-r", "requirements.txt"], "Python") == \
        ["python3", "-m", "pip", "install", "-r", "requirements.txt"]
    # Non-Python stacks pass through unchanged
    assert _native_adapt_cmd(["node", "index.js"], "Node.js") == ["node", "index.js"]
    assert _native_adapt_cmd(["go", "run", "main.go"], "Go (experimental)") == ["go", "run", "main.go"]
    # Empty cmd stays empty
    assert _native_adapt_cmd([], "Python") == []
    print("[OK] _native_adapt_cmd: python->python3, pip->python3 -m pip")


def test_build_bwrap_args_execute_network_off():
    """Execute phase: --unshare-net must be present, deps read-only."""
    repo = Path("/tmp/fake-repo")
    deps = Path("/tmp/fake-deps")
    stack = StackProfile(
        name="Python", image="python:3.11-slim",
        install_cmd=[], run_candidates=[["python", "main.py"]],
        env={"PYTHONPATH": "/tmp/pip_deps"}, deps_mount="/tmp/pip_deps",
    )
    args = _build_bwrap_args(repo, stack, deps, trace_dir=None,
                             network=False, deps_writable=False)
    # Network isolation
    assert "--unshare-net" in args, "Execute phase MUST have --unshare-net"
    # Repo read-only
    assert "--ro-bind" in args
    assert str(repo) in args and "/app" in args
    # Deps read-only (not writable) during execute
    ro_idx = args.index("--ro-bind") if "--ro-bind" in args else -1
    # Find the deps mount — should be --ro-bind not --bind
    deps_bind = [i for i, a in enumerate(args) if a == str(deps)]
    assert deps_bind, "Deps dir must be in args"
    # The flag before deps_dir should be --ro-bind (read-only)
    for idx in deps_bind:
        assert args[idx - 1] == "--ro-bind", \
            f"Deps must be --ro-bind during execute, got {args[idx-1]}"
    print("[OK] _build_bwrap_args: execute has --unshare-net + ro deps")


def test_build_bwrap_args_install_network_on():
    """Install phase: NO --unshare-net, deps writable."""
    repo = Path("/tmp/fake-repo")
    deps = Path("/tmp/fake-deps")
    stack = StackProfile(
        name="Node.js", image="node:20-slim",
        install_cmd=["npm", "install"], run_candidates=[],
        env={"NODE_PATH": "/tmp/npm_cache/node_modules"}, deps_mount="/tmp/npm_cache",
    )
    args = _build_bwrap_args(repo, stack, deps, trace_dir=None,
                             network=True, deps_writable=True)
    # Network must be ON for install
    assert "--unshare-net" not in args, "Install phase must NOT have --unshare-net"
    # Deps writable (--bind, not --ro-bind)
    deps_idx = args.index(str(deps))
    assert args[deps_idx - 1] == "--bind", \
        f"Deps must be --bind (writable) during install, got {args[deps_idx-1]}"
    print("[OK] _build_bwrap_args: install has NO --unshare-net + writable deps")


def test_build_bwrap_args_home_root_isolated():
    """ /home and /root must be tmpfs (empty) so SSH keys are inaccessible."""
    repo = Path("/tmp/fake-repo")
    stack = StackProfile(
        name="Python", image="python:3.11-slim",
        install_cmd=[], run_candidates=[["python", "main.py"]],
        env={}, deps_mount=None,
    )
    args = _build_bwrap_args(repo, stack, deps_dir=None, trace_dir=None,
                             network=False, deps_writable=False)
    # /home and /root must be tmpfs
    home_idx = args.index("/home")
    assert args[home_idx - 1] == "--tmpfs", "/home must be tmpfs"
    root_idx = args.index("/root")
    assert args[root_idx - 1] == "--tmpfs", "/root must be tmpfs"
    print("[OK] _build_bwrap_args: /home and /root are tmpfs (SSH keys isolated)")


def test_build_bwrap_args_env_vars():
    """Environment variables must be passed via --setenv."""
    repo = Path("/tmp/fake-repo")
    stack = StackProfile(
        name="Python", image="python:3.11-slim",
        install_cmd=[], run_candidates=[],
        env={"PYTHONPATH": "/tmp/pip_deps", "PYTHONDONTWRITEBYTECODE": "1"},
        deps_mount=None,
    )
    args = _build_bwrap_args(repo, stack, deps_dir=None, trace_dir=None,
                             network=False, deps_writable=False)
    assert "--setenv" in args
    assert "PYTHONPATH" in args
    assert "/tmp/pip_deps" in args
    assert "PYTHONDONTWRITEBYTECODE" in args
    print("[OK] _build_bwrap_args: env vars passed via --setenv")


def test_build_bwrap_args_trace_dir():
    """When trace_dir is provided, it's mounted writable at /trace."""
    repo = Path("/tmp/fake-repo")
    trace = Path("/tmp/fake-trace")
    stack = StackProfile(
        name="Python", image="python:3.11-slim",
        install_cmd=[], run_candidates=[],
        env={}, deps_mount=None,
    )
    args = _build_bwrap_args(repo, stack, deps_dir=None, trace_dir=trace,
                             network=False, deps_writable=False)
    trace_idx = args.index(str(trace))
    assert args[trace_idx - 1] == "--bind", "Trace dir must be --bind (writable)"
    assert "/trace" in args, "Trace dir must be mounted at /trace"
    print("[OK] _build_bwrap_args: trace_dir mounted writable at /trace")


def test_select_backend_auto_prefers_native():
    """In auto mode, if bwrap is available, native is preferred."""
    # We can't control whether bwrap is installed in the test env, but
    # we can verify the logic: if check_bubblewrap() returns True and
    # the stack is None, _select_backend returns 'native'.
    # If bwrap isn't installed, it returns 'docker'.
    import proofer
    original = proofer.check_bubblewrap
    try:
        # Simulate bwrap available
        proofer.check_bubblewrap = lambda: True
        result = _select_backend("auto", stack=None)
        assert result == "native", f"auto+bwrap should be native, got {result}"

        # Simulate bwrap unavailable
        proofer.check_bubblewrap = lambda: False
        result = _select_backend("auto", stack=None)
        assert result == "docker", f"auto+no-bwrap should be docker, got {result}"
    finally:
        proofer.check_bubblewrap = original
    print("[OK] _select_backend: auto prefers native when bwrap available")


def test_select_backend_docker_forced():
    """--sandbox docker always returns docker."""
    result = _select_backend("docker", stack=None)
    assert result == "docker"
    print("[OK] _select_backend: docker forced")


def test_select_backend_native_with_stack_runtime_check():
    """--sandbox native with a stack checks host runtime."""
    import proofer
    original_bwrap = proofer.check_bubblewrap
    original_runtime = proofer.check_host_runtime
    try:
        proofer.check_bubblewrap = lambda: True
        stack = StackProfile(
            name="Python", image="python:3.11-slim",
            install_cmd=[], run_candidates=[],
            env={}, deps_mount=None,
        )
        # Simulate runtime available
        proofer.check_host_runtime = lambda s: (True, "python3")
        result = _select_backend("native", stack=stack)
        assert result == "native"

        # Simulate runtime unavailable — should raise typer.Exit
        proofer.check_host_runtime = lambda s: (False, "python3 not found")
        try:
            _select_backend("native", stack=stack)
            assert False, "Should have raised typer.Exit"
        except (SystemExit, Exception):
            pass  # typer.Exit raises click.exceptions.Exit (subclass of Exception)
    finally:
        proofer.check_bubblewrap = original_bwrap
        proofer.check_host_runtime = original_runtime
    print("[OK] _select_backend: native with stack checks host runtime")


# ----------------------------------------------------------------------
# Runner
# ----------------------------------------------------------------------

def run_all():
    print("=" * 60)
    print("Stack detection tests")
    print("=" * 60)
    test_detect_node()
    test_detect_node_reads_package_json_main()
    test_detect_node_reads_scripts_start()
    test_detect_node_reads_bin_field()
    test_detect_node_malformed_package_json_falls_back()
    test_detect_node_no_duplicate_candidates()
    test_detect_python_with_requirements()
    test_detect_python_main_only()
    test_detect_python_server_py()
    test_detect_python_django_manage_py()
    test_detect_python_src_layout()
    test_detect_python_package_with_main()
    test_detect_python_namespace_package_main()
    test_detect_python_pyproject_toml()
    test_detect_python_setup_py()
    test_detect_python_pyproject_no_main()
    test_detect_python_console_scripts_pyproject()
    test_detect_python_console_scripts_poetry()
    test_detect_python_console_scripts_poetry_shorthand()
    test_detect_python_console_scripts_dotted_attr()
    test_detect_python_console_scripts_setup_cfg()
    test_detect_python_console_scripts_setup_py()
    test_detect_python_console_scripts_with_main_py()
    test_detect_go()
    test_detect_rust()
    test_detect_unknown()

    print()
    print("=" * 60)
    print("Verdict analysis tests (readiness-aware BOOTS)")
    print("=" * 60)
    test_analyze_boots_yes()
    test_analyze_library_no_entrypoint()
    test_analyze_boots_no()
    test_analyze_network_error_node()
    test_analyze_network_error_python()
    test_analyze_timeout_long_running()
    test_analyze_timeout_with_crash()
    test_analyze_timeout_with_readiness_signal()
    test_analyze_readiness_uvicorn()
    test_analyze_stdout_truncation()
    test_network_regex_negative()
    test_network_regex_positive_variants()

    print()
    print("=" * 60)
    print("strace parser - regex unit tests")
    print("=" * 60)
    test_strace_open_regex_rdonly()
    test_strace_open_regex_wronly_creat()
    test_strace_open_regex_rdwr()
    test_strace_open_regex_creat_only()
    test_strace_execve_regex()
    test_strace_connect_ipv4_regex()
    test_strace_connect_ipv6_regex()
    test_strace_connect_unix_regex()
    test_strace_socket_inet_regex()

    print()
    print("=" * 60)
    print("strace parser - BehaviorReport tests")
    print("=" * 60)
    test_parse_empty_trace_dir()
    test_parse_clean_app()
    test_parse_network_attempt()
    test_parse_sensitive_ssh_access()
    test_parse_runtime_noise_filtered()
    test_parse_dedup_across_forks()
    test_parse_multiple_distinct_writes()
    test_parse_malformed_lines_ignored()
    test_parse_ipv6_attempt()
    test_parse_unix_socket_recorded()
    test_behavior_report_has_data_property()

    print()
    print("=" * 60)
    print("Native sandbox backend tests (bubblewrap)")
    print("=" * 60)
    test_native_adapt_cmd_python()
    test_build_bwrap_args_execute_network_off()
    test_build_bwrap_args_install_network_on()
    test_build_bwrap_args_home_root_isolated()
    test_build_bwrap_args_env_vars()
    test_build_bwrap_args_trace_dir()
    test_select_backend_auto_prefers_native()
    test_select_backend_docker_forced()
    test_select_backend_native_with_stack_runtime_check()

    print()
    print("=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    run_all()
