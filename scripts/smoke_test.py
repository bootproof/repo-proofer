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


def test_detect_rails_priority_over_node():
    """A polyglot repo with BOTH Gemfile+config.ru AND package.json is a
    Rails app with frontend assets (GitLab, Discourse, Mastodon). The
    Ruby app is primary; package.json is secondary. Without priority
    detection, repo-proofer would pick Node.js, run `npm start`, and
    report 'Missing script: start' as a crash — missing the actual app.
    """
    repo = _make_repo({
        "Gemfile": 'source "https://rubygems.org"\ngem "rails"',
        "config.ru": 'require "./config/environment"\nrun Rails.application',
        "package.json": '{"name":"frontend","scripts":{"build":"webpack"}}',
        "app/controllers/application_controller.rb": "",
    })
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Ruby (Rails)", \
        f"Expected Ruby (Rails) for polyglot repo, got {s.name}"
    assert s.image == "ruby:3.3-slim"
    assert ["bundle", "exec", "rails", "server", "-b", "0.0.0.0"] in s.run_candidates
    print("[OK] detect_stack: Rails wins over Node.js for polyglot repos (GitLab fix)")


def test_detect_python_priority_over_node():
    """A polyglot repo with BOTH manage.py AND package.json is a Django
    app with frontend assets. Python is primary."""
    repo = _make_repo({
        "manage.py": "#!/usr/bin/env python",
        "requirements.txt": "django==5.0",
        "package.json": '{"name":"frontend","scripts":{"build":"webpack"}}',
    })
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python", \
        f"Expected Python for polyglot repo, got {s.name}"
    print("[OK] detect_stack: Python wins over Node.js for polyglot repos")


def test_detect_node_workspaces():
    """Detect npm workspaces (monorepo) in package.json."""
    from proofer import _detect_node_workspaces
    # Array-style workspaces
    repo = _make_repo({
        "package.json": '{"name":"mono","workspaces":["apps/*","packages/*"]}',
    })
    ws = _detect_node_workspaces(repo)
    assert ws == ["apps/*", "packages/*"], f"Expected workspace globs, got {ws}"

    # Object-style workspaces (npm/pnpm)
    repo2 = _make_repo({
        "package.json": '{"name":"mono","workspaces":{"packages":["apps/*"]}}',
    })
    ws2 = _detect_node_workspaces(repo2)
    assert ws2 == ["apps/*"], f"Expected packages list, got {ws2}"

    # No workspaces
    repo3 = _make_repo({"package.json": '{"name":"plain"}'})
    assert _detect_node_workspaces(repo3) is None
    print("[OK] _detect_node_workspaces: detects array + object + none")


def test_analyze_monorepo_no_root_entry():
    """A monorepo (npm workspaces) with no root start script should get
    a yellow NO RUNNABLE ENTRYPOINT verdict, NOT a red crash. The
    Supabase fix: 'npm error Missing script: start' on a workspace repo
    is not a crash — it's a missing root entrypoint."""
    r = ExecutionResult(
        stdout="",
        stderr="npm error Missing script: \"start\"\nnpm error",
        exit_code=1,
        monorepo_no_root_entry=True,
    )
    v = analyze_result(r)
    assert v.boots is False
    assert v.no_entrypoint is True, \
        "Monorepo with no root entry must set no_entrypoint for yellow display"
    assert v.monorepo is True
    assert "monorepo" in v.detail.lower(), f"Expected 'monorepo' in detail, got {v.detail}"
    print("[OK] analyze_result: monorepo no-root-entry -> yellow (not red crash)")


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
    assert "crash" in v.detail
    print("[OK] analyze_result: exit 1 (no crash sig) -> BOOTS:NO, 'crash'")


def test_analyze_exit_127_command_not_found():
    """Exit 127 = 'command not found' — an environment failure, NOT an
    application crash. The app never ran because a required tool/binary
    is missing. The verdict should say 'failed to start' not 'crash'.

    This is the formbricks case: `turbo: not found` because the monorepo's
    build tool wasn't installed in the sandbox. Lumping 127 in with real
    crashes flattened three distinct situations into one misleading label.
    """
    r = ExecutionResult(
        stdout="",
        stderr="sh: 1: turbo: not found",
        exit_code=127,
    )
    v = analyze_result(r)
    assert v.boots is False
    assert "failed to start" in v.detail, \
        f"Exit 127 should say 'failed to start', got {v.detail}"
    assert "turbo" in v.detail, \
        f"Should extract missing command 'turbo', got {v.detail}"
    assert "crash" not in v.detail.lower(), \
        f"Exit 127 is NOT a crash — don't use that word, got {v.detail}"
    assert any("environment failure" in w for w in v.warnings), \
        f"Should warn about environment failure, got {v.warnings}"
    print("[OK] analyze_result: exit 127 (turbo) -> 'failed to start' (not 'crash')")


def test_analyze_exit_127_bundler_command_not_found():
    """Exit 127 with bundler's format: 'bundler: command not found: rails'.
    The command name comes AFTER 'command not found', not before — the
    old regex missed this and gitlab fell through to the generic label.
    This is the GitLab case: bundle install failed → rails never installed
    → bundler couldn't find rails → exit 127.
    """
    r = ExecutionResult(
        stdout="",
        stderr="bundler: command not found: rails",
        exit_code=127,
    )
    v = analyze_result(r)
    assert v.boots is False
    assert "failed to start" in v.detail, \
        f"Exit 127 should say 'failed to start', got {v.detail}"
    assert "rails" in v.detail, \
        f"Should extract missing command 'rails' from bundler format, got {v.detail}"
    assert "crash" not in v.detail.lower(), \
        f"Exit 127 is NOT a crash, got {v.detail}"
    print("[OK] analyze_result: exit 127 (bundler: rails) -> 'failed to start'")


def test_analyze_install_failure_leads_verdict():
    """When install failed AND execution fails with 127, the install
    failure is the ROOT CAUSE. The verdict should lead with 'install
    failed', not 'command not found' or 'crash'.

    The GitLab case: bundle install failed (exit 15) → rails never
    installed → exit 127. The honest verdict leads with the install
    failure, because that's what actually went wrong.
    """
    install_result = ExecutionResult(
        stdout="",
        stderr="ERROR: --path flag is deprecated",
        exit_code=15,
    )
    exec_result = ExecutionResult(
        stdout="",
        stderr="bundler: command not found: rails",
        exit_code=127,
    )
    v = analyze_result(exec_result, install_result=install_result)
    assert v.boots is False
    assert "install failed" in v.detail, \
        f"Install-failure-first: should lead with 'install failed', got {v.detail}"
    assert "exit 15" in v.detail, \
        f"Should include install exit code, got {v.detail}"
    assert "rails" in v.detail, \
        f"Should include the unavailable command, got {v.detail}"
    assert "crash" not in v.detail.lower(), \
        f"Install failure is NOT a crash, got {v.detail}"
    assert any("environment failure" in w for w in v.warnings), \
        f"Should warn about environment failure, got {v.warnings}"
    print("[OK] analyze_result: install failure + 127 -> leads with 'install failed'")


def test_analyze_install_failure_leads_on_non_127_exit():
    """When install failed AND execution fails with a NON-127 exit code,
    the install failure is still the root cause. Bundler/Ruby may exit
    with 1 (not 127) when it can't find a command — the old check only
    fired on 127, so GitLab's verdict fell through to 'crash'. Now the
    check fires on ANY non-zero exec exit when install failed.
    """
    install_result = ExecutionResult(
        stdout="",
        stderr="ERROR: --path flag is deprecated",
        exit_code=15,
    )
    exec_result = ExecutionResult(
        stdout="",
        stderr="bundler: command not found: rails",
        exit_code=1,  # NOT 127 — bundler exits with 1
    )
    v = analyze_result(exec_result, install_result=install_result)
    assert v.boots is False
    assert "install failed" in v.detail, \
        f"Should lead with 'install failed' even on non-127 exit, got {v.detail}"
    assert "exit 15" in v.detail, \
        f"Should include install exit code, got {v.detail}"
    assert "rails" in v.detail, \
        f"Should extract 'rails' from bundler stderr, got {v.detail}"
    assert "crash" not in v.detail.lower(), \
        f"Install failure is NOT a crash, got {v.detail}"
    print("[OK] analyze_result: install failure + exit 1 (non-127) -> leads with 'install failed'")


def test_analyze_exit_127_no_command_extracted():
    """Exit 127 with unparseable stderr should still say 'failed to start'."""
    r = ExecutionResult(
        stdout="",
        stderr="some weird error",
        exit_code=127,
    )
    v = analyze_result(r)
    assert v.boots is False
    assert "failed to start" in v.detail
    assert "command not found" in v.detail
    print("[OK] analyze_result: exit 127 (unparseable) -> 'failed to start'")


def test_analyze_missing_script_not_crash():
    """'Missing script: start' in stderr should say 'no runnable entrypoint',
    NOT 'crash'. This is the case where npm couldn't find a start script —
    the entrypoint doesn't exist, the app didn't run and fall over."""
    r = ExecutionResult(
        stdout="",
        stderr='npm error Missing script: "start"',
        exit_code=1,
    )
    v = analyze_result(r)
    assert v.boots is False
    assert "no runnable entrypoint" in v.detail, \
        f"Missing script should say 'no runnable entrypoint', got {v.detail}"
    assert "crash" not in v.detail.lower(), \
        f"Missing script is NOT a crash, got {v.detail}"
    print("[OK] analyze_result: Missing script -> 'no runnable entrypoint' (not 'crash')")


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
    # SSH keys, AWS creds, .env are HIGH-severity — must NOT be in medium list
    assert "/root/.ssh/id_rsa" not in r.medium_sensitive_access
    assert "/home/user/.aws/credentials" not in r.medium_sensitive_access
    assert "/app/.env" not in r.medium_sensitive_access
    print("[OK] parse_strace_output: HIGH-severity paths (ssh, aws, .env) in sensitive_access")


def test_parse_npmrc_is_medium_not_high():
    """Regression test: .npmrc must be MEDIUM, not HIGH.

    npm reads .npmrc for registry/auth/config during normal operation.
    Flagging it as HIGH ("primary indicator of malicious intent") was a
    false alarm that destroyed credibility on legitimate repos like
    Supabase. .npmrc now goes to medium_sensitive_access (informational),
    NOT sensitive_access (hard fail).
    """
    d = Path(tempfile.mkdtemp(prefix="trace-npmrc-"))
    _write_trace(d, "trace.100", [
        'execve("/usr/local/bin/npm", ["npm", "start"], ...) = 0',
        'openat(AT_FDCWD, "/app/.npmrc", O_RDONLY) = 3',
        'openat(AT_FDCWD, "/root/.npmrc", O_RDONLY) = -1 ENOENT',
        '+++ exited with 1 +++',
    ])
    r = parse_strace_output(d)
    # .npmrc must be in MEDIUM, NOT HIGH
    assert "/app/.npmrc" in r.medium_sensitive_access, \
        f".npmrc must be MEDIUM-severity, got {r.medium_sensitive_access}"
    assert "/root/.npmrc" in r.medium_sensitive_access
    assert "/app/.npmrc" not in r.sensitive_access, \
        f".npmrc must NOT be HIGH-severity (false alarm), got {r.sensitive_access}"
    assert "/root/.npmrc" not in r.sensitive_access
    print("[OK] parse_strace_output: .npmrc is MEDIUM (not HIGH) — no false alarm")


def test_parse_pypirc_netrc_are_medium():
    """Other package-manager config files (.pypirc, .netrc) are also MEDIUM."""
    d = Path(tempfile.mkdtemp(prefix="trace-pm-config-"))
    _write_trace(d, "trace.200", [
        'execve("/usr/local/bin/pip", ["pip", "install"], ...) = 0',
        'openat(AT_FDCWD, "/root/.pypirc", O_RDONLY) = -1 ENOENT',
        'openat(AT_FDCWD, "/root/.netrc", O_RDONLY) = -1 ENOENT',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert "/root/.pypirc" in r.medium_sensitive_access
    assert "/root/.netrc" in r.medium_sensitive_access
    assert "/root/.pypirc" not in r.sensitive_access
    assert "/root/.netrc" not in r.sensitive_access
    print("[OK] parse_strace_output: .pypirc, .netrc are MEDIUM (package-manager config)")


def test_parse_mixed_high_and_medium():
    """A repo that reads both SSH keys (HIGH) and .npmrc/.passwd (MEDIUM)
    must classify them into separate tiers. HIGH triggers hard fail;
    MEDIUM is informational only."""
    d = Path(tempfile.mkdtemp(prefix="trace-mixed-"))
    _write_trace(d, "trace.300", [
        'execve("/usr/local/bin/node", ["node", "index.js"], ...) = 0',
        'openat(AT_FDCWD, "/app/.npmrc", O_RDONLY) = 3',       # MEDIUM
        'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 ENOENT',  # HIGH
        'openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 4',        # MEDIUM (libc reads it)
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    # HIGH tier: SSH key only (/etc/passwd is now MEDIUM — libc reads it)
    assert "/root/.ssh/id_rsa" in r.sensitive_access
    assert len(r.sensitive_access) == 1
    # MEDIUM tier: .npmrc + /etc/passwd
    assert "/app/.npmrc" in r.medium_sensitive_access
    assert "/etc/passwd" in r.medium_sensitive_access
    assert len(r.medium_sensitive_access) == 2
    # No cross-contamination
    assert "/app/.npmrc" not in r.sensitive_access
    assert "/etc/passwd" not in r.sensitive_access
    assert "/root/.ssh/id_rsa" not in r.medium_sensitive_access
    print("[OK] parse_strace_output: HIGH (ssh) and MEDIUM (.npmrc, /etc/passwd) tiers separated")


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


def test_parse_blocked_writes_not_counted_as_written():
    """Regression test: writes rejected by the read-only filesystem (open
    returns -1 EROFS/EACCES) must be reported as 'blocked', not 'written'.

    The Supabase bug: npm tried to write a debug log, the read-only FS
    rejected it (stderr said 'Log files were not written due to an
    error'), but the report counted it as 'Files Written 1'. That's
    dishonest. Now: -1 return → writes_blocked, not files_written.
    """
    d = Path(tempfile.mkdtemp(prefix="trace-blocked-"))
    _write_trace(d, "trace.100", [
        'execve("/usr/local/bin/npm", ["npm", "start"], ...) = 0',
        # Successful write to /tmp (writable via tmpfs)
        'openat(AT_FDCWD, "/tmp/ok.log", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4',
        # BLOCKED write to /root/.npm/_logs (read-only FS rejects it)
        'openat(AT_FDCWD, "/root/.npm/_logs/debug-0.log", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)',
        '+++ exited with 1 +++',
    ])
    r = parse_strace_output(d)
    # Successful write
    assert "/tmp/ok.log" in r.files_written, \
        f"Expected /tmp/ok.log in files_written, got {r.files_written}"
    # Blocked write — must be in writes_blocked, NOT files_written
    assert "/root/.npm/_logs/debug-0.log" in r.writes_blocked, \
        f"Expected blocked write in writes_blocked, got {r.writes_blocked}"
    assert "/root/.npm/_logs/debug-0.log" not in r.files_written, \
        f"Blocked write must NOT be in files_written, got {r.files_written}"
    print("[OK] parse_strace_output: blocked writes reported as 'blocked' not 'written'")


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


def test_parse_unix_socket_filtered():
    """AF_UNIX connects are local sockets (nscd, Docker daemon, etc) —
    NOT network egress. They must be filtered OUT of network_attempts
    so the count reflects real outbound attempts only. (The GitLab
    over-counting fix: 'connect unix:/var/run/nscd/socket' was inflating
    the network count.)"""
    d = Path(tempfile.mkdtemp(prefix="trace-unix-"))
    _write_trace(d, "trace.600", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        'connect(5, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = -1 ENOENT',
        'connect(6, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    # AF_UNIX connects must NOT appear in network_attempts
    assert not any("unix:" in n for n in r.network_attempts), \
        f"AF_UNIX must be filtered from network_attempts, got {r.network_attempts}"
    assert len(r.network_attempts) == 0, \
        f"Expected 0 network attempts (only AF_UNIX), got {r.network_attempts}"
    print("[OK] parse_strace_output: AF_UNIX connects filtered (not network egress)")


def test_parse_no_duplicate_from_bare_trace_file():
    """Regression test: glob 'trace.*' must NOT match a bare 'trace' file.

    The old glob 'trace*' matched both 'trace.1234' (per-pid) and 'trace'
    (combined output if one exists). If strace wrote both, every syscall
    was double-counted — the report rendered duplicated. This test creates
    a bare 'trace' file alongside per-pid files and verifies NO duplication.
    """
    d = Path(tempfile.mkdtemp(prefix="trace-dup-"))
    # Per-pid file with the real syscall
    _write_trace(d, "trace.100", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 ENOENT',
        '+++ exited with 0 +++',
    ])
    # Bare 'trace' file (combined output — should be IGNORED if per-pid exist)
    _write_trace(d, "trace", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 ENOENT',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    # Must see the sensitive path exactly once — not twice.
    assert r.sensitive_access.count("/root/.ssh/id_rsa") == 1, \
        f"Expected exactly 1 sensitive path, got {r.sensitive_access} (duplication bug!)"
    # Must see exactly 1 process spawn — not twice.
    assert r.processes_spawned.count("/usr/local/bin/python3") == 1, \
        f"Expected exactly 1 process, got {r.processes_spawned} (duplication bug!)"
    print("[OK] parse_strace_output: bare 'trace' file ignored when per-pid exist (no duplication)")


def test_parse_bare_trace_fallback():
    """If ONLY a bare 'trace' file exists (no per-pid), parse it.
    Some strace versions/modes write a single combined file. The parser
    should fall back to it rather than returning an empty report."""
    d = Path(tempfile.mkdtemp(prefix="trace-bare-"))
    _write_trace(d, "trace", [
        'execve("/usr/local/bin/python3", ["python3", "main.py"], ...) = 0',
        'openat(AT_FDCWD, "/app/main.py", O_RDONLY) = 3',
        '+++ exited with 0 +++',
    ])
    r = parse_strace_output(d)
    assert r.processes_spawned == ["/usr/local/bin/python3"], \
        f"Should parse bare trace file, got {r.processes_spawned}"
    assert "/app/main.py" in r.files_read
    print("[OK] parse_strace_output: bare 'trace' file parsed when no per-pid exist")


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
    test_detect_rails_priority_over_node()
    test_detect_python_priority_over_node()
    test_detect_node_workspaces()

    print()
    print("=" * 60)
    print("Verdict analysis tests (readiness-aware BOOTS)")
    print("=" * 60)
    test_analyze_boots_yes()
    test_analyze_library_no_entrypoint()
    test_analyze_monorepo_no_root_entry()
    test_analyze_boots_no()
    test_analyze_exit_127_command_not_found()
    test_analyze_exit_127_bundler_command_not_found()
    test_analyze_install_failure_leads_verdict()
    test_analyze_install_failure_leads_on_non_127_exit()
    test_analyze_exit_127_no_command_extracted()
    test_analyze_missing_script_not_crash()
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
    test_parse_npmrc_is_medium_not_high()
    test_parse_pypirc_netrc_are_medium()
    test_parse_mixed_high_and_medium()
    test_parse_runtime_noise_filtered()
    test_parse_dedup_across_forks()
    test_parse_multiple_distinct_writes()
    test_parse_blocked_writes_not_counted_as_written()
    test_parse_malformed_lines_ignored()
    test_parse_ipv6_attempt()
    test_parse_unix_socket_filtered()
    test_parse_no_duplicate_from_bare_trace_file()
    test_parse_bare_trace_fallback()
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
