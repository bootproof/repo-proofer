#!/usr/bin/env python3
"""Smoke test for proofer.py — exercises deterministic logic without Docker."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# Make proofer.py importable
sys.path.insert(0, "/home/z/my-project/download")
from proofer import (
    detect_stack,
    analyze_result,
    ExecutionResult,
    StackProfile,
    NETWORK_ERROR_RE,
)


def _make_repo(files: dict[str, str]) -> Path:
    d = Path(tempfile.mkdtemp(prefix="smoke-"))
    for name, content in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


def test_detect_node():
    repo = _make_repo({
        "package.json": '{"name":"x","version":"1.0.0"}',
        "index.js": "console.log('hi')",
    })
    s = detect_stack(repo)
    assert s is not None, "Expected Node.js stack"
    assert s.name == "Node.js"
    assert s.image == "node:20-slim"
    assert s.install_cmd == ["npm", "install", "--prefix", "/tmp/npm_cache"]
    assert s.run_candidates[0] == ["node", "index.js"]
    assert s.env == {"NODE_PATH": "/tmp/npm_cache/node_modules"}
    assert s.deps_mount == "/tmp/npm_cache"
    print("[OK] detect_stack: Node.js")


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
    assert s.run_candidates == [["python", "main.py"], ["python", "app.py"]]
    assert s.env["PYTHONPATH"] == "/tmp/pip_deps"
    assert s.env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert s.deps_mount == "/tmp/pip_deps"
    print("[OK] detect_stack: Python (with requirements.txt)")


def test_detect_python_main_only():
    repo = _make_repo({"main.py": "print('hi')"})
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Python"
    assert s.install_cmd == [], "main.py-only repo should have empty install_cmd"
    assert s.deps_mount is None
    print("[OK] detect_stack: Python (main.py only, no install)")


def test_detect_go():
    repo = _make_repo({"go.mod": "module x\ngo 1.22\n", "main.go": "package main\n"})
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Go"
    assert s.image == "golang:1.22-alpine"
    assert s.install_cmd == []
    assert s.run_candidates == [["go", "run", "main.go"]]
    print("[OK] detect_stack: Go")


def test_detect_rust():
    repo = _make_repo({"Cargo.toml": "[package]\nname = \"x\"\nversion = \"0.1.0\"\n"})
    s = detect_stack(repo)
    assert s is not None
    assert s.name == "Rust"
    assert s.image == "rust:1.75-slim"
    assert s.run_candidates == [["cargo", "run"]]
    print("[OK] detect_stack: Rust")


def test_detect_unknown():
    repo = _make_repo({"README.md": "nothing useful here"})
    s = detect_stack(repo)
    assert s is None
    print("[OK] detect_stack: unknown -> None")


def test_analyze_boots_yes():
    r = ExecutionResult(stdout="hello\n", stderr="", exit_code=0)
    v = analyze_result(r)
    assert v.boots is True
    assert v.network_egress_blocked is True
    assert v.filesystem_read_only is True
    assert v.warnings == []
    assert v.stdout_preview == "hello\n"
    print("[OK] analyze_result: exit 0 -> BOOTS:YES, no warnings")


def test_analyze_boots_no():
    r = ExecutionResult(stdout="", stderr="Traceback...", exit_code=1)
    v = analyze_result(r)
    assert v.boots is False
    assert v.warnings == []
    print("[OK] analyze_result: exit 1 -> BOOTS:NO, no warnings")


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


def test_analyze_timeout():
    r = ExecutionResult(stdout="", stderr="", exit_code=-1, timed_out=True)
    v = analyze_result(r)
    assert v.boots is False  # spec: exit code != 0 -> NO
    assert any("timed out" in w for w in v.warnings)
    print("[OK] analyze_result: timeout -> BOOTS:NO + timeout warning")


def test_analyze_stdout_truncation():
    long_out = "x" * 5000
    r = ExecutionResult(stdout=long_out, stderr="", exit_code=0)
    v = analyze_result(r)
    assert len(v.stdout_preview) == 500
    print("[OK] analyze_result: stdout truncated to 500 chars")


def test_network_regex_negative():
    # Verify the regex doesn't false-positive on innocent output.
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


def run_all():
    test_detect_node()
    test_detect_python_with_requirements()
    test_detect_python_main_only()
    test_detect_go()
    test_detect_rust()
    test_detect_unknown()
    test_analyze_boots_yes()
    test_analyze_boots_no()
    test_analyze_network_error_node()
    test_analyze_network_error_python()
    test_analyze_timeout()
    test_analyze_stdout_truncation()
    test_network_regex_negative()
    test_network_regex_positive_variants()
    print()
    print("ALL DETERMINISTIC TESTS PASSED")


if __name__ == "__main__":
    run_all()
