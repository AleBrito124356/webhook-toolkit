"""End-to-end: real processes, real sockets, loopback only."""

import os
import socket
import subprocess
import sys
import time

import httpx

from _helpers import REPO_ROOT

SECRET = "e2e" + "-" + "github-secret"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _env(**extra):
    # No PYTHONIOENCODING on purpose: redirected output on Windows is cp1252,
    # which used to crash `serve` on its first box-drawing character.
    env = {
        k: v for k, v in os.environ.items()
        if not k.endswith("_WEBHOOK_SECRET") and k not in ("PYTHONIOENCODING", "PYTHONUTF8")
    }
    env.update(extra)
    return env


def test_cli_serve_and_send_as_separate_processes(tmp_path):
    port = _free_port()
    env = _env(GITHUB_WEBHOOK_SECRET=SECRET)
    server = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "cli.py"), "serve", "--port", str(port), "--db", str(tmp_path / "e2e.db")],
        cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                if httpx.get(base + "/api/events", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            assert server.poll() is None, "serve exited early"
            assert time.monotonic() < deadline, "serve did not come up"
            time.sleep(0.1)

        sent = subprocess.run(
            [sys.executable, str(REPO_ROOT / "cli.py"), "send", "github", "push", "--to", base, "--sign", "--count", "2"],
            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
        )
        assert sent.returncode == 0, sent.stdout + sent.stderr
        assert sent.stdout.count("status 200") == 2

        events = httpx.get(base + "/api/events").json()
        assert events["count"] == 2
        assert [e["verified"] for e in events["events"]] == [1, 1]
        assert events["events"][0]["path"] == "/webhooks/github"
    finally:
        server.terminate()
        output, _ = server.communicate(timeout=20)
    text = output.decode("utf-8")
    assert "─ webhook-toolkit ─" in text  # the banner rule rendered, no UnicodeEncodeError
    assert "Traceback" not in text
    assert "#1 POST /webhooks/github | github | verified" in text


def test_offline_demo_passes_end_to_end(tmp_path):
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "examples" / "offline_demo.py")],
        cwd=tmp_path, env=_env(), capture_output=True, text=True, encoding="utf-8", timeout=180,
    )
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    assert "checks passed" in result.stdout
    assert "FAIL" not in result.stdout
