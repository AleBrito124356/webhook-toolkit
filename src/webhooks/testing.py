"""Run an ASGI app on a real loopback socket for integration tests and demos.

``BackgroundServer`` starts uvicorn in a daemon thread on an ephemeral port and
stops it again on exit::

    from webhooks.testing import BackgroundServer

    with BackgroundServer(my_handler_app) as server:
        httpx.post(server.url + "/webhooks/github", ...)

Unlike an in-process ``TestClient``, this exercises the real HTTP stack: the
exact bytes on the wire, header framing, and the client's connection handling.
That is what you want when testing webhook handlers against replays.
"""

from __future__ import annotations

import socket
import threading
import time


class BackgroundServer:
    """Context manager that serves ``app`` on ``http://127.0.0.1:<free port>``."""

    def __init__(self, app, *, host: str = "127.0.0.1", startup_timeout: float = 10.0):
        self.app = app
        self.host = host
        self.startup_timeout = startup_timeout
        self.port: int | None = None
        self._server = None
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    @property
    def url(self) -> str:
        if self.port is None:
            raise RuntimeError("server is not running")
        return f"http://{self.host}:{self.port}"

    def start(self) -> "BackgroundServer":
        import uvicorn

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, 0))
        sock.listen(128)
        self._sock = sock
        self.port = sock.getsockname()[1]

        config = uvicorn.Config(self.app, log_level="warning", lifespan="off")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [sock]}, daemon=True
        )
        self._thread.start()
        deadline = time.monotonic() + self.startup_timeout
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("uvicorn exited during startup")
            if time.monotonic() > deadline:
                self.stop()
                raise TimeoutError(f"server did not start within {self.startup_timeout}s")
            time.sleep(0.01)
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)
        if self._sock is not None:
            self._sock.close()
        self._server = None
        self._thread = None
        self._sock = None

    def __enter__(self) -> "BackgroundServer":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()
