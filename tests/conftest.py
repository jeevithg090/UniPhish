"""Test-suite guard rails.

* **No network by default.** Any DNS lookup or socket connect to a non-loopback host
  raises, so a test can never silently depend on the internet (or leak a request to a
  real phishing host). Opt in per test with ``@pytest.mark.network``.
* **Isolated state.** Every test gets its own ``UNIPHISH_DATA_DIR`` (SQLite DB, caches).
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "testserver", ""}


class NetworkBlocked(RuntimeError):
    """Raised when a test touches the network without @pytest.mark.network."""


def _is_local(host) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode(errors="ignore")
    host = str(host).strip("[]").lower()
    if host in _LOCAL_NAMES:
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True  # IP *literals* never trigger DNS; connect() is checked separately


def _guarded_getaddrinfo(host, *args, **kwargs):
    if not _is_local(host):
        raise NetworkBlocked(f"DNS lookup of {host!r} blocked in tests (use @pytest.mark.network)")
    return _real_getaddrinfo(host, *args, **kwargs)


def _addr_ok(sock, address) -> bool:
    if sock.family == getattr(socket, "AF_UNIX", object()):
        return True
    host = address[0] if isinstance(address, tuple) else address
    try:
        return ipaddress.ip_address(str(host).strip("[]")).is_loopback
    except ValueError:
        return str(host).lower() in _LOCAL_NAMES


def _guarded_connect(self, address):
    if not _addr_ok(self, address):
        raise NetworkBlocked(f"connect to {address!r} blocked in tests (use @pytest.mark.network)")
    return _real_connect(self, address)


def _guarded_connect_ex(self, address):
    if not _addr_ok(self, address):
        raise NetworkBlocked(f"connect to {address!r} blocked in tests (use @pytest.mark.network)")
    return _real_connect_ex(self, address)


def pytest_collection_modifyitems(config, items):
    if config.getoption("-m"):
        return
    skip = pytest.mark.skip(reason="network test (run with -m network)")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _no_network(request, monkeypatch):
    if "network" in request.keywords:
        yield
        return
    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
    yield


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIPHISH_DATA_DIR", str(tmp_path / "uniphish-data"))
    monkeypatch.delenv("UNIPHISH_DB", raising=False)
    monkeypatch.delenv("UNIPHISH_ONLINE", raising=False)
    monkeypatch.delenv("UNIPHISH_API_KEYS", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from uniphish.core.config import reset_settings

    reset_settings()
    yield
    reset_settings()
