"""
compat.py – Pre-import Scapy compatibility shim.

In some sandboxed/container environments the IPv6 address entries returned
by Linux rtnetlink are missing the 'scope' key, which causes scapy.route6
to crash at module-initialisation time with a KeyError.

This shim:
  1. Patches scapy.arch.linux.rtnetlink.read_routes6 so it returns []
     instead of crashing.
  2. Stubs out scapy.route6.Route6 so its __init__ never calls resync().

Both patches are applied BEFORE any other scapy module is imported.
"""

import sys
import types
import importlib.util as _ilu


# ── 1. Patch rtnetlink.read_routes6 ──────────────────────────────────────

def _patch_rtnetlink() -> None:
    import os

    # We need real scapy packages to exist with __path__ before find_spec works.
    # Locate scapy on disk instead of using find_spec.
    try:
        import scapy as _scapy_top  # noqa – just get its path
        scapy_root = os.path.dirname(_scapy_top.__file__)
    except Exception:
        return

    rtnetlink_path = os.path.join(
        scapy_root, "arch", "linux", "rtnetlink.py"
    )
    if not os.path.exists(rtnetlink_path):
        return  # not Linux – nothing to patch

    # Pre-register a stub so when scapy imports the module it gets our safe version
    stub_rtn = types.ModuleType("scapy.arch.linux.rtnetlink")
    stub_rtn.__file__ = rtnetlink_path

    stub_rtn.read_routes6 = lambda: []
    stub_rtn.read_routes = lambda: []
    stub_rtn.in6_getifaddr = lambda: []          # returns list of (addr, scope, iface)
    stub_rtn._get_if_list = lambda: {}           # returns dict of iface info

    sys.modules["scapy.arch.linux.rtnetlink"] = stub_rtn


# ── 2. Stub out scapy.route6 ─────────────────────────────────────────────

def _stub_route6() -> None:
    stub = types.ModuleType("scapy.route6")

    class Route6:
        def __init__(self):
            self.routes: list = []

        def resync(self) -> None:
            pass

        def route(self, dst=None, dev=None, verbose=None):
            return ("::", None, "::")

        def make_route(self, *a, **kw):
            return None

        def __repr__(self):
            return "<Route6 stub – IPv6 routing disabled>"

    stub.Route6 = Route6
    sys.modules["scapy.route6"] = stub


_patch_rtnetlink()
_stub_route6()
