"""pfSense collector: interfaces, gateway health, DHCP static mappings.

Auth: x-api-key header (Client-Secret from pfSense REST API package).
A 403 on any endpoint is logged and skipped; partial grants degrade
gracefully rather than failing the whole poll.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import httpx

from ..config import Settings
from .. import db
from . import register

NAME = "pfsense"

# Interface name prefixes that indicate VPN tunnels — not physical connections
# and not useful for topology. Skipped for both interfaces and gateways.
_TUNNEL_PREFIXES = ("tun", "ovpn", "gif", "gre")

# Interface types reported by pfSense REST API that are VPN/virtual only
_TUNNEL_TYPES = {"wireguard", "openvpn", "ipsec", "gif", "gre"}


def _is_tunnel(iface_id: str, iface_type: str | None = None) -> bool:
    name = iface_id.lower()
    return (
        name.startswith(_TUNNEL_PREFIXES)
        or (iface_type or "").lower() in _TUNNEL_TYPES
    )


class PfsenseCollector:
    name = NAME

    def configured(self, settings: Settings) -> bool:
        return bool(settings.pfsense_host and settings.pfsense_api_secret)

    def collect(self, settings: Settings, conn: sqlite3.Connection) -> str:
        host = settings.pfsense_host
        base = host.rstrip("/") if "://" in host else f"https://{host}"
        headers = {
            "x-api-key": settings.pfsense_api_secret,
            "Content-Type": "application/json",
        }
        notes: list[str] = []

        def get(path: str) -> Any | None:
            r = client.get(f"{base}/{path}", headers=headers)
            if r.status_code == 403:
                notes.append(f"{path}: 403")
                return None
            if r.status_code == 404:
                return None
            r.raise_for_status()
            data = r.json()
            # pfSense REST API v2 wraps responses in {"data": ..., "code": 200}
            if isinstance(data, dict) and "data" in data:
                return data["data"]
            return data

        with httpx.Client(verify=settings.tls_verify, timeout=20) as client:
            _hostname = base.split("://")[-1].split(":")[0]
            dev_name = _hostname.split(".")[0]

            sysinfo = get("api/v2/status/system") or {}
            version = None
            if isinstance(sysinfo, dict):
                version = (sysinfo.get("pfsense_version")
                           or sysinfo.get("base_firmware_version"))

            dev_id = db.upsert_device(
                conn, name=dev_name, source=NAME, role="firewall", status="up",
                vendor="pfSense",
                os=(f"pfsense {version}" if version else None),
            )

            # Build live-status index keyed by interface id
            iface_status_raw = get("api/v2/status/interfaces") or []
            iface_status: dict[str, dict] = {}
            for i in (iface_status_raw if isinstance(iface_status_raw, list) else []):
                key = i.get("if") or i.get("name") or i.get("id")
                if key:
                    iface_status[key] = i

            # Collect tunnel interface ids so we can skip their gateways too
            tunnel_iface_ids: set[str] = set()

            iface_cfg = get("api/v2/interfaces") or []
            n_ifaces = 0
            for iface in (iface_cfg if isinstance(iface_cfg, list) else []):
                iface_id = iface.get("if") or iface.get("id")
                if not iface_id:
                    continue
                if _is_tunnel(iface_id, iface.get("type")):
                    tunnel_iface_ids.add(iface_id)
                    continue
                live = iface_status.get(iface_id, {})
                mac = (live.get("mac") or iface.get("mac") or "").lower() or None
                oper_status = "up" if live.get("status") == "up" else (live.get("status") or None)
                ip = iface.get("ipaddr") or None
                if ip in ("dhcp", "pppoe", ""):
                    ip = live.get("ipaddr") or None
                db.upsert_interface(
                    conn, device_id=dev_id, name=iface_id,
                    oper_status=oper_status, mac=mac,
                    description=iface.get("descr") or None,
                    ip=ip,
                    speed_bps=None,
                )
                n_ifaces += 1

            # Gateway health — prune stale rows then re-insert filtered set.
            # Prune first so gateways removed from pfSense (or now filtered) don't linger.
            conn.execute("DELETE FROM gateways WHERE source = ?", (NAME,))
            gw_status = get("api/v2/status/gateways") or []
            for gw in (gw_status if isinstance(gw_status, list) else []):
                gw_name = gw.get("name")
                if not gw_name:
                    continue
                # Skip gateways whose interface is a tunnel (by id set or name prefix)
                gw_iface = gw.get("interface") or gw.get("friendlyiface") or ""
                if gw_iface in tunnel_iface_ids or _is_tunnel(gw_iface):
                    continue
                # Also skip if the gateway name itself ends with VPN tier suffixes
                # (catches WireGuard peers whose interface type isn't reported as wireguard)
                if gw_name.upper().endswith(("_VPNV4", "_VPNV6", "_VPN", "_GW")) \
                        and any(kw in gw_name.upper() for kw in ("VPN", "WG", "TUN", "OVPN")):
                    continue
                conn.execute(
                    "INSERT INTO gateways (name, address, status, loss, delay, source, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET address=excluded.address, "
                    "status=excluded.status, loss=excluded.loss, delay=excluded.delay, "
                    "last_seen=excluded.last_seen",
                    (gw_name, gw.get("gateway"),
                     "up" if gw.get("online") else "down",
                     gw.get("loss"), gw.get("delay"), NAME, db.now()),
                )

            # DHCP static mappings as endpoints (hostname + IP + MAC)
            dhcp_servers = get("api/v2/services/dhcp_servers") or []
            n_endpoints = 0
            for srv in (dhcp_servers if isinstance(dhcp_servers, list) else []):
                for sm in (srv.get("staticmap") or []):
                    mac = (sm.get("mac") or "").lower()
                    if mac:
                        db.upsert_endpoint(
                            conn, mac=mac, source=NAME,
                            ip=sm.get("ipaddr") or None,
                            hostname=sm.get("hostname") or None,
                        )
                        n_endpoints += 1

        parts = [f"{n_ifaces} interfaces", "gateways"]
        if n_endpoints:
            parts.append(f"{n_endpoints} DHCP static mappings")
        summary = "/".join(parts) + " polled"
        if notes:
            summary += f" ({'; '.join(notes)})"
        return summary


register(PfsenseCollector())
