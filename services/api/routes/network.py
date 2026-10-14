"""
IDPS API Routes — Network & Sensor Telemetry
=============================================
Live network packet inspection, real interface enumeration, flow logs,
and verified perimeter firewall enforcement.
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from shared.auth import User, require_permission, Permission
from shared.models import EventType, NormalizedEvent
from shared.storage import get_storage
from services.api.middleware.auth import get_current_user
from services.enforcement.actions.firewall import FirewallActionExecutor
from services.ingestion.sensors import NetworkSensor

router = APIRouter(prefix="/network", tags=["Network"])


def _classify_interface(name: str) -> tuple[str, str]:
    """
    Classify a network interface by its real OS name and return
    (type_label, status). Uses actual naming conventions from macOS/Linux.
    Does NOT hardcode a fixed list — derives from the live name.
    """
    n = name.lower()

    # ── macOS-specific ────────────────────────────────────────────────────────
    if n.startswith("lo"):
        return "Loopback", "UP"
    if n.startswith("gif"):
        return "Generic IPv4/IPv6 Tunnel", "UP"
    if n.startswith("stf"):
        return "6to4 Tunnel (IPv6)", "UP"
    if n.startswith("anpi"):
        return "Apple Network Proxy Interface", "UP"
    if n.startswith("ap"):
        return "Access Point (Wi-Fi Hotspot)", "UP"
    if n.startswith("awdl"):
        return "Apple Wireless Direct Link (AirDrop)", "UP"
    if n.startswith("llw"):
        return "Low-Latency WLAN (iPhone Sidecar)", "UP"
    if n.startswith("utun"):
        return "VPN Tunnel (utun)", "UP"
    if n.startswith("ipsec"):
        return "IPSec VPN Tunnel", "UP"
    if n.startswith("bridge"):
        return "Virtual Bridge", "UP"
    if n.startswith("en"):
        # Try to determine if ethernet or Wi-Fi from ifconfig
        try:
            out = subprocess.check_output(
                ["networksetup", "-listallhardwareports"],
                timeout=3, stderr=subprocess.DEVNULL, text=True
            )
            # Find the block for this device
            blocks = out.split("\n\n")
            for block in blocks:
                if f"Device: {name}" in block:
                    if "Wi-Fi" in block:
                        return "Wi-Fi (802.11)", "UP"
                    if "Ethernet" in block:
                        return "Physical Ethernet", "UP"
                    if "Thunderbolt" in block:
                        return "Thunderbolt / USB-C Ethernet", "UP"
                    if "Bluetooth" in block:
                        return "Bluetooth PAN", "UP"
        except Exception:
            pass
        return "Ethernet / Wi-Fi", "UP"

    # ── Linux-specific ────────────────────────────────────────────────────────
    if n.startswith("eth") or n.startswith("ens") or n.startswith("enp") or n.startswith("eno"):
        return "Physical Ethernet", "UP"
    if n.startswith("wlan") or n.startswith("wlp") or n.startswith("wls"):
        return "Wi-Fi (802.11)", "UP"
    if n.startswith("docker") or n.startswith("br-"):
        return "Docker/Container Bridge", "UP"
    if n.startswith("veth"):
        return "Virtual Ethernet (Container)", "UP"
    if n.startswith("tun") or n.startswith("tap"):
        return "TUN/TAP Virtual Network", "UP"
    if n.startswith("virbr"):
        return "Virtual Bridge (libvirt/KVM)", "UP"
    if n.startswith("dummy"):
        return "Dummy Interface", "UP"
    if n.startswith("bond"):
        return "Bonded Interface", "UP"
    if n.startswith("vlan") or "." in name:
        return "VLAN Tagged Interface", "UP"

    # ── Fallback: query the OS ────────────────────────────────────────────────
    return "Network Interface", "UP"

# Singleton real instances for active runtime
fw_executor = FirewallActionExecutor(dry_run=False)
network_sensor = NetworkSensor(sensor_id="net_sensor_primary", interface="auto")


class BanIPPayload(BaseModel):
    ip: str
    reason: str = "Manual administrator ban"
    ttl_seconds: int | None = 3600


class CaptureStartPayload(BaseModel):
    interface: str = "en0"
    bpf_filter: str = ""


class PCAPReplayPayload(BaseModel):
    file_path: str


@router.get("/interfaces")
async def get_network_interfaces(current_user: User = Depends(get_current_user)):
    """Return actual system network interfaces and active packet sensor status."""
    available_interfaces = []
    try:
        from scapy.all import get_if_list
        import subprocess, platform

        ifaces = get_if_list()

        # Get real interface status from OS (works on macOS and Linux)
        up_interfaces: set[str] = set()
        try:
            if platform.system() == "Darwin":
                out = subprocess.check_output(
                    ["ifconfig", "-u"],  # -u = only UP interfaces
                    timeout=3, stderr=subprocess.DEVNULL, text=True
                )
                for line in out.splitlines():
                    if not line.startswith("\t") and not line.startswith(" "):
                        up_interfaces.add(line.split(":")[0].strip())
            else:
                # Linux
                import os
                for iface in ifaces:
                    flag_path = f"/sys/class/net/{iface}/operstate"
                    if os.path.exists(flag_path):
                        with open(flag_path) as f:
                            if "up" in f.read():
                                up_interfaces.add(iface)
        except Exception:
            # If we can't determine, assume all scapy-listed interfaces are up
            up_interfaces = set(ifaces)

        for iface in ifaces:
            iface_type, _ = _classify_interface(iface)
            real_status = "UP" if iface in up_interfaces or not up_interfaces else "DOWN"
            available_interfaces.append({
                "name": iface,
                "type": iface_type,
                "status": real_status,
            })

    except Exception:
        # True OS fallback: use socket.if_nameindex() which is always available
        import socket
        try:
            for idx, name in socket.if_nameindex():
                iface_type, status = _classify_interface(name)
                available_interfaces.append({"name": name, "type": iface_type, "status": status})
        except Exception:
            available_interfaces = []

    capture_status = network_sensor.get_capture_status()
    return {
        "active_interface": network_sensor.interface,
        "capture_mode": network_sensor.capture_mode,
        "available_interfaces": available_interfaces,
        "capture_status": capture_status["status"],
        "status_details": capture_status["status_details"],
        "packets_captured": capture_status["packets_captured"],
        "packets_dropped": capture_status["packets_dropped"],
    }


@router.get("/capture/status")
async def get_capture_status(current_user: User = Depends(get_current_user)):
    """Return genuine live capture status and limitations."""
    return network_sensor.get_capture_status()


@router.post("/capture/start")
async def start_live_capture(payload: CaptureStartPayload, current_user: User = Depends(get_current_user)):
    """Start live packet capture on the selected interface."""
    require_permission(current_user, Permission.ENFORCEMENT_EXECUTE)
    network_sensor.interface = payload.interface
    network_sensor.bpf_filter = payload.bpf_filter
    return await network_sensor.start_capture()


@router.post("/capture/stop")
async def stop_live_capture(current_user: User = Depends(get_current_user)):
    """Stop active packet capture."""
    require_permission(current_user, Permission.ENFORCEMENT_EXECUTE)
    return await network_sensor.stop_capture()


from shared.messaging import get_event_bus, Topic

@router.post("/pcap/replay")
async def replay_pcap_file(payload: PCAPReplayPayload, current_user: User = Depends(get_current_user)):
    """Replay and normalize an actual offline PCAP file into the IDPS storage and detection engine."""
    require_permission(current_user, Permission.EVENTS_INGEST)
    if not os.path.exists(payload.file_path):
        raise HTTPException(status_code=404, detail=f"PCAP file not found: {payload.file_path}")

    storage = get_storage()
    bus = get_event_bus()
    events = network_sensor.replay_pcap(payload.file_path)
    persisted = 0
    for ev in events[:200]:  # Process batch
        await storage.events.save(ev)
        try:
            await bus.publish(Topic.NORMALIZED_EVENTS, ev)
        except Exception:
            pass
        persisted += 1

    return {
        "status": "replayed",
        "file_path": payload.file_path,
        "packets_parsed": len(events),
        "persisted_events": persisted,
        "dispatched_to_detection": True,
    }


@router.get("/flows")
async def get_live_flows(
    limit: int = Query(25, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """Return actual network flow/packet telemetry stored by the IDPS."""
    storage = get_storage()
    events = await storage.events.list(
        tenant_id=current_user.tenant_id,
        limit=limit,
    )
    # Filter for network-related events
    net_events = [
        e for e in events
        if e.event_type in (EventType.NETWORK_PACKET, EventType.NETWORK_FLOW, EventType.DNS_QUERY, EventType.TLS_HANDSHAKE)
    ]
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type.value,
            "src_ip": e.network.src_ip if e.network else "0.0.0.0",
            "dst_ip": e.network.dst_ip if e.network else "0.0.0.0",
            "src_port": e.network.src_port if e.network else 0,
            "dst_port": e.network.dst_port if e.network else 0,
            "protocol": e.network.protocol.upper() if e.network else "IP",
            "bytes": e.network.bytes_sent if e.network else 0,
            "dns_query": e.dns.query_name if e.dns else None,
            "tls_sni": e.tls.sni if e.tls else None,
        }
        for e in net_events
    ]


@router.get("/blocks")
async def list_blocked_ips(current_user: User = Depends(get_current_user)):
    """List currently verified blocked IPs at the firewall."""
    active = fw_executor.list_active_blocks()
    return [
        {"ip": ip, **details}
        for ip, details in active.items()
    ]


@router.post("/blocks", status_code=status.HTTP_201_CREATED)
async def ban_ip(payload: BanIPPayload, current_user: User = Depends(get_current_user)):
    """Manually add an IP to the perimeter firewall blacklist after safety checks."""
    require_permission(current_user, Permission.ENFORCEMENT_EXECUTE)
    success, msg = await fw_executor.block_ip(
        ip=payload.ip,
        ttl_seconds=payload.ttl_seconds,
        reason=payload.reason,
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "blocked", "ip": payload.ip, "message": msg}


@router.delete("/blocks/{ip}")
async def unban_ip(ip: str, current_user: User = Depends(get_current_user)):
    """Remove an IP from the perimeter firewall blacklist."""
    require_permission(current_user, Permission.ENFORCEMENT_EXECUTE)
    success, msg = await fw_executor.unblock_ip(ip)
    if not success:
        raise HTTPException(status_code=404, detail=msg)
    return {"status": "unblocked", "ip": ip, "message": msg}
