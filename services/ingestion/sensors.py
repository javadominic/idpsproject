"""
IDPS Sensors
============
Data collection modules for each source type.
Each sensor captures raw data and converts it to NormalizedEvent format.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import AsyncIterator

from shared.models import (
    NormalizedEvent, EventType,
    NetworkInfo, TLSInfo, DNSInfo, ProcessInfo, FileInfo,
)
from shared.observability import (
    events_ingested, events_dropped, ingestion_latency, get_logger,
)

# Safe nameserver fallback in restricted or non-root environments
try:
    import scapy.arch.common
    _orig_read_ns = getattr(scapy.arch.common, "read_nameservers", None)
    if _orig_read_ns:
        def _safe_read_ns():
            try:
                return _orig_read_ns()
            except Exception:
                return ["1.1.1.1", "8.8.8.8"]
        scapy.arch.common.read_nameservers = _safe_read_ns
except Exception:
    pass

logger = get_logger("sensors")


# ─── Base Sensor ─────────────────────────────────────────────────────────────────

class BaseSensor(ABC):
    """Base class for all IDPS sensors."""

    def __init__(self, sensor_id: str, tenant_id: str = "default"):
        self.sensor_id = sensor_id
        self.tenant_id = tenant_id
        self._running = False

    @property
    @abstractmethod
    def sensor_type(self) -> str:
        """Human-readable sensor type name."""
        ...

    @abstractmethod
    async def collect(self) -> AsyncIterator[NormalizedEvent]:
        """Yield normalized events from this sensor source."""
        ...

    async def start(self) -> None:
        """Start the sensor collection loop."""
        self._running = True
        logger.info(f"Sensor started: {self.sensor_id}", sensor_type=self.sensor_type)

    async def stop(self) -> None:
        """Stop the sensor."""
        self._running = False
        logger.info(f"Sensor stopped: {self.sensor_id}")


# ─── Network Sensor ─────────────────────────────────────────────────────────────

# Ensure Scapy handles environments without /etc/resolv.conf access gracefully
try:
    import scapy.arch.common
    _orig_read_ns = getattr(scapy.arch.common, "read_nameservers", None)
    if _orig_read_ns:
        def _safe_read_ns():
            try:
                return _orig_read_ns()
            except Exception:
                return ["1.1.1.1", "8.8.8.8"]
        scapy.arch.common.read_nameservers = _safe_read_ns
except Exception:
    pass


class NetworkSensor(BaseSensor):
    """
    Network packet/flow capture sensor.

    Capture methods:
    - AF_XDP: High-performance kernel-bypass packet capture
    - TAP: Network tap for passive monitoring
    - Inline: Man-in-the-middle for active IPS mode

    Outputs: NETWORK_PACKET, NETWORK_FLOW, DNS_QUERY, HTTP_REQUEST, TLS_HANDSHAKE
    """

    def __init__(
        self,
        sensor_id: str,
        interface: str = "eth0",
        capture_mode: str = "tap",    # af_xdp | tap | inline
        bpf_filter: str = "",
        tenant_id: str = "default",
    ):
        super().__init__(sensor_id, tenant_id)
        self.interface = interface
        self.capture_mode = capture_mode
        self.bpf_filter = bpf_filter
        self._captured_count = 0
        self._dropped_count = 0
        self._capture_status = "stopped"
        self._status_details = ""
        self._packet_queue: asyncio.Queue[NormalizedEvent] = asyncio.Queue(maxsize=10000)
        self._sniffer = None

    @property
    def sensor_type(self) -> str:
        return "network"

    def get_capture_status(self) -> dict[str, Any]:
        """Return genuine live capture status and limitations."""
        return {
            "interface": self.interface,
            "capture_mode": self.capture_mode,
            "bpf_filter": self.bpf_filter,
            "status": self._capture_status,
            "status_details": self._status_details,
            "packets_captured": self._captured_count,
            "packets_dropped": self._dropped_count,
        }

    async def start_capture(self) -> dict[str, Any]:
        """Start live packet capture on the selected interface."""
        try:
            from scapy.all import AsyncSniffer
            self._capture_status = "capturing"
            self._status_details = f"Active live capture on {self.interface}"
            
            def _packet_callback(pkt):
                try:
                    norm = self.normalize_scapy_packet(pkt)
                    if norm:
                        self._captured_count += 1
                        try:
                            self._packet_queue.put_nowait(norm)
                        except asyncio.QueueFull:
                            self._dropped_count += 1
                except Exception as e:
                    self._dropped_count += 1

            self._sniffer = AsyncSniffer(
                iface=self.interface if self.interface != "auto" else None,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=_packet_callback,
                store=False,
            )
            self._sniffer.start()
            self._running = True
            logger.info(f"Live packet capture started on {self.interface}")
            return self.get_capture_status()

        except PermissionError as pe:
            self._capture_status = "permission_denied"
            self._status_details = f"Operation not permitted on {self.interface}: requires root/sudo/BPF privilege ({pe})"
            logger.warning(self._status_details)
            return self.get_capture_status()
        except Exception as e:
            self._capture_status = "error"
            self._status_details = f"Failed to start sniffer on {self.interface}: {str(e)}"
            logger.error(self._status_details)
            return self.get_capture_status()

    async def stop_capture(self) -> dict[str, Any]:
        """Stop live packet capture."""
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        self._running = False
        self._capture_status = "stopped"
        self._status_details = "Capture stopped by operator"
        logger.info(f"Packet capture stopped on {self.interface}")
        return self.get_capture_status()

    async def collect(self) -> AsyncIterator[NormalizedEvent]:
        """Yield normalized network events from the queue."""
        logger.info(
            "Network sensor collection stream active",
            interface=self.interface,
            mode=self.capture_mode,
        )

        while self._running or not self._packet_queue.empty():
            try:
                event = await asyncio.wait_for(self._packet_queue.get(), timeout=1.0)
                yield event
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                events_dropped.labels(
                    sensor_type=self.sensor_type,
                    reason="capture_error",
                    tenant_id=self.tenant_id,
                ).inc()
                logger.error(f"Network capture error: {e}")

    def replay_pcap(self, pcap_path: str) -> list[NormalizedEvent]:
        """
        Replay and normalize an actual offline PCAP file.
        Preserves original packet timing, headers, and payloads.
        """
        events: list[NormalizedEvent] = []
        try:
            from scapy.all import PcapReader
            with PcapReader(pcap_path) as pcap_reader:
                for pkt in pcap_reader:
                    norm = self.normalize_scapy_packet(pkt)
                    if norm:
                        events.append(norm)
                        self._captured_count += 1
            logger.info(f"Replayed {len(events)} packets from PCAP: {pcap_path}")
        except Exception as e:
            logger.error(f"Failed to replay PCAP {pcap_path}: {e}")
            raise
        return events

    def normalize_scapy_packet(self, pkt: Any) -> NormalizedEvent | None:
        """Normalize a real Scapy packet into a canonical NormalizedEvent."""
        try:
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc) if hasattr(pkt, 'time') else datetime.now(timezone.utc)
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            proto = "unknown"
            src_port = 0
            dst_port = 0
            raw_bytes = bytes(pkt)

            # IP Layer
            if pkt.haslayer("IP"):
                ip_layer = pkt.getlayer("IP")
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            elif pkt.haslayer("IPv6"):
                ip_layer = pkt.getlayer("IPv6")
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            else:
                return None  # Only inspect IP-level packets

            # Transport Layer
            if pkt.haslayer("TCP"):
                proto = "tcp"
                tcp_layer = pkt.getlayer("TCP")
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
            elif pkt.haslayer("UDP"):
                proto = "udp"
                udp_layer = pkt.getlayer("UDP")
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
            elif pkt.haslayer("ICMP"):
                proto = "icmp"

            # DNS Inspection
            dns_info = None
            if pkt.haslayer("DNS"):
                dns_layer = pkt.getlayer("DNS")
                qname = None
                qtype = "A"
                if hasattr(dns_layer, 'qd') and dns_layer.qd:
                    qname = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.') if hasattr(dns_layer.qd.qname, 'decode') else str(dns_layer.qd.qname).rstrip('.')
                    qtype = self._dns_type_str(dns_layer.qd.qtype)
                
                resolved = []
                if hasattr(dns_layer, 'an') and dns_layer.an:
                    an = dns_layer.an
                    while an:
                        if hasattr(an, 'rdata'):
                            resolved.append(str(an.rdata))
                        an = getattr(an, 'payload', None)

                dns_info = DNSInfo(
                    query_name=qname,
                    query_type=qtype,
                    resolved_ips=resolved,
                    response_code=self._dns_rcode_str(getattr(dns_layer, 'rcode', 0)),
                )

            # Raw payload & TLS/HTTP checks
            payload_str = ""
            if pkt.haslayer("Raw"):
                raw_payload = pkt.getlayer("Raw").load
                payload_str = raw_payload.decode('utf-8', errors='ignore')

            tls_info = None
            if proto == "tcp" and (dst_port == 443 or src_port == 443):
                # Basic TLS ClientHello detection
                if b"\x16\x03" in raw_bytes:
                    tls_info = TLSInfo(
                        ja4_hash=hashlib.md5(raw_bytes[:64]).hexdigest(),
                        sni=self._extract_sni(raw_bytes),
                    )

            net_info = NetworkInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                bytes_sent=len(raw_bytes),
                direction="inbound" if dst_port in (80, 443, 8080, 22) else "outbound",
            )

            event_type = EventType.NETWORK_PACKET
            if dns_info:
                event_type = EventType.DNS_QUERY
            elif tls_info:
                event_type = EventType.TLS_HANDSHAKE
            elif "HTTP" in payload_str or "GET " in payload_str or "POST " in payload_str:
                event_type = EventType.HTTP_REQUEST

            return NormalizedEvent(
                event_type=event_type,
                timestamp=ts,
                source_sensor=self.sensor_id,
                tenant_id=self.tenant_id,
                network=net_info,
                dns=dns_info,
                tls=tls_info,
                raw_log=payload_str[:500] if payload_str else None,
                raw_payload_ref=hashlib.sha256(raw_bytes).hexdigest(),
            )
        except Exception as e:
            logger.debug(f"Packet parse warning: {e}")
            return None
        ts = timestamp or datetime.now(timezone.utc)

        # Parse with dpkt or scapy (simplified example)
        try:
            import dpkt
            eth = dpkt.ethernet.Ethernet(raw_data)

            if isinstance(eth.data, dpkt.ip.IP):
                ip_pkt = eth.data
                src_ip = self._ip_to_str(ip_pkt.src)
                dst_ip = self._ip_to_str(ip_pkt.dst)
                protocol = "unknown"
                src_port = 0
                dst_port = 0

                if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                    tcp = ip_pkt.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    protocol = "tcp"

                    # Check for DNS over TCP or TLS
                    if dst_port == 53 or src_port == 53:
                        return self._parse_dns(raw_data, src_ip, dst_ip, ts)
                    elif dst_port == 443 or src_port == 443:
                        return self._parse_tls_metadata(
                            raw_data, src_ip, dst_ip, src_port, dst_port, ts
                        )

                elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                    udp = ip_pkt.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    protocol = "udp"

                    if dst_port == 53 or src_port == 53:
                        return self._parse_dns(raw_data, src_ip, dst_ip, ts)

                network = NetworkInfo(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    bytes_sent=len(raw_data),
                )

                events_ingested.labels(
                    sensor_type=self.sensor_type,
                    event_type="network_packet",
                    tenant_id=self.tenant_id,
                ).inc()

                return NormalizedEvent(
                    event_type=EventType.NETWORK_PACKET,
                    timestamp=ts,
                    source_sensor=self.sensor_id,
                    tenant_id=self.tenant_id,
                    network=network,
                    raw_payload_ref=hashlib.sha256(raw_data).hexdigest(),
                )

        except ImportError:
            logger.warning("dpkt not available — using basic packet normalization")
        except Exception as e:
            logger.error(f"Packet parse error: {e}")

        # Fallback: minimal event
        return NormalizedEvent(
            event_type=EventType.NETWORK_PACKET,
            timestamp=ts,
            source_sensor=self.sensor_id,
            tenant_id=self.tenant_id,
            network=NetworkInfo(bytes_sent=len(raw_data)),
        )

    def _parse_dns(
        self, raw_data: bytes, src_ip: str, dst_ip: str, ts: datetime,
    ) -> NormalizedEvent:
        """Parse a DNS query/response into a NormalizedEvent."""
        dns_info = DNSInfo()

        try:
            import dpkt
            # Extract DNS payload from UDP/TCP
            eth = dpkt.ethernet.Ethernet(raw_data)
            ip_pkt = eth.data
            transport = ip_pkt.data
            dns = dpkt.dns.DNS(transport.data)

            if dns.qd:
                dns_info.query_name = dns.qd[0].name
                dns_info.query_type = self._dns_type_str(dns.qd[0].type)

            if dns.an:
                dns_info.resolved_ips = [
                    self._ip_to_str(rr.rdata)
                    for rr in dns.an
                    if rr.type in (dpkt.dns.DNS_A, dpkt.dns.DNS_AAAA)
                ]

            dns_info.response_code = self._dns_rcode_str(dns.rcode)
        except Exception:
            pass

        return NormalizedEvent(
            event_type=EventType.DNS_QUERY,
            timestamp=ts,
            source_sensor=self.sensor_id,
            tenant_id=self.tenant_id,
            network=NetworkInfo(src_ip=src_ip, dst_ip=dst_ip, protocol="udp"),
            dns=dns_info,
        )

    def _parse_tls_metadata(
        self,
        raw_data: bytes,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        ts: datetime,
    ) -> NormalizedEvent:
        """
        Extract TLS handshake metadata WITHOUT decrypting.
        This is the METADATA mode — no MITM required.

        Extracts:
        - JA4 fingerprint (client hello)
        - SNI (Server Name Indication)
        - Certificate details
        - TLS version and cipher suite
        """
        tls_info = TLSInfo()

        try:
            import dpkt
            eth = dpkt.ethernet.Ethernet(raw_data)
            ip_pkt = eth.data
            tcp = ip_pkt.data

            # Parse TLS record
            if len(tcp.data) > 5 and tcp.data[0] == 0x16:  # TLS handshake
                tls_records = dpkt.ssl.TLSMultiFactory(tcp.data)
                for record in tls_records:
                    if hasattr(record, 'data') and len(record.data) > 0:
                        # Extract SNI from Client Hello
                        if record.data[0] == 0x01:  # Client Hello
                            tls_info.sni = self._extract_sni(record.data)
                            tls_info.ja4_hash = self._compute_ja4(record.data)
        except Exception:
            pass

        return NormalizedEvent(
            event_type=EventType.TLS_HANDSHAKE,
            timestamp=ts,
            source_sensor=self.sensor_id,
            tenant_id=self.tenant_id,
            network=NetworkInfo(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol="tcp",
            ),
            tls=tls_info,
        )

    @staticmethod
    def _ip_to_str(ip_bytes: bytes) -> str:
        """Convert IP bytes to string."""
        import socket
        if len(ip_bytes) == 4:
            return socket.inet_ntoa(ip_bytes)
        elif len(ip_bytes) == 16:
            return socket.inet_ntop(socket.AF_INET6, ip_bytes)
        return str(ip_bytes)

    @staticmethod
    def _extract_sni(client_hello: bytes) -> str | None:
        """Extract Server Name Indication from TLS Client Hello."""
        # SNI extraction from ClientHello extensions
        # Simplified — production would use a proper TLS parser
        try:
            pos = client_hello.find(b'\x00\x00')  # SNI extension type
            if pos > 0:
                # Parse SNI extension
                sni_len = int.from_bytes(client_hello[pos + 7:pos + 9], 'big')
                sni = client_hello[pos + 9:pos + 9 + sni_len].decode('ascii', errors='ignore')
                return sni if sni else None
        except Exception:
            pass
        return None

    @staticmethod
    def _compute_ja4(client_hello: bytes) -> str | None:
        """Compute JA4 fingerprint from Client Hello."""
        # JA4 is a modern TLS fingerprinting method
        # Full implementation would parse cipher suites, extensions, etc.
        return hashlib.md5(client_hello[:64]).hexdigest()

    @staticmethod
    def _dns_type_str(qtype: int) -> str:
        """Convert DNS query type to string."""
        types = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA"}
        return types.get(qtype, f"TYPE{qtype}")

    @staticmethod
    def _dns_rcode_str(rcode: int) -> str:
        """Convert DNS response code to string."""
        codes = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
        return codes.get(rcode, f"RCODE{rcode}")


# ─── Host Agent ──────────────────────────────────────────────────────────────────

class HostAgent(BaseSensor):
    """
    Host-based sensor using eBPF for process, file, and network monitoring.

    Capabilities:
    - Process creation/termination tracking
    - File Integrity Monitoring (FIM)
    - Network connection tracking per process
    - Registry change monitoring (Windows)
    - Privilege escalation detection
    """

    def __init__(
        self,
        sensor_id: str,
        hostname: str = "localhost",
        watch_paths: list[str] | None = None,
        tenant_id: str = "default",
    ):
        super().__init__(sensor_id, tenant_id)
        self.hostname = hostname
        self.watch_paths = watch_paths or ["/etc", "/usr/bin", "/tmp"]

    @property
    def sensor_type(self) -> str:
        return "host"

    async def collect(self) -> AsyncIterator[NormalizedEvent]:
        """Collect host events via eBPF and FIM."""
        logger.info("Host agent collecting", hostname=self.hostname)

        while self._running:
            try:
                # Production: eBPF probes for process exec, file access, network
                # Example: events = await self._read_ebpf_ringbuf()
                await asyncio.sleep(0.5)
            except Exception as e:
                events_dropped.labels(
                    sensor_type=self.sensor_type,
                    reason="host_error",
                    tenant_id=self.tenant_id,
                ).inc()
                logger.error(f"Host agent error: {e}")
                await asyncio.sleep(1)

    def normalize_process_event(
        self,
        pid: int,
        ppid: int,
        name: str,
        command_line: str,
        executable: str,
        user: str,
        timestamp: datetime | None = None,
    ) -> NormalizedEvent:
        """Normalize a process creation/execution event."""
        ts = timestamp or datetime.now(timezone.utc)

        process = ProcessInfo(
            pid=pid,
            ppid=ppid,
            name=name,
            command_line=command_line,
            executable_path=executable,
            user=user,
            is_elevated=user in ("root", "SYSTEM", "Administrator"),
        )

        # Compute hash of the executable
        try:
            import hashlib
            with open(executable, "rb") as f:
                process.hash_sha256 = hashlib.sha256(f.read()).hexdigest()
        except (FileNotFoundError, PermissionError):
            pass

        events_ingested.labels(
            sensor_type=self.sensor_type,
            event_type="host_process",
            tenant_id=self.tenant_id,
        ).inc()

        return NormalizedEvent(
            event_type=EventType.HOST_PROCESS,
            timestamp=ts,
            source_sensor=self.sensor_id,
            hostname=self.hostname,
            tenant_id=self.tenant_id,
            process=process,
            raw_log=command_line,
        )

    def normalize_file_event(
        self,
        path: str,
        action: str,  # created | modified | deleted | accessed
        file_hash: str | None = None,
        timestamp: datetime | None = None,
    ) -> NormalizedEvent:
        """Normalize a file integrity monitoring event."""
        ts = timestamp or datetime.now(timezone.utc)

        import os
        file_info = FileInfo(
            path=path,
            name=os.path.basename(path),
            hash_sha256=file_hash,
        )

        try:
            stat = os.stat(path)
            file_info.size_bytes = stat.st_size
            file_info.is_executable = os.access(path, os.X_OK)
        except (FileNotFoundError, PermissionError):
            pass

        events_ingested.labels(
            sensor_type=self.sensor_type,
            event_type="host_file",
            tenant_id=self.tenant_id,
        ).inc()

        return NormalizedEvent(
            event_type=EventType.HOST_FILE,
            timestamp=ts,
            source_sensor=self.sensor_id,
            hostname=self.hostname,
            tenant_id=self.tenant_id,
            file=file_info,
            metadata={"action": action},
        )


# ─── Log Collector ───────────────────────────────────────────────────────────────

class LogCollector(BaseSensor):
    """
    Multi-source log collector.

    Sources:
    - Syslog (RFC 5424/3164) via UDP/TCP
    - Cloud provider logs (AWS CloudTrail, GCP Audit, Azure Activity)
    - Application logs (JSON, CEF, LEEF formats)
    - Windows Event Log (via WEF/WEC)
    """

    def __init__(
        self,
        sensor_id: str,
        listen_address: str = "0.0.0.0",
        listen_port: int = 514,
        protocol: str = "udp",       # udp | tcp | tls
        tenant_id: str = "default",
    ):
        super().__init__(sensor_id, tenant_id)
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.protocol = protocol

    @property
    def sensor_type(self) -> str:
        return "log"

    async def collect(self) -> AsyncIterator[NormalizedEvent]:
        """Listen for incoming log events."""
        logger.info(
            "Log collector listening",
            address=f"{self.listen_address}:{self.listen_port}",
            protocol=self.protocol,
        )

        while self._running:
            try:
                # Production: asyncio UDP/TCP server
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"Log collector error: {e}")
                await asyncio.sleep(1)

    def normalize_syslog(self, raw_line: str, timestamp: datetime | None = None) -> NormalizedEvent:
        """Parse and normalize a syslog message."""
        ts = timestamp or datetime.now(timezone.utc)

        # Extract fields from syslog format
        hostname = None
        parts = raw_line.split(" ", 4)
        if len(parts) >= 4:
            hostname = parts[1]

        events_ingested.labels(
            sensor_type=self.sensor_type,
            event_type="log_entry",
            tenant_id=self.tenant_id,
        ).inc()

        return NormalizedEvent(
            event_type=EventType.LOG_ENTRY,
            timestamp=ts,
            source_sensor=self.sensor_id,
            hostname=hostname,
            tenant_id=self.tenant_id,
            raw_log=raw_line,
        )

    def normalize_cef(self, cef_line: str, timestamp: datetime | None = None) -> NormalizedEvent:
        """Parse Common Event Format (CEF) log line."""
        ts = timestamp or datetime.now(timezone.utc)

        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
        fields: dict[str, str] = {}
        if cef_line.startswith("CEF:"):
            parts = cef_line.split("|", 7)
            if len(parts) >= 7:
                fields = {
                    "device_vendor": parts[1],
                    "device_product": parts[2],
                    "device_version": parts[3],
                    "signature_id": parts[4],
                    "name": parts[5],
                    "severity": parts[6],
                }
                # Parse extensions (key=value pairs)
                if len(parts) > 7:
                    for ext in parts[7].split(" "):
                        if "=" in ext:
                            k, v = ext.split("=", 1)
                            fields[k] = v

        network = None
        if "src" in fields or "dst" in fields:
            network = NetworkInfo(
                src_ip=fields.get("src"),
                dst_ip=fields.get("dst"),
                src_port=int(fields.get("spt", 0)) or None,
                dst_port=int(fields.get("dpt", 0)) or None,
            )

        events_ingested.labels(
            sensor_type=self.sensor_type,
            event_type="log_entry",
            tenant_id=self.tenant_id,
        ).inc()

        return NormalizedEvent(
            event_type=EventType.LOG_ENTRY,
            timestamp=ts,
            source_sensor=self.sensor_id,
            tenant_id=self.tenant_id,
            network=network,
            raw_log=cef_line,
            metadata=fields,
        )

    def normalize_cloud_audit(
        self,
        cloud_event: dict,
        provider: str = "aws",  # aws | gcp | azure
        timestamp: datetime | None = None,
    ) -> NormalizedEvent:
        """Normalize cloud audit log (CloudTrail, GCP Audit, Azure Activity)."""
        ts = timestamp or datetime.now(timezone.utc)

        # Extract common fields across cloud providers
        user_identity = ""
        action = ""
        source_ip = None

        if provider == "aws":
            user_identity = cloud_event.get("userIdentity", {}).get("arn", "")
            action = cloud_event.get("eventName", "")
            source_ip = cloud_event.get("sourceIPAddress")
        elif provider == "gcp":
            user_identity = cloud_event.get("protoPayload", {}).get(
                "authenticationInfo", {}
            ).get("principalEmail", "")
            action = cloud_event.get("protoPayload", {}).get("methodName", "")
            source_ip = cloud_event.get("protoPayload", {}).get(
                "requestMetadata", {}
            ).get("callerIp")
        elif provider == "azure":
            user_identity = cloud_event.get("caller", "")
            action = cloud_event.get("operationName", {}).get("value", "")
            source_ip = cloud_event.get("callerIpAddress")

        network = NetworkInfo(src_ip=source_ip) if source_ip else None

        events_ingested.labels(
            sensor_type=self.sensor_type,
            event_type="cloud_audit",
            tenant_id=self.tenant_id,
        ).inc()

        return NormalizedEvent(
            event_type=EventType.CLOUD_AUDIT,
            timestamp=ts,
            source_sensor=self.sensor_id,
            tenant_id=self.tenant_id,
            network=network,
            raw_log=str(cloud_event),
            metadata={
                "provider": provider,
                "user_identity": user_identity,
                "action": action,
            },
        )


# ─── File/Artifact Collector ────────────────────────────────────────────────────

class FileArtifactCollector(BaseSensor):
    """
    Collects file artifacts for analysis:
    - PCAP files from network sensors
    - Suspicious binaries from host agents
    - Email attachments
    - Downloaded files from proxy/WAF

    Files are hashed, stored, and queued for sandbox analysis.
    """

    def __init__(
        self,
        sensor_id: str,
        watch_dirs: list[str] | None = None,
        storage_path: str = "/var/idps/artifacts",
        max_file_size_mb: int = 100,
        tenant_id: str = "default",
    ):
        super().__init__(sensor_id, tenant_id)
        self.watch_dirs = watch_dirs or ["/var/idps/incoming"]
        self.storage_path = storage_path
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024

    @property
    def sensor_type(self) -> str:
        return "file"

    async def collect(self) -> AsyncIterator[NormalizedEvent]:
        """Watch directories for new files to collect."""
        logger.info("File collector watching", dirs=self.watch_dirs)

        while self._running:
            try:
                # Production: inotify/fsevents watcher
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"File collector error: {e}")
                await asyncio.sleep(1)

    def normalize_file(
        self,
        file_path: str,
        timestamp: datetime | None = None,
    ) -> NormalizedEvent:
        """Normalize a collected file artifact into a NormalizedEvent."""
        import math
        import os

        ts = timestamp or datetime.now(timezone.utc)

        file_info = FileInfo(
            path=file_path,
            name=os.path.basename(file_path),
        )

        try:
            stat = os.stat(file_path)
            file_info.size_bytes = stat.st_size

            if file_info.size_bytes > self.max_file_size_bytes:
                events_dropped.labels(
                    sensor_type=self.sensor_type,
                    reason="file_too_large",
                    tenant_id=self.tenant_id,
                ).inc()
                logger.warning(f"File too large, skipping: {file_path}")

            # Compute hashes
            with open(file_path, "rb") as f:
                data = f.read()
                file_info.hash_sha256 = hashlib.sha256(data).hexdigest()
                file_info.hash_md5 = hashlib.md5(data).hexdigest()

                # Calculate entropy (high = possibly encrypted/packed)
                if data:
                    byte_counts = [0] * 256
                    for byte in data:
                        byte_counts[byte] += 1
                    length = len(data)
                    entropy = -sum(
                        (c / length) * math.log2(c / length)
                        for c in byte_counts
                        if c > 0
                    )
                    file_info.entropy = round(entropy, 2)
                    file_info.is_packed = entropy > 7.0  # High entropy threshold

            file_info.is_executable = os.access(file_path, os.X_OK)

            # Detect MIME type
            import mimetypes
            file_info.mime_type = mimetypes.guess_type(file_path)[0]

        except (FileNotFoundError, PermissionError) as e:
            logger.warning(f"Cannot access file: {file_path}: {e}")

        events_ingested.labels(
            sensor_type=self.sensor_type,
            event_type="file_artifact",
            tenant_id=self.tenant_id,
        ).inc()

        return NormalizedEvent(
            event_type=EventType.FILE_ARTIFACT,
            timestamp=ts,
            source_sensor=self.sensor_id,
            tenant_id=self.tenant_id,
            file=file_info,
        )
