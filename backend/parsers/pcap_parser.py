"""Passive security observation parser for PCAP and PCAPNG captures."""

from __future__ import annotations

import io
from collections.abc import Iterator

from backend.models.schemas import Severity, VulnerabilityItem

_PRIVATE_IP_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")
_WEAK_TLS_CIPHER_IDS = (b"\x00\x04", b"\x00\x05", b"\x00\x0a", b"\x00\x2f", b"\x00\x35")


def _packet_endpoints(packet) -> tuple[str, str]:
    if packet.haslayer("IP"):
        return packet["IP"].src, packet["IP"].dst
    if packet.haslayer("IPv6"):
        return packet["IPv6"].src, packet["IPv6"].dst
    return "unknown", "unknown"


def _raw_bytes(packet) -> bytes:
    raw = packet.getlayer("Raw")
    return bytes(raw.load) if raw is not None else b""


def _item(title: str, severity: Severity, endpoint: str, evidence: str, cwe: str) -> VulnerabilityItem:
    return VulnerabilityItem(
        title=title,
        tool_source="Wireshark PCAP",
        severity=severity,
        target_url=endpoint,
        cwe=cwe,
        raw_evidence=evidence[:4000],
    )


def _observations(packets: Iterator) -> list[VulnerabilityItem]:
    findings: dict[tuple[str, str], VulnerabilityItem] = {}
    internal_ips: set[str] = set()

    def add(title: str, severity: Severity, endpoint: str, evidence: str, cwe: str) -> None:
        findings.setdefault((title, endpoint), _item(title, severity, endpoint, evidence, cwe))

    for packet in packets:
        source, destination = _packet_endpoints(packet)
        endpoint = f"{source} -> {destination}"
        for address in (source, destination):
            if address.startswith(_PRIVATE_IP_PREFIXES):
                internal_ips.add(address)

        raw = _raw_bytes(packet)
        text = raw.decode("latin-1", errors="ignore")
        lower = text.lower()
        tcp = packet.getlayer("TCP")
        ports = {int(tcp.sport), int(tcp.dport)} if tcp is not None else set()

        if b"authorization: basic " in raw.lower():
            add("HTTP Basic Authentication Sent in Cleartext", Severity.HIGH, endpoint, text, "CWE-522")
        if any(header in lower for header in ("authorization: bearer ", "x-api-key:", "api_key=", "access_token=")):
            add("Unencrypted API Token Observed", Severity.HIGH, endpoint, text, "CWE-319")
        if "set-cookie:" in lower and ("secure" not in lower or "httponly" not in lower):
            add("Cookie Missing Secure or HttpOnly Attribute", Severity.MEDIUM, endpoint, text, "CWE-1004")
        if any(header in lower for header in ("server:", "x-powered-by:", "x-aspnet-version:")):
            add("Sensitive HTTP Response Header Disclosure", Severity.LOW, endpoint, text, "CWE-200")
        if 21 in ports:
            add("FTP Traffic Observed", Severity.MEDIUM, endpoint, "FTP uses cleartext authentication and data channels.", "CWE-319")
        if 23 in ports:
            add("Telnet Traffic Observed", Severity.HIGH, endpoint, "Telnet exposes credentials and session traffic in cleartext.", "CWE-319")
        if b"\xffSMB" in raw:
            add("SMBv1 Traffic Observed", Severity.HIGH, endpoint, "SMBv1 protocol signature observed in packet capture.", "CWE-757")
        if b"NTLMSSP\x00" in raw:
            add("NTLM Authentication Observed", Severity.MEDIUM, endpoint, "NTLM authentication challenge/response observed.", "CWE-287")
        if b"\x16\x03\x01" in raw or b"\x16\x03\x02" in raw:
            add("Deprecated TLS 1.0/1.1 Observed", Severity.MEDIUM, endpoint, "TLS record version indicates TLS 1.0 or 1.1.", "CWE-326")
        if b"\x16\x03" in raw and any(cipher in raw for cipher in _WEAK_TLS_CIPHER_IDS):
            add("Potential Weak TLS Cipher Suite Offered", Severity.MEDIUM, endpoint, "Weak TLS cipher-suite identifier observed in handshake data.", "CWE-327")

        dns_query = packet.getlayer("DNSQR")
        if dns_query is not None:
            query = bytes(dns_query.qname).decode("utf-8", errors="replace").rstrip(".")
            add("DNS Query Information Leakage", Severity.LOW, endpoint, f"Cleartext DNS query observed: {query}", "CWE-200")

    if internal_ips:
        add(
            "Internal IP Address Discovery",
            Severity.LOW,
            "network-capture",
            f"Private addresses observed: {', '.join(sorted(internal_ips))}",
            "CWE-200",
        )
    return list(findings.values())


def parse_pcap(content: bytes) -> list[VulnerabilityItem]:
    """Parse PCAP or PCAPNG bytes using Scapy without requiring Wireshark/tshark."""
    try:
        from scapy.utils import PcapReader
    except ImportError as exc:  # pragma: no cover - installation error is environment-specific
        raise RuntimeError("PCAP support requires scapy. Install backend requirements.") from exc

    reader = PcapReader(io.BytesIO(content))
    try:
        return _observations(iter(reader))
    finally:
        reader.close()
