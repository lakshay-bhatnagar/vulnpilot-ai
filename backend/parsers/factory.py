"""Scanner parser selection for uploaded vulnerability artifacts."""

from collections.abc import Callable

from backend.models.schemas import VulnerabilityItem
from backend.parsers.burp_parser import parse_burp_xml
from backend.parsers.nessus_parser import parse_nessus_xml
from backend.parsers.nuclei_parser import parse_nuclei_json
from backend.parsers.pcap_parser import parse_pcap

Parser = Callable[[bytes], list[VulnerabilityItem]]

PCAP_EXTENSIONS = (".pcap", ".pcapng")
PCAP_MAGIC_NUMBERS = (
    b"\xd4\xc3\xb2\xa1",  # little-endian PCAP
    b"\xa1\xb2\xc3\xd4",  # big-endian PCAP
    b"\x4d\x3c\xb2\xa1",  # nanosecond PCAP
    b"\xa1\xb2\x3c\x4d",  # big-endian nanosecond PCAP
    b"\x0a\x0d\x0d\x0a",  # PCAPNG section header
)


def get_parser(filename: str, content: bytes) -> Parser:
    """Return the parser matching an upload's extension and recognizable format."""
    lower_name = filename.lower()
    sample = content[:4096].lstrip().lower()

    if lower_name.endswith(PCAP_EXTENSIONS) or content.startswith(PCAP_MAGIC_NUMBERS):
        return parse_pcap
    if lower_name.endswith(".json"):
        return parse_nuclei_json
    if lower_name.endswith(".nessus") or b"<nessusclientdata" in sample:
        return parse_nessus_xml
    if lower_name.endswith(".xml") and (b"<issues" in sample or b"<burpversion" in sample):
        return parse_burp_xml

    raise ValueError(
        "Unsupported scan artifact. Upload Burp XML, Nuclei JSON, Nessus .nessus/XML, "
        "or a PCAP/PCAPNG capture."
    )
