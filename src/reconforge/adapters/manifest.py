"""Built-in adapter manifest.

This is metadata only; executable adapters are added behind the common adapter
contract so the intelligence core never depends on a particular toolchain.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AdapterSpec:
    name: str
    purpose: str
    passive: bool
    active: bool
    requires_external_binary: bool


BUILTIN_ADAPTERS = (
    AdapterSpec("subfinder", "passive subdomain discovery", True, False, True),
    AdapterSpec("amass", "asset and DNS relationship discovery", True, True, True),
    AdapterSpec("crtsh", "certificate transparency hostname discovery", True, False, False),
    AdapterSpec("dnsx", "DNS resolution and record validation", True, True, True),
    AdapterSpec("puredns", "controlled DNS resolution", False, True, True),
    AdapterSpec("httpx", "HTTP probing and fingerprinting", False, True, True),
    AdapterSpec("katana", "web crawling and endpoint discovery", False, True, True),
    AdapterSpec("gau", "historical URL discovery", True, False, True),
    AdapterSpec("waybackurls", "archive URL discovery", True, False, True),
    AdapterSpec("subjs", "JavaScript asset discovery", False, True, True),
    AdapterSpec("naabu", "controlled port discovery", False, True, True),
    AdapterSpec("nmap", "targeted service/version enrichment", False, True, True),
    AdapterSpec("nuclei", "template-based security observations", False, True, True),
)
