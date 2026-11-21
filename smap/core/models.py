"""Shared data model. Everything downstream (intelligence, correlation,
recommendations, reporting) speaks these dataclasses."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"      # exact version, or fully-bounded range includes it
    PROBABLE = "PROBABLE"        # single-bounded range, or bounded but loose parse
    POSSIBLE = "POSSIBLE"        # product matches but version unbounded/unknown
    UNKNOWN = "UNKNOWN"          # no version to reason about
    NOT_APPLICABLE = "NOT_APPLICABLE"  # version explicitly outside every range

    @property
    def rank(self) -> int:
        return {"CONFIRMED": 0, "PROBABLE": 1, "POSSIBLE": 2,
                "UNKNOWN": 3, "NOT_APPLICABLE": 4}[self.value]


@dataclass
class Reference:
    url: str
    tags: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def is_exploit(self) -> bool:
        return any("exploit" in t.lower() for t in self.tags)


@dataclass
class ExploitRef:
    """A concrete public exploit/PoC, traceable to a source."""
    title: str
    source: str                 # "Exploit-DB", "NVD-ref", "GitHub", "Metasploit"
    url: str = ""
    edb_id: str = ""
    path: str = ""              # local searchsploit path, if any
    cves: list[str] = field(default_factory=list)
    is_metasploit: bool = False
    verified: bool = False      # ExploitDB "verified" flag / KEV-backed


@dataclass
class CveFinding:
    cve_id: str
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: str = ""
    cvss_vector: str = ""
    cvss_version: str = ""
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev: bool = False
    kev_date: str = ""
    confidence: Confidence = Confidence.UNKNOWN
    evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    affected: list[str] = field(default_factory=list)   # human-readable ranges
    cwe: list[str] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    exploits: list[ExploitRef] = field(default_factory=list)
    published: str = ""
    source: str = "NVD"

    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"

    @property
    def actionability(self) -> float:
        """Evidence-based score (higher = act on it first). Uses exploit
        *existence* + KEV + severity + EPSS — never description keywords.

        Weighted for foothold-finding: a public exploit and raw impact (CVSS)
        dominate, so a 9.8 RCE with a PoC ranks above a 5.4 XSS with high EPSS.
        EPSS is a tie-breaker, not the driver."""
        s = 0.0
        if self.confidence == Confidence.CONFIRMED:
            s += 1.5
        if self.kev:
            s += 5.0
        if self.exploits:
            s += 4.0
        s += 0.6 * (self.cvss_score or 0.0)     # impact dominates (9.8 -> +5.9)
        s += 1.5 * (self.epss or 0.0)            # likelihood tie-breaker
        return s

    @property
    def priority(self) -> tuple:
        """Sort key (ascending = most important first). Tier keeps uncertain
        findings below likely ones; within a tier, rank by actionability."""
        tier = {"CONFIRMED": 0, "PROBABLE": 0, "POSSIBLE": 1,
                "UNKNOWN": 2, "NOT_APPLICABLE": 3}[self.confidence.value]
        return (tier, -self.actionability)


@dataclass
class Recommendation:
    title: str
    rationale: str = ""
    research: list[str] = field(default_factory=list)      # commands to investigate
    manual_test: list[str] = field(default_factory=list)   # operator-driven steps
    validation: str = ""                                    # how to confirm present
    prerequisites: str = ""
    exam_safe: bool = True


@dataclass
class EnumStep:
    """A protocol-specific investigation step."""
    what: str
    command: str
    why: str = ""
    look_for: str = ""
    needs_creds: bool = False
    exam_safe: bool = True


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    nmap_cpes: list[str] = field(default_factory=list)
    tunnel: str = ""
    host_ip: str = ""
    # enrichment
    fingerprints: list[dict] = field(default_factory=list)   # evidence from active probing
    resolved_cpe: str = ""
    cpe_source: str = ""
    findings: list[CveFinding] = field(default_factory=list)
    exploits: list[ExploitRef] = field(default_factory=list)
    enum_steps: list[EnumStep] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    default_creds: list[str] = field(default_factory=list)   # known defaults to try
    creds_tested: list[str] = field(default_factory=list)     # lab-only --creds-test hits
    notes: list[str] = field(default_factory=list)

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version) if x).strip()

    @property
    def confidence(self) -> str:
        """Confidence in the product+version identification itself.
        HIGH = we have product AND a version (from nmap or fingerprint)."""
        if not self.product:
            return "NONE"
        if self.version:
            return "HIGH"
        if self.fingerprints:
            return "MEDIUM"
        return "LOW"


@dataclass
class Host:
    ip: str
    hostname: str = ""
    os: str = ""
    services: list[Service] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    hosts: list[Host] = field(default_factory=list)
    profile: str = "exam"
    started: str = ""
    finished: str = ""
    sources_used: list[str] = field(default_factory=list)
    tool_version: str = ""

    @property
    def all_services(self) -> list[Service]:
        return [s for h in self.hosts for s in h.services]
