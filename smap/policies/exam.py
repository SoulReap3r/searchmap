"""Operating-profile enforcement (exam vs lab).

The policy is declared in policy.yaml and loaded here. Enforcement is positive:
a capability runs only if the active profile lists it under ``allowed`` or
``flagged``; ``flagged`` additionally prints a caution. Nothing is assumed
exam-safe just because it is read-only.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

import yaml

_MANIFEST = Path(__file__).with_name("policy.yaml")


@dataclass
class Decision:
    capability: str
    allowed: bool
    flagged: bool
    reason: str


class Policy:
    def __init__(self, profile: str = "exam"):
        data = yaml.safe_load(_MANIFEST.read_text())
        self.basis = data.get("basis", "")
        self.capabilities = data.get("capabilities", {})
        profiles = data.get("profiles", {})
        if profile not in profiles:
            profile = "exam"
        self.profile = profile
        p = profiles[profile]
        self.description = p.get("description", "")
        self._allowed = set(p.get("allowed", []))
        self._flagged = set(p.get("flagged", []))
        self._denied = set(p.get("denied", []))

    def check(self, capability: str) -> Decision:
        if capability in self._flagged:
            return Decision(capability, True, True,
                            "permitted but intrusive — verify it is exam-legal for you")
        if capability in self._allowed:
            return Decision(capability, True, False, "allowed")
        if capability in self._denied:
            return Decision(capability, False, False,
                            f"blocked in '{self.profile}' profile — use --profile lab on authorized targets")
        return Decision(capability, False, False,
                        f"not listed for '{self.profile}' profile (treated as blocked)")

    def allows(self, capability: str) -> bool:
        return self.check(capability).allowed

    def enabled_summary(self) -> str:
        return ", ".join(sorted(self._allowed | self._flagged)) or "(none)"
