"""WraithOSINT Collectors Module"""

from specter.collectors.attack_surface import AttackSurfaceCollector
from specter.collectors.identity import (
    EmailInvestigator,
    HoleheHunter,
    IdentityCollector,
    MaigretHunter,
    UsernameInvestigator,
)

__all__ = [
    "AttackSurfaceCollector",
    "UsernameInvestigator",
    "EmailInvestigator",
    "MaigretHunter",
    "HoleheHunter",
    "IdentityCollector",
]
