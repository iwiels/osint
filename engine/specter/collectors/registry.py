"""
WraithOSINT - Collector Registry
Catálogo de colectores: los built-ins del kernel + plugins de terceros.

Un plugin se declara en el `pyproject.toml` de su paquete:

    [project.entry-points."specter.collectors"]
    mi_fuente = "mi_paquete.colectores:MiColector"

El kernel descubre esos entry-points al arrancar y los expone con las tools
genéricas `list_collectors` / `run_collector`, sin tocar el código del kernel:
ingesta en el grafo y sello en la cadena de custodia son responsabilidad del
kernel, no del plugin.

Un plugin roto **no** impide arrancar: el error se registra en `errors` y el
resto del catálogo sigue operativo.
"""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass, field
from typing import Any

from specter.collectors.base import BaseCollector
from specter.collectors.blockchain import (
    BitcoinAbuseCollector,
    BitcoinWhoIsWhoCollector,
    BlockchainInfoCollector,
    EtherscanCollector,
)
from specter.collectors.breach_data import (
    HaveIBeenPwnedCollector,
    IntelligenceXCollector,
    LeakIXCollector,
    LeakLookupCollector,
)
from specter.collectors.cloud_buckets import (
    AzureBlobFinderCollector,
    DigitalOceanSpaceFinderCollector,
    GoogleCloudStorageFinderCollector,
    GrayhatWarfareCollector,
    S3BucketFinderCollector,
)
from specter.collectors.company_data import (
    ClearbitCollector,
    FullContactCollector,
    GLEIFCollector,
    OpenCorporatesCollector,
)
from specter.collectors.darkweb import (
    AhmiaCollector,
    OnionLinkCollector,
    TorCHCollector,
)
from specter.collectors.dns_bruteforce import DNSBruteForceCollector
from specter.collectors.dns_zonexfer import DNSZoneTransferCollector
from specter.collectors.external_tools import (
    CMSeeKDetectorCollector,
    NmapScannerCollector,
    NucleiScannerCollector,
    RetireJSScannerCollector,
    SnallygasterScannerCollector,
    TestSSLScannerCollector,
    TruffleHogScannerCollector,
    WAFW00FDetectorCollector,
    WhatWebScannerCollector,
)
from specter.collectors.extractors import (
    CreditCardExtractorCollector,
    EmailExtractorCollector,
    HashExtractorCollector,
    IBANExtractorCollector,
    NameExtractorCollector,
    PhoneExtractorCollector,
)
from specter.collectors.passive_dns import (
    CIRCLPassiveDNSCollector,
    DNSDBChecker,
    DNSGrepCollector,
    MnemonicPassiveDNSCollector,
)
from specter.collectors.portscan import PortScanCollector
from specter.collectors.public_info import (
    HostingProviderIdentifierCollector,
    PasteBinSearchCollector,
    PGPKeyServerCollector,
    TORExitNodeCollector,
    WikipediaEditsCollector,
    ZoneHDefacementCollector,
)
from specter.collectors.search_engines import (
    BingSearchCollector,
    CommonCrawlCollector,
    DuckDuckGoCollector,
    GrepAppCollector,
    SearchcodeCollector,
)
from specter.collectors.similar_domains import (
    SimilarDomainFinderCollector,
    TLDSearchCollector,
)
from specter.collectors.social_media import (
    FlickrCollector,
    KeybaseCollector,
    MySpaceCollector,
    SlideShareCollector,
    TwitterCollector,
    VenmoCollector,
)
from specter.collectors.subdomain_takeover import SubdomainTakeoverCollector
from specter.collectors.threatintel_enhanced import (
    CensysCollector,
    ShodanCollector,
    VirusTotalCollector,
)
from specter.collectors.threatintel_free import (
    AlienVaultOTXCollector,
    BlocklistCollector,
    DroneBLCollector,
    MalwarePatrolCollector,
    OpenPhishCollector,
    PhishTankCollector,
    SpamhausCollector,
    ThreatCrowdCollector,
    ThreatMinerCollector,
)
from specter.collectors.web_analytics import WebAnalyticsExtractorCollector
from specter.collectors.web_spider import WebSpiderCollector
from specter.collectors.web_tech import (
    CookieExtractorCollector,
    ErrorStringExtractorCollector,
    StrangeHeadersCollector,
    WebFrameworkIdentifierCollector,
    WebServerIdentifierCollector,
)

ENTRY_POINT_GROUP = "specter.collectors"
BUILTIN_ORIGIN = "builtin"

ENHANCED_COLLECTORS = (
    ShodanCollector,
    CensysCollector,
    VirusTotalCollector,
    HaveIBeenPwnedCollector,
)

SEARCH_ENGINE_COLLECTORS = (
    DuckDuckGoCollector,
    BingSearchCollector,
    CommonCrawlCollector,
    GrepAppCollector,
    SearchcodeCollector,
)

BREACH_DATA_COLLECTORS = (
    HaveIBeenPwnedCollector,
    LeakLookupCollector,
    LeakIXCollector,
    IntelligenceXCollector,
)

FREE_COLLECTORS = (
    AlienVaultOTXCollector,
    ThreatCrowdCollector,
    ThreatMinerCollector,
    PhishTankCollector,
    OpenPhishCollector,
    MalwarePatrolCollector,
    SpamhausCollector,
    BlocklistCollector,
    DroneBLCollector,
    SubdomainTakeoverCollector,
    DNSZoneTransferCollector,
    DNSBruteForceCollector,
    PortScanCollector,
    WebSpiderCollector,
    EmailExtractorCollector,
    PhoneExtractorCollector,
    NameExtractorCollector,
    HashExtractorCollector,
    CreditCardExtractorCollector,
    IBANExtractorCollector,
    WebAnalyticsExtractorCollector,
    WebFrameworkIdentifierCollector,
    WebServerIdentifierCollector,
    StrangeHeadersCollector,
    CookieExtractorCollector,
    ErrorStringExtractorCollector,
)

CLOUD_BUCKET_COLLECTORS = (
    S3BucketFinderCollector,
    AzureBlobFinderCollector,
    DigitalOceanSpaceFinderCollector,
    GoogleCloudStorageFinderCollector,
    GrayhatWarfareCollector,
)

COMPANY_DATA_COLLECTORS = (
    OpenCorporatesCollector,
    GLEIFCollector,
    ClearbitCollector,
    FullContactCollector,
)

BLOCKCHAIN_COLLECTORS = (
    BitcoinWhoIsWhoCollector,
    BitcoinAbuseCollector,
    BlockchainInfoCollector,
    EtherscanCollector,
)

PASSIVE_DNS_COLLECTORS = (
    DNSGrepCollector,
    MnemonicPassiveDNSCollector,
    CIRCLPassiveDNSCollector,
    DNSDBChecker,
)

DARKWEB_COLLECTORS = (
    AhmiaCollector,
    TorCHCollector,
    OnionLinkCollector,
)

SIMILAR_DOMAIN_COLLECTORS = (
    SimilarDomainFinderCollector,
    TLDSearchCollector,
)

PUBLIC_INFO_COLLECTORS = (
    PasteBinSearchCollector,
    WikipediaEditsCollector,
    ZoneHDefacementCollector,
    PGPKeyServerCollector,
    HostingProviderIdentifierCollector,
    TORExitNodeCollector,
)

EXTERNAL_TOOLS_COLLECTORS = (
    CMSeeKDetectorCollector,
    NucleiScannerCollector,
    NmapScannerCollector,
    RetireJSScannerCollector,
    SnallygasterScannerCollector,
    TestSSLScannerCollector,
    TruffleHogScannerCollector,
    WAFW00FDetectorCollector,
    WhatWebScannerCollector,
)

SOCIAL_MEDIA_COLLECTORS = (
    FlickrCollector,
    KeybaseCollector,
    MySpaceCollector,
    SlideShareCollector,
    TwitterCollector,
    VenmoCollector,
)


@dataclass(frozen=True)
class CollectorSpec:
    name: str
    instance: Any
    origin: str


@dataclass
class CollectorRegistry:
    _collectors: dict[str, CollectorSpec] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def register(self, instance: Any, origin: str = BUILTIN_ORIGIN) -> CollectorSpec:
        """Registra un colector (instancia o clase) bajo su `name`."""
        if isinstance(instance, type):
            instance = instance()
        name = getattr(instance, "name", None) or type(instance).__name__
        spec = CollectorSpec(name=str(name), instance=instance, origin=origin)
        self._collectors[spec.name] = spec
        return spec

    def register_enhanced_collectors(self, origin: str = BUILTIN_ORIGIN) -> list[CollectorSpec]:
        """Registra los colectores avanzados (Shodan, Censys, VirusTotal, HIBP)."""
        return [self.register(cls(), origin=origin) for cls in ENHANCED_COLLECTORS]

    def register_free_collectors(self, origin: str = BUILTIN_ORIGIN) -> list[CollectorSpec]:
        """Registra los colectores gratuitos sin API key (OTX, ThreatCrowd, etc.)."""
        return [self.register(cls(), origin=origin) for cls in FREE_COLLECTORS]

    def register_search_engine_collectors(
        self, origin: str = BUILTIN_ORIGIN
    ) -> list[CollectorSpec]:
        """Registra los colectores de motores de búsqueda (DuckDuckGo, Bing, etc.)."""
        return [self.register(cls(), origin=origin) for cls in SEARCH_ENGINE_COLLECTORS]

    def register_breach_data_collectors(self, origin: str = BUILTIN_ORIGIN) -> list[CollectorSpec]:
        """Registra los colectores de brechas de datos (HIBP, LeakLookup, etc.)."""
        return [self.register(cls(), origin=origin) for cls in BREACH_DATA_COLLECTORS]

    def register_cloud_bucket_collectors(self, origin: str = BUILTIN_ORIGIN) -> list[CollectorSpec]:
        """Registra los colectores de cloud buckets (S3, Azure, GCS, etc.)."""
        return [self.register(cls(), origin=origin) for cls in CLOUD_BUCKET_COLLECTORS]

    def register_company_data_collectors(self, origin: str = BUILTIN_ORIGIN) -> list[CollectorSpec]:
        """Registra los colectores de datos de empresa (OpenCorporates, GLEIF, etc.)."""
        return [self.register(cls(), origin=origin) for cls in COMPANY_DATA_COLLECTORS]

    def register_blockchain_collectors(self, origin: str = BUILTIN_ORIGIN) -> list[CollectorSpec]:
        """Registra los colectores de blockchain (Bitcoin, Ethereum, etc.)."""
        return [self.register(cls(), origin=origin) for cls in BLOCKCHAIN_COLLECTORS]

    def register_similar_domain_collectors(
        self, origin: str = BUILTIN_ORIGIN
    ) -> list[CollectorSpec]:
        """Registra los colectores de dominios similares (typosquatting, TLDs)."""
        return [self.register(cls(), origin=origin) for cls in SIMILAR_DOMAIN_COLLECTORS]

    def register_public_info_collectors(self, origin: str = BUILTIN_ORIGIN) -> list[CollectorSpec]:
        """Registra los colectores de información pública (PasteBin, Wikipedia, etc.)."""
        return [self.register(cls(), origin=origin) for cls in PUBLIC_INFO_COLLECTORS]

    def register_external_tools_collectors(
        self, origin: str = BUILTIN_ORIGIN
    ) -> list[CollectorSpec]:
        """Registra los colectores de herramientas externas (nmap, nuclei, etc.)."""
        return [self.register(cls(), origin=origin) for cls in EXTERNAL_TOOLS_COLLECTORS]

    def register_social_media_collectors(self, origin: str = BUILTIN_ORIGIN) -> list[CollectorSpec]:
        """Registra los colectores de social media (Twitter, Flickr, etc.)."""
        return [self.register(cls(), origin=origin) for cls in SOCIAL_MEDIA_COLLECTORS]

    def unregister(self, name: str) -> bool:
        return self._collectors.pop(name, None) is not None

    def spec(self, name: str) -> CollectorSpec:
        spec = self._collectors.get(name)
        if spec is None:
            raise KeyError(name)
        return spec

    def get(self, name: str) -> Any:
        return self.spec(name).instance

    def __contains__(self, name: object) -> bool:
        return name in self._collectors

    def __len__(self) -> int:
        return len(self._collectors)

    def names(self) -> list[str]:
        return sorted(self._collectors)

    def describe(self) -> list[dict[str, Any]]:
        """Catálogo serializable para la UI y el agente."""
        return [
            {
                "name": spec.name,
                "origin": spec.origin,
                "class": type(spec.instance).__name__,
                "kind": "plugin" if spec.origin.startswith("plugin:") else "builtin",
            }
            for spec in sorted(self._collectors.values(), key=lambda s: s.name)
        ]

    def load_entry_points(self, group: str = ENTRY_POINT_GROUP) -> list[str]:
        """Descubre y registra colectores externos. Devuelve los nombres cargados."""
        loaded: list[str] = []
        for entry in importlib.metadata.entry_points(group=group):
            try:
                target = entry.load()
                instance = target() if isinstance(target, type) else target
                if not isinstance(instance, BaseCollector) and not hasattr(instance, "collect"):
                    raise TypeError(f"{entry.value} no expone collect()")  # noqa: TRY301
            except Exception as exc:  # un plugin roto no debe tumbar el kernel
                self.errors.append(f"{entry.name}: {exc}")
                continue
            self.register(instance, origin=f"plugin:{entry.name}")
            loaded.append(str(entry.name))
        return loaded


def create_default_registry() -> CollectorRegistry:
    """Crea una instancia de CollectorRegistry con los colectores base registrados."""
    from specter.collectors.attack_surface import AttackSurfaceCollector

    reg = CollectorRegistry()
    reg.register(AttackSurfaceCollector())
    return reg


default_registry = create_default_registry()
