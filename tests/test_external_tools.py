"""
Tests de los colectores de herramientas externas (nmap, nuclei, whatweb, wafw00f,
cmseek, trufflehog, retire.js, testssl.sh, snallygaster).

Los tests verifican que:
1. Retornan requires_tool cuando la herramienta no está instalada
2. Manejan errores de subprocess gracefully
3. Retornan CollectorResult con entidades apropiadas cuando la herramienta está instalada
"""

from __future__ import annotations

import pytest
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

pytestmark = pytest.mark.asyncio


# --- NmapScannerCollector ---


async def test_nmap_requiere_tool_no_instalado(monkeypatch) -> None:
    """NmapScannerCollector retorna requires_tool cuando nmap no está instalado."""
    monkeypatch.setattr("specter.collectors.external_tools._check_tool_installed", lambda _: None)
    collector = NmapScannerCollector()
    result = await collector.collect("192.168.1.1")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "nmap"
    assert result.entities == []


async def test_nmap_parsea_output(monkeypatch) -> None:
    """NmapScannerCollector parsea correctamente el output de nmap."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/nmap"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (
            0,
            "Nmap scan report for 192.168.1.1\n"
            "Host is up (0.001s latency).\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "80/tcp   open  http\n"
            "OS details: Linux 5.x",
            "",
        )

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = NmapScannerCollector()
    result = await collector.collect("192.168.1.1")
    assert result.metadata["ok"] is True
    assert result.metadata["tool"] == "nmap"
    assert result.metadata["open_ports"] == 2
    assert result.metadata["os_detected"] == "Linux 5.x"
    assert len(result.entities) > 0


async def test_nmap_maneja_error_subprocess(monkeypatch) -> None:
    """NmapScannerCollector maneja errores de subprocess gracefully."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/nmap"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (1, "", "nmap: command not found")

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = NmapScannerCollector()
    result = await collector.collect("192.168.1.1")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "nmap"


# --- NucleiScannerCollector ---


async def test_nuclei_requiere_tool_no_instalado(monkeypatch) -> None:
    """NucleiScannerCollector retorna requires_tool cuando nuclei no está instalado."""
    monkeypatch.setattr("specter.collectors.external_tools._check_tool_installed", lambda _: None)
    collector = NucleiScannerCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "nuclei"
    assert result.entities == []


async def test_nuclei_parsea_output(monkeypatch) -> None:
    """NucleiScannerCollector parsea correctamente el output JSON de nuclei."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/nuclei"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (
            0,
            '{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical"},'
            '"matched-at":"https://example.com"}',
            "",
        )

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = NucleiScannerCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is True
    assert result.metadata["tool"] == "nuclei"
    assert result.metadata["vulnerabilities_found"] == 1
    assert len(result.entities) > 0


# --- WhatWebScannerCollector ---


async def test_whatweb_requiere_tool_no_instalado(monkeypatch) -> None:
    """WhatWebScannerCollector retorna requires_tool cuando whatweb no está instalado."""
    monkeypatch.setattr("specter.collectors.external_tools._check_tool_installed", lambda _: None)
    collector = WhatWebScannerCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "whatweb"
    assert result.entities == []


async def test_whatweb_parsea_output(monkeypatch) -> None:
    """WhatWebScannerCollector parsea correctamente el output JSON de whatweb."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/whatweb"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (
            0,
            '[{"plugins": {"Apache": {"string": ["2.4.41"]}, "PHP": {"string": ["7.4"]}}}]',
            "",
        )

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = WhatWebScannerCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is True
    assert result.metadata["tool"] == "whatweb"
    assert result.metadata["technologies_found"] == 2
    assert len(result.entities) > 0


# --- WAFW00FDetectorCollector ---


async def test_wafw00f_requiere_tool_no_instalado(monkeypatch) -> None:
    """WAFW00FDetectorCollector retorna requires_tool cuando wafw00f no está instalado."""
    monkeypatch.setattr("specter.collectors.external_tools._check_tool_installed", lambda _: None)
    collector = WAFW00FDetectorCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "wafw00f"
    assert result.entities == []


async def test_wafw00f_parsea_output(monkeypatch) -> None:
    """WAFW00FDetectorCollector parsea correctamente el output JSON de wafw00f."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/wafw00f"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (
            0,
            '[{"firewall": "Cloudflare", "manufacturer": "Cloudflare"}]',
            "",
        )

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = WAFW00FDetectorCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is True
    assert result.metadata["tool"] == "wafw00f"
    assert result.metadata["waf_detected"] == "Cloudflare Cloudflare"
    assert len(result.entities) > 0


# --- CMSeeKDetectorCollector ---


async def test_cmseek_requiere_tool_no_instalado(monkeypatch) -> None:
    """CMSeeKDetectorCollector retorna requires_tool cuando cmseek no está instalado."""
    monkeypatch.setattr("specter.collectors.external_tools._check_tool_installed", lambda _: None)
    collector = CMSeeKDetectorCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "cmseek"
    assert result.entities == []


async def test_cmseek_parsea_output(monkeypatch) -> None:
    """CMSeeKDetectorCollector parsea correctamente el output de cmseek."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/cmseek"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (
            0,
            "CMS: WordPress (version 5.8)",
            "",
        )

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = CMSeeKDetectorCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is True
    assert result.metadata["tool"] == "cmseek"
    assert result.metadata["cms_detected"] == "WordPress (version 5.8)"
    assert len(result.entities) > 0


# --- TruffleHogScannerCollector ---


async def test_trufflehog_requiere_tool_no_instalado(monkeypatch) -> None:
    """TruffleHogScannerCollector retorna requires_tool cuando trufflehog no está instalado."""
    monkeypatch.setattr("specter.collectors.external_tools._check_tool_installed", lambda _: None)
    collector = TruffleHogScannerCollector()
    result = await collector.collect("https://github.com/user/repo")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "trufflehog"
    assert result.entities == []


async def test_trufflehog_parsea_output(monkeypatch) -> None:
    """TruffleHogScannerCollector parsea correctamente el output JSON de trufflehog."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/trufflehog"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (
            0,
            '{"DetectorName":"AWS","SourceMetadata":{"Data":"AKIAIOSFODNN7EXAMPLE"},'
            '"Raw":"AKIAIOSFODNN7EXAMPLE"}',
            "",
        )

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = TruffleHogScannerCollector()
    result = await collector.collect("https://github.com/user/repo")
    assert result.metadata["ok"] is True
    assert result.metadata["tool"] == "trufflehog"
    assert result.metadata["secrets_found"] == 1
    assert len(result.entities) > 0


# --- RetireJSScannerCollector ---


async def test_retirejs_requiere_tool_no_instalado(monkeypatch) -> None:
    """RetireJSScannerCollector retorna requires_tool cuando retire.js no está instalado."""
    monkeypatch.setattr("specter.collectors.external_tools._check_tool_installed", lambda _: None)
    collector = RetireJSScannerCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "retire"
    assert result.entities == []


async def test_retirejs_parsea_output(monkeypatch) -> None:
    """RetireJSScannerCollector parsea correctamente el output JSON de retire.js."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/retire"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (
            13,
            '{"data":[{"results":[{"vulnerabilities":[{"identifiers":{"summary":"XSS"},'
            '"severity":"high","info":["http://example.com"]}]}]}]}',
            "",
        )

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = RetireJSScannerCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is True
    assert result.metadata["tool"] == "retirejs"
    assert result.metadata["vulnerabilities_found"] == 1
    assert len(result.entities) > 0


# --- TestSSLScannerCollector ---


async def test_testssl_requiere_tool_no_instalado(monkeypatch) -> None:
    """TestSSLScannerCollector retorna requires_tool cuando testssl.sh no está instalado."""
    monkeypatch.setattr("specter.collectors.external_tools._check_tool_installed", lambda _: None)
    collector = TestSSLScannerCollector()
    result = await collector.collect("example.com")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "testssl.sh"
    assert result.entities == []


async def test_testssl_parsea_output(monkeypatch) -> None:
    """TestSSLScannerCollector parsea correctamente el output JSON de testssl.sh."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/testssl.sh"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (
            0,
            '[{"finding":"Heartbleed","severity":"CRITICAL","id":"heartbleed",'
            '"cve":"CVE-2014-0160"}]',
            "",
        )

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = TestSSLScannerCollector()
    result = await collector.collect("example.com")
    assert result.metadata["ok"] is True
    assert result.metadata["tool"] == "testssl"
    assert result.metadata["vulnerabilities_found"] == 1
    assert len(result.entities) > 0


# --- SnallygasterScannerCollector ---


async def test_snallygaster_requiere_tool_no_instalado(monkeypatch) -> None:
    """SnallygasterScannerCollector retorna requires_tool cuando snallygaster no está instalado."""
    monkeypatch.setattr("specter.collectors.external_tools._check_tool_installed", lambda _: None)
    collector = SnallygasterScannerCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is False
    assert result.metadata["requires_tool"] == "snallygaster"
    assert result.entities == []


async def test_snallygaster_parsea_output(monkeypatch) -> None:
    """SnallygasterScannerCollector parsea correctamente el output JSON de snallygaster."""
    monkeypatch.setattr(
        "specter.collectors.external_tools._check_tool_installed", lambda _: "/usr/bin/snallygaster"
    )

    async def mock_run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
        return (
            0,
            '[{"cause":".git/config","url":"https://example.com/.git/config",'
            '"misc":"Git repository"}]',
            "",
        )

    monkeypatch.setattr("specter.collectors.external_tools._run_subprocess", mock_run_subprocess)
    collector = SnallygasterScannerCollector()
    result = await collector.collect("https://example.com")
    assert result.metadata["ok"] is True
    assert result.metadata["tool"] == "snallygaster"
    assert result.metadata["exposed_files"] == 1
    assert len(result.entities) > 0
