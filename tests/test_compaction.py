"""
Tests del Compaction Service: compactación de resultados y evidencia en disco.
"""

from __future__ import annotations

import json
from pathlib import Path

from specter.osint_core.compaction import CompactionService
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)


def _make_entity(
    value: str,
    etype: EntityType = EntityType.DOMAIN,
    confidence: float = 1.0,
    attributes: dict | None = None,
) -> EntityNode:
    return EntityNode.create(
        type=etype,
        value=value,
        confidence=confidence,
        attributes=attributes or {},
    )


def _make_relation(
    source: str,
    target: str,
    rtype: RelationType = RelationType.RESOLVES_TO,
    confidence: float = 1.0,
) -> RelationEdge:
    return RelationEdge(
        source_id=source,
        target_id=target,
        relation_type=rtype,
        confidence=confidence,
    )


def _make_result(
    entities: list[EntityNode] | None = None,
    relations: list[RelationEdge] | None = None,
    raw_payload: str | None = None,
) -> CollectorResult:
    return CollectorResult(
        collector_name="test_collector",
        source_target="example.com",
        entities=entities or [],
        relations=relations or [],
        raw_payload=raw_payload,
        metadata={"test": True},
    )


def test_compact_collector_result_basico(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    result = _make_result(
        entities=[_make_entity("example.com")],
        relations=[_make_relation("domain:example.com", "ip:1.2.3.4")],
        raw_payload='{"data": "test"}',
    )

    compacted = svc.compact_collector_result(result)

    assert compacted.collector_name == "test_collector"
    assert compacted.source_target == "example.com"
    assert len(compacted.entities) == 1
    assert len(compacted.relations) == 1
    assert compacted.raw_payload_ref is not None
    assert compacted.raw_payload_ref.startswith("compaction://")
    assert compacted.original_size_bytes > 0
    assert compacted.compacted_size_bytes > 0


def test_compact_entities_preserva_campos_clave(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    entities = [
        _make_entity("example.com", confidence=0.95),
        _make_entity("sub.example.com", etype=EntityType.SUBDOMAIN, confidence=0.8),
    ]

    compacted = svc.compact_entities(entities)

    assert len(compacted) == 2
    assert compacted[0].id == "domain:example.com"
    assert compacted[0].type == "DOMAIN"
    assert compacted[0].value == "example.com"
    assert compacted[0].confidence == 0.95
    assert compacted[1].id == "subdomain:sub.example.com"


def test_compact_entities_con_attributes_guarda_en_disco(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    entities = [
        _make_entity(
            "example.com",
            attributes={"server": "nginx", "ip": "1.2.3.4", "extra": "x" * 100},
        )
    ]

    compacted = svc.compact_entities(entities)

    assert compacted[0].attributes_ref is not None
    assert compacted[0].attributes_ref.startswith("compaction://")

    # Verificar que los attributes están en disco
    loaded = svc.load_evidence(compacted[0].attributes_ref)
    assert loaded is not None
    attrs = json.loads(loaded)
    assert attrs["server"] == "nginx"
    assert attrs["ip"] == "1.2.3.4"


def test_compact_entities_sin_attributes_no_guarda(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    entities = [_make_entity("example.com", attributes={})]

    compacted = svc.compact_entities(entities)

    assert compacted[0].attributes_ref is None


def test_compact_relations_preserva_campos_clave(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    relations = [
        _make_relation("domain:example.com", "ip:1.2.3.4", confidence=0.9),
        _make_relation(
            "domain:example.com",
            "domain:sub.example.com",
            rtype=RelationType.SUBDOMAIN_OF,
        ),
    ]

    compacted = svc.compact_relations(relations)

    assert len(compacted) == 2
    assert compacted[0].source_id == "domain:example.com"
    assert compacted[0].target_id == "ip:1.2.3.4"
    assert compacted[0].relation_type == "RESOLVES_TO"
    assert compacted[0].confidence == 0.9
    assert compacted[1].relation_type == "SUBDOMAIN_OF"


def test_compact_relations_con_attributes_guarda_en_disco(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    relations = [
        RelationEdge(
            source_id="domain:example.com",
            target_id="ip:1.2.3.4",
            relation_type=RelationType.RESOLVES_TO,
            attributes={"dns_server": "8.8.8.8", "ttl": 300},
        )
    ]

    compacted = svc.compact_relations(relations)

    assert compacted[0].attributes_ref is not None
    loaded = svc.load_evidence(compacted[0].attributes_ref)
    assert loaded is not None
    attrs = json.loads(loaded)
    assert attrs["dns_server"] == "8.8.8.8"
    assert attrs["ttl"] == 300


def test_create_summary_basico(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    result = _make_result(
        entities=[
            _make_entity("example.com", confidence=0.95),
            _make_entity("sub.example.com", etype=EntityType.SUBDOMAIN, confidence=0.85),
            _make_entity("1.2.3.4", etype=EntityType.IP_ADDRESS, confidence=0.7),
        ],
        relations=[
            _make_relation("domain:example.com", "ip:1.2.3.4"),
            _make_relation(
                "domain:sub.example.com",
                "domain:example.com",
                rtype=RelationType.SUBDOMAIN_OF,
            ),
        ],
    )

    summary = svc.create_summary(result)

    assert "test_collector" in summary
    assert "example.com" in summary
    assert "DOMAIN: 1" in summary
    assert "SUBDOMAIN: 1" in summary
    assert "IP_ADDRESS: 1" in summary
    assert "RESOLVES_TO: 1" in summary
    assert "SUBDOMAIN_OF: 1" in summary
    assert "Hallazgos clave" in summary


def test_create_summary_con_metadata(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    result = _make_result(
        entities=[_make_entity("example.com")],
        raw_payload=None,
    )
    result.metadata = {"source": "test", "count": 42}

    summary = svc.create_summary(result)

    assert "source: test" in summary
    assert "count: 42" in summary


def test_should_compact_por_debajo_del_umbral(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    result = _make_result(entities=[_make_entity("example.com")])

    assert svc.should_compact(result, threshold_bytes=10000) is False


def test_should_compact_por_encima_del_umbral(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    # Resultado grande: muchas entidades
    entities = [_make_entity(f"sub{i}.example.com", etype=EntityType.SUBDOMAIN) for i in range(100)]
    result = _make_result(entities=entities, raw_payload=json.dumps({"data": "x" * 5000}))

    assert svc.should_compact(result, threshold_bytes=10000) is True


def test_load_evidence_inexistente_retorna_none(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    assert svc.load_evidence("compaction://raw_payload/no_existe") is None


def test_load_evidence_uri_invalida_retorna_none(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    assert svc.load_evidence("invalid://uri") is None
    assert svc.load_evidence("compaction://") is None


def test_compact_collector_result_reducir_tamaño(tmp_path: Path):
    """La compactación debe reducir el tamaño del contexto."""
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    # Resultado con attributes grandes
    entities = [
        _make_entity(
            f"sub{i}.example.com",
            etype=EntityType.SUBDOMAIN,
            attributes={"data": "x" * 200, "extra": "y" * 200},
        )
        for i in range(20)
    ]
    result = _make_result(
        entities=entities,
        raw_payload=json.dumps({"items": list(range(100))}),
    )

    compacted = svc.compact_collector_result(result)

    assert compacted.compacted_size_bytes < compacted.original_size_bytes


def test_compact_collector_result_con_resumen(tmp_path: Path):
    svc = CompactionService(storage_dir=tmp_path / "compactions")

    result = _make_result(
        entities=[
            _make_entity("example.com", confidence=0.95),
            _make_entity("1.2.3.4", etype=EntityType.IP_ADDRESS, confidence=0.9),
        ],
        relations=[_make_relation("domain:example.com", "ip:1.2.3.4")],
    )

    compacted = svc.compact_collector_result(result)

    assert "Resumen" in compacted.summary
    assert "example.com" in compacted.summary
    assert "Hallazgos clave" in compacted.summary
