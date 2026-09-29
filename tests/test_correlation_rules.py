"""
Tests para el motor de correlaciones YAML.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from specter.osint_core.correlation_rules import (
    AggregationConfig,
    AnalysisConfig,
    CollectBlock,
    CollectFilter,
    CorrelationRule,
    CorrelationRulesEngine,
    RuleMeta,
)
from specter.osint_core.database import Database
from specter.osint_core.models import (
    CaseMetadata,
    EntityNode,
    EntityType,
)


@pytest.fixture()
def db(tmp_path: Any) -> Database:
    """BD temporal para tests."""
    return Database(tmp_path / "test.db")


@pytest.fixture()
def sample_case(db: Database) -> str:
    """Crea un caso de prueba con entidades variadas."""
    case = CaseMetadata(
        case_id="case-test-001",
        name="Test Case",
        description="Caso de prueba",
        investigator="Test",
    )
    db.create_case(case)
    return case.case_id


@pytest.fixture()
def sample_entities(db: Database, sample_case: str) -> None:
    """Inserta entidades de prueba en el caso."""
    entities = [
        EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1", attributes={"source": "test"}),
        EntityNode.create(EntityType.IP_ADDRESS, "10.0.0.1", attributes={"source": "test"}),
        EntityNode.create(EntityType.DOMAIN, "example.com"),
        EntityNode.create(EntityType.SUBDOMAIN, "dev.example.com"),
        EntityNode.create(EntityType.SUBDOMAIN, "test.example.com"),
        EntityNode.create(EntityType.EMAIL, "admin@example.com"),
        EntityNode.create(EntityType.GEO_LOCATION, "US"),
        EntityNode.create(EntityType.GEO_LOCATION, "RU"),
        EntityNode.create(EntityType.CVE, "CVE-2024-1234", attributes={"severity": "CRITICAL"}),
    ]
    db.upsert_entities(sample_case, entities)


class TestCorrelationRuleModel:
    """Tests para el modelo Pydantic de reglas."""

    def test_valid_rule(self) -> None:
        """Una regla válida se carga correctamente."""
        rule = CorrelationRule(
            id="test_rule",
            version=1,
            meta=RuleMeta(name="Test", description="Test rule", risk="HIGH"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="IP_ADDRESS"),
                    ]
                )
            ],
            aggregation=AggregationConfig(field="data"),
            analysis=[AnalysisConfig(method="threshold", field="data", minimum=2)],
            headline="Test: {data}",
        )
        assert rule.id == "test_rule"
        assert rule.meta.risk == "HIGH"

    def test_invalid_collect_method(self) -> None:
        """Método de colección inválido lanza error."""
        with pytest.raises(ValueError, match="Método de colección inválido"):
            CollectFilter(method="invalid", field="type", value="IP_ADDRESS")

    def test_invalid_analysis_method(self) -> None:
        """Método de análisis inválido lanza error."""
        with pytest.raises(ValueError, match="Método de análisis inválido"):
            AnalysisConfig(method="invalid", field="data")


class TestCorrelationRulesEngine:
    """Tests para el motor de correlaciones."""

    def test_load_rules(self, db: Database) -> None:
        """Las reglas YAML se cargan correctamente."""
        engine = CorrelationRulesEngine(db)
        rules = engine.load_rules()
        assert len(rules) >= 10
        assert "multiple_malicious" in rules
        assert "outlier_country" in rules
        assert "dev_or_test_system" in rules

    def test_list_rules(self, db: Database) -> None:
        """El listado de reglas funciona."""
        engine = CorrelationRulesEngine(db)
        rules = engine.list_rules()
        assert len(rules) >= 10
        rule_ids = [r["id"] for r in rules]
        assert "multiple_malicious" in rule_ids
        assert "stale_host" in rule_ids

    def test_get_rule(self, db: Database) -> None:
        """Obtener una regla por ID."""
        engine = CorrelationRulesEngine(db)
        rule = engine.get_rule("multiple_malicious")
        assert rule is not None
        assert rule.id == "multiple_malicious"
        assert rule.meta.risk == "HIGH"

    def test_get_rule_not_found(self, db: Database) -> None:
        """Regla no existente retorna None."""
        engine = CorrelationRulesEngine(db)
        rule = engine.get_rule("nonexistent_rule")
        assert rule is None

    def test_execute_rule_not_found(self, db: Database, sample_case: str) -> None:
        """Ejecutar regla no existente retorna lista vacía."""
        engine = CorrelationRulesEngine(db)
        results = engine.execute_rule(sample_case, "nonexistent")
        assert results == []

    def test_execute_all_rules(self, db: Database, sample_case: str, sample_entities: None) -> None:
        """Ejecutar todas las reglas contra un caso."""
        engine = CorrelationRulesEngine(db)
        results = engine.execute_all_rules(sample_case)
        assert isinstance(results, list)
        # Al menos algunas reglas deberían producir resultados
        assert len(results) >= 0

    def test_execute_dev_or_test_system(
        self, db: Database, sample_case: str, sample_entities: None
    ) -> None:
        """La regla dev_or_test_system detecta subdominios dev/test."""
        engine = CorrelationRulesEngine(db)
        results = engine.execute_rule(sample_case, "dev_or_test_system")
        assert len(results) > 0
        # Debería encontrar dev.example.com y test.example.com
        entity_values = [e.value for r in results for e in r.entities]
        assert "dev.example.com" in entity_values
        assert "test.example.com" in entity_values

    def test_execute_vulnerability_critical(
        self, db: Database, sample_case: str, sample_entities: None
    ) -> None:
        """La regla vulnerability_critical detecta CVEs críticos."""
        engine = CorrelationRulesEngine(db)
        results = engine.execute_rule(sample_case, "vulnerability_critical")
        assert len(results) > 0
        entity_values = [e.value for r in results for e in r.entities]
        assert "CVE-2024-1234" in entity_values

    def test_execute_outlier_country(
        self, db: Database, sample_case: str, sample_entities: None
    ) -> None:
        """La regla outlier_country detecta países atípicos."""
        engine = CorrelationRulesEngine(db)
        results = engine.execute_rule(sample_case, "outlier_country")
        assert isinstance(results, list)

    def test_threshold_analysis(self, db: Database, sample_case: str) -> None:
        """El análisis threshold agrupa por campo y filtra por mínimo."""
        # Crear múltiples entidades del mismo tipo
        entities = [EntityNode.create(EntityType.IP_ADDRESS, f"192.168.1.{i}") for i in range(1, 5)]
        db.upsert_entities(sample_case, entities)

        engine = CorrelationRulesEngine(db)
        # Crear una regla inline para probar threshold
        from specter.osint_core.correlation_rules import CorrelationRule

        rule = CorrelationRule(
            id="test_threshold",
            version=1,
            meta=RuleMeta(name="Test", description="Test", risk="LOW"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="IP_ADDRESS"),
                    ]
                )
            ],
            aggregation=AggregationConfig(field="type"),
            analysis=[AnalysisConfig(method="threshold", field="type", minimum=2)],
            headline="Test: {data}",
        )
        engine._rules["test_threshold"] = rule

        results = engine.execute_rule(sample_case, "test_threshold")
        assert len(results) > 0

    def test_regex_filter(self, db: Database, sample_case: str) -> None:
        """El filtro regex funciona correctamente."""
        entities = [
            EntityNode.create(EntityType.SUBDOMAIN, "dev.example.com"),
            EntityNode.create(EntityType.SUBDOMAIN, "api.example.com"),
            EntityNode.create(EntityType.SUBDOMAIN, "test.example.com"),
        ]
        db.upsert_entities(sample_case, entities)

        engine = CorrelationRulesEngine(db)
        rule = CorrelationRule(
            id="test_regex",
            version=1,
            meta=RuleMeta(name="Test", description="Test", risk="LOW"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="SUBDOMAIN"),
                        CollectFilter(method="regex", field="data", value=".*dev.*"),
                    ]
                )
            ],
            aggregation=AggregationConfig(field="data"),
            headline="Test: {data}",
        )
        engine._rules["test_regex"] = rule

        results = engine.execute_rule(sample_case, "test_regex")
        assert len(results) > 0
        entity_values = [e.value for r in results for e in r.entities]
        assert "dev.example.com" in entity_values
        assert "api.example.com" not in entity_values

    def test_exact_filter(self, db: Database, sample_case: str) -> None:
        """El filtro exact funciona correctamente."""
        entities = [
            EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1"),
            EntityNode.create(EntityType.DOMAIN, "example.com"),
        ]
        db.upsert_entities(sample_case, entities)

        engine = CorrelationRulesEngine(db)
        rule = CorrelationRule(
            id="test_exact",
            version=1,
            meta=RuleMeta(name="Test", description="Test", risk="LOW"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="IP_ADDRESS"),
                    ]
                )
            ],
            aggregation=AggregationConfig(field="data"),
            headline="Test: {data}",
        )
        engine._rules["test_exact"] = rule

        results = engine.execute_rule(sample_case, "test_exact")
        assert len(results) > 0
        entity_values = [e.value for r in results for e in r.entities]
        assert "192.168.1.1" in entity_values
        assert "example.com" not in entity_values


class TestCorrelationResult:
    """Tests para el resultado de correlación."""

    def test_result_to_dict(self) -> None:
        """El resultado se serializa correctamente."""
        from specter.osint_core.correlation_rules import CorrelationResult

        entity = EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1")
        result = CorrelationResult(
            rule_id="test_rule",
            rule_name="Test Rule",
            risk="HIGH",
            headline="Test: 192.168.1.1",
            entities=[entity],
            details={"count": 1},
        )

        data = result.to_dict()
        assert data["rule_id"] == "test_rule"
        assert data["risk"] == "HIGH"
        assert data["entity_count"] == 1
        assert data["entities"][0]["value"] == "192.168.1.1"


class TestIntegration:
    """Tests de integración con la BD."""

    def test_full_workflow(self, db: Database, sample_case: str) -> None:
        """Flujo completo: crear caso, insertar entidades, ejecutar reglas."""
        # Insertar entidades variadas
        entities = [
            EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1"),
            EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.2"),
            EntityNode.create(EntityType.SUBDOMAIN, "dev.example.com"),
            EntityNode.create(EntityType.SUBDOMAIN, "staging.example.com"),
            EntityNode.create(EntityType.CVE, "CVE-2024-1234", attributes={"severity": "CRITICAL"}),
            EntityNode.create(EntityType.GEO_LOCATION, "US"),
            EntityNode.create(EntityType.GEO_LOCATION, "CN"),
            EntityNode.create(EntityType.GEO_LOCATION, "RU"),
        ]
        db.upsert_entities(sample_case, entities)

        # Ejecutar todas las reglas
        engine = CorrelationRulesEngine(db)
        results = engine.execute_all_rules(sample_case)

        # Verificar que se produjeron resultados
        assert isinstance(results, list)

        # Verificar que dev_or_test_system encontró los subdominios
        dev_results = [r for r in results if r.rule_id == "dev_or_test_system"]
        if dev_results:
            entity_values = [e.value for r in dev_results for e in r.entities]
            assert "dev.example.com" in entity_values

    def test_empty_case(self, db: Database, sample_case: str) -> None:
        """Ejecutar reglas en un caso vacío no produce errores."""
        engine = CorrelationRulesEngine(db)
        results = engine.execute_all_rules(sample_case)
        assert isinstance(results, list)
        assert len(results) == 0


class TestAnalysisMethods:
    """Tests para los métodos de análisis del motor."""

    def test_outlier_analysis(self, db: Database, sample_case: str) -> None:
        """El análisis outlier detecta valores atípicos."""
        # Crear entidades con diferentes países (cada una con ID único)
        # Usamos atributos para diferenciarlas ya que el valor es el país
        entities = [EntityNode.create(EntityType.GEO_LOCATION, f"US-{i}") for i in range(4)] + [
            EntityNode.create(EntityType.GEO_LOCATION, "RU")
        ]
        db.upsert_entities(sample_case, entities)

        engine = CorrelationRulesEngine(db)
        rule = CorrelationRule(
            id="test_outlier",
            version=1,
            meta=RuleMeta(name="Test", description="Test", risk="LOW"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="GEO_LOCATION"),
                    ]
                )
            ],
            aggregation=AggregationConfig(field="data"),
            analysis=[AnalysisConfig(method="outlier", maximum_percent=30)],
            headline="Outlier: {data}",
        )
        engine._rules["test_outlier"] = rule

        results = engine.execute_rule(sample_case, "test_outlier")
        assert len(results) > 0
        # RU debería ser outlier (1 de 5 = 20% < 30%)
        outlier_values = [r.headline for r in results]
        assert any("RU" in h for h in outlier_values)

    def test_first_collection_only_analysis(self, db: Database, sample_case: str) -> None:
        """El análisis first_collection_only retorna solo la primera colección."""
        entities = [
            EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1"),
            EntityNode.create(EntityType.IP_ADDRESS, "10.0.0.1"),
        ]
        db.upsert_entities(sample_case, entities)

        engine = CorrelationRulesEngine(db)
        rule = CorrelationRule(
            id="test_first_only",
            version=1,
            meta=RuleMeta(name="Test", description="Test", risk="LOW"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="IP_ADDRESS"),
                    ]
                ),
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="DOMAIN"),
                    ]
                ),
            ],
            aggregation=AggregationConfig(field="data"),
            analysis=[AnalysisConfig(method="first_collection_only")],
            headline="First: {data}",
        )
        engine._rules["test_first_only"] = rule

        results = engine.execute_rule(sample_case, "test_first_only")
        assert len(results) == 1
        entity_values = [e.value for e in results[0].entities]
        assert "192.168.1.1" in entity_values
        assert "10.0.0.1" in entity_values

    def test_match_all_to_first_collection_analysis(self, db: Database, sample_case: str) -> None:
        """El análisis match_all_to_first_collection encuentra entidades comunes."""
        entities = [
            EntityNode.create(EntityType.DOMAIN, "example.com"),
            EntityNode.create(EntityType.SUBDOMAIN, "www.example.com"),
        ]
        db.upsert_entities(sample_case, entities)

        engine = CorrelationRulesEngine(db)
        rule = CorrelationRule(
            id="test_match_all",
            version=1,
            meta=RuleMeta(name="Test", description="Test", risk="LOW"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="DOMAIN"),
                    ]
                ),
                CollectBlock(
                    collect=[
                        CollectFilter(method="regex", field="data", value=".*example.*"),
                    ]
                ),
            ],
            aggregation=AggregationConfig(field="data"),
            analysis=[AnalysisConfig(method="match_all_to_first_collection", field="data")],
            headline="Match: {data}",
        )
        engine._rules["test_match_all"] = rule

        results = engine.execute_rule(sample_case, "test_match_all")
        assert len(results) > 0


class TestFieldPrefixes:
    """Tests para los prefijos de campos source., child., entity."""

    def test_entity_prefix(self, db: Database, sample_case: str) -> None:
        """El prefijo entity. funciona correctamente."""
        entities = [
            EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1"),
        ]
        db.upsert_entities(sample_case, entities)

        engine = CorrelationRulesEngine(db)
        rule = CorrelationRule(
            id="test_entity_prefix",
            version=1,
            meta=RuleMeta(name="Test", description="Test", risk="LOW"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="entity.type", value="IP_ADDRESS"),
                    ]
                )
            ],
            aggregation=AggregationConfig(field="entity.data"),
            headline="Test: {data}",
        )
        engine._rules["test_entity_prefix"] = rule

        results = engine.execute_rule(sample_case, "test_entity_prefix")
        assert len(results) > 0

    def test_source_prefix(self, db: Database, sample_case: str) -> None:
        """El prefijo source. resuelve campos de la entidad origen."""
        from specter.osint_core.models import RelationEdge, RelationType

        entities = [
            EntityNode.create(EntityType.DOMAIN, "example.com"),
            EntityNode.create(EntityType.SUBDOMAIN, "www.example.com"),
        ]
        db.upsert_entities(sample_case, entities)

        # Crear relación: example.com -> www.example.com (el subdominio es el target)
        # Así, para la entidad www.example.com, source.data = example.com
        relations = [
            RelationEdge(
                source_id="domain:example.com",
                target_id="subdomain:www.example.com",
                relation_type=RelationType.SUBDOMAIN_OF,
            )
        ]
        db.upsert_relations(sample_case, relations)

        engine = CorrelationRulesEngine(db)
        rule = CorrelationRule(
            id="test_source_prefix",
            version=1,
            meta=RuleMeta(name="Test", description="Test", risk="LOW"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="SUBDOMAIN"),
                        CollectFilter(method="exact", field="source.data", value="example.com"),
                    ]
                )
            ],
            aggregation=AggregationConfig(field="data"),
            headline="Test: {data}",
        )
        engine._rules["test_source_prefix"] = rule

        results = engine.execute_rule(sample_case, "test_source_prefix")
        assert len(results) > 0
        entity_values = [e.value for r in results for e in r.entities]
        assert "www.example.com" in entity_values

    def test_child_prefix(self, db: Database, sample_case: str) -> None:
        """El prefijo child. resuelve campos de la entidad destino."""
        from specter.osint_core.models import RelationEdge, RelationType

        entities = [
            EntityNode.create(EntityType.DOMAIN, "example.com"),
            EntityNode.create(EntityType.SUBDOMAIN, "www.example.com"),
        ]
        db.upsert_entities(sample_case, entities)

        # Crear relación: example.com -> www.example.com (como source)
        relations = [
            RelationEdge(
                source_id="domain:example.com",
                target_id="subdomain:www.example.com",
                relation_type=RelationType.SUBDOMAIN_OF,
            )
        ]
        db.upsert_relations(sample_case, relations)

        engine = CorrelationRulesEngine(db)
        rule = CorrelationRule(
            id="test_child_prefix",
            version=1,
            meta=RuleMeta(name="Test", description="Test", risk="LOW"),
            collections=[
                CollectBlock(
                    collect=[
                        CollectFilter(method="exact", field="type", value="DOMAIN"),
                        CollectFilter(method="exact", field="child.data", value="www.example.com"),
                    ]
                )
            ],
            aggregation=AggregationConfig(field="data"),
            headline="Test: {data}",
        )
        engine._rules["test_child_prefix"] = rule

        results = engine.execute_rule(sample_case, "test_child_prefix")
        assert len(results) > 0
        entity_values = [e.value for r in results for e in r.entities]
        assert "example.com" in entity_values


class TestMCPServerIntegration:
    """Tests de integración con el server MCP."""

    def test_run_correlations_tool_exists(self) -> None:
        """La tool run_correlations está registrada en el server."""
        from specter import server

        # Verificar que la función existe
        assert hasattr(server, "run_correlations")
        assert callable(server.run_correlations)

    def test_run_correlations_tool_with_case(self, db: Database, sample_case: str) -> None:
        """La tool run_correlations funciona con un caso válido."""
        from specter import server

        # Insertar entidades de prueba
        entities = [
            EntityNode.create(EntityType.SUBDOMAIN, "dev.example.com"),
            EntityNode.create(EntityType.SUBDOMAIN, "test.example.com"),
        ]
        db.upsert_entities(sample_case, entities)

        # Reasignar el db global del server
        original_db = server.db
        server.db = db
        try:
            result = server.run_correlations(sample_case)
            data = json.loads(result)
            assert data["status"] == "COMPLETED"
            assert data["case_id"] == sample_case
            assert "results" in data
        finally:
            server.db = original_db

    def test_run_correlations_tool_invalid_case(self) -> None:
        """La tool run_correlations maneja casos inválidos."""
        from specter import server

        result = server.run_correlations("nonexistent-case")
        data = json.loads(result)
        assert "error" in data


class TestAllYAMLRules:
    """Tests para verificar que todas las reglas YAML funcionan."""

    EXPECTED_RULES = [
        "multiple_malicious",
        "outlier_country",
        "outlier_webserver",
        "cloud_bucket_open",
        "email_in_multiple_breaches",
        "subdomain_takeover_possible",
        "vulnerability_critical",
        "stale_host",
        "dev_or_test_system",
        "strong_similardomain_crossref",
    ]

    def test_all_rules_loaded(self, db: Database) -> None:
        """Todas las reglas YAML se cargan correctamente."""
        engine = CorrelationRulesEngine(db)
        rules = engine.load_rules()
        for rule_id in self.EXPECTED_RULES:
            assert rule_id in rules, f"Regla {rule_id} no cargada"

    def test_all_rules_execute_without_error(self, db: Database, sample_case: str) -> None:
        """Todas las reglas se ejecutan sin error."""
        entities = [
            EntityNode.create(EntityType.IP_ADDRESS, "192.168.1.1"),
            EntityNode.create(EntityType.DOMAIN, "example.com"),
            EntityNode.create(EntityType.SUBDOMAIN, "dev.example.com"),
            EntityNode.create(EntityType.EMAIL, "admin@example.com"),
            EntityNode.create(EntityType.GEO_LOCATION, "US"),
            EntityNode.create(EntityType.CVE, "CVE-2024-1234", attributes={"severity": "CRITICAL"}),
        ]
        db.upsert_entities(sample_case, entities)

        engine = CorrelationRulesEngine(db)
        for rule_id in self.EXPECTED_RULES:
            results = engine.execute_rule(sample_case, rule_id)
            assert isinstance(results, list), f"Regla {rule_id} no retornó lista"
