import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from specter.osint_core.models import (
    CollectorResult,
    EntityNode,
    EntityType,
    RelationEdge,
    RelationType,
)
from specter.server import (
    analyze_network_metrics,
    create_case,
    export_case_dossier,
    investigate_domain,
    list_cases,
    query_graph,
    verify_case_integrity,
)


@pytest.mark.asyncio
async def test_full_server_workflow(tmp_path: Path):
    # 1. Crear Caso
    res_case_raw = create_case(
        name="Operación E2E",
        description="Prueba integral de herramientas FastMCP",
        investigator="Agente_MCP",
    )
    res_case = json.loads(res_case_raw)
    assert res_case["status"] == "CASE_CREATED"
    case_id = res_case["case_id"]

    # 2. Listar Casos
    cases_list = json.loads(list_cases())
    assert any(c["case_id"] == case_id for c in cases_list)

    # 3. Simular investigación de dominio con Mock
    dummy_entity = EntityNode.create(EntityType.DOMAIN, "acme.corp", "ACME Corp")
    dummy_ip = EntityNode.create(EntityType.IP_ADDRESS, "198.51.100.10", "ACME Web")
    dummy_rel = RelationEdge(
        source_id=dummy_entity.id, target_id=dummy_ip.id, relation_type=RelationType.RESOLVES_TO
    )

    mock_dns_result = CollectorResult(
        collector_name="dns_collector",
        source_target="acme.corp",
        entities=[dummy_entity, dummy_ip],
        relations=[dummy_rel],
        raw_payload='{"mock": true}',
    )
    mock_tls_result = CollectorResult(
        collector_name="tls_collector",
        source_target="acme.corp",
        entities=[],
        relations=[],
        raw_payload='{"tls": false}',
    )

    with (
        patch("specter.server.dns_collector.collect", new_callable=AsyncMock) as mock_dns,
        patch("specter.server.tls_collector.collect", new_callable=AsyncMock) as mock_tls,
    ):
        mock_dns.return_value = mock_dns_result
        mock_tls.return_value = mock_tls_result

        inv_res = json.loads(await investigate_domain(case_id, "acme.corp"))
        assert inv_res["status"] == "COMPLETED"
        assert inv_res["dns_entities_found"] == 2

    # 4. Consultar Grafo
    graph_res = json.loads(query_graph(case_id))
    assert graph_res["total_nodes"] >= 2
    assert graph_res["total_edges"] >= 1

    # 5. Métricas de Red
    metrics_res = json.loads(analyze_network_metrics(case_id))
    assert metrics_res["total_nodes"] >= 2

    # 6. Verificación de Integridad de Custodia
    audit_res = json.loads(verify_case_integrity(case_id))
    assert audit_res["valid"] is True
    assert audit_res["status"] == "CHAIN_INTEGRITY_VERIFIED"
    assert audit_res["total_blocks"] >= 3

    # 7. Exportación de Dossier
    export_html_res = json.loads(export_case_dossier(case_id, format="html"))
    assert export_html_res["status"] == "DOSSIER_EXPORTED"
    assert Path(export_html_res["file_path"]).exists()

    export_md_res = json.loads(export_case_dossier(case_id, format="md"))
    assert export_md_res["status"] == "DOSSIER_EXPORTED"
    assert Path(export_md_res["file_path"]).exists()
