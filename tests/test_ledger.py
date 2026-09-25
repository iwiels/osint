import tempfile
from pathlib import Path

import pytest
from specter.osint_core.database import Database
from specter.osint_core.ledger import ForensicLedger
from specter.osint_core.models import CaseMetadata, RawEvidence


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_osint.db"
        yield Database(db_path)


@pytest.fixture
def sample_case(temp_db):
    case = CaseMetadata(
        case_id="case-2026-001",
        name="Operación Fénix",
        description="Investigación de infraestructura y huella digital",
        investigator="Analista_Forense_01",
    )
    temp_db.create_case(case)
    return case


def test_genesis_and_chain_verification(temp_db, sample_case):
    ledger = ForensicLedger(temp_db)
    genesis = ledger.initialize_case_genesis(sample_case)

    assert genesis.block_index == 0
    assert genesis.prev_hash == "0" * 64

    # Registrar evidencia 1
    evidence1 = RawEvidence(
        id="ev-001",
        case_id=sample_case.case_id,
        collector="dns_collector",
        source_url="dns://8.8.8.8",
        raw_payload='{"domain": "target.corp", "ip": "198.51.100.1"}',
        payload_hash="auto",
    )
    block1 = ledger.record_evidence_action(
        case_id=sample_case.case_id,
        collector="dns_collector",
        action="RESOLVED_A_RECORD",
        raw_evidence=evidence1,
    )

    assert block1.block_index == 1
    assert block1.prev_hash == genesis.block_hash

    # Registrar acción 2 (sin evidencia cruda adjunta)
    block2 = ledger.record_evidence_action(
        case_id=sample_case.case_id,
        collector="analyst",
        action="PIVOT_TO_SUBNET",
    )
    assert block2.block_index == 2
    assert block2.prev_hash == block1.block_hash

    # Verificar integridad
    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is True
    assert audit["total_blocks"] == 3
    assert audit["status"] == "CHAIN_INTEGRITY_VERIFIED"


def test_tamper_detection_on_block_hash(temp_db, sample_case):
    ledger = ForensicLedger(temp_db)
    ledger.initialize_case_genesis(sample_case)

    evidence = RawEvidence(
        id="ev-002",
        case_id=sample_case.case_id,
        collector="whois_collector",
        source_url="whois://arin.net",
        raw_payload="Registrant: John Doe",
        payload_hash="auto",
    )
    ledger.record_evidence_action(
        case_id=sample_case.case_id,
        collector="whois_collector",
        action="WHOIS_QUERY",
        raw_evidence=evidence,
    )

    # Simular ataque / manipulación directa en SQLite alterando el block_hash del bloque 1
    with temp_db.get_connection() as conn:
        conn.execute("UPDATE forensic_ledger SET block_hash = 'badhash123' WHERE block_index = 1")

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is False
    assert audit["tampered_block_index"] == 1
    assert "adulterada" in audit["error"].lower() or "ruptura" in audit["error"].lower()


def test_tamper_detection_on_raw_payload(temp_db, sample_case):
    ledger = ForensicLedger(temp_db)
    ledger.initialize_case_genesis(sample_case)

    evidence = RawEvidence(
        id="ev-003",
        case_id=sample_case.case_id,
        collector="crt_sh",
        source_url="https://crt.sh/?q=target.com",
        raw_payload="sub1.target.com, sub2.target.com",
        payload_hash="auto",
    )
    ledger.record_evidence_action(
        case_id=sample_case.case_id,
        collector="crt_sh",
        action="CERT_TRANSPARENCY",
        raw_evidence=evidence,
    )

    # Simular manipulación directa en SQLite modificando el payload de la evidencia
    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE evidences SET raw_payload = 'malicious_injected.target.com' WHERE id = 'ev-003'"
        )

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is False
    assert audit["tampered_block_index"] == 1
    assert "adulteración de evidencia" in audit["error"].lower()
