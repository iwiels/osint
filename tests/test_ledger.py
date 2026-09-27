from pathlib import Path

import pytest
from specter import config
from specter.osint_core.database import Database
from specter.osint_core.ledger import (
    ForensicLedger,
    compute_block_hash,
    compute_block_signature,
    key_fingerprint,
    verify_attestation,
)
from specter.osint_core.models import CaseMetadata, RawEvidence

# Clave de firma inyectada: los tests nunca dependen de data_dir/ledger.key.
KEY = bytes(range(32))
ROGUE_KEY = bytes(reversed(range(32)))


@pytest.fixture
def temp_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("SPECTER_LEDGER_KEY", raising=False)
    db_path = tmp_path / "test_osint.db"
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


# --- Firma HMAC (fase B) ---


def _sealed_ledger(temp_db, sample_case, key: bytes = KEY) -> ForensicLedger:
    """Caso sellado: génesis + una recolección con evidencia cruda."""
    ledger = ForensicLedger(temp_db, signing_key=key)
    ledger.initialize_case_genesis(sample_case)
    ledger.record_evidence_action(
        case_id=sample_case.case_id,
        collector="dns_collector",
        action="DNS_ENUMERATION: target.corp",
        raw_evidence=RawEvidence(
            id="ev-sealed",
            case_id=sample_case.case_id,
            collector="dns_collector",
            source_url="dns://target.corp",
            raw_payload='{"A": "198.51.100.1"}',
            payload_hash="auto",
        ),
    )
    return ledger


def test_signed_ledger_seals_every_block(temp_db, sample_case):
    ledger = _sealed_ledger(temp_db, sample_case)

    blocks = temp_db.get_case_ledger(sample_case.case_id)
    assert [b.signature for b in blocks] == [
        compute_block_signature(b.block_hash, KEY) for b in blocks
    ]
    assert all(b.signature for b in blocks)

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is True
    assert audit["status"] == "CHAIN_INTEGRITY_VERIFIED"
    assert audit["signature_status"] == "SEALED"
    assert audit["signed_blocks"] == 2
    assert audit["unsigned_blocks"] == 0
    assert audit["invalid_signature_blocks"] == []
    assert audit["key_id"] == key_fingerprint(KEY)
    assert audit["signature_version"] == "hmac-sha256-v1"


def test_clave_generada_despues_del_import_sigue_firmando(temp_db, sample_case, monkeypatch):
    """Regresión de arranque: la app crea la clave *después* de importar el kernel.

    El ledger se construye al importar los servicios (module-level) y la clave
    aparece cuando la app llama a `config.ensure_ledger_key()`; sin resolución
    perezosa, la cadena entera nacía sin firmar pese a existir la clave.
    """
    monkeypatch.delenv("SPECTER_LEDGER_KEY", raising=False)
    ledger = ForensicLedger(temp_db)  # se construye antes de que exista la clave
    assert ledger.signing_key is None

    # Bloque génesis nace sin firmar (antes de existir la clave)
    ledger.initialize_case_genesis(sample_case)

    generated = config.ensure_ledger_key()

    block = ledger.record_evidence_action(
        case_id=sample_case.case_id, collector="analyst", action="SEÑAL_POST_CLAVE"
    )
    assert block.signature == compute_block_signature(block.block_hash, generated)
    assert ledger.verify_case_integrity(sample_case.case_id)["signature_status"] == "PARTIAL"


def test_ledger_without_key_reports_unsigned(temp_db, sample_case):
    ledger = ForensicLedger(temp_db, signing_key=None)
    ledger.initialize_case_genesis(sample_case)

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is True
    assert audit["signature_status"] == "KEY_UNAVAILABLE"
    assert audit["signed_blocks"] == 0
    assert audit["unsigned_blocks"] == 1
    assert audit["key_id"] is None


def test_verificacion_sin_clave_de_cadena_firmada(temp_db, sample_case):
    _sealed_ledger(temp_db, sample_case)

    audit = ForensicLedger(temp_db, signing_key=None).verify_case_integrity(sample_case.case_id)

    assert audit["valid"] is True  # la cadena SHA-256 sigue siendo verificable
    assert audit["signature_status"] == "KEY_UNAVAILABLE"
    assert audit["unsigned_blocks"] == 2  # no se puede comprobar la firma sin la clave


def test_cadena_reconstruida_sin_la_clave_se_detecta(temp_db, sample_case):
    """Ataque realista: se reescribe un bloque y se rehace toda la cadena SHA-256.

    Sin firma ese ataque pasaría desapercibido; con HMAC sobrevive el sello
    del analista y la auditoría lo marca como firma inválida.
    """
    _sealed_ledger(temp_db, sample_case)
    blocks = temp_db.get_case_ledger(sample_case.case_id)

    forged_action = "DNS_ENUMERATION: otro-objetivo.corp"
    forged_hash = compute_block_hash(
        block_index=1,
        case_id=sample_case.case_id,
        timestamp=blocks[1].timestamp,
        collector=blocks[1].collector,
        action=forged_action,
        evidence_id=blocks[1].evidence_id,
        evidence_hash=blocks[1].evidence_hash,
        prev_hash=blocks[1].prev_hash,
    )
    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE forensic_ledger SET action = ?, block_hash = ?, signature = ? "
            "WHERE block_index = 1",
            (forged_action, forged_hash, compute_block_signature(forged_hash, ROGUE_KEY)),
        )

    audit = ForensicLedger(temp_db, signing_key=KEY).verify_case_integrity(sample_case.case_id)

    assert audit["valid"] is False
    assert audit["tampered_block_index"] == 1
    assert audit["invalid_signature_blocks"] == [1]
    assert "Firma HMAC inválida" in audit["error"]


def test_attest_case_emite_atestacion_verificable(temp_db, sample_case):
    ledger = _sealed_ledger(temp_db, sample_case)

    attestation = ledger.attest_case(sample_case.case_id)

    assert attestation["sealed"] is True
    assert attestation["chain_valid"] is True
    assert attestation["signature_status"] == "SEALED"
    assert attestation["algorithm"] == "hmac-sha256-v1"
    assert attestation["key_id"] == key_fingerprint(KEY)
    assert attestation["total_blocks"] == 2
    assert attestation["head"]["block_index"] == 1
    assert attestation["head"]["signature"] == attestation["head"]["signature"]

    payload = attestation["attestation"]["payload"]
    signature = attestation["attestation"]["signature"]
    assert attestation["head"]["block_hash"] in payload
    assert verify_attestation(payload, signature, KEY) is True
    assert verify_attestation(payload, signature, ROGUE_KEY) is False
    assert verify_attestation(payload + " ", signature, KEY) is False
    assert verify_attestation(payload, signature, None) is False


def test_attest_case_sin_clave_o_sin_cadena(temp_db, sample_case):
    unsigned = ForensicLedger(temp_db, signing_key=None)
    unsigned.initialize_case_genesis(sample_case)

    attestation = unsigned.attest_case(sample_case.case_id)
    assert attestation["sealed"] is False
    assert attestation["algorithm"] is None
    assert attestation["attestation"]["signature"] is None
    assert verify_attestation(attestation["attestation"]["payload"], "x", None) is False

    missing = unsigned.attest_case("case-inexistente")
    assert missing == {
        "case_id": "case-inexistente",
        "sealed": False,
        "error": "No hay cadena de custodia registrada para el caso case-inexistente",
    }


def test_cli_verify_audita_un_caso(temp_db, sample_case, capsys):
    import json as jsonlib

    from specter import verify

    _sealed_ledger(temp_db, sample_case)
    db_path = str(temp_db.db_path)

    assert verify.main([sample_case.case_id, "--db", db_path, "--key", KEY.hex()]) == 0
    payload = jsonlib.loads(capsys.readouterr().out)
    assert payload["valid"] is True and payload["signature_status"] == "SEALED"

    assert verify.main([sample_case.case_id, "--db", db_path, "--key", KEY.hex(), "--attest"]) == 0
    combined = jsonlib.loads(capsys.readouterr().out)
    assert combined["audit"]["valid"] is True
    assert combined["attestation"]["sealed"] is True

    # Con otra clave las firmas existen pero no verifican: INVALID, no UNSIGNED.
    assert verify.main([sample_case.case_id, "--db", db_path, "--key", ROGUE_KEY.hex()]) == 1
    tampered = jsonlib.loads(capsys.readouterr().out)
    assert tampered["valid"] is False
    assert tampered["signature_status"] == "INVALID"
    assert tampered["invalid_signature_blocks"] == [0, 1]


def test_cli_verify_caso_inexistente(temp_db, capsys):
    import json as jsonlib

    from specter import verify

    assert verify.main(["case-nada", "--db", str(temp_db.db_path)]) == 1
    payload = jsonlib.loads(capsys.readouterr().out)
    assert payload == {
        "valid": False,
        "error": "No se encontraron registros forenses para el caso case-nada",
        "total_blocks": 0,
    }
