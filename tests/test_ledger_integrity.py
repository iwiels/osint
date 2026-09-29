"""Regresiones de la auditoría de la cadena de custodia (fase 1).

Cada test reproduce un ataque que la verificación ANTIGUA daba por bueno:
límites de campo ambiguos, truncamiento de cola, firma borrada y cabeza
editada. Si alguno vuelve a pasar, la cadena miente diciendo "verificada".
"""

from __future__ import annotations

from pathlib import Path

import pytest
from specter.osint_core.database import Database
from specter.osint_core.ledger import (
    GENESIS_PREV_HASH,
    ForensicLedger,
    compute_block_hash,
    compute_block_hash_v1,
    compute_block_signature,
    compute_head_payload,
)
from specter.osint_core.models import CaseMetadata, RawEvidence

KEY = bytes(range(32))
ROGUE_KEY = bytes(reversed(range(32)))


@pytest.fixture
def temp_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SPECTER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("SPECTER_LEDGER_KEY", raising=False)
    yield Database(tmp_path / "audit_ledger.db")


@pytest.fixture
def sample_case(temp_db):
    case = CaseMetadata(
        case_id="case-2026-audit-1",
        name="Cadena bajo ataque",
        description="Regresiones de integridad",
        investigator="Auditor",
    )
    temp_db.create_case(case)
    return case


def _sealed_chain(temp_db, sample_case) -> ForensicLedger:
    """Génesis + dos registros, todo firmado con KEY."""
    ledger = ForensicLedger(temp_db, signing_key=KEY)
    ledger.initialize_case_genesis(sample_case)
    ledger.record_evidence_action(
        case_id=sample_case.case_id,
        collector="dns_collector",
        action="DNS_ENUMERATION: target.corp",
        raw_evidence=RawEvidence(
            id="ev-1",
            case_id=sample_case.case_id,
            collector="dns_collector",
            source_url="dns://target.corp",
            raw_payload='{"A": "198.51.100.1"}',
            payload_hash="auto",
        ),
    )
    ledger.record_evidence_action(
        case_id=sample_case.case_id,
        collector="analyst",
        action="PIVOT_TO_SUBNET",
    )
    return ledger


def test_intercambio_de_limitos_de_campo_se_detecta(temp_db, sample_case):
    """El ataque que hacía invisible la reescritura con el formato v1.

    `action` contiene ':', así que un string unido con ':' era ambiguo: mover
    texto de `action` a `collector` dejaba la cadena byte-idéntica y hash +
    HMAC seguían validando con un significado forense distinto.
    """
    ledger = _sealed_chain(temp_db, sample_case)
    blocks = temp_db.get_case_ledger(sample_case.case_id)
    original = blocks[1]

    # Premisa del bug: con el formato v1, los dos conjuntos de campos producen
    # EXACTAMENTE el mismo string.
    assert compute_block_hash_v1(
        block_index=original.block_index,
        case_id=original.case_id,
        timestamp=original.timestamp,
        collector=original.collector,
        action=original.action,
        evidence_id=original.evidence_id,
        evidence_hash=original.evidence_hash,
        prev_hash=original.prev_hash,
    ) == compute_block_hash_v1(
        block_index=original.block_index,
        case_id=original.case_id,
        timestamp=original.timestamp,
        collector="dns_collector:DNS_ENUMERATION",
        action=" target.corp",
        evidence_id=original.evidence_id,
        evidence_hash=original.evidence_hash,
        prev_hash=original.prev_hash,
    )

    # El ataque real: campos reescritos, hash y firma intactos.
    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE forensic_ledger SET collector = ?, action = ? WHERE block_index = 1",
            ("dns_collector:DNS_ENUMERATION", " target.corp"),
        )

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is False
    assert audit["tampered_block_index"] == 1
    assert "adulterada" in audit["error"].lower()


def test_truncamiento_de_cola_se_detecta(temp_db, sample_case):
    """Borrar los últimos bloques dejaba la cadena restante "verificada"."""
    ledger = _sealed_chain(temp_db, sample_case)  # bloques 0, 1, 2

    with temp_db.get_connection() as conn:
        conn.execute(
            "DELETE FROM forensic_ledger WHERE case_id = ? AND block_index = 2",
            (sample_case.case_id,),
        )

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is False
    assert audit["code"] == "HEAD_MISMATCH"

    # Variante: reescriben la cabeza para que "cuadre" con la cadena recortada.
    remaining = temp_db.get_case_ledger(sample_case.case_id)
    last = remaining[-1]
    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE ledger_heads SET block_index = ?, block_hash = ?, updated_at = ? "
            "WHERE case_id = ?",
            (last.block_index, last.block_hash, last.timestamp, sample_case.case_id),
        )
    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is False
    assert audit["code"] == "HEAD_SIGNATURE_INVALID"

    # Variante: borran también la cabeza.
    with temp_db.get_connection() as conn:
        conn.execute("DELETE FROM ledger_heads WHERE case_id = ?", (sample_case.case_id,))
    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is False
    assert audit["code"] == "MISSING_HEAD"


def test_firma_borrada_no_anula_el_hmac(temp_db, sample_case):
    """Poner la firma a NULL no debe devolver `valid: True` con clave disponible."""
    ledger = _sealed_chain(temp_db, sample_case)

    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE forensic_ledger SET signature = NULL WHERE case_id = ? AND block_index = 1",
            (sample_case.case_id,),
        )

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is False
    assert audit["code"] == "UNSIGNED_BLOCKS"
    assert audit["signature_status"] == "INVALID"
    assert audit["missing_signature_blocks"] == [1]


def test_cabeza_editada_se_detecta(temp_db, sample_case):
    """Alterar la fila de ancla invalida su HMAC aunque todo lo demás cuadre."""
    ledger = _sealed_chain(temp_db, sample_case)

    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE ledger_heads SET updated_at = ? WHERE case_id = ?",
            ("2030-01-01T00:00:00Z", sample_case.case_id),
        )

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is False
    assert audit["code"] == "HEAD_SIGNATURE_INVALID"


def test_cadena_intacta_sigue_verificando(temp_db, sample_case):
    """Regresión del camino feliz: intacta = válida + SEALED + cabeza firmada."""
    ledger = _sealed_chain(temp_db, sample_case)

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is True
    assert audit["status"] == "CHAIN_INTEGRITY_VERIFIED"
    assert audit["signature_status"] == "SEALED"
    assert audit["missing_signature_blocks"] == []

    head = temp_db.get_ledger_head(sample_case.case_id)
    assert head is not None
    assert head["block_index"] == 2
    assert head["signature"] == compute_block_signature(
        compute_head_payload(
            sample_case.case_id, head["block_index"], head["block_hash"], head["updated_at"]
        ),
        KEY,
    )


def test_cadena_v1_se_detecta_y_migra_con_reseal(temp_db, sample_case):
    """Migración (opción A): detectar el formato legado y re-sellarlo."""
    ledger = _sealed_chain(temp_db, sample_case)
    blocks = temp_db.get_case_ledger(sample_case.case_id)

    # Reconstruir la cadena exactamente como existía antes de la migración:
    # hashes en formato v1, sin firmas (preadolescente a la clave) y sin cabeza.
    prev = GENESIS_PREV_HASH
    with temp_db.get_connection() as conn:
        for block in blocks:
            legacy_hash = compute_block_hash_v1(
                block_index=block.block_index,
                case_id=block.case_id,
                timestamp=block.timestamp,
                collector=block.collector,
                action=block.action,
                evidence_id=block.evidence_id,
                evidence_hash=block.evidence_hash,
                prev_hash=prev,
            )
            conn.execute(
                "UPDATE forensic_ledger SET prev_hash = ?, block_hash = ?, signature = NULL "
                "WHERE case_id = ? AND block_index = ?",
                (prev, legacy_hash, sample_case.case_id, block.block_index),
            )
            prev = legacy_hash
        conn.execute("DELETE FROM ledger_heads WHERE case_id = ?", (sample_case.case_id,))

    audit = ledger.verify_case_integrity(sample_case.case_id)
    assert audit["valid"] is False
    assert audit["code"] == "LEGACY_HASH_FORMAT"
    assert f"/cases/{sample_case.case_id}/ledger/reseal" in audit["fix"]

    result = ledger.reseal_case_chain(sample_case.case_id)
    assert result["resealed"] is True
    assert result["signed"] is True
    assert result["total_blocks"] == len(blocks)

    healed = ledger.verify_case_integrity(sample_case.case_id)
    assert healed["valid"] is True
    assert healed["signature_status"] == "SEALED"

    # Idempotente: volver a re-sellar no cambia nada.
    again = ledger.reseal_case_chain(sample_case.case_id)
    assert again["resealed"] is True
    assert again["head_block_hash"] == result["head_block_hash"]
    assert ledger.verify_case_integrity(sample_case.case_id)["valid"] is True


def test_reseal_no_lavura_cadenas_adulteradas(temp_db, sample_case):
    """Campos alterados + hash rehecho + firma obsoleta: el reseal se niega."""
    ledger = _sealed_chain(temp_db, sample_case)
    blocks = temp_db.get_case_ledger(sample_case.case_id)
    victim = blocks[-1]  # el último bloque: sin sucesor que delate el trucazo

    forged_action = "PIVOT_TO_NAT"
    forged_hash = compute_block_hash(
        block_index=victim.block_index,
        case_id=victim.case_id,
        timestamp=victim.timestamp,
        collector=victim.collector,
        action=forged_action,
        evidence_id=victim.evidence_id,
        evidence_hash=victim.evidence_hash,
        prev_hash=victim.prev_hash,
    )
    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE forensic_ledger SET action = ?, block_hash = ? "
            "WHERE case_id = ? AND block_index = ?",
            (forged_action, forged_hash, sample_case.case_id, victim.block_index),
        )

    result = ledger.reseal_case_chain(sample_case.case_id)
    assert result["resealed"] is False
    assert result["code"] == "SIGNATURE_MISMATCH"


def test_reseal_no_lavura_cabeza_reescrita(temp_db, sample_case):
    """Firma del bloque borrada + cabeza re-apuntada: también se niega."""
    ledger = _sealed_chain(temp_db, sample_case)
    blocks = temp_db.get_case_ledger(sample_case.case_id)
    victim = blocks[-1]

    forged_action = "PIVOT_TO_NAT"
    forged_hash = compute_block_hash(
        block_index=victim.block_index,
        case_id=victim.case_id,
        timestamp=victim.timestamp,
        collector=victim.collector,
        action=forged_action,
        evidence_id=victim.evidence_id,
        evidence_hash=victim.evidence_hash,
        prev_hash=victim.prev_hash,
    )
    with temp_db.get_connection() as conn:
        conn.execute(
            "UPDATE forensic_ledger SET action = ?, block_hash = ?, signature = NULL "
            "WHERE case_id = ? AND block_index = ?",
            (forged_action, forged_hash, sample_case.case_id, victim.block_index),
        )
        conn.execute(
            "UPDATE ledger_heads SET block_hash = ? WHERE case_id = ?",
            (forged_hash, sample_case.case_id),
        )

    result = ledger.reseal_case_chain(sample_case.case_id)
    assert result["resealed"] is False
    assert result["code"] in ("HEAD_SIGNATURE_INVALID", "HEAD_MISMATCH")


def test_reseal_con_otra_clave_no_pasa(temp_db, sample_case):
    """Cadena firmada con una clave ajena: re-sellarla con otra clave se niega."""
    _sealed_chain(temp_db, sample_case)
    ledger = ForensicLedger(temp_db, signing_key=KEY)
    result = ledger.reseal_case_chain(sample_case.case_id)
    assert result["resealed"] is True  # cadena intacta con su clave: reseal legítimo

    # La cadena está firmada con KEY; alguien intenta re-sellarla con ROGUE:
    # el guard se niega en vez de reescribir la historia con otra clave.
    rotated = ForensicLedger(temp_db, signing_key=ROGUE_KEY)
    denied = rotated.reseal_case_chain(sample_case.case_id)
    assert denied["resealed"] is False
    assert denied["code"] == "SIGNATURE_MISMATCH"
