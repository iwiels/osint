"""
SpecterOSINT - Forensic Ledger
Cadena de custodia criptográfica inmutable con encadenamiento de hashes SHA-256.
"""

import hashlib
from typing import Any

from specter.osint_core.database import Database
from specter.osint_core.models import (
    CaseMetadata,
    LedgerBlock,
    RawEvidence,
    current_utc_iso,
)

GENESIS_PREV_HASH = "0" * 64


def compute_sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_block_hash(
    block_index: int,
    case_id: str,
    timestamp: str,
    collector: str,
    action: str,
    evidence_id: str | None,
    evidence_hash: str | None,
    prev_hash: str,
) -> str:
    serialized = (
        f"{block_index}:{case_id}:{timestamp}:{collector}:{action}:"
        f"{evidence_id or 'none'}:{evidence_hash or 'none'}:{prev_hash}"
    )
    return compute_sha256(serialized)


class ForensicLedger:
    def __init__(self, db: Database):
        self.db = db

    def initialize_case_genesis(self, case: CaseMetadata) -> LedgerBlock:
        existing = self.db.get_case_ledger(case.case_id)
        if existing:
            return existing[0]

        timestamp = case.created_at
        block_hash = compute_block_hash(
            block_index=0,
            case_id=case.case_id,
            timestamp=timestamp,
            collector="core_engine",
            action=f"GENESIS_CASE_INITIALIZED: {case.name}",
            evidence_id=None,
            evidence_hash=None,
            prev_hash=GENESIS_PREV_HASH,
        )

        genesis_block = LedgerBlock(
            block_index=0,
            case_id=case.case_id,
            timestamp=timestamp,
            collector="core_engine",
            action=f"GENESIS_CASE_INITIALIZED: {case.name}",
            evidence_id=None,
            evidence_hash=None,
            prev_hash=GENESIS_PREV_HASH,
            block_hash=block_hash,
        )
        self.db.insert_ledger_block(genesis_block)
        return genesis_block

    def record_evidence_action(
        self,
        case_id: str,
        collector: str,
        action: str,
        raw_evidence: RawEvidence | None = None,
    ) -> LedgerBlock:
        latest = self.db.get_latest_ledger_block(case_id)
        if not latest:
            raise ValueError(f"El caso {case_id} no tiene bloque Génesis inicializado.")

        if raw_evidence:
            computed_payload_hash = compute_sha256(raw_evidence.raw_payload)
            if raw_evidence.payload_hash != computed_payload_hash:
                raw_evidence.payload_hash = computed_payload_hash
            self.db.insert_evidence(raw_evidence)

        block_index = latest.block_index + 1
        timestamp = current_utc_iso()
        prev_hash = latest.block_hash
        ev_id = raw_evidence.id if raw_evidence else None
        ev_hash = raw_evidence.payload_hash if raw_evidence else None

        block_hash = compute_block_hash(
            block_index=block_index,
            case_id=case_id,
            timestamp=timestamp,
            collector=collector,
            action=action,
            evidence_id=ev_id,
            evidence_hash=ev_hash,
            prev_hash=prev_hash,
        )

        block = LedgerBlock(
            block_index=block_index,
            case_id=case_id,
            timestamp=timestamp,
            collector=collector,
            action=action,
            evidence_id=ev_id,
            evidence_hash=ev_hash,
            prev_hash=prev_hash,
            block_hash=block_hash,
        )
        self.db.insert_ledger_block(block)
        return block

    def verify_case_integrity(self, case_id: str) -> dict[str, Any]:
        blocks = self.db.get_case_ledger(case_id)
        if not blocks:
            return {
                "valid": False,
                "error": f"No se encontraron registros forenses para el caso {case_id}",
                "total_blocks": 0,
            }

        # Validar Bloque Génesis (índice 0)
        genesis = blocks[0]
        if genesis.block_index != 0 or genesis.prev_hash != GENESIS_PREV_HASH:
            return {
                "valid": False,
                "error": "Bloque Génesis corrupto o apuntador previo inválido",
                "tampered_block_index": 0,
            }

        expected_genesis_hash = compute_block_hash(
            block_index=0,
            case_id=genesis.case_id,
            timestamp=genesis.timestamp,
            collector=genesis.collector,
            action=genesis.action,
            evidence_id=genesis.evidence_id,
            evidence_hash=genesis.evidence_hash,
            prev_hash=genesis.prev_hash,
        )
        if genesis.block_hash != expected_genesis_hash:
            return {
                "valid": False,
                "error": "Hash del Bloque Génesis ha sido modificado deliberadamente",
                "tampered_block_index": 0,
            }

        # Validar encadenamiento progresivo de bloques
        for i in range(1, len(blocks)):
            curr = blocks[i]
            prev = blocks[i - 1]

            if curr.prev_hash != prev.block_hash:
                return {
                    "valid": False,
                    "error": f"Ruptura en la cadena de custodia: prev_hash en bloque {curr.block_index} no coincide con bloque previo",
                    "tampered_block_index": curr.block_index,
                }

            expected_curr_hash = compute_block_hash(
                block_index=curr.block_index,
                case_id=curr.case_id,
                timestamp=curr.timestamp,
                collector=curr.collector,
                action=curr.action,
                evidence_id=curr.evidence_id,
                evidence_hash=curr.evidence_hash,
                prev_hash=curr.prev_hash,
            )
            if curr.block_hash != expected_curr_hash:
                return {
                    "valid": False,
                    "error": f"Firma criptográfica adulterada en el bloque {curr.block_index}",
                    "tampered_block_index": curr.block_index,
                }

            # Si el bloque referencia evidencia, validar el payload crudo almacenado
            if curr.evidence_id:
                evidence = self.db.get_evidence(curr.evidence_id)
                if not evidence:
                    return {
                        "valid": False,
                        "error": f"Evidencia faltante {curr.evidence_id} referenciada en bloque {curr.block_index}",
                        "tampered_block_index": curr.block_index,
                    }
                payload_recomputed_hash = compute_sha256(evidence.raw_payload)
                if payload_recomputed_hash != curr.evidence_hash:
                    return {
                        "valid": False,
                        "error": f"Adulteración de evidencia cruda detectada en bloque {curr.block_index} (Payload SHA-256 no coincide)",
                        "tampered_block_index": curr.block_index,
                    }

        return {
            "valid": True,
            "case_id": case_id,
            "total_blocks": len(blocks),
            "head_block_hash": blocks[-1].block_hash,
            "verified_at": current_utc_iso(),
            "status": "CHAIN_INTEGRITY_VERIFIED",
        }
