"""
WraithOSINT - Forensic Ledger
Ledger de auditoría con encadenamiento de hashes SHA-256 y firma HMAC opcional.

Dos capas de integridad:
  1. Encadenamiento SHA-256 (siempre): cada bloque referencia el hash previo.
  2. Firma HMAC-SHA256 por bloque (cuando hay clave): la cadena rota una
     alteración, la firma impide *rehacerla* sin la clave del analista.

La clave se resuelve en `specter.config` (env → data_dir/ledger.key → None).
Sin clave el ledger funciona en modo sin firmar y la auditoría lo reporta como
`UNSIGNED` en vez de mentir diciendo que el caso está sellado.
"""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from specter import config as specter_config
from specter.osint_core.database import Database
from specter.osint_core.models import (
    CaseMetadata,
    LedgerBlock,
    RawEvidence,
    current_utc_iso,
)

GENESIS_PREV_HASH = "0" * 64
SIGNATURE_VERSION = "hmac-sha256-v1"

_UNSET = object()


def compute_sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_block_signature(block_hash: str, key: bytes | None) -> str | None:
    """HMAC-SHA256 del hash del bloque; None si el ledger corre sin clave.

    La firma cubre block_hash, que a su vez compromete índice, caso, timestamp,
    collector, acción, evidencia y prev_hash: alterar cualquier campo rompe la
    firma. Sin la clave, quien tenga acceso a SQLite puede recomputar toda la
    cadena SHA-256, pero no volver a firmarla.
    """
    if not key:
        return None
    return hmac.new(key, block_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def key_fingerprint(key: bytes | None) -> str | None:
    """Identificador público de la clave: dice *qué* clave firmó, sin revelarla."""
    if not key:
        return None
    return hashlib.sha256(key).hexdigest()[:16]


def verify_attestation(payload: str, signature: str, key: bytes | None) -> bool:
    """Verifica una atestación detached emitida por `attest_case()`."""
    if not key:
        return False
    expected = compute_block_signature(payload, key)
    return bool(expected) and hmac.compare_digest(expected, signature)


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
    """Hash canónico del bloque: JSON de la tupla de campos, sin límites ambiguos.

    v1 unía los campos con ':' sin escapar y `action` contiene ':' en datos
    reales ("GENESIS_CASE_INITIALIZED: nombre"), de modo que mover texto de un
    campo a otro dejaba la cadena byte-idéntica: hash Y HMAC seguían validando
    con un significado forense distinto. Con JSON el límite de campo es
    inequívoco (y `ensure_ascii=False` + separadores fijos lo hacen estable).
    """
    serialized = json.dumps(
        [
            block_index,
            case_id,
            timestamp,
            collector,
            action,
            evidence_id or "none",
            evidence_hash or "none",
            prev_hash,
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return compute_sha256(serialized)


def compute_block_hash_v1(
    block_index: int,
    case_id: str,
    timestamp: str,
    collector: str,
    action: str,
    evidence_id: str | None,
    evidence_hash: str | None,
    prev_hash: str,
) -> str:
    """Formato legado (':' sin escapar): sólo para detectar y migrar cadenas v1."""
    serialized = (
        f"{block_index}:{case_id}:{timestamp}:{collector}:{action}:"
        f"{evidence_id or 'none'}:{evidence_hash or 'none'}:{prev_hash}"
    )
    return compute_sha256(serialized)


def compute_head_payload(case_id: str, block_index: int, block_hash: str, updated_at: str) -> str:
    """Payload canónico de la cabeza firmada que ancla la cola de la cadena.

    Sin este ancla, borrar los últimos N bloques deja una cadena autoconsistente
    y la verificación la daba por buena; la firma de la cabeza no se puede rehacer
    sin la clave, así que el truncamiento queda visible.
    """
    return json.dumps(
        {
            "block_hash": block_hash,
            "block_index": block_index,
            "case_id": case_id,
            "updated_at": updated_at,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


class ForensicLedger:
    def __init__(self, db: Database, signing_key: bytes | None | object = _UNSET):
        self.db = db
        # Sin clave explícita (`_UNSET`) la bóveda se consulta en el primer uso;
        # pasar None fija un ledger sin firmar (auditoría de sólo lectura, tests).
        self._explicit_key = signing_key is not _UNSET
        self._signing_key: bytes | None = None if not self._explicit_key else signing_key  # type: ignore[assignment]

    @property
    def signing_key(self) -> bytes | None:
        """Clave HMAC, resuelta **en el primer uso** y no al importar el módulo.

        El kernel construye sus servicios al importarse (module-level), es decir
        antes de que la app llame a `config.ensure_ledger_key()`. Resolviendo la
        clave en el import, la cadena nacía sin firmar aun existiendo la clave;
        con resolución perezosa el primer bloque ya sale firmado.
        """
        if self._signing_key is not None or self._explicit_key:
            return self._signing_key
        found = specter_config.ledger_signing_key()
        if found is not None:
            self._signing_key = found
        return self._signing_key

    def _head_signature(
        self, case_id: str, block_index: int, block_hash: str, updated_at: str
    ) -> str | None:
        """HMAC de la cabeza firmada (None en ledgers sin clave)."""
        return compute_block_signature(
            compute_head_payload(case_id, block_index, block_hash, updated_at),
            self.signing_key,
        )

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
            signature=compute_block_signature(block_hash, self.signing_key),
        )
        self.db.insert_ledger_block(
            genesis_block,
            head_signature=self._head_signature(case.case_id, 0, block_hash, timestamp),
        )
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
            signature=compute_block_signature(block_hash, self.signing_key),
        )
        self.db.insert_ledger_block(
            block,
            head_signature=self._head_signature(case_id, block_index, block_hash, timestamp),
        )
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
            # ¿No coincide pero sí con el formato v1? La cadena es anterior a la
            # serialización canónica: no está adulterada, está sin migrar.
            legacy_genesis_hash = compute_block_hash_v1(
                block_index=0,
                case_id=genesis.case_id,
                timestamp=genesis.timestamp,
                collector=genesis.collector,
                action=genesis.action,
                evidence_id=genesis.evidence_id,
                evidence_hash=genesis.evidence_hash,
                prev_hash=genesis.prev_hash,
            )
            if genesis.block_hash == legacy_genesis_hash:
                return {
                    "valid": False,
                    "error": (
                        "Cadena en formato de hash legado (v1, límites de campo "
                        "ambiguos): no es verificable con el formato vigente. "
                        "Ejecuta el reseal (POST /cases/{case_id}/ledger/reseal)."
                    ),
                    "code": "LEGACY_HASH_FORMAT",
                    "fix": f"POST /cases/{case_id}/ledger/reseal",
                    "tampered_block_index": 0,
                }
            return {
                "valid": False,
                "error": "Hash del Bloque Génesis ha sido modificado deliberadamente",
                "tampered_block_index": 0,
            }

        # Validar encadenamiento progresivo de bloques
        for i in range(1, len(blocks)):
            curr = blocks[i]
            prev = blocks[i - 1]

            if curr.block_index != i:
                return {
                    "valid": False,
                    "error": (
                        f"Índice de bloque no contiguo: se esperaba {i} y llegó "
                        f"{curr.block_index} (bloques borrados del medio de la cadena)"
                    ),
                    "tampered_block_index": curr.block_index,
                }

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

                try:
                    artifact = json.loads(evidence.raw_payload)
                except (TypeError, json.JSONDecodeError):
                    artifact = None
                if isinstance(artifact, dict) and artifact.get("evidence_type") == "WARC_CAPTURE":
                    path_value = artifact.get("warc_path")
                    expected_warc_hash = artifact.get("sha256")
                    if not isinstance(path_value, str) or not isinstance(expected_warc_hash, str):
                        return {
                            "valid": False,
                            "error": f"Referencia WARC inválida en bloque {curr.block_index}",
                            "tampered_block_index": curr.block_index,
                        }
                    try:
                        warc_root = (specter_config.data_dir() / "warc").resolve()
                        case_root = (warc_root / case_id).resolve()
                        warc_path = Path(path_value).resolve(strict=True)
                        if not warc_path.is_relative_to(case_root) or not warc_path.is_file():
                            raise OSError("ruta fuera del caso o no es un archivo")
                        digest = hashlib.sha256()
                        with warc_path.open("rb") as warc_file:
                            for chunk in iter(lambda: warc_file.read(1024 * 1024), b""):
                                digest.update(chunk)
                    except (OSError, RuntimeError, ValueError) as exc:
                        return {
                            "valid": False,
                            "error": f"WARC faltante o inaccesible en bloque {curr.block_index}: {exc}",
                            "tampered_block_index": curr.block_index,
                        }
                    if digest.hexdigest() != expected_warc_hash:
                        return {
                            "valid": False,
                            "error": f"Hash del archivo WARC no coincide en bloque {curr.block_index}",
                            "tampered_block_index": curr.block_index,
                        }

        signatures = self._verify_signatures(blocks)
        if signatures["invalid_signature_blocks"]:
            first_invalid = signatures["invalid_signature_blocks"][0]
            return {
                "valid": False,
                "error": (
                    f"Firma HMAC inválida en el bloque {first_invalid}: la cadena fue "
                    "reconstruida sin la clave de custodia"
                ),
                "tampered_block_index": first_invalid,
                **signatures,
            }
        if signatures["missing_signature_blocks"]:
            first_missing = signatures["missing_signature_blocks"][0]
            return {
                "valid": False,
                "error": (
                    f"{len(signatures['missing_signature_blocks'])} bloques sin firma "
                    "habiendo clave de custodia: la capa HMAC fue eliminada (o la "
                    "cadena es anterior a la migración). Ejecuta el reseal "
                    f"(POST /cases/{case_id}/ledger/reseal) para volver a sellarla."
                ),
                "code": "UNSIGNED_BLOCKS",
                "tampered_block_index": first_missing,
                **signatures,
            }

        head_error = self._verify_head(case_id, blocks[-1])
        if head_error is not None:
            return head_error

        return {
            "valid": True,
            "case_id": case_id,
            "total_blocks": len(blocks),
            "head_block_hash": blocks[-1].block_hash,
            "verified_at": current_utc_iso(),
            "status": "CHAIN_INTEGRITY_VERIFIED",
            **signatures,
        }

    def _verify_head(self, case_id: str, last: LedgerBlock) -> dict[str, Any] | None:
        """Comprueba la cabeza firmada contra el último bloque (None si todo cuadra).

        Es lo que detecta el truncamiento de cola: borrar bloques finales deja
        la cadena restante autoconsistente, pero la cabeza firmada sigue
        apuntando al bloque que ya no está (o su firma deja de cuadrar).
        """
        head = self.db.get_ledger_head(case_id)
        if head is None:
            return {
                "valid": False,
                "error": (
                    "Sin cabeza firmada para la cadena: la fila de ancla fue "
                    "eliminada o la cadena es anterior a la migración. Ejecuta el "
                    f"reseal (POST /cases/{case_id}/ledger/reseal)."
                ),
                "code": "MISSING_HEAD",
                "tampered_block_index": last.block_index,
            }
        if head["block_index"] != last.block_index or head["block_hash"] != last.block_hash:
            return {
                "valid": False,
                "error": (
                    f"Cabeza firmada no coincide con el final de la cadena "
                    f"(head={head['block_index']}/{head['block_hash'][:12]}…, "
                    f"último={last.block_index}/{last.block_hash[:12]}…): "
                    "bloques eliminados de la cola"
                ),
                "code": "HEAD_MISMATCH",
                "tampered_block_index": last.block_index,
            }
        key = self.signing_key
        if key is not None:
            expected = compute_block_signature(
                compute_head_payload(
                    case_id, head["block_index"], head["block_hash"], head["updated_at"]
                ),
                key,
            )
            if (
                not head["signature"]
                or expected is None
                or not hmac.compare_digest(head["signature"], expected)
            ):
                return {
                    "valid": False,
                    "error": (
                        "Firma HMAC de la cabeza inválida: la cabeza fue reescrita "
                        "sin la clave de custodia"
                    ),
                    "code": "HEAD_SIGNATURE_INVALID",
                    "tampered_block_index": last.block_index,
                }
        return None

    def _verify_signatures(self, blocks: list[LedgerBlock]) -> dict[str, Any]:
        """Estado de sellado de la cadena: cuántos bloques están firmados y válidos.

        Con clave disponible, un bloque SIN firma es **inválido**, no "unsigned":
        borrar la columna firma no debe anular la capa HMAC (regresión de la
        auditoría: con el criterio antiguo, un atacante con SQLite dejaba la
        cadena en `UNSIGNED`/`PARTIAL` y la verificación seguía dando `valid`).
        Sólo sin clave se cuenta como no juzgable (`KEY_UNAVAILABLE`).
        """
        verified = 0
        unsigned = 0
        missing: list[int] = []
        invalid: list[int] = []

        key = self.signing_key
        for block in blocks:
            if key is None:
                unsigned += 1
                continue
            if not block.signature:
                missing.append(block.block_index)
                continue
            expected = compute_block_signature(block.block_hash, key)
            if expected is not None and hmac.compare_digest(block.signature, expected):
                verified += 1
            else:
                invalid.append(block.block_index)

        if key is None:
            status = "KEY_UNAVAILABLE"
        elif invalid or missing:
            status = "INVALID"
        elif blocks and verified == len(blocks):
            status = "SEALED"
        else:
            status = "UNSIGNED"

        return {
            "signature_status": status,
            "signature_version": SIGNATURE_VERSION,
            "signed_blocks": verified,
            "unsigned_blocks": unsigned,
            "invalid_signature_blocks": invalid,
            "missing_signature_blocks": missing,
            "key_id": key_fingerprint(key),
        }

    def _reseal_guard(self, case_id: str, blocks: list[LedgerBlock]) -> dict[str, Any] | None:
        """Motivo para rechazar el reseal, o None si la migración es segura.

        Comprueba tres cosas antes de reescribir nada:
        1. Cada bloque validaba en el formato v1 **o** en el vigente (admite
           cadenas mixtas: bloques v1 + añadidos por el código nuevo).
        2. Las firmas existentes (si las hay) siguen verificando con la clave
           actual: una firma que no cuadra significa campos alterados + hash
           rehecho.
        3. La cabeza firmada existe si la cadena ya fue migrada y coincide con
           la cola: detecta truncamientos recientes.
        Sin clave no hay ground truth criptográfico que comprobar (una cadena
        nunca firmada es reformateable por cualquiera con SQLite); en ese caso
        sólo se juzga la estructura.
        """
        prev = GENESIS_PREV_HASH
        for index, block in enumerate(blocks):
            if block.block_index != index or block.prev_hash != prev:
                return {
                    "code": "CHAIN_INVALID_FOR_RESEAL",
                    "error": (
                        f"Índices/encadenamiento incoherentes en el bloque "
                        f"{block.block_index}: la cadena no es candidata a reseal."
                    ),
                }
            known = {
                compute_block_hash_v1(
                    block_index=block.block_index,
                    case_id=block.case_id,
                    timestamp=block.timestamp,
                    collector=block.collector,
                    action=block.action,
                    evidence_id=block.evidence_id,
                    evidence_hash=block.evidence_hash,
                    prev_hash=prev,
                ),
                compute_block_hash(
                    block_index=block.block_index,
                    case_id=block.case_id,
                    timestamp=block.timestamp,
                    collector=block.collector,
                    action=block.action,
                    evidence_id=block.evidence_id,
                    evidence_hash=block.evidence_hash,
                    prev_hash=prev,
                ),
            }
            if block.block_hash not in known:
                return {
                    "code": "CHAIN_INVALID_FOR_RESEAL",
                    "error": (
                        f"Los campos del bloque {block.block_index} no producen su "
                        "hash en ningún formato conocido: posible adulteración. "
                        "El reseal queda rechazado; audita la cadena antes de continuar."
                    ),
                }
            prev = block.block_hash

        key = self.signing_key
        if key is None:
            return None

        for block in blocks:
            if not block.signature:
                continue
            expected = compute_block_signature(block.block_hash, key)
            if expected is None or not hmac.compare_digest(block.signature, expected):
                return {
                    "code": "SIGNATURE_MISMATCH",
                    "error": (
                        f"La firma existente del bloque {block.block_index} no "
                        "verifica con la clave actual: los campos fueron alterados "
                        "y el hash rehecho. El reseal queda rechazado."
                    ),
                }

        head = self.db.get_ledger_head(case_id)
        if head is None:
            return None  # cadena v1 sin cabeza: migración pendiente, esperado
        last = blocks[-1]
        if head["block_index"] != last.block_index or head["block_hash"] != last.block_hash:
            return {
                "code": "HEAD_MISMATCH",
                "error": (
                    "La cabeza firmada no coincide con la cola de la cadena "
                    "(posible truncamiento). El reseal queda rechazado."
                ),
            }
        expected_head = compute_block_signature(
            compute_head_payload(
                case_id, head["block_index"], head["block_hash"], head["updated_at"]
            ),
            key,
        )
        if (
            not head["signature"]
            or expected_head is None
            or not hmac.compare_digest(head["signature"], expected_head)
        ):
            return {
                "code": "HEAD_SIGNATURE_INVALID",
                "error": (
                    "La firma de la cabeza no verifica: la cabeza fue reescrita "
                    "sin la clave. El reseal queda rechazado."
                ),
            }
        return None

    def reseal_case_chain(self, case_id: str) -> dict[str, Any]:
        """Reescribe hashes, encadenamiento, firmas y cabeza con el formato vigente.

        Migración de cadenas v1 (y de cadenas con bloques sin firma): recalcula
        desde los campos de cada bloque, que son inmutables, así que la
        operación es idempotente. Sólo con clave se firman los bloques y la
        cabeza; sin clave re-hashea y la cadena queda `KEY_UNAVAILABLE`.

        El `_reseal_guard` evita usarlo para lavar una manipulación: una cadena
        que no valida en ningún formato, con firmas que no cuadran o con la
        cabeza desincronizada se rechaza.
        """
        blocks = self.db.get_case_ledger(case_id)
        if not blocks:
            return {
                "resealed": False,
                "case_id": case_id,
                "error": f"No hay cadena de custodia para el caso {case_id}",
            }
        guard = self._reseal_guard(case_id, blocks)
        if guard is not None:
            return {"resealed": False, "case_id": case_id, **guard}

        key = self.signing_key
        prev = GENESIS_PREV_HASH
        rows: list[tuple[int, str, str, str | None]] = []
        for block in blocks:
            new_hash = compute_block_hash(
                block_index=block.block_index,
                case_id=block.case_id,
                timestamp=block.timestamp,
                collector=block.collector,
                action=block.action,
                evidence_id=block.evidence_id,
                evidence_hash=block.evidence_hash,
                prev_hash=prev,
            )
            rows.append((block.block_index, prev, new_hash, compute_block_signature(new_hash, key)))
            prev = new_hash

        last = blocks[-1]
        head_hash = rows[-1][2]
        self.db.reseal_ledger_chain(
            case_id,
            rows=rows,
            head_block_index=last.block_index,
            head_block_hash=head_hash,
            head_updated_at=last.timestamp,
            head_signature=self._head_signature(
                case_id, last.block_index, head_hash, last.timestamp
            ),
        )
        return {
            "resealed": True,
            "case_id": case_id,
            "total_blocks": len(blocks),
            "head_block_hash": head_hash,
            "signed": key is not None,
        }

    def attest_case(self, case_id: str) -> dict[str, Any]:
        """Sella el estado actual y emite una atestación HMAC detached.

        La atestación es *detached*: payload canónico (JSON con claves
        ordenadas) + HMAC. Un auditor necesita la clave secreta para validarla;
        compartirla también permite crear atestaciones. El objeto solo resume
        la cabeza de la cadena, no contiene el ledger ni prueba por sí mismo
        cada evidencia del caso.
        """
        blocks = self.db.get_case_ledger(case_id)
        if not blocks:
            return {
                "case_id": case_id,
                "sealed": False,
                "error": f"No hay cadena de custodia registrada para el caso {case_id}",
            }

        audit = self.verify_case_integrity(case_id)
        head = blocks[-1]
        payload = json.dumps(
            {
                "case_id": case_id,
                "block_index": head.block_index,
                "block_hash": head.block_hash,
                "head_signature": head.signature,
                "total_blocks": len(blocks),
                "sealed_at": current_utc_iso(),
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        signature = compute_block_signature(payload, self.signing_key)

        return {
            "case_id": case_id,
            "sealed": bool(signature) and bool(audit.get("valid")),
            "algorithm": SIGNATURE_VERSION if signature else None,
            "key_id": key_fingerprint(self.signing_key),
            "chain_valid": bool(audit.get("valid")),
            "signature_status": audit.get("signature_status"),
            "total_blocks": len(blocks),
            "head": {
                "block_index": head.block_index,
                "block_hash": head.block_hash,
                "signature": head.signature,
                "action": head.action,
                "timestamp": head.timestamp,
            },
            "attestation": {"payload": payload, "signature": signature},
        }
