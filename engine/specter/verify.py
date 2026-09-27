"""
SpecterOSINT - Verificador de cadena de custodia (CLI)

Permite a un tercero auditar un caso sin abrir la app:

    python -m specter.verify case-20260924-abc123
    python -m specter.verify case-20260924-abc123 --attest --db C:/casos/mia.db

Sale con código 1 si la cadena no verifica, así que sirve en un pipeline de
peritaje (`... || echo "CADENA INVÁLIDA"`). La lógica vive en
`osint_core.ledger`; este módulo sólo resuelve rutas y formato de salida.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from specter import config
from specter.osint_core.database import Database
from specter.osint_core.ledger import ForensicLedger


def build_ledger(db_path: str | None = None, key_hex: str | None = None) -> ForensicLedger:
    """Reconstruye el ledger para auditar una base concreta con una clave dada."""
    database = Database(db_path or config.database_path())
    key = bytes.fromhex(key_hex) if key_hex else config.ledger_signing_key()
    return ForensicLedger(database, signing_key=key)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m specter.verify",
        description="Verifica la cadena de custodia forense de un caso",
    )
    parser.add_argument("case_id", help="Identificador del caso a auditar")
    parser.add_argument(
        "--db", default=None, help="Ruta de la base forense (por defecto: la del usuario)"
    )
    parser.add_argument("--key", default=None, help="Clave HMAC en hexadecimal")
    parser.add_argument(
        "--attest", action="store_true", help="Emite además la atestación firmada del caso"
    )
    args = parser.parse_args(argv)

    ledger = build_ledger(args.db, args.key)
    audit = ledger.verify_case_integrity(args.case_id)
    payload: Any = audit
    if args.attest:
        payload = {"audit": audit, "attestation": ledger.attest_case(args.case_id)}

    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if audit.get("valid") else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
