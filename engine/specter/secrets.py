"""
SpecterOSINT - Bóveda local de secretos
Almacén de API keys del motor (no del renderer).

Una key escrita en el ajuste del renderer acaba en el almacenamiento del
navegador y hay que reescribirla en cada sesión. Aquí vive en el directorio de
datos del motor, con permisos 0600, y **nunca** vuelve a salir por la API: sólo
se exponen el nombre y una versión enmascarada.

Sólo se aceptan nombres de una lista blanca (`ALLOWED_SECRETS`): la bóveda no es
un almacén genérico de claves ni un lugar donde volcar rutas o credenciales de
terceros.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from specter import config as specter_config

# Nombres admitidos → variable de entorno equivalente en el engine.
ALLOWED_SECRETS: dict[str, str] = {
    "opencode_api_key": "OPENCODE_API_KEY",
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "openai_api_key": "OPENAI_API_KEY",
    # Fase B (threat intel con key): solo se usan si están configuradas en la
    # UI (bóveda) o por env. Sin key, esos colectores se omiten en silencio.
    "virustotal_api_key": "VIRUSTOTAL_API_KEY",
    "shodan_api_key": "SHODAN_API_KEY",
    "greynoise_api_key": "GREYNOISE_API_KEY",
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
    "hunter_api_key": "HUNTER_API_KEY",
}

PROVIDER_SECRETS: dict[str, str] = {
    "opencode": "opencode_api_key",
    "anthropic": "anthropic_api_key",
    "openai": "openai_api_key",
}


class SecretError(ValueError):
    """Nombre de secreto no admitido o valor inválido."""


def provider_secret_name(provider: str) -> str | None:
    return PROVIDER_SECRETS.get(provider.lower())


def mask(value: str) -> str:
    """Versión mostrable de una clave: opaca total, sin prefijos ni sufijos.

    Mostrar 4+4 (práctica común) sigue permitiendo correlacionar claves entre
    capturas/SSE/logs. Aquí solo se expone `configured: true/false`.
    """
    return "•" * max(len(value), 8)


def _load() -> dict[str, str]:
    path = specter_config.secrets_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(name): str(value)
        for name, value in data.items()
        if name in ALLOWED_SECRETS and isinstance(value, str)
    }


def _store(data: dict[str, str]) -> None:
    path: Path = specter_config.secrets_path()
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)


def _validate_name(name: str) -> str:
    normalized = name.strip().lower()
    if normalized not in ALLOWED_SECRETS:
        raise SecretError(f"Secreto '{name}' no admitido. Válidos: {sorted(ALLOWED_SECRETS)}")
    return normalized


def set_secret(name: str, value: str) -> None:
    """Guarda (o reemplaza) una clave en la bóveda local."""
    normalized = _validate_name(name)
    if not value.strip():
        raise SecretError("El valor del secreto no puede estar vacío")
    data = _load()
    data[normalized] = value.strip()
    _store(data)


def get_secret(name: str) -> str | None:
    """Lee una clave; devuelve None si no está configurada."""
    try:
        normalized = _validate_name(name)
    except SecretError:
        return None
    return _load().get(normalized)


def delete_secret(name: str) -> bool:
    normalized = _validate_name(name)
    data = _load()
    if normalized not in data:
        return False
    del data[normalized]
    _store(data)
    return True


def list_secrets() -> list[dict[str, object]]:
    """Estado de la bóveda, sin valores en claro."""
    data = _load()
    return [
        {
            "name": name,
            "env_var": env_var,
            "configured": name in data,
            "masked": mask(data[name]) if name in data else None,
        }
        for name, env_var in sorted(ALLOWED_SECRETS.items())
    ]
