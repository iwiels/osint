"""
SpecterOSINT - Permission Gate
Motor de permisos con wildcards para control de acceso a herramientas y recursos.

Inspirado en OpenCode pero adaptado a la arquitectura Python/FastAPI del proyecto.
Soporta reglas con wildcards (*, ?, [seq]) mediante fnmatch.
"""

import fnmatch
import uuid
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class PermissionEffect(StrEnum):
    """Efecto de una regla de permiso."""

    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


class PermissionAction(StrEnum):
    """Acciones que pueden ser reguladas por el Permission Gate."""

    COLLECT = "collect"
    RESOLVE = "resolve"
    CORRELATE = "correlate"
    EXPORT = "export"
    DELETE = "delete"


class PermissionRule(BaseModel):
    """Regla de permisos con soporte para wildcards.

    Attributes:
        action: Acción a regular (collect, resolve, correlate, export, delete)
        resource: Patrón del recurso con wildcards (ej: "collector:dns_*")
        effect: Efecto de la regla (allow, deny, ask)
        rule_id: Identificador único de la regla (auto-generado)
        description: Descripción opcional de la regla
    """

    action: str = Field(description="Acción: collect, resolve, correlate, export, delete")
    resource: str = Field(description="Patrón del recurso con wildcards (ej: 'collector:dns_*')")
    effect: Literal["allow", "deny", "ask"] = Field(description="Efecto: allow, deny o ask")
    rule_id: str = Field(default_factory=lambda: f"rule-{uuid.uuid4().hex[:8]}")
    description: str = Field(default="", description="Descripción opcional de la regla")

    def matches(self, action: str, resource: str) -> bool:
        """Verifica si la regla coincide con la acción y recurso dados."""
        return fnmatch.fnmatch(action, self.action) and fnmatch.fnmatch(resource, self.resource)


class PermissionRequest(BaseModel):
    """Solicitud de permiso cuando una regla tiene effect='ask'."""

    request_id: str = Field(default_factory=lambda: f"perm-{uuid.uuid4().hex[:8]}")
    action: str
    resource: str
    message: str = Field(default="", description="Mensaje para el usuario solicitando confirmación")
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class PermissionGate:
    """Motor de permisos con soporte para wildcards.

    Evalúa reglas en orden de inserción. La primera regla que coincide determina
    el efecto. Si ninguna regla coincide, el efecto por defecto es 'ask' (fail-closed).

    El gate puede emitir eventos cuando se encuentra una regla 'ask', permitiendo
    que el agente solicite confirmación al usuario antes de proceder.
    """

    def __init__(self) -> None:
        self._rules: list[PermissionRule] = []
        self._listeners: list[Callable[[PermissionRequest], Any]] = []
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        """Carga las reglas pre-definidas del sistema."""
        defaults: list[PermissionRule] = [
            # Colectores DNS: permitir
            PermissionRule(
                action="collect",
                resource="collector:dns_*",
                effect="allow",
                description="Permitir colectores DNS (zonexfer, bruteforce, etc.)",
            ),
            # Colectores CRT: permitir
            PermissionRule(
                action="collect",
                resource="collector:crt_*",
                effect="allow",
                description="Permitir colectores de Certificate Transparency",
            ),
            # ThreatFox: permitir
            PermissionRule(
                action="collect",
                resource="collector:threatfox",
                effect="allow",
                description="Permitir consultas a ThreatFox",
            ),
            # VirusTotal: requiere confirmación
            PermissionRule(
                action="collect",
                resource="collector:virustotal",
                effect="ask",
                description="VirusTotal requiere confirmación del analista",
            ),
            # Resolución de entidades: permitir
            PermissionRule(
                action="resolve",
                resource="entity:*",
                effect="allow",
                description="Permitir resolución de cualquier entidad",
            ),
            # Correlación de casos: permitir
            PermissionRule(
                action="correlate",
                resource="case:*",
                effect="allow",
                description="Permitir correlación entre casos",
            ),
            # Exportar casos: requiere confirmación
            PermissionRule(
                action="export",
                resource="case:*",
                effect="ask",
                description="Exportar casos requiere confirmación del analista",
            ),
            # Eliminar casos: denegar por defecto
            PermissionRule(
                action="delete",
                resource="case:*",
                effect="deny",
                description="Eliminar casos está denegado por defecto",
            ),
        ]
        for rule in defaults:
            self._rules.append(rule)

    def add_rule(self, rule: PermissionRule) -> PermissionRule:
        """Agrega una nueva regla al gate.

        Args:
            rule: La regla a agregar

        Returns:
            La regla agregada (con su rule_id generado)
        """
        self._rules.append(rule)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        """Elimina una regla por su ID.

        Args:
            rule_id: ID de la regla a eliminar

        Returns:
            True si la regla fue eliminada, False si no existía
        """
        initial_len = len(self._rules)
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        return len(self._rules) < initial_len

    def get_rules(self) -> list[PermissionRule]:
        """Retorna una copia de todas las reglas activas."""
        return list(self._rules)

    def clear_rules(self) -> None:
        """Elimina todas las reglas (útil para testing)."""
        self._rules.clear()

    def evaluate(self, action: str, resource: str) -> PermissionEffect:
        """Evalúa los permisos para una acción y recurso.

        Evalúa reglas en orden. La primera regla que coincide determina el efecto.
        Si ninguna regla coincide, retorna 'ask' (fail-closed por seguridad).

        Args:
            action: Acción a evaluar (ej: "collect")
            resource: Recurso a evaluar (ej: "collector:dns_zonexfer")

        Returns:
            El efecto de la primera regla coincidente, o 'ask' si ninguna coincide
        """
        for rule in self._rules:
            if rule.matches(action, resource):
                return PermissionEffect(rule.effect)
        # Fail-closed: si ninguna regla coincide, pedir confirmación
        return PermissionEffect.ASK

    def check(self, action: str, resource: str) -> tuple[bool, PermissionRequest | None]:
        """Verifica si una acción está permitida.

        Args:
            action: Acción a verificar
            resource: Recurso a verificar

        Returns:
            Tupla (permitido, solicitud). Si permitido es False y hay una solicitud,
            el caller debe emitir el evento permission.request y esperar confirmación.
        """
        effect = self.evaluate(action, resource)

        if effect == PermissionEffect.ALLOW:
            return True, None

        if effect == PermissionEffect.DENY:
            return False, None

        # ASK: crear solicitud de permiso
        request = PermissionRequest(
            action=action,
            resource=resource,
            message=f"Se requiere confirmación para '{action}' sobre '{resource}'",
        )
        return False, request

    def add_listener(self, listener: Callable[[PermissionRequest], Any]) -> None:
        """Registra un listener para eventos de solicitud de permiso.

        Args:
            listener: Callable que recibe un PermissionRequest
        """
        self._listeners.append(listener)

    def remove_listener(self, listener: Callable[[PermissionRequest], Any]) -> bool:
        """Elimina un listener de eventos de permiso.

        Args:
            listener: El listener a eliminar

        Returns:
            True si el listener fue eliminado
        """
        if listener in self._listeners:
            self._listeners.remove(listener)
            return True
        return False

    def emit_permission_request(self, request: PermissionRequest) -> None:
        """Emite un evento de solicitud de permiso a todos los listeners.

        Args:
            request: La solicitud de permiso a emitir
        """
        for listener in self._listeners:
            with suppress(Exception):
                # Los listeners no deben romper el flujo principal
                listener(request)

    def check_and_emit(self, action: str, resource: str) -> tuple[bool, PermissionRequest | None]:
        """Verifica permisos y emite evento si es necesario.

        Combina check() con emit_permission_request() para conveniencia.

        Args:
            action: Acción a verificar
            resource: Recurso a verificar

        Returns:
            Tupla (permitido, solicitud)
        """
        allowed, request = self.check(action, resource)
        if request is not None:
            self.emit_permission_request(request)
        return allowed, request


# Instancia global del Permission Gate
# Se inicializa con las reglas por defecto y puede ser reemplazado en tests
permission_gate = PermissionGate()
