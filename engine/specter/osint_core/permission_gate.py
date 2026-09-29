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


# ------------------------------------------------------------------
# Política de tools (fuente única): la consumen el diálogo del agente
# (SAFE/SENSITIVE + cola de permisos) y el gate de llamadas directas.
# ------------------------------------------------------------------

# Tools que se pueden ejecutar sin preguntar (lecturas pasivas).
SAFE_TOOLS = {
    "list_cases",
    "query_graph",
    "analyze_network_metrics",
    "verify_case_integrity",
    "correlate_cases",
    "suggest_identity_links_fs",
    "estimate_capture_time",
    "case_timeline",
    "attest_case_ledger",
    "list_collectors",
    "triage_entity",
    "web_search",
    "parallel_search",
    "load_skill",
    "todowrite",
    # Lectura pura: descarga y extrae texto, no escribe en el caso (la ingesta
    # la hacen los wrappers de escritura, que sí piden permiso). Pedir
    # aprobación por cada fetch ahogó la sesión real de investigación en
    # timeouts de 300s.
    "web_fetch",
    # Lecturas del navegador sin navegación nueva ni persistencia.
    "browser_snapshot",
    "browser_status",
    # Válvula de escape del loop: bloquearla podría dejar al agente sin salida
    # ante una ambigüedad (p.ej. un DNI sin pivotes), así que nunca pide permiso.
    "ask_analyst",
}

# Tools que disparan recolección activa / escritura en el caso.
SENSITIVE_TOOLS = {
    "create_case",
    "investigate_domain",
    "enumerate_subdomains",
    "investigate_ip",
    "investigate_identity",
    "investigate_email",
    "investigate_person",
    "deep_research",
    "hunt_documents_and_leaks",
    "deep_investigate_github",
    "analyze_file_metadata",
    "link_entities",
    "export_case_dossier",
    "run_collector",
    "browser_capture_warc",
}

# Bloqueo duro (ni con aprobación): patrones fnmatch sobre el nombre.
# Vacío por defecto; el analista puede endurecerlo sin tocar código.
DENY_PATTERNS: tuple[str, ...] = ()

# Tools bloqueadas por nombre exacto (ni el diálogo las desbloquea).
DENY_TOOLS: set[str] = set()


def _permission_action(name: str) -> str:
    """allow | ask | deny para una tool (reglas estilo opencode permission).

    Orden: deny explícito > allow explícito (SAFE_TOOLS) > ask por defecto.
    Las tools futuras/desconocidas piden permiso en vez de ejecutarse solas.
    """
    if name in DENY_TOOLS or any(fnmatch.fnmatchcase(name, pat) for pat in DENY_PATTERNS):
        return "deny"
    if name in SAFE_TOOLS:
        return "allow"
    return "ask"


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


def _is_exact_rule(rule: PermissionRule) -> bool:
    """True si la regla no usa wildcards (apunta a un recurso concreto)."""
    return not any(c in rule.action for c in "*?[") and not any(
        c in rule.resource for c in "*?["
    )


class PermissionGate:
    """Motor de permisos con soporte para wildcards.

    Las reglas exactas (sin wildcards) preceden a las genéricas; dentro del
    mismo nivel, la primera regla que coincide determina el efecto. Si ninguna
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
            # Tools que la propia UI/API llama directamente (POST /tools/...):
            # se contemplan explícitamente. El resto de tools sensibles queda
            # denegado en llamadas directas hasta que se añada una regla
            # (add_permission_rule): deny por defecto para lo no contemplado.
            PermissionRule(
                action="collect",
                resource="tool:create_case",
                effect="allow",
                description="La UI crea casos por POST /cases (directo, no vía agente)",
            ),
            PermissionRule(
                action="collect",
                resource="tool:run_collector",
                effect="allow",
                description="Ejecución directa de colectores desde la API",
            ),
            PermissionRule(
                action="correlate",
                resource="tool:link_entities",
                effect="allow",
                description="La UI enlaza entidades desde la vista de correlaciones",
            ),
            PermissionRule(
                action="export",
                resource="tool:export_case_dossier",
                effect="allow",
                description="La UI exporta el dossier desde la tabla de custodia",
            ),
            # Meta-herramientas del propio gate: sin ellas no se puede ni
            # consultar ni conceder el allow explícito desde la API directa.
            PermissionRule(
                action="*",
                resource="tool:list_permissions",
                effect="allow",
                description="Consultar reglas activas",
            ),
            PermissionRule(
                action="*",
                resource="tool:add_permission_rule",
                effect="allow",
                description="Conceder allow explícito (escape hatch del gate)",
            ),
            PermissionRule(
                action="*",
                resource="tool:remove_permission_rule",
                effect="allow",
                description="Retirar reglas",
            ),
            PermissionRule(
                action="*",
                resource="tool:check_permission",
                effect="allow",
                description="Comprobar una acción/recurso concretos",
            ),
            PermissionRule(
                action="*",
                resource="tool:evaluate_permission",
                effect="allow",
                description="Evaluar el efecto de las reglas",
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

        Las reglas exactas (sin wildcards) preceden a las genéricas: un allow
        explícito para un recurso concreto (`delete` sobre `case:abc`) gana al
        deny por defecto (`delete` sobre `case:*`). Dentro del mismo nivel,
        la primera regla que coincide determina el efecto.
        Si ninguna regla coincide, retorna 'ask' (fail-closed por seguridad).

        Args:
            action: Acción a evaluar (ej: "collect")
            resource: Recurso a evaluar (ej: "collector:dns_zonexfer")

        Returns:
            El efecto de la regla coincidente con más precedencia, o 'ask'
        """
        matches = [r for r in self._rules if r.matches(action, resource)]
        # Estable: conserva el orden de inserción dentro de cada nivel.
        matches.sort(key=lambda r: not _is_exact_rule(r))
        if matches:
            return PermissionEffect(matches[0].effect)
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


# Mapa tool -> acción del gate para las llamadas directas (las tools sin
# entrada caen a "collect", la acción por defecto de recolección activa).
TOOL_ACTIONS: dict[str, str] = {
    "run_collector": "collect",
    "investigate_domain": "collect",
    "investigate_ip": "collect",
    "investigate_identity": "collect",
    "investigate_person": "collect",
    "investigate_email": "collect",
    "analyze_file_metadata": "collect",
    "hunt_office_docs": "collect",
    "hunt_documents_and_leaks": "collect",
    "deep_investigate_github": "collect",
    "deep_research": "collect",
    "enumerate_subdomains": "collect",
    "link_entities": "correlate",
    "correlate_cases": "correlate",
    "run_correlations": "correlate",
    "export_case_dossier": "export",
    "export_case_stix": "export",
    "delete_case": "delete",
}


def tool_resource(tool_name: str, arguments: dict[str, Any] | None = None) -> str:
    """Recurso gate para una llamada directa.

    El borrado se evalúa contra la regla `delete/case:*` (deny por defecto,
    salvo allow explícito); el resto se evalúa a escala de tool
    (`tool:{nombre}`), que es lo que las reglas por defecto contemplan.
    """
    if TOOL_ACTIONS.get(tool_name) == "delete":
        case_id = (arguments or {}).get("case_id")
        return f"case:{case_id}" if case_id else "case:*"
    return f"tool:{tool_name}"


def _check_tool_permission(tool_name: str, resource: str) -> tuple[bool, str]:
    """Verifica si una tool puede ejecutarse por la vía directa (API/MCP).

    Args:
        tool_name: Nombre de la tool (ej: "delete_case")
        resource: Recurso gate (usa `tool_resource()` para derivarlo)

    Returns:
        Tupla (permitido, mensaje_error). `""` cuando está permitido.
    """
    policy = _permission_action(tool_name)
    if policy == "deny":
        return False, f"PERMISSION_DENIED: {tool_name} bloqueada por política (deny)"

    action = TOOL_ACTIONS.get(tool_name, "collect")
    allowed, request = permission_gate.check(action, resource)
    if allowed:
        return True, ""
    if request is None:
        return False, (
            f"PERMISSION_DENIED: {action} sobre {resource} no está permitido "
            "(regla deny o sin regla allow; usa add_permission_rule para autorizarlo)"
        )
    # ASK (fail-closed): las tools SAFE pasan; en la vía directa no hay
    # diálogo con el analista, así que el resto se deniega.
    if policy == "allow":
        return True, ""
    permission_gate.emit_permission_request(request)
    return False, f"PERMISSION_REQUIRED: {request.message}"
