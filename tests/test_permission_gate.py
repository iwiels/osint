"""
Tests para el Permission Gate de WraithOSINT.

Cubre:
- Motor de permisos con wildcards
- Reglas pre-definidas
- Integración con el motor (herramientas MCP)
- API HTTP (endpoints de permisos)
"""

import pytest
from specter.osint_core.permission_gate import (
    PermissionEffect,
    PermissionGate,
    PermissionRequest,
    PermissionRule,
    _check_tool_permission,
    tool_resource,
)


class TestPermissionRule:
    """Tests para el modelo PermissionRule."""

    def test_rule_creation(self) -> None:
        """Creación básica de una regla."""
        rule = PermissionRule(
            action="collect",
            resource="collector:dns_*",
            effect="allow",
        )
        assert rule.action == "collect"
        assert rule.resource == "collector:dns_*"
        assert rule.effect == "allow"
        assert rule.rule_id.startswith("rule-")
        assert rule.description == ""

    def test_rule_with_description(self) -> None:
        """Regla con descripción."""
        rule = PermissionRule(
            action="export",
            resource="case:*",
            effect="ask",
            description="Exportar requiere confirmación",
        )
        assert rule.description == "Exportar requiere confirmación"

    def test_rule_auto_id(self) -> None:
        """El rule_id se auto-genera."""
        rule1 = PermissionRule(action="collect", resource="*", effect="allow")
        rule2 = PermissionRule(action="collect", resource="*", effect="allow")
        assert rule1.rule_id != rule2.rule_id

    def test_rule_matches_exact(self) -> None:
        """Matching exacto sin wildcards."""
        rule = PermissionRule(action="collect", resource="collector:threatfox", effect="allow")
        assert rule.matches("collect", "collector:threatfox")
        assert not rule.matches("collect", "collector:virustotal")
        assert not rule.matches("export", "collector:threatfox")

    def test_rule_matches_wildcard_star(self) -> None:
        """Matching con wildcard *."""
        rule = PermissionRule(action="collect", resource="collector:dns_*", effect="allow")
        assert rule.matches("collect", "collector:dns_zonexfer")
        assert rule.matches("collect", "collector:dns_bruteforce")
        assert rule.matches("collect", "collector:dns_")
        assert not rule.matches("collect", "collector:crt_sh")

    def test_rule_matches_wildcard_question(self) -> None:
        """Matching con wildcard ?."""
        rule = PermissionRule(action="collect", resource="collector:dns_?", effect="allow")
        assert rule.matches("collect", "collector:dns_a")
        assert rule.matches("collect", "collector:dns_1")
        assert not rule.matches("collect", "collector:dns_ab")
        assert not rule.matches("collect", "collector:dns_")

    def test_rule_matches_wildcard_sequence(self) -> None:
        """Matching con wildcard [seq]."""
        rule = PermissionRule(action="collect", resource="collector:[a-c]*", effect="allow")
        assert rule.matches("collect", "collector:ahmia")
        assert rule.matches("collect", "collector:blockchain")
        assert rule.matches("collect", "collector:crt_sh")
        assert not rule.matches("collect", "collector:dns_collector")

    def test_rule_matches_action_wildcard(self) -> None:
        """Matching con wildcard en la acción."""
        rule = PermissionRule(action="*", resource="collector:*", effect="allow")
        assert rule.matches("collect", "collector:dns")
        assert rule.matches("export", "collector:something")
        assert rule.matches("delete", "collector:other")
        # No coincide si el recurso no coincide
        assert not rule.matches("export", "case:123")


class TestPermissionGateDefaults:
    """Tests para las reglas pre-definidas del PermissionGate."""

    def test_default_rules_loaded(self) -> None:
        """El gate carga las reglas por defecto al inicializarse."""
        gate = PermissionGate()
        rules = gate.get_rules()
        assert len(rules) >= 8  # Al menos las 8 reglas pre-definidas

    def test_default_dns_collectors_allowed(self) -> None:
        """Los colectores DNS están permitidos por defecto."""
        gate = PermissionGate()
        assert gate.evaluate("collect", "collector:dns_zonexfer") == PermissionEffect.ALLOW
        assert gate.evaluate("collect", "collector:dns_bruteforce") == PermissionEffect.ALLOW

    def test_default_crt_collectors_allowed(self) -> None:
        """Los colectores CRT están permitidos por defecto."""
        gate = PermissionGate()
        assert gate.evaluate("collect", "collector:crt_sh") == PermissionEffect.ALLOW

    def test_default_threatfox_allowed(self) -> None:
        """ThreatFox está permitido por defecto."""
        gate = PermissionGate()
        assert gate.evaluate("collect", "collector:threatfox") == PermissionEffect.ALLOW

    def test_default_virustotal_ask(self) -> None:
        """VirusTotal requiere confirmación por defecto."""
        gate = PermissionGate()
        assert gate.evaluate("collect", "collector:virustotal") == PermissionEffect.ASK

    def test_default_resolve_entity_allowed(self) -> None:
        """La resolución de entidades está permitida por defecto."""
        gate = PermissionGate()
        assert gate.evaluate("resolve", "entity:domain:example.com") == PermissionEffect.ALLOW
        assert gate.evaluate("resolve", "entity:ip:1.2.3.4") == PermissionEffect.ALLOW

    def test_default_correlate_case_allowed(self) -> None:
        """La correlación de casos está permitida por defecto."""
        gate = PermissionGate()
        assert gate.evaluate("correlate", "case:123") == PermissionEffect.ALLOW

    def test_default_export_case_ask(self) -> None:
        """Exportar casos requiere confirmación por defecto."""
        gate = PermissionGate()
        assert gate.evaluate("export", "case:123") == PermissionEffect.ASK

    def test_default_delete_case_deny(self) -> None:
        """Eliminar casos está denegado por defecto."""
        gate = PermissionGate()
        assert gate.evaluate("delete", "case:123") == PermissionEffect.DENY

    def test_default_fail_closed(self) -> None:
        """Si ninguna regla coincide, el efecto es 'ask' (fail-closed)."""
        gate = PermissionGate()
        # Acción no definida en las reglas por defecto
        assert gate.evaluate("unknown_action", "unknown:resource") == PermissionEffect.ASK


class TestPermissionGateOperations:
    """Tests para las operaciones del PermissionGate."""

    def test_add_rule(self) -> None:
        """Agregar una regla al gate."""
        gate = PermissionGate()
        initial_count = len(gate.get_rules())

        rule = PermissionRule(action="collect", resource="collector:custom_*", effect="allow")
        gate.add_rule(rule)

        assert len(gate.get_rules()) == initial_count + 1
        assert rule in gate.get_rules()

    def test_remove_rule(self) -> None:
        """Eliminar una regla por ID."""
        gate = PermissionGate()
        rule = PermissionRule(action="collect", resource="collector:temp_*", effect="allow")
        gate.add_rule(rule)

        assert gate.remove_rule(rule.rule_id) is True
        assert rule not in gate.get_rules()

    def test_remove_nonexistent_rule(self) -> None:
        """Eliminar una regla que no existe retorna False."""
        gate = PermissionGate()
        assert gate.remove_rule("rule-nonexistent") is False

    def test_get_rules_returns_copy(self) -> None:
        """get_rules retorna una copia, no la lista interna."""
        gate = PermissionGate()
        rules = gate.get_rules()
        rules.clear()  # Modificar la copia
        assert len(gate.get_rules()) > 0  # La interna no se afectó

    def test_clear_rules(self) -> None:
        """Eliminar todas las reglas."""
        gate = PermissionGate()
        gate.clear_rules()
        assert len(gate.get_rules()) == 0

    def test_evaluate_returns_effect(self) -> None:
        """evaluate retorna el efecto de la primera regla coincidente."""
        gate = PermissionGate()
        gate.clear_rules()

        gate.add_rule(PermissionRule(action="collect", resource="*", effect="allow"))
        gate.add_rule(PermissionRule(action="collect", resource="collector:dns_*", effect="deny"))

        # La primera regla coincide primero
        assert gate.evaluate("collect", "collector:dns_zonexfer") == PermissionEffect.ALLOW

    def test_evaluate_first_match_wins(self) -> None:
        """La primera regla que coincide determina el efecto."""
        gate = PermissionGate()
        gate.clear_rules()

        gate.add_rule(PermissionRule(action="collect", resource="collector:dns_*", effect="deny"))
        gate.add_rule(PermissionRule(action="collect", resource="*", effect="allow"))

        # La primera regla (deny) coincide primero
        assert gate.evaluate("collect", "collector:dns_zonexfer") == PermissionEffect.DENY


class TestPermissionGateCheck:
    """Tests para el método check del PermissionGate."""

    def test_check_allowed(self) -> None:
        """check retorna (True, None) cuando está permitido."""
        gate = PermissionGate()
        allowed, request = gate.check("collect", "collector:dns_zonexfer")
        assert allowed is True
        assert request is None

    def test_check_denied(self) -> None:
        """check retorna (False, None) cuando está denegado."""
        gate = PermissionGate()
        allowed, request = gate.check("delete", "case:123")
        assert allowed is False
        assert request is None

    def test_check_ask(self) -> None:
        """check retorna (False, PermissionRequest) cuando requiere confirmación."""
        gate = PermissionGate()
        allowed, request = gate.check("collect", "collector:virustotal")
        assert allowed is False
        assert request is not None
        assert isinstance(request, PermissionRequest)
        assert request.action == "collect"
        assert request.resource == "collector:virustotal"

    def test_check_and_emit(self) -> None:
        """check_and_emit emite el evento cuando es necesario."""
        gate = PermissionGate()
        emitted: list[PermissionRequest] = []

        def listener(req: PermissionRequest) -> None:
            emitted.append(req)

        gate.add_listener(listener)

        # Permitido: no emite
        allowed, _ = gate.check_and_emit("collect", "collector:dns_zonexfer")
        assert allowed is True
        assert len(emitted) == 0

        # Ask: emite
        allowed, request = gate.check_and_emit("collect", "collector:virustotal")
        assert allowed is False
        assert request is not None
        assert len(emitted) == 1
        assert emitted[0].action == "collect"

    def test_emit_permission_request(self) -> None:
        """emit_permission_request llama a todos los listeners."""
        gate = PermissionGate()
        emitted: list[PermissionRequest] = []

        def listener1(req: PermissionRequest) -> None:
            emitted.append(req)

        def listener2(req: PermissionRequest) -> None:
            emitted.append(req)

        gate.add_listener(listener1)
        gate.add_listener(listener2)

        request = PermissionRequest(action="test", resource="test:*")
        gate.emit_permission_request(request)

        assert len(emitted) == 2

    def test_remove_listener(self) -> None:
        """Eliminar un listener."""
        gate = PermissionGate()

        def listener(req: PermissionRequest) -> None:
            pass

        gate.add_listener(listener)
        assert gate.remove_listener(listener) is True
        assert gate.remove_listener(listener) is False

    def test_listener_exception_handled(self) -> None:
        """Las excepciones en listeners no rompen el flujo."""
        gate = PermissionGate()

        def bad_listener(req: PermissionRequest) -> None:
            raise RuntimeError("Error en listener")

        def good_listener(req: PermissionRequest) -> None:
            pass

        gate.add_listener(bad_listener)
        gate.add_listener(good_listener)

        # No debe lanzar excepción
        request = PermissionRequest(action="test", resource="test:*")
        gate.emit_permission_request(request)


class TestPermissionGateIntegration:
    """Tests de integración con el motor (herramientas MCP)."""

    def test_import_from_server(self) -> None:
        """El permission gate se puede importar desde el server."""
        from specter.server import permission_gate as server_gate

        assert isinstance(server_gate, PermissionGate)
        assert len(server_gate.get_rules()) >= 8

    def test_server_has_permission_tools(self) -> None:
        """El server tiene las herramientas de permisos registradas."""
        from specter import server

        # Verificar que las funciones existen
        assert hasattr(server, "list_permissions")
        assert hasattr(server, "add_permission_rule")
        assert hasattr(server, "remove_permission_rule")
        assert hasattr(server, "check_permission")
        assert hasattr(server, "evaluate_permission")

    def test_check_tool_permission_helper(self) -> None:
        """El helper _check_tool_permission funciona correctamente."""
        from specter.server import _check_tool_permission

        # Permitido
        allowed, msg = _check_tool_permission("run_collector", "collector:dns_zonexfer")
        assert allowed is True
        assert msg == ""

        # Denegado
        allowed, msg = _check_tool_permission("run_collector", "case:123")
        assert allowed is False
        assert "PERMISSION_DENIED" in msg or "PERMISSION_REQUIRED" in msg

    def test_permission_event_listener_registered(self) -> None:
        """El listener de eventos está registrado en el gate global."""
        from specter.server import permission_gate

        # El listener debe estar registrado
        assert len(permission_gate._listeners) >= 1


class TestPermissionGateWildcards:
    """Tests específicos para wildcards."""

    def test_star_matches_empty(self) -> None:
        """* coincide con cadena vacía."""
        gate = PermissionGate()
        gate.clear_rules()
        gate.add_rule(PermissionRule(action="collect", resource="collector:*", effect="allow"))
        assert gate.evaluate("collect", "collector:") == PermissionEffect.ALLOW

    def test_star_matches_multiple_chars(self) -> None:
        """* coincide con múltiples caracteres."""
        gate = PermissionGate()
        gate.clear_rules()
        gate.add_rule(PermissionRule(action="collect", resource="collector:*", effect="allow"))
        assert gate.evaluate("collect", "collector:very_long_name") == PermissionEffect.ALLOW

    def test_question_mark_single_char(self) -> None:
        """? coincide con exactamente un carácter."""
        gate = PermissionGate()
        gate.clear_rules()
        gate.add_rule(PermissionRule(action="collect", resource="collector:?", effect="allow"))
        assert gate.evaluate("collect", "collector:a") == PermissionEffect.ALLOW
        assert gate.evaluate("collect", "collector:ab") == PermissionEffect.ASK  # No coincide

    def test_sequence_bracket(self) -> None:
        """[seq] coincide con cualquier carácter en la secuencia."""
        gate = PermissionGate()
        gate.clear_rules()
        gate.add_rule(PermissionRule(action="collect", resource="collector:[abc]", effect="allow"))
        assert gate.evaluate("collect", "collector:a") == PermissionEffect.ALLOW
        assert gate.evaluate("collect", "collector:b") == PermissionEffect.ALLOW
        assert gate.evaluate("collect", "collector:c") == PermissionEffect.ALLOW
        assert gate.evaluate("collect", "collector:d") == PermissionEffect.ASK  # No coincide

    def test_negated_sequence(self) -> None:
        """[!seq] coincide con cualquier carácter NO en la secuencia."""
        gate = PermissionGate()
        gate.clear_rules()
        gate.add_rule(PermissionRule(action="collect", resource="collector:[!abc]", effect="allow"))
        assert gate.evaluate("collect", "collector:d") == PermissionEffect.ALLOW
        assert gate.evaluate("collect", "collector:a") == PermissionEffect.ASK  # No coincide

    def test_multiple_wildcards(self) -> None:
        """Múltiples wildcards en un patrón."""
        gate = PermissionGate()
        gate.clear_rules()
        gate.add_rule(
            PermissionRule(action="collect", resource="collector:*_dns_*", effect="allow")
        )
        assert gate.evaluate("collect", "collector:my_dns_collector") == PermissionEffect.ALLOW
        assert gate.evaluate("collect", "collector:a_dns_b") == PermissionEffect.ALLOW
        assert gate.evaluate("collect", "collector:my_http_collector") == PermissionEffect.ASK


class TestPermissionGatePersistence:
    """Tests para la persistencia de reglas (memoria)."""

    def test_rules_survive_evaluation(self) -> None:
        """Las reglas persisten entre evaluaciones."""
        gate = PermissionGate()
        gate.clear_rules()
        gate.add_rule(PermissionRule(action="custom", resource="*", effect="allow"))

        assert gate.evaluate("custom", "anything") == PermissionEffect.ALLOW
        assert gate.evaluate("custom", "other") == PermissionEffect.ALLOW

    def test_remove_rule_affects_evaluation(self) -> None:
        """Eliminar una regla afecta la evaluación."""
        gate = PermissionGate()
        gate.clear_rules()
        rule = PermissionRule(action="custom", resource="*", effect="allow")
        gate.add_rule(rule)

        assert gate.evaluate("custom", "anything") == PermissionEffect.ALLOW

        gate.remove_rule(rule.rule_id)
        assert gate.evaluate("custom", "anything") == PermissionEffect.ASK  # Fail-closed


class TestPermissionRequest:
    """Tests para el modelo PermissionRequest."""

    def test_request_creation(self) -> None:
        """Creación básica de una solicitud."""
        request = PermissionRequest(action="collect", resource="collector:virustotal")
        assert request.action == "collect"
        assert request.resource == "collector:virustotal"
        assert request.request_id.startswith("perm-")
        assert request.message == ""

    def test_request_with_message(self) -> None:
        """Solicitud con mensaje personalizado."""
        request = PermissionRequest(
            action="export",
            resource="case:123",
            message="¿Desea exportar el caso?",
        )
        assert request.message == "¿Desea exportar el caso?"

    def test_request_auto_id(self) -> None:
        """El request_id se auto-genera."""
        req1 = PermissionRequest(action="a", resource="b")
        req2 = PermissionRequest(action="a", resource="b")
        assert req1.request_id != req2.request_id


# Tests de integración con el motor usando el gate global
class TestPermissionGateGlobalInstance:
    """Tests para la instancia global del Permission Gate."""

    def test_global_instance_exists(self) -> None:
        """La instancia global existe y tiene reglas por defecto."""
        from specter.osint_core.permission_gate import permission_gate

        assert isinstance(permission_gate, PermissionGate)
        assert len(permission_gate.get_rules()) >= 8

    def test_global_instance_has_default_rules(self) -> None:
        """La instancia global tiene las reglas pre-definidas."""
        from specter.osint_core.permission_gate import permission_gate

        # Verificar algunas reglas por defecto
        assert (
            permission_gate.evaluate("collect", "collector:dns_zonexfer") == PermissionEffect.ALLOW
        )
        assert permission_gate.evaluate("collect", "collector:virustotal") == PermissionEffect.ASK
        assert permission_gate.evaluate("delete", "case:123") == PermissionEffect.DENY


class TestDirectCallGate:
    """El gate de llamadas directas (registry/HTTP): deny por defecto."""

    def test_tool_resource_deriva_borrado_y_resto(self) -> None:
        assert tool_resource("delete_case", {"case_id": "case-1"}) == "case:case-1"
        assert tool_resource("delete_case", {}) == "case:*"
        assert tool_resource("investigate_domain", {"case_id": "case-1"}) == (
            "tool:investigate_domain"
        )
        assert tool_resource("list_collectors", {}) == "tool:list_collectors"

    def test_herramienta_segura_pasa(self) -> None:
        allowed, msg = _check_tool_permission(
            "list_collectors", tool_resource("list_collectors", {})
        )
        assert allowed is True
        assert msg == ""

    def test_herramienta_sensible_sin_regla_denegada(self) -> None:
        allowed, msg = _check_tool_permission(
            "investigate_domain", tool_resource("investigate_domain", {})
        )
        assert allowed is False
        assert "PERMISSION_REQUIRED" in msg

    def test_borrado_sin_allow_denegado(self) -> None:
        allowed, msg = _check_tool_permission("delete_case", "case:case-1")
        assert allowed is False
        assert "PERMISSION_DENIED" in msg

    def test_allow_exacto_gana_al_deny_generico(self) -> None:
        """El allow explícito para un caso concreto abre el borrado de ese caso."""
        from specter.osint_core.permission_gate import permission_gate

        rule = permission_gate.add_rule(
            PermissionRule(action="delete", resource="case:case-x", effect="allow")
        )
        try:
            allowed, _ = _check_tool_permission("delete_case", "case:case-x")
            assert allowed is True
            # ... pero el resto de casos sigue denegado.
            denied, _ = _check_tool_permission("delete_case", "case:case-y")
            assert denied is False
        finally:
            permission_gate.remove_rule(rule.rule_id)

    def test_exacta_gana_a_generica_en_evaluate(self) -> None:
        """Semántica documentada: exacta > genérica; mismo nivel, primera gana."""
        gate = PermissionGate()
        gate.clear_rules()
        gate.add_rule(PermissionRule(action="delete", resource="case:*", effect="deny"))
        gate.add_rule(PermissionRule(action="delete", resource="case:x", effect="allow"))
        assert gate.evaluate("delete", "case:x") == PermissionEffect.ALLOW
        assert gate.evaluate("delete", "case:y") == PermissionEffect.DENY


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
