"""Catálogo fechado de ações SOAR; nenhum comando arbitrário vem da IA."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


class CommandNotAllowed(PermissionError):
    pass


@dataclass(frozen=True)
class CommandSpec:
    name: str
    description: str
    handler_name: str


CATALOG: dict[str, CommandSpec] = {
    "BLOCK_IP": CommandSpec(
        name="BLOCK_IP",
        description="Bloqueia um IPv4 usando o mecanismo de firewall do agente",
        handler_name="block_ip",
    ),
    "UNBLOCK_IP": CommandSpec(
        name="UNBLOCK_IP",
        description="Remove um bloqueio de IPv4 criado pelo SOAR",
        handler_name="unblock_ip",
    ),
    "KILL_SESSION": CommandSpec(
        name="KILL_SESSION",
        description="Encerra uma sessão SSH associada ao IPv4 alvo",
        handler_name="kill_session",
    ),
}


def get_action(name: str) -> CommandSpec:
    try:
        return CATALOG[name.upper()]
    except KeyError as exc:
        raise CommandNotAllowed(f"Ação SOAR não cadastrada: {name}") from exc
