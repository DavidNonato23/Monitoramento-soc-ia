"""Configuração segura e centralizada da VanguardSec V2."""
from __future__ import annotations

import os
from dataclasses import dataclass


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "sim"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} deve ser um inteiro válido") from exc


@dataclass(frozen=True)
class SecurityConfig:
    """Políticas de segurança; ações defensivas ficam desativadas por padrão."""

    active_defense: bool = False
    auto_remediation: bool = False
    require_human_approval_for_production: bool = True
    max_action_ttl_seconds: int = 3600
    max_ai_confidence_for_auto_action: float = 0.90


@dataclass(frozen=True)
class AppConfig:
    database_url: str
    ssh_timeout: int
    security: SecurityConfig


def load_config() -> AppConfig:
    return AppConfig(
        database_url=os.getenv("VANGUARD_DB", "data/vanguard.db"),
        ssh_timeout=env_int("SSH_TIMEOUT", 5),
        security=SecurityConfig(
            active_defense=env_bool("ACTIVE_DEFENSE", False),
            auto_remediation=env_bool("AUTO_REMEDIATION", False),
            require_human_approval_for_production=env_bool(
                "REQUIRE_HUMAN_APPROVAL_PRODUCTION", True
            ),
            max_action_ttl_seconds=env_int("MAX_ACTION_TTL_SECONDS", 3600),
            max_ai_confidence_for_auto_action=float(
                os.getenv("AI_AUTO_ACTION_CONFIDENCE", "0.90")
            ),
        ),
    )
