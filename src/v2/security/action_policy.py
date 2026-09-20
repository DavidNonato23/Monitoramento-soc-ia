"""Policy engine: IA pode propor ações; somente políticas autorizam execução."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Action(str, Enum):
    NO_ACTION = "NO_ACTION"
    BLOCK_IP = "BLOCK_IP"
    UNBLOCK_IP = "UNBLOCK_IP"
    KILL_SESSION = "KILL_SESSION"


@dataclass(frozen=True)
class ActionRequest:
    action: Action
    target_ip: str | None
    confidence: float
    environment: str = "lab"
    human_approved: bool = False


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class ActionPolicy:
    """Regras determinísticas para impedir execução arbitrária."""

    def __init__(self, auto_remediation: bool, min_confidence: float, require_human_approval_production: bool = True):
        self.auto_remediation = auto_remediation
        self.min_confidence = min_confidence
        self.require_human_approval_production = require_human_approval_production

    def authorize(self, request: ActionRequest) -> PolicyDecision:
        if request.action == Action.NO_ACTION:
            return PolicyDecision(True, "Nenhuma ação defensiva solicitada")

        if request.action not in {
            Action.BLOCK_IP,
            Action.UNBLOCK_IP,
            Action.KILL_SESSION,
        }:
            return PolicyDecision(False, "Ação não permitida pelo catálogo SOAR")

        if not 0.0 <= request.confidence <= 1.0:
            return PolicyDecision(False, "Confidence fora do intervalo 0..1")

        if not self.auto_remediation:
            return PolicyDecision(False, "Auto-remediation desativada")

        if request.confidence < self.min_confidence:
            return PolicyDecision(False, "Confidence abaixo do mínimo para ação automática")

        if request.environment.lower() == "production" and self.require_human_approval_production:
            if not request.human_approved:
                return PolicyDecision(False, "Produção exige aprovação humana")

        if request.action != Action.NO_ACTION and not request.target_ip:
            return PolicyDecision(False, "Ação exige alvo explícito")

        return PolicyDecision(True, "Ação autorizada pela política")
