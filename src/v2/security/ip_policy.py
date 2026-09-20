"""Validação e proteção de alvos usados por ações defensivas."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


class SecurityPolicyError(ValueError):
    """A solicitação viola uma política de segurança."""


@dataclass(frozen=True)
class IPPolicy:
    protected_ips: frozenset[str] = frozenset()
    allow_private_networks: bool = True

    def validate_target(self, ip: str) -> str:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise SecurityPolicyError("IP de destino inválido") from exc

        normalized = str(address)
        if normalized in self.protected_ips:
            raise SecurityPolicyError("IP protegido não pode receber ação automática")
        if not self.allow_private_networks and address.is_private:
            raise SecurityPolicyError("Redes privadas não são permitidas por esta política")
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise SecurityPolicyError("Endereço especial não pode ser alvo de ação")
        return normalized
