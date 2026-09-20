import pytest

from src.v2.security import Action, ActionPolicy, ActionRequest, IPPolicy, SecurityPolicyError


def test_ip_policy_rejects_loopback():
    with pytest.raises(SecurityPolicyError):
        IPPolicy().validate_target("127.0.0.1")


def test_ip_policy_rejects_protected_ip():
    with pytest.raises(SecurityPolicyError):
        IPPolicy(protected_ips=frozenset({"192.168.1.10"})).validate_target("192.168.1.10")


def test_action_policy_denies_auto_remediation_by_default():
    policy = ActionPolicy(auto_remediation=False, min_confidence=0.90)
    decision = policy.authorize(ActionRequest(Action.BLOCK_IP, "8.8.8.8", 0.99))
    assert not decision.allowed


def test_action_policy_requires_human_approval_in_production():
    policy = ActionPolicy(auto_remediation=True, min_confidence=0.90)
    decision = policy.authorize(
        ActionRequest(Action.BLOCK_IP, "8.8.8.8", 0.99, environment="production")
    )
    assert not decision.allowed


def test_action_policy_allows_lab_action_when_enabled():
    policy = ActionPolicy(auto_remediation=True, min_confidence=0.90)
    decision = policy.authorize(ActionRequest(Action.BLOCK_IP, "8.8.8.8", 0.99))
    assert decision.allowed
