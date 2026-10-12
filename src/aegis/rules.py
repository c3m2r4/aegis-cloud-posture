"""Evidence-driven, read-only cloud posture rules."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any, Callable


OUTCOMES = {"PASS", "FAIL", "NOT_APPLICABLE", "NOT_SUPPORTED", "ERROR"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


@dataclass(frozen=True)
class RuleResult:
    outcome: str
    reason: str


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    description: str
    resource_type: str
    required_evidence: tuple[str, ...]
    remediation: str
    detect: Callable[[dict[str, Any]], RuleResult]


def _missing(resource: dict[str, Any]) -> RuleResult:
    return RuleResult("NOT_SUPPORTED", "Required configuration evidence was not returned by the API.")


def _iam_wildcards(resource: dict[str, Any]) -> RuleResult:
    if "attributes" not in resource:
        return RuleResult("NOT_SUPPORTED", "Normalized policy attributes were not observed.")
    attrs = resource.get("attributes")
    if not isinstance(attrs, dict):
        return RuleResult("ERROR", "Policy attributes are malformed; expected an object.")
    version = attrs.get("PolicyVersion")
    if not isinstance(version, dict):
        return _missing(resource)
    document = version.get("Document")
    if not isinstance(document, dict):
        return RuleResult("ERROR", "Policy document is malformed or unavailable.")
    statements = document.get("Statement")
    if not isinstance(statements, (list, dict)):
        return RuleResult("ERROR", "Policy document Statement must be an object or list.")
    statements = [statements] if isinstance(statements, dict) else statements
    if not statements:
        return RuleResult("ERROR", "Policy document has no statements to evaluate.")
    broad: list[str] = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            return RuleResult("ERROR", f"Policy statement {index} is malformed.")
        effect = statement.get("Effect")
        if effect not in {"Allow", "Deny"}:
            return RuleResult("ERROR", f"Policy statement {index} has a missing or invalid Effect.")
        if effect != "Allow":
            continue
        if "Action" not in statement or "Resource" not in statement:
            if "NotAction" in statement or "NotResource" in statement:
                return RuleResult("NOT_SUPPORTED", f"Allow statement {index} uses NotAction or NotResource, which this rule does not evaluate.")
            return RuleResult("ERROR", f"Allow statement {index} lacks Action or Resource.")
        actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        resources = statement["Resource"] if isinstance(statement["Resource"], list) else [statement["Resource"]]
        if not actions or not all(isinstance(v, str) for v in actions) or not resources or not all(isinstance(v, str) for v in resources):
            return RuleResult("ERROR", f"Allow statement {index} has malformed Action or Resource values.")
        if any("*" in action for action in actions):
            broad.append(f"statement {index} has wildcard Action")
        if any("*" in resource_pattern for resource_pattern in resources):
            broad.append(f"statement {index} has wildcard Resource pattern")
    if broad:
        return RuleResult("FAIL", "; ".join(broad))
    return RuleResult("PASS", "All observed Allow statements specify non-wildcard actions and resources.")


def _public_admin_ingress(resource: dict[str, Any]) -> RuleResult:
    if "attributes" not in resource:
        return RuleResult("NOT_SUPPORTED", "Normalized security-group attributes were not observed.")
    attrs = resource.get("attributes")
    if not isinstance(attrs, dict):
        return RuleResult("ERROR", "Security group attributes are malformed; expected an object.")
    if "IpPermissions" not in attrs:
        return _missing(resource)
    permissions = attrs["IpPermissions"]
    if not isinstance(permissions, list):
        return RuleResult("ERROR", "IpPermissions must be a list.")
    for index, permission in enumerate(permissions):
        if not isinstance(permission, dict):
            return RuleResult("ERROR", f"Ingress permission {index} is malformed.")
        protocol = permission.get("IpProtocol")
        if not isinstance(protocol, str):
            return RuleResult("ERROR", f"Ingress permission {index} lacks a valid IpProtocol.")
        if protocol == "-1":
            sensitive_port = True
        elif protocol.lower() in {"tcp", "6"}:
            start, end = permission.get("FromPort"), permission.get("ToPort")
            if not isinstance(start, int) or not isinstance(end, int) or start > end:
                return RuleResult("ERROR", f"TCP ingress permission {index} has malformed port bounds.")
            sensitive_port = any(start <= port <= end for port in (22, 3389))
        else:
            sensitive_port = False
        if not sensitive_port:
            continue
        for range_key, cidr_key, any_cidr in (("IpRanges", "CidrIp", "0.0.0.0/0"),
                                               ("Ipv6Ranges", "CidrIpv6", "::/0")):
            if range_key not in permission:
                return RuleResult("NOT_SUPPORTED", f"Ingress permission {index} omitted {range_key}; public exposure cannot be excluded.")
            ranges = permission[range_key]
            if not isinstance(ranges, list):
                return RuleResult("ERROR", f"Ingress permission {index} {range_key} must be a list.")
            for cidr in ranges:
                if not isinstance(cidr, dict) or not isinstance(cidr.get(cidr_key), str):
                    return RuleResult("ERROR", f"Ingress permission {index} contains malformed {cidr_key} data.")
                try:
                    ipaddress.ip_network(cidr[cidr_key], strict=False)
                except ValueError:
                    return RuleResult("ERROR", f"Ingress permission {index} contains an invalid {cidr_key}.")
                if cidr[cidr_key] == any_cidr:
                    return RuleResult("FAIL", f"Ingress permission {index} exposes TCP management port(s) to {any_cidr}.")
    return RuleResult("PASS", "Observed ingress rules do not expose SSH or RDP to an unrestricted IPv4 or IPv6 CIDR.")


def _log_retention_baseline(resource: dict[str, Any]) -> RuleResult:
    if "attributes" not in resource:
        return RuleResult("NOT_SUPPORTED", "Normalized log-group attributes were not observed.")
    attrs = resource.get("attributes")
    if not isinstance(attrs, dict):
        return RuleResult("ERROR", "Log group attributes are malformed; expected an object.")
    if "retentionInDays" not in attrs:
        return _missing(resource)
    retention = attrs["retentionInDays"]
    if not isinstance(retention, int) or isinstance(retention, bool) or retention < 0:
        return RuleResult("ERROR", "retentionInDays is malformed; expected a non-negative integer.")
    if retention == 0:
        return RuleResult("NOT_SUPPORTED", "API returned a non-expiring retention value whose semantics are unverified.")
    if retention < 30:
        return RuleResult("FAIL", f"Observed retention is {retention} days, below the AEGIS local baseline of 30 days.")
    return RuleResult("PASS", f"Observed retention is {retention} days, meeting the AEGIS local baseline of 30 days.")


RULES: tuple[Rule, ...] = (
    Rule("AEGIS-IAM-001", "Avoid wildcard IAM permissions", "HIGH",
         "Detect Allow statements that use wildcard action or resource patterns. Conditions and effective permissions are not evaluated.",
         "iam_policy", ("iam:ListPolicies", "iam:GetPolicyVersion"),
         "Replace wildcard actions and resources with the smallest explicit action and resource sets required.", _iam_wildcards),
    Rule("AEGIS-EC2-001", "Restrict public SSH and RDP ingress", "HIGH",
         "Detect security-group ingress rules that expose TCP 22 or 3389, or all protocols, to all IPv4 or IPv6 addresses.",
         "ec2_security_group", ("ec2:DescribeSecurityGroups",),
         "Restrict management ingress to approved, narrow source ranges or a controlled access path.", _public_admin_ingress),
    Rule("AEGIS-LOGS-001", "Use at least 30 days of log retention", "MEDIUM",
         "Compare an explicitly returned CloudWatch log retention value with the AEGIS local 30-day assessment baseline. This is not a framework compliance claim.",
         "cloudwatch_log_group", ("logs:DescribeLogGroups",),
         "Set and periodically review a retention period of at least 30 days according to organizational requirements.", _log_retention_baseline),
)


def evaluate(rule: Rule, resource: dict[str, Any]) -> RuleResult:
    """Validate rule metadata and run one pure detector over normalized evidence."""
    if rule.rule_id == "" or rule.severity not in SEVERITIES:
        return RuleResult("ERROR", "Rule metadata is invalid.")
    try:
        result = rule.detect(resource)
    except Exception:
        return RuleResult("ERROR", "Rule evaluation failed on malformed input.")
    if result.outcome not in OUTCOMES or not isinstance(result.reason, str):
        return RuleResult("ERROR", "Rule returned an invalid outcome.")
    return result
