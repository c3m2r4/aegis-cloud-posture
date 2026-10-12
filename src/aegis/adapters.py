"""Read-only adapters for operation-level verified Floci APIs."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, OperationNotPageableError, UnknownServiceError

from aegis.config import Settings


@dataclass(frozen=True)
class AdapterSpec:
    service: str
    operation: str
    resource_type: str | None
    invoke: Callable[[Any], dict[str, Any]]
    normalize: Callable[[dict[str, Any]], list[dict[str, Any]]]


@dataclass
class OperationResult:
    service: str
    operation: str
    capability: str
    status: str
    response: dict[str, Any] | None = None
    resources: list[dict[str, Any]] | None = None
    error: str | None = None
    observed_at: str = ""
    subject_resource_id: str | None = None


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _list_field(response: dict[str, Any], field: str) -> list[Any]:
    value = response.get(field)
    if not isinstance(value, list):
        raise ValueError(f"Response field {field} is missing or is not a list")
    return value


def _identity(response: dict[str, Any]) -> list[dict[str, Any]]:
    identity = response.get("UserId") or response.get("Arn") or response.get("Account")
    if not identity:
        raise ValueError("STS response lacks UserId, Arn, and Account")
    return [{"resource_type": "aws_identity", "resource_id": str(identity), "name": str(response.get("Arn", identity)), "attributes": response}]


def _buckets(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in _list_field(response, "Buckets"):
        if not isinstance(item, dict) or not isinstance(item.get("Name"), str):
            raise ValueError("S3 bucket entry lacks a string Name")
        name = item["Name"]
        result.append({"resource_type": "s3_bucket", "resource_id": name, "name": name, "attributes": item})
    return result


def _instances(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for reservation in _list_field(response, "Reservations"):
        if not isinstance(reservation, dict):
            raise ValueError("EC2 reservation entry is malformed")
        for item in _list_field(reservation, "Instances"):
            if not isinstance(item, dict) or not isinstance(item.get("InstanceId"), str):
                raise ValueError("EC2 instance entry lacks a string InstanceId")
            instance_id = item["InstanceId"]
            result.append({"resource_type": "ec2_instance", "resource_id": instance_id,
                           "name": _tag_name(item) or instance_id, "attributes": item})
    return result


def _tag_name(item: dict[str, Any]) -> str | None:
    for tag in item.get("Tags", []) or []:
        if tag.get("Key") == "Name":
            return tag.get("Value")
    return None


def _policies(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in _list_field(response, "Policies"):
        if not isinstance(item, dict) or not isinstance(item.get("Arn"), str):
            raise ValueError("IAM policy entry lacks a string Arn")
        arn = item["Arn"]
        result.append({"resource_type": "iam_policy", "resource_id": arn,
                       "name": item.get("PolicyName") or arn, "attributes": item})
    return result


def _log_groups(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in _list_field(response, "logGroups"):
        if not isinstance(item, dict) or not isinstance(item.get("logGroupName"), str):
            raise ValueError("CloudWatch log-group entry lacks a string logGroupName")
        name = item["logGroupName"]
        result.append({"resource_type": "cloudwatch_log_group", "resource_id": name,
                       "name": name, "attributes": item})
    return result


def _security_groups(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in _list_field(response, "SecurityGroups"):
        if not isinstance(item, dict) or not isinstance(item.get("GroupId"), str):
            raise ValueError("Security-group entry lacks a string GroupId")
        group_id = item["GroupId"]
        result.append({"resource_type": "ec2_security_group", "resource_id": group_id,
                       "name": item.get("GroupName") or group_id, "attributes": item})
    return result


def specifications() -> list[AdapterSpec]:
    """Return the allowlisted read-only operation set. No mutation calls exist here."""
    return [
        AdapterSpec("sts", "GetCallerIdentity", "aws_identity", lambda c: c.get_caller_identity(), _identity),
        AdapterSpec("s3", "ListBuckets", "s3_bucket", lambda c: c.list_buckets(), _buckets),
        AdapterSpec("ec2", "DescribeInstances", "ec2_instance", lambda c: c.describe_instances(), _instances),
        AdapterSpec("iam", "ListPolicies", "iam_policy", lambda c: c.list_policies(Scope="Local"), _policies),
        AdapterSpec("logs", "DescribeLogGroups", "cloudwatch_log_group", lambda c: c.describe_log_groups(), _log_groups),
        AdapterSpec("ec2", "DescribeSecurityGroups", "ec2_security_group", lambda c: c.describe_security_groups(), _security_groups),
    ]


class FlociAdapter:
    def __init__(self, settings: Settings, session: Any | None = None):
        self.settings = settings
        self.session = session or boto3.Session(region_name=settings.region)
        self.config = Config(connect_timeout=settings.connect_timeout, read_timeout=settings.read_timeout,
                             retries={"max_attempts": 0})

    def _client(self, service: str) -> Any:
        return self.session.client(service, endpoint_url=self.settings.endpoint_url,
                                   region_name=self.settings.region, config=self.config)

    def collect_one(self, spec: AdapterSpec) -> OperationResult:
        observed = _utcnow()
        try:
            client = self._client(spec.service)
            # Never auto-paginate an operation whose Floci pagination behavior is unverified.
            response = spec.invoke(client)
            if not isinstance(response, dict):
                raise ValueError("API returned a non-object response")
            try:
                resources = spec.normalize(response)
            except Exception as exc:
                return OperationResult(spec.service, spec.operation, "SUPPORTED_AND_TESTED", "ERROR",
                                      response=response, resources=[], error=f"MalformedResponse: {type(exc).__name__}",
                                      observed_at=observed)
            return OperationResult(spec.service, spec.operation, "SUPPORTED_AND_TESTED", "SUCCESS",
                                  response=response, resources=resources, observed_at=observed)
        except UnknownServiceError as exc:
            return OperationResult(spec.service, spec.operation, "UNSUPPORTED", "UNSUPPORTED",
                                   error=f"Service is unavailable: {exc}", observed_at=observed)
        except OperationNotPageableError as exc:
            return OperationResult(spec.service, spec.operation, "UNSUPPORTED", "UNSUPPORTED",
                                   error=f"Required operation is unavailable: {exc}", observed_at=observed)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            message = exc.response.get("Error", {}).get("Message", "API request failed")
            if code in {"UnknownOperationException", "UnsupportedOperation", "NotImplemented", "NotImplementedException", "InvalidAction", "OperationNotFound"}:
                state, status = "UNSUPPORTED", "UNSUPPORTED"
            else:
                state, status = "SUPPORTED_AND_TESTED", "ERROR"
            return OperationResult(spec.service, spec.operation, state, status,
                                   error=f"{code}: {message}", observed_at=observed)
        except (BotoCoreError, TimeoutError, OSError, ValueError) as exc:
            return OperationResult(spec.service, spec.operation, "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                   error=type(exc).__name__, observed_at=observed)
        except Exception as exc:
            return OperationResult(spec.service, spec.operation, "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                   error=type(exc).__name__, observed_at=observed)

    def collect(self) -> list[OperationResult]:
        results = [self.collect_one(spec) for spec in specifications()]
        # Policy listing omits documents. Query only the default versions of ARNs
        # returned by the verified Local-scope listing operation.
        list_result = next((r for r in results if r.operation == "ListPolicies"), None)
        if list_result and list_result.status == "SUCCESS":
            for policy in (list_result.response or {}).get("Policies", []) or []:
                if not isinstance(policy, dict):
                    results.append(OperationResult("iam", "GetPolicyVersion", "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                                   error="Listed policy entry is malformed", observed_at=_utcnow()))
                    continue
                arn, version = policy.get("Arn"), policy.get("DefaultVersionId")
                if not arn or not version:
                    results.append(OperationResult("iam", "GetPolicyVersion", "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                                   error="Listed policy lacks ARN or default version ID", observed_at=_utcnow()))
                    continue
                result = self._get_policy_version(arn, version)
                results.append(result)
                if result.status == "SUCCESS":
                    resource = next((r for r in list_result.resources or [] if r["resource_id"] == arn), None)
                    version_data = (result.response or {}).get("PolicyVersion", {})
                    if resource and isinstance(version_data, dict):
                        resource["attributes"]["PolicyVersion"] = version_data
                    result.resources = [{"resource_type": "iam_policy_version", "resource_id": f"{arn}#{version}",
                                         "name": f"{policy.get('PolicyName', arn)} {version}",
                                         "attributes": version_data}]
        return results

    def _get_policy_version(self, arn: str, version: str) -> OperationResult:
        observed = _utcnow()
        subject = f"{arn}#{version}"
        try:
            response = self._client("iam").get_policy_version(PolicyArn=arn, VersionId=version)
            if not isinstance(response, dict) or not isinstance(response.get("PolicyVersion"), dict):
                return OperationResult("iam", "GetPolicyVersion", "SUPPORTED_AND_TESTED", "ERROR",
                                       response=response if isinstance(response, dict) else None,
                                       error="MalformedResponse: missing PolicyVersion object", observed_at=observed,
                                       subject_resource_id=subject)
            return OperationResult("iam", "GetPolicyVersion", "SUPPORTED_AND_TESTED", "SUCCESS",
                                  response=response, resources=[], observed_at=observed, subject_resource_id=subject)
        except UnknownServiceError:
            return OperationResult("iam", "GetPolicyVersion", "UNSUPPORTED", "UNSUPPORTED",
                                   error="IAM service is unavailable", observed_at=observed, subject_resource_id=subject)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "ClientError")
            message = error.get("Message", "API request failed")
            unsupported_codes = {"UnknownOperationException", "UnsupportedOperation", "NotImplemented",
                                 "NotImplementedException", "InvalidAction", "OperationNotFound"}
            status = "UNSUPPORTED" if code in unsupported_codes else "ERROR"
            capability = "UNSUPPORTED" if status == "UNSUPPORTED" else "SUPPORTED_AND_TESTED"
            return OperationResult("iam", "GetPolicyVersion", capability, status,
                                   error=f"{code}: {message}", observed_at=observed, subject_resource_id=subject)
        except (BotoCoreError, TimeoutError, OSError, ValueError) as exc:
            return OperationResult("iam", "GetPolicyVersion", "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                   error=type(exc).__name__, observed_at=observed, subject_resource_id=subject)
