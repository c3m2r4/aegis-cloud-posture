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


_CONTINUATION_FIELDS = ("NextToken", "nextToken", "NextMarker", "Marker", "position", "MarkerToken",
                       "NextPageToken", "ContinuationToken", "NextContinuationToken",
                       "LastEvaluatedTableName", "LastEvaluatedKey")


def _has_continuation(response: dict[str, Any]) -> bool:
    """Detect incomplete pagination without assuming a shared token shape."""
    if any(response.get(field) not in (None, "", False) for field in _CONTINUATION_FIELDS):
        return True
    return response.get("IsTruncated") is True or response.get("Truncated") is True


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
                       "name": item.get("PolicyName") or arn,
                       "attributes": {key: item[key] for key in ("Arn", "PolicyName", "DefaultVersionId", "Path", "AttachmentCount", "PermissionsBoundaryUsageCount") if key in item}})
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
                       "name": item.get("GroupName") or group_id,
                       "attributes": {key: item[key] for key in ("GroupId", "GroupName", "VpcId", "OwnerId",
                                                                   "IpPermissions", "IpPermissionsEgress", "Tags") if key in item}})
    return result


def _items(response: dict[str, Any], field: str, resource_type: str,
           identifier: str, name_field: str | None = None,
           *, metadata: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    """Normalize a known AWS list shape without turning malformed data into empty results."""
    result = []
    for item in _list_field(response, field):
        if not isinstance(item, dict) or not isinstance(item.get(identifier), str) or not item[identifier]:
            raise ValueError(f"{field} entry lacks a string {identifier}")
        resource_id = item[identifier]
        attrs = item if metadata is None else {key: item[key] for key in metadata if key in item}
        result.append({"resource_type": resource_type, "resource_id": resource_id,
                       "name": item.get(name_field) if name_field else resource_id,
                       "attributes": attrs})
    return result


def _images(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Images", "ec2_image", "ImageId", "Name",
                  metadata=("ImageId", "Name", "OwnerId", "Architecture",
                            "CreationDate", "State", "Public", "RootDeviceType", "VirtualizationType",
                            "Tags"))


def _vpcs(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = _items(response, "Vpcs", "ec2_vpc", "VpcId", metadata=(
        "VpcId", "CidrBlock", "DhcpOptionsId", "State", "IsDefault", "OwnerId", "Tags",
        "CidrBlockAssociationSet", "Ipv6CidrBlockAssociationSet"))
    for resource, item in zip(result, response["Vpcs"]):
        resource["name"] = _tag_name(item) or resource["resource_id"]
    return result


def _lambda_functions(response: dict[str, Any]) -> list[dict[str, Any]]:
    # ListFunctions may return arbitrary function environment variables. Keep only
    # inventory metadata; never persist those variables as evidence.
    return _items(response, "Functions", "lambda_function", "FunctionArn", "FunctionName",
                  metadata=("FunctionArn", "FunctionName", "Runtime", "Role", "Handler", "CodeSize",
                            "Timeout", "MemorySize", "LastModified", "State", "PackageType"))


def _eks_clusters(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _string_resources(response, "clusters", "eks_cluster")


def _eks_related_names(response: dict[str, Any], field: str, resource_type: str,
                       cluster_name: str, id_key: str, name_key: str) -> list[dict[str, Any]]:
    names = _list_field(response, field)
    result = []
    for name in names:
        if not isinstance(name, str) or not name:
            raise ValueError(f"{field} entry must be a non-empty string")
        resource_id = f"{cluster_name}/{name}"
        result.append({"resource_type": resource_type, "resource_id": resource_id, "name": name,
                       "attributes": {id_key: resource_id, name_key: name, "clusterName": cluster_name}})
    return result


def _string_resources(response: dict[str, Any], field: str, resource_type: str) -> list[dict[str, Any]]:
    result = []
    for value in _list_field(response, field):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} entry must be a non-empty string")
        result.append({"resource_type": resource_type, "resource_id": value, "name": value,
                       "attributes": {"id": value}})
    return result


def _rds_instances(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "DBInstances", "rds_db_instance", "DBInstanceArn", "DBInstanceIdentifier",
                  metadata=("DBInstanceArn", "DBInstanceIdentifier", "DBInstanceClass", "Engine",
                            "EngineVersion", "DBInstanceStatus", "AvailabilityZone", "MultiAZ",
                            "PubliclyAccessible", "StorageEncrypted", "AllocatedStorage"))


def _rds_clusters(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "DBClusters", "rds_db_cluster", "DBClusterArn", "DBClusterIdentifier",
                  metadata=("DBClusterArn", "DBClusterIdentifier", "Engine", "EngineVersion", "Status",
                            "AvailabilityZones", "MultiAZ", "StorageEncrypted", "Port"))


def _dynamodb_tables(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for name in _list_field(response, "TableNames"):
        if not isinstance(name, str) or not name:
            raise ValueError("TableNames entry must be a non-empty string")
        result.append({"resource_type": "dynamodb_table", "resource_id": name, "name": name,
                       "attributes": {"TableName": name}})
    return result


def _lambda_layers(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in _list_field(response, "Layers"):
        if not isinstance(item, dict) or not isinstance(item.get("LayerArn"), str):
            raise ValueError("Layers entry lacks a string LayerArn")
        arn = item["LayerArn"]
        name = item.get("LayerName") or arn
        result.append({"resource_type": "lambda_layer", "resource_id": arn, "name": name,
                       "attributes": {"LayerArn": arn, "LayerName": name}})
    return result


def _apigatewayv2_apis(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Items", "apigatewayv2_api", "ApiId", "Name",
                  metadata=("ApiId", "Name", "ProtocolType", "ApiEndpoint", "CreatedDate"))


def _load_balancers(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "LoadBalancers", "elbv2_load_balancer", "LoadBalancerArn", "LoadBalancerName",
                  metadata=("LoadBalancerArn", "LoadBalancerName", "DNSName", "Type", "Scheme",
                            "VpcId", "State", "IpAddressType", "CreatedTime"))


def _classic_load_balancers(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "LoadBalancerDescriptions", "elb_load_balancer", "LoadBalancerName",
                  "LoadBalancerName", metadata=("LoadBalancerName", "DNSName", "Scheme", "VPCId",
                                                  "AvailabilityZones", "Subnets", "SecurityGroups",
                                                  "CreatedTime"))


def _queues(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for url in _list_field(response, "QueueUrls"):
        if not isinstance(url, str) or not url:
            raise ValueError("QueueUrls entry must be a non-empty string")
        name = url.rsplit("/", 1)[-1]
        result.append({"resource_type": "sqs_queue", "resource_id": url, "name": name,
                       "attributes": {"QueueUrl": url, "QueueName": name}})
    return result


def _rest_apis(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "items", "apigateway_rest_api", "id", "name",
                  metadata=("id", "name", "createdDate", "version", "endpointConfiguration"))


def _event_buses(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "EventBuses", "eventbridge_event_bus", "Arn", "Name",
                  metadata=("Arn", "Name", "KmsKeyIdentifier"))


def _event_rules(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Rules", "eventbridge_rule", "Arn", "Name",
                  metadata=("Arn", "Name", "EventBusName", "State", "ScheduleExpression", "RoleArn"))


def _ses_identities(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for identity in _list_field(response, "Identities"):
        if not isinstance(identity, str) or not identity:
            raise ValueError("Identities entry must be a non-empty string")
        result.append({"resource_type": "ses_identity", "resource_id": identity, "name": identity,
                       "attributes": {"Identity": identity}})
    return result


def _state_machines(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "stateMachines", "stepfunctions_state_machine", "stateMachineArn", "name",
                  metadata=("stateMachineArn", "name", "type", "creationDate"))


def _stacks(response: dict[str, Any]) -> list[dict[str, Any]]:
    # ListStacks returns summaries only; do not fetch stack parameters/outputs.
    field = "StackSummaries" if "StackSummaries" in response else "Stacks"
    return _items(response, field, "cloudformation_stack", "StackId", "StackName",
                  metadata=("StackId", "StackName", "StackStatus", "CreationTime", "LastUpdatedTime",
                            "ParentId", "RootId", "Tags"))


def _iam_users(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Users", "iam_user", "Arn", "UserName",
                  metadata=("Arn", "UserName", "UserId", "Path", "CreateDate"))


def _secrets(response: dict[str, Any]) -> list[dict[str, Any]]:
    # ListSecrets returns metadata only; exclude free-form descriptions that can
    # accidentally contain secret material.
    return _items(response, "SecretList", "secretsmanager_secret", "ARN", "Name",
                  metadata=("ARN", "Name", "KmsKeyId", "RotationEnabled", "LastChangedDate",
                            "LastAccessedDate", "DeletedDate", "CreatedDate", "OwningService"))


def _kms_keys(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Keys", "kms_key", "KeyArn", "KeyId")


def _parameters(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Parameters", "ssm_parameter", "Name", "Name",
                  metadata=("Name", "Type", "KeyId", "LastModifiedDate", "Version", "Tier", "DataType"))


def _ec2_instances(response: dict[str, Any]) -> list[dict[str, Any]]:
    result = _instances(response)
    by_id = {resource["resource_id"]: resource for resource in result}
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            resource = by_id[instance["InstanceId"]]
            resource["attributes"] = {key: instance[key] for key in (
                "InstanceId", "InstanceType", "State", "VpcId", "SubnetId", "PublicIpAddress",
                "PrivateIpAddress", "IamInstanceProfile", "SecurityGroups", "Tags", "LaunchTime",
                "ImageId", "Architecture", "PlatformDetails") if key in instance}
    return result


def _volumes(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Volumes", "ec2_volume", "VolumeId", metadata=(
        "VolumeId", "Size", "VolumeType", "State", "Encrypted", "KmsKeyId", "AvailabilityZone",
        "CreateTime", "Attachments", "Tags"))


def _subnets(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Subnets", "ec2_subnet", "SubnetId", metadata=(
        "SubnetId", "VpcId", "CidrBlock", "AvailabilityZone", "AvailableIpAddressCount",
        "MapPublicIpOnLaunch", "DefaultForAz", "State", "Tags"))


def _network_interfaces(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "NetworkInterfaces", "ec2_network_interface", "NetworkInterfaceId", metadata=(
        "NetworkInterfaceId", "VpcId", "SubnetId", "Status", "InterfaceType", "PrivateIpAddress",
        "Association", "Groups", "Attachment", "TagSet"))


def _route_tables(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "RouteTables", "ec2_route_table", "RouteTableId", metadata=(
        "RouteTableId", "VpcId", "Associations", "Routes", "Tags"))


def _internet_gateways(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "InternetGateways", "ec2_internet_gateway", "InternetGatewayId", metadata=(
        "InternetGatewayId", "Attachments", "Tags"))


def _iam_roles(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Roles", "iam_role", "Arn", "RoleName", metadata=(
        "Arn", "RoleName", "RoleId", "Path", "CreateDate", "MaxSessionDuration"))


def _iam_groups(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Groups", "iam_group", "Arn", "GroupName", metadata=(
        "Arn", "GroupName", "GroupId", "Path", "CreateDate"))


def _iam_instance_profiles(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "InstanceProfiles", "iam_instance_profile", "Arn", "InstanceProfileName",
                  metadata=("Arn", "InstanceProfileName", "InstanceProfileId", "Path", "CreateDate"))


def _schedules(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "Schedules", "scheduler_schedule", "Arn", "Name", metadata=(
        "Arn", "Name", "GroupName", "State", "ScheduleExpression", "ScheduleExpressionTimezone",
        "CreationDate", "LastModificationDate", "FlexibleTimeWindow"))


def _ecs_clusters(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _string_resources(response, "clusterArns", "ecs_cluster")


def _ecr_repositories(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "repositories", "ecr_repository", "repositoryArn", "repositoryName",
                  metadata=("repositoryArn", "registryId", "repositoryName", "createdAt", "imageTagMutability",
                            "imageScanningConfiguration", "encryptionConfiguration"))


def _db_subnet_groups(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "DBSubnetGroups", "rds_db_subnet_group", "DBSubnetGroupArn", "DBSubnetGroupName",
                  metadata=("DBSubnetGroupArn", "DBSubnetGroupName", "VpcId", "SubnetGroupStatus", "Subnets"))


def _db_snapshots(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "DBSnapshots", "rds_db_snapshot", "DBSnapshotArn", "DBSnapshotIdentifier",
                  metadata=("DBSnapshotArn", "DBSnapshotIdentifier", "DBInstanceIdentifier", "SnapshotType",
                            "Status", "Engine", "EngineVersion", "SnapshotCreateTime", "Encrypted"))


def _nat_gateways(response: dict[str, Any]) -> list[dict[str, Any]]:
    return _items(response, "NatGateways", "ec2_nat_gateway", "NatGatewayId", metadata=(
        "NatGatewayId", "VpcId", "SubnetId", "State", "ConnectivityType", "CreateTime",
        "NatGatewayAddresses", "Tags"))


def specifications() -> list[AdapterSpec]:
    """Return the allowlisted read-only operation set. No mutation calls exist here."""
    return [
        AdapterSpec("sts", "GetCallerIdentity", "aws_identity", lambda c: c.get_caller_identity(), _identity),
        AdapterSpec("s3", "ListBuckets", "s3_bucket", lambda c: c.list_buckets(MaxBuckets=100), _buckets),
        AdapterSpec("ec2", "DescribeInstances", "ec2_instance", lambda c: c.describe_instances(MaxResults=100), _ec2_instances),
        AdapterSpec("ec2", "DescribeImages", "ec2_image", lambda c: c.describe_images(MaxResults=100), _images),
        AdapterSpec("ec2", "DescribeVpcs", "ec2_vpc", lambda c: c.describe_vpcs(MaxResults=100), _vpcs),
        AdapterSpec("ec2", "DescribeVolumes", "ec2_volume", lambda c: c.describe_volumes(MaxResults=100), _volumes),
        AdapterSpec("ec2", "DescribeSubnets", "ec2_subnet", lambda c: c.describe_subnets(MaxResults=100), _subnets),
        AdapterSpec("ec2", "DescribeNetworkInterfaces", "ec2_network_interface", lambda c: c.describe_network_interfaces(MaxResults=100), _network_interfaces),
        AdapterSpec("ec2", "DescribeRouteTables", "ec2_route_table", lambda c: c.describe_route_tables(MaxResults=100), _route_tables),
        AdapterSpec("ec2", "DescribeInternetGateways", "ec2_internet_gateway", lambda c: c.describe_internet_gateways(MaxResults=100), _internet_gateways),
        AdapterSpec("ec2", "DescribeNatGateways", "ec2_nat_gateway", lambda c: c.describe_nat_gateways(MaxResults=100), _nat_gateways),
        AdapterSpec("iam", "ListPolicies", "iam_policy", lambda c: c.list_policies(Scope="Local", MaxItems=100), _policies),
        AdapterSpec("iam", "ListUsers", "iam_user", lambda c: c.list_users(MaxItems=100), _iam_users),
        AdapterSpec("iam", "ListRoles", "iam_role", lambda c: c.list_roles(MaxItems=100), _iam_roles),
        AdapterSpec("iam", "ListGroups", "iam_group", lambda c: c.list_groups(MaxItems=100), _iam_groups),
        AdapterSpec("iam", "ListInstanceProfiles", "iam_instance_profile", lambda c: c.list_instance_profiles(MaxItems=100), _iam_instance_profiles),
        AdapterSpec("logs", "DescribeLogGroups", "cloudwatch_log_group", lambda c: c.describe_log_groups(limit=50), _log_groups),
        AdapterSpec("ec2", "DescribeSecurityGroups", "ec2_security_group", lambda c: c.describe_security_groups(MaxResults=100), _security_groups),
        AdapterSpec("lambda", "ListFunctions", "lambda_function", lambda c: c.list_functions(MaxItems=50), _lambda_functions),
        AdapterSpec("lambda", "ListLayers", "lambda_layer", lambda c: c.list_layers(MaxItems=50), _lambda_layers),
        AdapterSpec("eks", "ListClusters", "eks_cluster", lambda c: c.list_clusters(maxResults=100), _eks_clusters),
        AdapterSpec("rds", "DescribeDBInstances", "rds_db_instance", lambda c: c.describe_db_instances(MaxRecords=100), _rds_instances),
        AdapterSpec("rds", "DescribeDBClusters", "rds_db_cluster", lambda c: c.describe_db_clusters(MaxRecords=100), _rds_clusters),
        AdapterSpec("rds", "DescribeDBSubnetGroups", "rds_db_subnet_group", lambda c: c.describe_db_subnet_groups(MaxRecords=100), _db_subnet_groups),
        AdapterSpec("rds", "DescribeDBSnapshots", "rds_db_snapshot", lambda c: c.describe_db_snapshots(MaxRecords=100), _db_snapshots),
        AdapterSpec("dynamodb", "ListTables", "dynamodb_table", lambda c: c.list_tables(Limit=100), _dynamodb_tables),
        AdapterSpec("elb", "DescribeLoadBalancers", "elb_load_balancer", lambda c: c.describe_load_balancers(PageSize=100), _classic_load_balancers),
        AdapterSpec("elbv2", "DescribeLoadBalancers", "elbv2_load_balancer", lambda c: c.describe_load_balancers(PageSize=100), _load_balancers),
        AdapterSpec("sqs", "ListQueues", "sqs_queue", lambda c: c.list_queues(MaxResults=1000), _queues),
        AdapterSpec("apigateway", "GetRestApis", "apigateway_rest_api", lambda c: c.get_rest_apis(limit=100), _rest_apis),
        AdapterSpec("apigatewayv2", "GetApis", "apigatewayv2_api", lambda c: c.get_apis(MaxResults="100"), _apigatewayv2_apis),
        AdapterSpec("events", "ListEventBuses", "eventbridge_event_bus", lambda c: c.list_event_buses(Limit=100), _event_buses),
        AdapterSpec("events", "ListRules", "eventbridge_rule", lambda c: c.list_rules(EventBusName="default", Limit=100), _event_rules),
        AdapterSpec("ses", "ListIdentities", "ses_identity", lambda c: c.list_identities(IdentityType="EmailAddress", MaxItems=100), _ses_identities),
        AdapterSpec("stepfunctions", "ListStateMachines", "stepfunctions_state_machine", lambda c: c.list_state_machines(maxResults=100), _state_machines),
        AdapterSpec("cloudformation", "ListStacks", "cloudformation_stack", lambda c: c.list_stacks(), _stacks),
        AdapterSpec("secretsmanager", "ListSecrets", "secretsmanager_secret", lambda c: c.list_secrets(MaxResults=100), _secrets),
        AdapterSpec("kms", "ListKeys", "kms_key", lambda c: c.list_keys(Limit=100), _kms_keys),
        AdapterSpec("ssm", "DescribeParameters", "ssm_parameter", lambda c: c.describe_parameters(MaxResults=50), _parameters),
        AdapterSpec("scheduler", "ListSchedules", "scheduler_schedule", lambda c: c.list_schedules(MaxResults=100), _schedules),
        AdapterSpec("ecs", "ListClusters", "ecs_cluster", lambda c: c.list_clusters(maxResults=100), _ecs_clusters),
        AdapterSpec("ecr", "DescribeRepositories", "ecr_repository", lambda c: c.describe_repositories(maxResults=100), _ecr_repositories),
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
                                      response=None, resources=[], error=f"MalformedResponse: {type(exc).__name__}",
                                      observed_at=observed)
            if _has_continuation(response):
                return OperationResult(spec.service, spec.operation, "SUPPORTED_BUT_UNVERIFIED", "INCOMPLETE",
                                       response=response, resources=resources,
                                       error="Pagination is required; continuation behavior is not verified.",
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
        default_rules = next((r for r in results if r.service == "events" and r.operation == "ListRules"), None)
        if default_rules:
            default_rules.subject_resource_id = "default"
        # ListRules without EventBusName covers the default bus. Enumerate rules
        # on additional buses returned by the verified bus-list operation.
        bus_result = next((r for r in results if r.service == "events" and r.operation == "ListEventBuses"), None)
        if bus_result and bus_result.status in {"SUCCESS", "INCOMPLETE"}:
            for bus in (bus_result.response or {}).get("EventBuses", []) or []:
                if not isinstance(bus, dict) or not isinstance(bus.get("Name"), str) or not bus["Name"]:
                    results.append(OperationResult("events", "ListRules", "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                                   error="Event bus response lacks a valid name", observed_at=_utcnow()))
                    continue
                if bus["Name"].lower() == "default":
                    continue
                result = self._list_rules_for_bus(bus["Name"])
                result.subject_resource_id = bus["Name"]
                results.append(result)
        eks_result = next((r for r in results if r.service == "eks" and r.operation == "ListClusters"), None)
        if eks_result and eks_result.status in {"SUCCESS", "INCOMPLETE"}:
            for cluster_name in (eks_result.response or {}).get("clusters", []) or []:
                if not isinstance(cluster_name, str) or not cluster_name:
                    results.append(OperationResult("eks", "ListNodegroups", "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                                   error="Cluster list contains a malformed name", observed_at=_utcnow()))
                    continue
                results.append(self._list_eks_related(cluster_name, "ListNodegroups", "list_nodegroups",
                                                      "nodegroups", "eks_nodegroup", "nodegroupName"))
                results.append(self._list_eks_related(cluster_name, "ListFargateProfiles", "list_fargate_profiles",
                                                      "fargateProfileNames", "eks_fargate_profile", "fargateProfileName"))
        # Policy listing omits documents. Query only the default versions of ARNs
        # returned by the verified Local-scope listing operation.
        list_result = next((r for r in results if r.operation == "ListPolicies"), None)
        if list_result and list_result.status in {"SUCCESS", "INCOMPLETE"}:
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
        # Persist only the normalized, minimal inventory representation for
        # discovery-only calls. It omits API response fields not required for
        # inventory and prevents environment, parameter, output, and descriptive
        # payloads from becoming part of stored evidence. IAM policy documents
        # remain attached to their dedicated, verified GetPolicyVersion records.
        for result in results:
            if result.status in {"SUCCESS", "INCOMPLETE"} and result.operation != "GetPolicyVersion" and result.resources is not None:
                result.response = {"resources": result.resources}
        return results

    def _list_rules_for_bus(self, bus_name: str) -> OperationResult:
        observed = _utcnow()
        try:
            response = self._client("events").list_rules(EventBusName=bus_name, Limit=100)
            if not isinstance(response, dict):
                raise ValueError("API returned a non-object response")
            resources = _event_rules(response)
            if _has_continuation(response):
                return OperationResult("events", "ListRules", "SUPPORTED_BUT_UNVERIFIED", "INCOMPLETE",
                                       response=response, resources=resources,
                                       error="Pagination is required; continuation behavior is not verified.",
                                       observed_at=observed, subject_resource_id=bus_name)
            return OperationResult("events", "ListRules", "SUPPORTED_AND_TESTED", "SUCCESS",
                                   response=response, resources=resources, observed_at=observed,
                                   subject_resource_id=bus_name)
        except UnknownServiceError:
            return OperationResult("events", "ListRules", "UNSUPPORTED", "UNSUPPORTED",
                                   error="EventBridge service is unavailable", observed_at=observed,
                                   subject_resource_id=bus_name)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "ClientError")
            unsupported = code in {"UnknownOperationException", "UnsupportedOperation", "NotImplemented",
                                   "NotImplementedException", "InvalidAction", "OperationNotFound"}
            return OperationResult("events", "ListRules", "UNSUPPORTED" if unsupported else "SUPPORTED_AND_TESTED",
                                   "UNSUPPORTED" if unsupported else "ERROR", error=code,
                                   observed_at=observed, subject_resource_id=bus_name)
        except (BotoCoreError, TimeoutError, OSError, ValueError) as exc:
            return OperationResult("events", "ListRules", "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                   error=type(exc).__name__, observed_at=observed, subject_resource_id=bus_name)
        except Exception as exc:
            return OperationResult("events", "ListRules", "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                   error=type(exc).__name__, observed_at=observed, subject_resource_id=bus_name)

    def _list_eks_related(self, cluster_name: str, operation: str, method: str, field: str,
                          resource_type: str, name_key: str) -> OperationResult:
        observed = _utcnow()
        try:
            response = getattr(self._client("eks"), method)(clusterName=cluster_name, maxResults=100)
            if not isinstance(response, dict):
                raise ValueError("API returned a non-object response")
            resources = _eks_related_names(response, field, resource_type, cluster_name,
                                           "resourceId", name_key)
            if _has_continuation(response):
                return OperationResult("eks", operation, "SUPPORTED_BUT_UNVERIFIED", "INCOMPLETE",
                                       response=response, resources=resources,
                                       error="Pagination is required; continuation behavior is not verified.",
                                       observed_at=observed, subject_resource_id=cluster_name)
            return OperationResult("eks", operation, "SUPPORTED_AND_TESTED", "SUCCESS",
                                   response=response, resources=resources, observed_at=observed,
                                   subject_resource_id=cluster_name)
        except UnknownServiceError:
            return OperationResult("eks", operation, "UNSUPPORTED", "UNSUPPORTED",
                                   error="EKS service is unavailable", observed_at=observed,
                                   subject_resource_id=cluster_name)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "ClientError")
            unsupported = code in {"UnknownOperationException", "UnsupportedOperation", "NotImplemented",
                                   "NotImplementedException", "InvalidAction", "OperationNotFound"}
            return OperationResult("eks", operation, "UNSUPPORTED" if unsupported else "SUPPORTED_AND_TESTED",
                                   "UNSUPPORTED" if unsupported else "ERROR", error=code,
                                   observed_at=observed, subject_resource_id=cluster_name)
        except (BotoCoreError, TimeoutError, OSError, ValueError) as exc:
            return OperationResult("eks", operation, "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                   error=type(exc).__name__, observed_at=observed,
                                   subject_resource_id=cluster_name)
        except Exception as exc:
            return OperationResult("eks", operation, "SUPPORTED_BUT_UNVERIFIED", "ERROR",
                                   error=type(exc).__name__, observed_at=observed,
                                   subject_resource_id=cluster_name)

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
