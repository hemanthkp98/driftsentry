"""Unit tests for Elastic IPs, Key Pairs, Network Interfaces, Load Balancers, and EKS scanners."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from driftsentry.providers.aws.catalog import ResourceCatalog
from driftsentry.providers.aws.declarative import GenericAWSDeclarativeScanner
from driftsentry.providers.aws.resources.ec2 import EC2Scanner


@pytest.fixture
def mock_session() -> MagicMock:
    session = MagicMock()
    return session


def test_ec2_scanner_supported_types(mock_session: MagicMock) -> None:
    scanner = EC2Scanner(mock_session, "us-east-1")
    expected = {
        "aws_instance",
        "aws_security_group",
        "aws_vpc",
        "aws_subnet",
        "aws_eip",
        "aws_key_pair",
        "aws_network_interface",
    }
    assert expected.issubset(set(scanner.resource_types))


def test_eip_listing_and_get(mock_session: MagicMock) -> None:
    mock_ec2 = MagicMock()
    mock_session.client.return_value = mock_ec2

    sample_eip = {
        "AllocationId": "eipalloc-0123456789abcdef0",
        "PublicIp": "54.210.10.20",
        "Domain": "vpc",
        "InstanceId": "i-0123456789abcdef0",
        "NetworkInterfaceId": "eni-0123456789abcdef0",
        "Tags": [{"Key": "Name", "Value": "bastion-ip"}],
    }

    mock_ec2.describe_addresses.return_value = {"Addresses": [sample_eip]}

    scanner = EC2Scanner(mock_session, "us-east-1")
    eips = scanner._list_eips()
    assert len(eips) == 1
    eip = eips[0]
    assert eip.resource_id == "eipalloc-0123456789abcdef0"
    assert eip.resource_type == "aws_eip"
    assert eip.attributes["public_ip"] == "54.210.10.20"
    assert eip.attributes["instance"] == "i-0123456789abcdef0"
    assert eip.attributes["domain"] == "vpc"
    assert eip.tags["Name"] == "bastion-ip"

    # Test get_by_id by allocation ID
    fetched = scanner.get_by_id("eipalloc-0123456789abcdef0")
    assert fetched is not None
    assert fetched.resource_id == "eipalloc-0123456789abcdef0"

    # Test get_by_id by public IP address
    fetched_by_ip = scanner.get_by_id("54.210.10.20")
    assert fetched_by_ip is not None
    assert fetched_by_ip.resource_id == "eipalloc-0123456789abcdef0"


def test_key_pair_listing_and_get(mock_session: MagicMock) -> None:
    mock_ec2 = MagicMock()
    mock_session.client.return_value = mock_ec2

    sample_kp = {
        "KeyPairId": "key-0123456789abcdef0",
        "KeyName": "prod-ssh-key",
        "KeyFingerprint": "11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff",
        "KeyType": "ed25519",
        "Tags": [{"Key": "Environment", "Value": "Production"}],
    }

    mock_ec2.describe_key_pairs.return_value = {"KeyPairs": [sample_kp]}

    scanner = EC2Scanner(mock_session, "us-east-1")
    key_pairs = scanner._list_key_pairs()
    assert len(key_pairs) == 1
    kp = key_pairs[0]
    assert kp.resource_id == "prod-ssh-key"
    assert kp.resource_type == "aws_key_pair"
    assert kp.attributes["key_name"] == "prod-ssh-key"
    assert kp.attributes["key_pair_id"] == "key-0123456789abcdef0"
    assert kp.attributes["key_type"] == "ed25519"
    assert kp.tags["Environment"] == "Production"

    # Test get_by_id with key ID
    fetched = scanner.get_by_id("key-0123456789abcdef0")
    assert fetched is not None
    assert fetched.resource_id == "prod-ssh-key"

    # Test get_by_id with key name
    fetched_by_name = scanner.get_by_id("prod-ssh-key")
    assert fetched_by_name is not None
    assert fetched_by_name.attributes["key_name"] == "prod-ssh-key"


def test_network_interface_listing_and_get(mock_session: MagicMock) -> None:
    mock_ec2 = MagicMock()
    mock_session.client.return_value = mock_ec2

    sample_eni = {
        "NetworkInterfaceId": "eni-0123456789abcdef0",
        "SubnetId": "subnet-12345678",
        "VpcId": "vpc-12345678",
        "PrivateIpAddress": "10.0.1.50",
        "Description": "Primary ENI",
        "Groups": [{"GroupId": "sg-12345678", "GroupName": "default"}],
        "Tags": [{"Key": "Role", "Value": "web"}],
    }

    paginator = MagicMock()
    paginator.paginate.return_value = [{"NetworkInterfaces": [sample_eni]}]
    mock_ec2.get_paginator.return_value = paginator

    scanner = EC2Scanner(mock_session, "us-east-1")
    enis = scanner._list_network_interfaces()
    assert len(enis) == 1
    eni = enis[0]
    assert eni.resource_id == "eni-0123456789abcdef0"
    assert eni.resource_type == "aws_network_interface"
    assert eni.attributes["private_ip"] == "10.0.1.50"
    assert eni.attributes["subnet_id"] == "subnet-12345678"
    assert eni.attributes["security_groups"] == ["sg-12345678"]
    assert eni.tags["Role"] == "web"

    # Test get_by_id
    mock_ec2.describe_network_interfaces.return_value = {"NetworkInterfaces": [sample_eni]}
    fetched = scanner.get_by_id("eni-0123456789abcdef0")
    assert fetched is not None
    assert fetched.resource_id == "eni-0123456789abcdef0"


def test_catalog_loads_lb_and_eks() -> None:
    catalog = ResourceCatalog()
    definitions = catalog.load_all()

    assert "aws_lb" in definitions
    lb_def = definitions["aws_lb"]
    assert lb_def.service == "elbv2"
    assert lb_def.discovery.list_operation == "describe_load_balancers"
    assert lb_def.discovery.id_field == "LoadBalancerArn"

    assert "aws_eks_cluster" in definitions
    eks_def = definitions["aws_eks_cluster"]
    assert eks_def.service == "eks"
    assert eks_def.discovery.list_operation == "list_clusters"
    assert eks_def.discovery.describe_operation == "describe_cluster"


def test_declarative_scanner_lb(mock_session: MagicMock) -> None:
    catalog = ResourceCatalog()
    defs = catalog.load_all()
    lb_def = defs["aws_lb"]

    mock_elbv2 = MagicMock()
    mock_session.client.return_value = mock_elbv2

    sample_lb = {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890abcdef",
        "LoadBalancerName": "my-alb",
        "DNSName": "my-alb-1234567890.us-east-1.elb.amazonaws.com",
        "Scheme": "internet-facing",
        "VpcId": "vpc-12345678",
        "Type": "application",
        "State": {"Code": "active"},
        "SecurityGroups": ["sg-12345678"],
        "AvailabilityZones": [
            {"ZoneName": "us-east-1a", "SubnetId": "subnet-11111111"},
            {"ZoneName": "us-east-1b", "SubnetId": "subnet-22222222"},
        ],
        "IpAddressType": "ipv4",
        "Tags": [{"Key": "Env", "Value": "prod"}],
    }

    paginator = MagicMock()
    paginator.paginate.return_value = [{"LoadBalancers": [sample_lb]}]
    mock_elbv2.get_paginator.return_value = paginator

    scanner = GenericAWSDeclarativeScanner(mock_session, "us-east-1", lb_def)
    resources = scanner.list_all()
    assert len(resources) == 1
    res = resources[0]
    assert res.resource_id == sample_lb["LoadBalancerArn"]
    assert res.attributes["name"] == "my-alb"
    assert res.attributes["load_balancer_type"] == "application"
    assert res.attributes["scheme"] == "internet-facing"
    assert res.attributes["security_groups"] == ["sg-12345678"]
    assert "subnet-11111111" in res.attributes["subnets"]
    assert res.tags.get("Env") == "prod"


def test_declarative_scanner_eks(mock_session: MagicMock) -> None:
    catalog = ResourceCatalog()
    defs = catalog.load_all()
    eks_def = defs["aws_eks_cluster"]

    mock_eks = MagicMock()
    mock_session.client.return_value = mock_eks

    paginator = MagicMock()
    paginator.paginate.return_value = [{"clusters": ["my-prod-cluster"]}]
    mock_eks.get_paginator.return_value = paginator

    mock_eks.describe_cluster.return_value = {
        "cluster": {
            "name": "my-prod-cluster",
            "arn": "arn:aws:eks:us-east-1:123456789012:cluster/my-prod-cluster",
            "version": "1.30",
            "endpoint": "https://ABCDEF123456.gr7.us-east-1.eks.amazonaws.com",
            "roleArn": "arn:aws:iam::123456789012:role/eksClusterRole",
            "resourcesVpcConfig": {
                "subnetIds": ["subnet-1111", "subnet-2222"],
                "securityGroupIds": ["sg-3333"],
                "clusterSecurityGroupId": "sg-4444",
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
            },
            "tags": {"Owner": "DevOps"},
        }
    }

    scanner = GenericAWSDeclarativeScanner(mock_session, "us-east-1", eks_def)
    resources = scanner.list_all()
    assert len(resources) == 1
    res = resources[0]
    assert res.resource_id == "my-prod-cluster"
    assert res.attributes["name"] == "my-prod-cluster"
    assert res.attributes["version"] == "1.30"
    assert res.attributes["role_arn"] == "arn:aws:iam::123456789012:role/eksClusterRole"
    assert res.attributes["endpoint_public_access"] is True
    assert res.attributes["subnet_ids"] == ["subnet-1111", "subnet-2222"]
    assert res.tags.get("Owner") == "DevOps"
