import datetime
from unittest.mock import MagicMock

from driftsentry.attribution.cloudtrail import CloudTrailAttributor
from driftsentry.core.models import DriftItem, DriftType


def test_parse_event_datetime_and_iso_string() -> None:
    """Ensure _parse_event parses datetime, ISO string, and None uniformly."""
    # 1. Boto3 datetime object
    dt = datetime.datetime(2026, 8, 20, 14, 30, tzinfo=datetime.UTC)
    evt1 = {"EventName": "AuthorizeSecurityGroupIngress", "EventTime": dt}
    parsed1 = CloudTrailAttributor._parse_event(evt1)
    assert parsed1["eventTime"] == dt

    # 2. ISO string inside CloudTrailEvent JSON detail
    evt2 = {
        "EventName": "AuthorizeSecurityGroupIngress",
        "CloudTrailEvent": '{"eventTime": "2026-08-20T15:30:00Z", "eventName": "AuthorizeSecurityGroupIngress"}',
    }
    parsed2 = CloudTrailAttributor._parse_event(evt2)
    expected_dt2 = datetime.datetime(2026, 8, 20, 15, 30, tzinfo=datetime.UTC)
    assert parsed2["eventTime"] == expected_dt2

    # 3. Missing/None timestamp
    evt3 = {"EventName": "AuthorizeSecurityGroupIngress"}
    parsed3 = CloudTrailAttributor._parse_event(evt3)
    assert parsed3["eventTime"] is None


def test_lookup_events_sorting_mixed_and_none_timestamps() -> None:
    """Ensure _lookup_events_with_client sorts mixed datetime, string, and None without TypeError."""
    mock_client = MagicMock()
    mock_paginator = MagicMock()

    t_earlier = datetime.datetime(2026, 8, 20, 10, 0, tzinfo=datetime.UTC)
    t_latest = "2026-08-20T16:00:00Z"

    # Mixed events: Boto3 datetime, CloudTrailEvent JSON string, and None
    mock_paginator.paginate.return_value = [
        {
            "Events": [
                {
                    "EventName": "AuthorizeSecurityGroupIngress",
                    "EventTime": t_earlier,
                    "Username": "user-early",
                },
                {
                    "EventName": "AuthorizeSecurityGroupIngress",
                    "CloudTrailEvent": f'{{"eventTime": "{t_latest}", "eventName": "AuthorizeSecurityGroupIngress", "userIdentity": {{"userName": "user-latest"}}}}',
                },
                {
                    "EventName": "AuthorizeSecurityGroupIngress",
                    # No EventTime or CloudTrailEvent timestamp
                    "Username": "user-none",
                },
            ]
        }
    ]
    mock_client.get_paginator.return_value = mock_paginator

    attributor = CloudTrailAttributor(region="us-east-1")
    events = attributor._lookup_events_with_client(
        mock_client,
        resource_id="sg-12345",
        event_names=["AuthorizeSecurityGroupIngress"],
    )

    assert len(events) == 3
    # Most recent first
    assert events[0]["userIdentity"]["userName"] == "user-latest"
    assert events[1]["userIdentity"]["userName"] == "user-early"
    assert events[2]["userIdentity"]["userName"] == "user-none"


def test_attribute_with_mixed_timestamp_events() -> None:
    """Test full attribute flow when CloudTrail returns events with mixed timestamp formats."""
    mock_client = MagicMock()
    mock_paginator = MagicMock()

    t_earlier = datetime.datetime(2026, 8, 19, 10, 0, tzinfo=datetime.UTC)
    t_latest = "2026-08-20T12:00:00Z"

    mock_paginator.paginate.return_value = [
        {
            "Events": [
                {
                    "EventName": "AuthorizeSecurityGroupIngress",
                    "EventTime": t_earlier,
                    "userIdentity": {"type": "IAMUser", "userName": "alice"},
                },
                {
                    "EventName": "AuthorizeSecurityGroupIngress",
                    "CloudTrailEvent": f'{{"eventTime": "{t_latest}", "eventName": "AuthorizeSecurityGroupIngress", "userIdentity": {{"type": "IAMUser", "userName": "bob"}}}}',
                },
            ]
        }
    ]
    mock_client.get_paginator.return_value = mock_paginator

    attributor = CloudTrailAttributor(region="us-east-1")
    attributor._clients = {("default", "us-east-1"): mock_client}

    item = DriftItem(
        resource_address="aws_security_group.web",
        resource_type="aws_security_group",
        resource_id="sg-12345",
        drift_type=DriftType.CHANGED,
    )

    result = attributor.attribute(item)
    assert result is not None
    assert result.principal == "bob"
    assert result.event_time == datetime.datetime(2026, 8, 20, 12, 0, tzinfo=datetime.UTC)
