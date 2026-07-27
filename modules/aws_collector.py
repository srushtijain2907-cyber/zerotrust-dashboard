"""
modules/aws_collector.py

Collects REAL logs from AWS CloudTrail using boto3.
No fake data — connects to actual AWS account via ~/.aws/credentials
(set up once with `aws configure`).

How it works:
1. Calls CloudTrail lookup_events() API
2. Extracts user, action, IP, time, region from each event
3. Returns a list of normalized log dicts ready for ML processing

If AWS credentials are not configured, returns empty list with a warning.
"""

import boto3
import json
import socket
from datetime import datetime, timedelta, timezone
from botocore.exceptions import NoCredentialsError, ClientError
from config import AWS_REGION, AWS_LOG_HOURS_BACK, ACTION_RISK_SCORES


_country_cache = {}

def get_country_from_ip(ip: str) -> str:
    """
    Best-effort country detection from IP.
    Uses ip-api.com with a hard-enforced timeout so a hung
    connection can never block event collection.
    Falls back to 'Unknown' gracefully if offline or slow.
    """
    if ip in _country_cache:
        return _country_cache[ip]

    result = {"value": "Unknown"}

    def _fetch():
        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=countryCode"
            with urllib.request.urlopen(url, timeout=2) as resp:
                data = json.loads(resp.read())
                result["value"] = data.get("countryCode", "Unknown")
        except Exception:
            result["value"] = "Unknown"

    import threading
    t = threading.Thread(target=_fetch, daemon=True)
    t.start()
    t.join(timeout=2.5)  # hard cap — never wait longer than this, no matter what

    _country_cache[ip] = result["value"]
    return result["value"]

def collect_aws_logs(hours_back: int = AWS_LOG_HOURS_BACK) -> list[dict]:
    """
    Fetch real AWS CloudTrail events from the past `hours_back` hours.

    Returns list of normalized event dicts, each with:
    - cloud: "AWS"
    - timestamp: ISO string
    - user: IAM username or role
    - action: CloudTrail event name (e.g. "CreateUser")
    - ip_address: source IP
    - region: AWS region
    - country: country code from IP geolocation
    - action_risk: risk score from ACTION_RISK_SCORES
    - raw: full original CloudTrail event (for audit)
    """
    events = []

    try:
        session = boto3.Session(region_name=AWS_REGION)
        client = session.client("cloudtrail")

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        paginator = client.get_paginator("lookup_events")
        pages = paginator.paginate(
            StartTime=start_time,
            EndTime=end_time,
            PaginationConfig={"MaxItems": 2000, "PageSize": 50},
        )

        for page in pages:
            for raw_event in page.get("Events", []):
                try:
                    # Parse the nested CloudTrail JSON record
                    ct = json.loads(raw_event.get("CloudTrailEvent", "{}"))

                    user_identity = ct.get("userIdentity", {})
                    user = (
                        user_identity.get("userName")
                        or user_identity.get("sessionContext", {})
                           .get("sessionIssuer", {})
                           .get("userName")
                        or user_identity.get("arn", "unknown").split("/")[-1]
                    )

                    action = ct.get("eventName", "Unknown")
                    ip = ct.get("sourceIPAddress", "0.0.0.0")
                    region = ct.get("awsRegion", AWS_REGION)
                    timestamp = ct.get("eventTime", raw_event.get("EventTime", ""))
                    if hasattr(timestamp, "isoformat"):
                        timestamp = timestamp.isoformat()

                    # Get country for IP (skip AWS service IPs)
                    country = "Unknown"
                    if ip and not ip.startswith("AWS"):
                        country = get_country_from_ip(ip)

                    events.append({
                        "cloud":       "AWS",
                        "timestamp":   str(timestamp),
                        "user":        user,
                        "action":      action,
                        "ip_address":  ip,
                        "region":      region,
                        "country":     country,
                        "action_risk": ACTION_RISK_SCORES.get(action, 3),
                        "error_code":  ct.get("errorCode", ""),
                        "raw":         ct,
                    })
                except Exception:
                    continue

    except NoCredentialsError:
        print("[AWS Collector] No credentials found. Run `aws configure` first.")
    except ClientError as e:
        print(f"[AWS Collector] AWS API error: {e}")
    except Exception as e:
        print(f"[AWS Collector] Unexpected error: {e}")

    print(f"[AWS Collector] Collected {len(events)} real AWS CloudTrail events.")
    return events
