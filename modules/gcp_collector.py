"""
modules/gcp_collector.py

Collects REAL logs from Google Cloud Logging (Cloud Audit Logs).
Uses Application Default Credentials — no hardcoded keys.
User runs: gcloud auth application-default login

How it works:
1. Reads GCP project from environment or gcloud config
2. Queries Cloud Audit Logs (cloudaudit.googleapis.com/activity)
3. Normalizes to same schema as AWS and Azure collectors
"""

import os
from datetime import datetime, timedelta, timezone

GCP_OPERATION_RISK = {
    "google.iam.admin.v1.CreateServiceAccount":         9,
    "google.iam.admin.v1.DeleteServiceAccount":         8,
    "google.iam.admin.v1.SetIamPolicy":                 9,
    "google.iam.v1.IAMPolicy.SetIamPolicy":             9,
    "google.cloud.storage.v1.BucketService.DeleteBucket": 9,
    "google.cloud.storage.v1.BucketService.InsertBucket": 5,
    "google.cloud.compute.v1.Instances.Delete":         9,
    "google.cloud.compute.v1.Instances.Insert":         6,
    "google.cloud.compute.v1.Instances.Start":          4,
    "google.cloud.compute.v1.Instances.Stop":           6,
    "google.cloud.compute.v1.Firewalls.Insert":         7,
    "google.cloud.compute.v1.Firewalls.Delete":         7,
    "google.cloud.sql.v1beta4.SqlInstancesService.Delete": 9,
    "google.cloud.kms.v1.KeyManagementService.CreateCryptoKey": 6,
}


def collect_gcp_logs(hours_back: int = 24) -> list[dict]:
    """
    Fetch real GCP Cloud Audit Log events.
    Requires: pip install google-cloud-logging
    Requires: gcloud auth application-default login
              OR GOOGLE_APPLICATION_CREDENTIALS env var pointing to service account JSON
    """
    events = []

    project_id = os.environ.get(
        "GOOGLE_CLOUD_PROJECT",
        os.environ.get("GCP_PROJECT_ID", "")
    )

    if not project_id:
        # Try to get from gcloud config
        try:
            import subprocess
            result = subprocess.run(
                ["gcloud", "config", "get-value", "project"],
                capture_output=True, text=True, timeout=5
            )
            project_id = result.stdout.strip()
        except Exception:
            pass

    if not project_id:
        print("[GCP Collector] No GCP project found. Set GOOGLE_CLOUD_PROJECT env var "
              "or run: gcloud config set project YOUR_PROJECT_ID")
        return events

    try:
        from google.cloud import logging as gcp_logging
        from google.cloud.logging_v2.types import LogEntry

        client = gcp_logging.Client(project=project_id)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        # Filter for admin activity audit logs only
        filter_str = (
            f'logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Factivity" '
            f'timestamp>="{start_time.isoformat()}" '
            f'timestamp<="{end_time.isoformat()}"'
        )

        log_entries = client.list_entries(filter_=filter_str, max_results=1000)

        for entry in log_entries:
            try:
                payload = entry.payload if hasattr(entry, "payload") else {}

                # Extract method/operation name
                method_name = "Unknown"
                if hasattr(payload, "method_name"):
                    method_name = payload.method_name
                elif isinstance(payload, dict):
                    method_name = (
                        payload.get("methodName")
                        or payload.get("protoPayload", {}).get("methodName", "Unknown")
                    )

                # Extract caller email
                caller = "unknown"
                if hasattr(payload, "authentication_info"):
                    caller = getattr(payload.authentication_info, "principal_email", "unknown")
                elif isinstance(payload, dict):
                    caller = (
                        payload.get("authenticationInfo", {}).get("principalEmail", "unknown")
                    )

                # Extract IP
                ip = "Unknown"
                if hasattr(payload, "request_metadata"):
                    ip = getattr(payload.request_metadata, "caller_ip", "Unknown")
                elif isinstance(payload, dict):
                    ip = (
                        payload.get("requestMetadata", {}).get("callerIp", "Unknown")
                    )

                timestamp = ""
                if entry.timestamp:
                    timestamp = entry.timestamp.isoformat()

                action_name = method_name.split(".")[-1] if "." in method_name else method_name

                events.append({
                    "cloud":       "GCP",
                    "timestamp":   str(timestamp),
                    "user":        caller,
                    "action":      action_name,
                    "operation":   method_name,
                    "ip_address":  ip,
                    "region":      "gcp-global",
                    "country":     "Unknown",
                    "action_risk": GCP_OPERATION_RISK.get(method_name, 3),
                    "error_code":  "",
                    "raw":         {"method": method_name},
                })
            except Exception:
                continue

    except ImportError:
        print("[GCP Collector] google-cloud-logging not installed.")
    except Exception as e:
        print(f"[GCP Collector] Error: {e}")

    print(f"[GCP Collector] Collected {len(events)} real GCP Cloud Audit Log events.")
    return events
