"""
modules/azure_collector.py

Collects REAL logs from Azure Monitor Activity Log.
Uses ClientSecretCredential (Service Principal) if set, else AzureCliCredential.
"""

import os
import json
from datetime import datetime, timedelta, timezone
from config import ACTION_RISK_SCORES

AZURE_OPERATION_RISK = {
    "Microsoft.Authorization/roleAssignments/write":   9,
    "Microsoft.Authorization/roleAssignments/delete":  8,
    "Microsoft.Storage/storageAccounts/delete":        9,
    "Microsoft.Storage/storageAccounts/write":         6,
    "Microsoft.Compute/virtualMachines/delete":        9,
    "Microsoft.Compute/virtualMachines/write":         6,
    "Microsoft.Compute/virtualMachines/start/action":  5,
    "Microsoft.Compute/virtualMachines/stop/action":   6,
    "Microsoft.Network/networkSecurityGroups/write":   7,
    "Microsoft.KeyVault/vaults/write":                 7,
    "Microsoft.KeyVault/vaults/delete":                9,
    "Microsoft.Sql/servers/delete":                    9,
    "Microsoft.Resources/subscriptions/resourceGroups/write": 5,
    "Microsoft.Insights/activityLogAlerts/write":      6,
}


def collect_azure_logs(hours_back: int = 72) -> list[dict]:
    events = []

    subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not subscription_id:
        print("[Azure Collector] AZURE_SUBSCRIPTION_ID not set. Skipping Azure logs.")
        return events

    try:
        from azure.identity import AzureCliCredential, ClientSecretCredential
        from azure.mgmt.monitor import MonitorManagementClient

        tenant_id = os.environ.get("AZURE_TENANT_ID")
        client_id = os.environ.get("AZURE_CLIENT_ID")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET")

        if tenant_id and client_id and client_secret:
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            credential = AzureCliCredential()

        client = MonitorManagementClient(credential, subscription_id)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        start_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        end_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

        filter_str = (
            f"eventTimestamp ge '{start_str}' "
            f"and eventTimestamp le '{end_str}'"
        )
        print(f"[DEBUG] Subscription: {subscription_id}")
        print(f"[DEBUG] Filter: {filter_str}")
        activity_logs = client.activity_logs.list(
            filter=filter_str,
            select="eventTimestamp,caller,operationName,resourceGroupName,"
                   "resourceId,level,status,httpRequest,claims"
        )

        activity_logs = list(activity_logs)
        print(f"[DEBUG] Raw count from Azure: {len(activity_logs)}")
        for log in activity_logs:
            try:
                def _safe_val(x, default="Unknown"):
                    if x is None:
                        return default
                    return x.value if hasattr(x, "value") else str(x)

                operation = _safe_val(log.operation_name, "Unknown")
                caller = log.caller or "unknown"
                timestamp = (
                    log.event_timestamp.isoformat()
                    if log.event_timestamp else ""
                )
                level = _safe_val(log.level, "Informational")
                status = _safe_val(log.status, "Unknown")
                ip = "Unknown"
                if log.http_request:
                    ip = getattr(log.http_request, "client_ip_address", "Unknown") or "Unknown"

                action_name = operation.split("/")[-1] if "/" in operation else operation

                events.append({
                    "cloud":       "Azure",
                    "timestamp":   str(timestamp),
                    "user":        caller,
                    "action":      action_name,
                    "operation":   operation,
                    "ip_address":  ip,
                    "region":      "azure-global",
                    "country":     "Unknown",
                    "action_risk": AZURE_OPERATION_RISK.get(operation, 3),
                    "error_code":  "" if status == "Succeeded" else status,
                    "raw":         {"operation": operation, "level": level},
                })
            except Exception as e:
                print(f"[DEBUG] Event processing error: {e}")
                continue

    except ImportError:
        print("[Azure Collector] azure-identity or azure-mgmt-monitor not installed.")
    except Exception as e:
        print(f"[Azure Collector] Error: {e}")

    print(f"[Azure Collector] Collected {len(events)} real Azure Activity Log events.")
    return events