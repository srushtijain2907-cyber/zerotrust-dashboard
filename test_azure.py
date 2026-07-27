from azure.identity import AzureCliCredential
from azure.mgmt.monitor import MonitorManagementClient
from datetime import datetime, timedelta, timezone

credential = AzureCliCredential()
client = MonitorManagementClient(credential, '048f4755-97cd-4f6d-a23c-108bd916a919')


end = datetime.now(timezone.utc)
start = end - timedelta(hours=72)

start_str = start.strftime('%Y-%m-%dT%H:%M:%SZ')
end_str = end.strftime('%Y-%m-%dT%H:%M:%SZ')

filter_str = f"eventTimestamp ge '{start_str}' and eventTimestamp le '{end_str}'"
events = list(client.activity_logs.list(filter=filter_str))
print(f'Azure events found: {len(events)}')
for e in events[:5]:
    print(f'  - {e.event_name.value if e.event_name else "unknown"} by {e.caller} at {e.event_timestamp}')
