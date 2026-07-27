import re

with open('modules/azure_collector.py', 'r') as f:
    content = f.read()

content = re.sub(
    r'[ \t]*activity_logs = list\(activity_logs\)\n',
    '        activity_logs = list(activity_logs)\n',
    content
)

with open('modules/azure_collector.py', 'w') as f:
    f.write(content)

print('Fixed!')