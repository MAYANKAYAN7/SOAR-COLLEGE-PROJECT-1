from app.playbooks.playbook_engine import execute_playbook

alert = {
    "risk": "Critical",
    "source_ip": "192.168.1.100",
    "hostname": "SERVER-01"
}

result = execute_playbook(alert)

print(result)