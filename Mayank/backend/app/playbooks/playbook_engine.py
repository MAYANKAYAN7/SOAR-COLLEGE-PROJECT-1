from app.playbooks.host_isolation import isolate_host
from app.playbooks.ip_blocking import block_ip
from app.playbooks.aws_security_group import update_security_group


def execute_playbook(alert):

    risk = alert.get("risk")

    ip = alert.get("source_ip")

    hostname = alert.get("hostname", "Unknown Host")

    if risk == "Critical":
        return {
            "host": isolate_host(hostname),
            "ip": block_ip(ip),
            "aws": update_security_group(ip)
        }

    elif risk == "High":
        return {
            "ip": block_ip(ip)
        }

    else:
        return {
            "message": "No automated action required."
        }