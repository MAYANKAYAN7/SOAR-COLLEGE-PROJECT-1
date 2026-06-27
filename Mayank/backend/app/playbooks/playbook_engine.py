from app.core.logger import logger
from app.playbooks.host_isolation import isolate_host
from app.playbooks.ip_blocking import block_ip
from app.playbooks.aws_security_group import update_security_group



def execute_playbook(alert):

    risk = alert.get("risk")
    ip = alert.get("source_ip")
    hostname = alert.get("hostname", "Unknown Host")

    logger.info(f"Executing playbook for {risk} alert from {ip}")

    if risk == "Critical":

        logger.info(f"Isolating host: {hostname}")
        host_result = isolate_host(hostname)

        logger.info(f"Blocking IP: {ip}")
        ip_result = block_ip(ip)

        logger.info(f"Updating AWS Security Group for {ip}")
        aws_result = update_security_group(ip)

        return {
            "host": host_result,
            "ip": ip_result,
            "aws": aws_result
        }

    elif risk == "High":

        logger.info(f"Blocking IP: {ip}")
        ip_result = block_ip(ip)

        return {
            "ip": ip_result
        }

    else:

        logger.info(f"No automated action required for {ip}")

        return {
            "message": "Monitoring only"
        }