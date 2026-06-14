from app.services.abuseipdb_service import check_ip_reputation

result = check_ip_reputation("8.8.8.8")

print(result)