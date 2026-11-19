import ipaddress
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, field_validator


class Alert(BaseModel):
    alert_type: str
    source_ip: str
    timestamp: Optional[str] = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def default_timestamp(cls, v):
        if not v or not str(v).strip():
            return datetime.now().isoformat()
        return str(v).strip()

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: str) -> str:
        clean = v.strip()
        try:
            ipaddress.ip_address(clean)
            return clean
        except ValueError:
            raise ValueError(f"'{v}' is not a syntactically valid IPv4 or IPv6 address.")
