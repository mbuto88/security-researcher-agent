from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlparse


HOST_RE = re.compile(r"^[a-zA-Z0-9.-]+$")


@dataclass(frozen=True)
class TargetScope:
    raw: str
    host: str

    @classmethod
    def parse(cls, raw: str) -> "TargetScope":
        target = raw.strip()
        try:
            ipaddress.ip_network(target, strict=False)
            return cls(raw=raw, host=target.lower())
        except ValueError:
            pass
        parsed = urlparse(target if "://" in target else f"//{target}")
        host = parsed.hostname or target
        host = host.strip("[]").lower()
        if not host:
            raise ValueError("Target host is empty.")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                ipaddress.ip_network(host, strict=False)
            except ValueError:
                if not HOST_RE.match(host):
                    raise ValueError(f"Unsupported target host: {raw}")
        return cls(raw=raw, host=host)

    def contains_token(self, token: str) -> bool:
        clean = token.strip("'\"[](),;")
        if clean == self.host or clean == self.raw:
            return True
        parsed = urlparse(clean)
        return parsed.hostname == self.host
