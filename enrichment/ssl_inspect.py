"""SSL/TLS certificate inspector — analyses certificates on target IPs.

Uses Python stdlib ssl + socket (no extra dependencies).
Attempts TLS handshake on port 443 and reports certificate metadata.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from models import SSLResult
from utils.logger import get_logger

log = get_logger("ssl_inspect")


def _inspect_cert(ip: str, port: int = 443, timeout: float = 5.0) -> SSLResult:
    """Perform a blocking TLS handshake and extract certificate details."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Accept self-signed for inspection

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False)
                cert_bin = tls_sock.getpeercert(binary_form=True)

                if not cert and not cert_bin:
                    # Got a TLS connection but no cert info (CERT_NONE mode)
                    # Try to get DER cert for basic info
                    return SSLResult(has_ssl=True)

                # Parse issuer
                issuer_parts = []
                for rdn in cert.get("issuer", ()):
                    for attr_type, attr_value in rdn:
                        issuer_parts.append(f"{attr_type}={attr_value}")
                issuer = ", ".join(issuer_parts)

                # Parse subject
                subject_parts = []
                for rdn in cert.get("subject", ()):
                    for attr_type, attr_value in rdn:
                        subject_parts.append(f"{attr_type}={attr_value}")
                subject = ", ".join(subject_parts)

                # Parse SANs
                sans = []
                for san_type, san_value in cert.get("subjectAltName", ()):
                    sans.append(f"{san_type}:{san_value}")

                # Parse dates
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                # Check expiry
                is_expired = False
                if not_after:
                    try:
                        expiry = datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        is_expired = expiry < datetime.now(timezone.utc)
                    except ValueError:
                        pass

                # Check self-signed (issuer == subject)
                is_self_signed = issuer == subject and bool(issuer)

                # Serial number
                serial = cert.get("serialNumber", "")

                # Cipher info
                cipher = tls_sock.cipher()
                sig_algo = cipher[0] if cipher else ""

                return SSLResult(
                    has_ssl=True,
                    issuer=issuer,
                    subject=subject,
                    sans=sans[:20],  # Cap at 20 SANs
                    not_before=not_before,
                    not_after=not_after,
                    is_expired=is_expired,
                    is_self_signed=is_self_signed,
                    key_size=cipher[2] if cipher and len(cipher) > 2 else 0,
                    serial_number=serial,
                    signature_algorithm=sig_algo,
                )

    except (socket.timeout, socket.gaierror):
        log.debug("SSL handshake timed out for %s:%d", ip, port)
        return SSLResult()
    except ConnectionRefusedError:
        log.debug("Connection refused for %s:%d — no TLS service", ip, port)
        return SSLResult()
    except OSError as exc:
        log.debug("SSL inspection failed for %s:%d: %s", ip, port, exc)
        return SSLResult()
    except Exception as exc:
        log.warning("Unexpected SSL error for %s:%d: %s", ip, port, exc)
        return SSLResult()


async def inspect_ssl(ip: str, timeout: float = 5.0) -> SSLResult:
    """Inspect TLS certificate on *ip*:443 asynchronously.

    Parameters
    ----------
    ip:
        Target IP address.
    timeout:
        Maximum seconds for the TLS handshake.

    Returns
    -------
    SSLResult
        Certificate metadata, or empty result if no TLS service.
    """
    log.debug("SSL inspection: %s", ip)

    result = await asyncio.to_thread(_inspect_cert, ip, 443, timeout)

    if result.has_ssl:
        status = []
        if result.is_expired:
            status.append("EXPIRED")
        if result.is_self_signed:
            status.append("SELF-SIGNED")
        if status:
            log.info("SSL %s: %s → %s", ip, ", ".join(status), result.subject)
        else:
            log.debug("SSL %s: valid cert → %s", ip, result.subject)
    else:
        log.debug("No TLS on %s:443", ip)

    return result
