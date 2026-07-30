# Traffic Analysis: MiniC2 vs Meterpreter

> **Lab environment:** Kali Linux (attacker/C2 server) — Metasploitable2 or Windows VM (target agent)
> **Capture tool:** Wireshark / tcpdump on the shared NAT interface
> **Filter:** `tcp.port == 4443` for MiniC2 | `tcp.port == 4444` for Meterpreter (default reverse TCP)

---

## 1. MiniC2 Traffic Profile

### Protocol stack
```
Ethernet → IP → TCP → TLS 1.2 → HTTP/1.1 → AES-256-GCM payload
```

### What Wireshark shows

| Layer      | Observable                                                    |
|------------|---------------------------------------------------------------|
| TCP        | Regular SYN to port 4443, reused connection across beacons   |
| TLS        | TLS Client Hello, Server Hello, Certificate (self-signed)    |
| HTTP       | POST /beacon, POST /result (encrypted body, unreadable)      |
| Timing     | ~10s ± 3s between POST requests (beacon interval + jitter)   |
| Payload    | Opaque base64 blob — no plaintext commands visible            |

### Detection indicators (blue-team perspective)

- Self-signed certificate (unusual CA, short validity, generic CN)
- Regular POST intervals to a single non-standard port (4443)
- Fixed `Content-Type: application/json` with base64-only bodies
- No `User-Agent` customisation (Python requests default)

### How to reduce these indicators (for writeup discussion)

1. Use a legitimate-looking domain + Let's Encrypt cert
2. Randomise the `User-Agent` header (mimic a browser)
3. Use port 443 or 80 instead of 4443
4. Increase jitter range (e.g. ± 30s or domain-fronting delays)

---

## 2. Meterpreter (reverse_tcp) Traffic Profile

### Protocol stack (default, no TLS)
```
Ethernet → IP → TCP → Meterpreter TLV protocol
```

### What Wireshark shows

| Layer       | Observable                                                        |
|-------------|-------------------------------------------------------------------|
| TCP         | SYN to port 4444 (default), persistent connection                |
| Application | Binary TLV (Type-Length-Value) frames — no HTTP                  |
| Timing      | Continuous connection; keepalives; bursts on command execution    |
| Payload     | Partially obfuscated; Meterpreter magic bytes identifiable        |

### Meterpreter signatures
- Connection to port 4444 (well-known in IDS signatures)
- Meterpreter TLV header bytes detectable by Snort/Suricata
- No HTTP layer — pure binary protocol stands out vs web traffic

### With `meterpreter/reverse_https`
- Similar profile to MiniC2 (HTTPS-based)
- Still uses Meterpreter TLV inside TLS — detectable if TLS inspection is in place
- Certificate is auto-generated, often flagged by TLS fingerprinting (JA3)

---

## 3. Side-by-Side Comparison

| Property            | MiniC2 (this lab)              | Meterpreter reverse_tcp         |
|---------------------|--------------------------------|----------------------------------|
| Transport           | HTTPS (TLS 1.2+)               | Raw TCP (or HTTPS variant)       |
| Application layer   | HTTP/1.1 with JSON             | Binary TLV                       |
| Payload encryption  | AES-256-GCM (application layer)| Meterpreter XOR/RC4 or none      |
| Beacon pattern      | Polling (10s ± jitter)         | Persistent connection            |
| Detection surface   | TLS cert, timing, User-Agent   | Port 4444, TLV header bytes      |
| Evasion difficulty  | Medium (improvable)            | Low (well-signatured)            |

---

## 4. Capture Commands

```bash
# On Kali — capture all traffic on the lab interface to a file
sudo tcpdump -i eth0 -w c2_capture.pcap 'tcp port 4443 or tcp port 4444'

# Open in Wireshark and apply display filter
# For MiniC2:
tcp.port == 4443

# For Meterpreter:
tcp.port == 4444
```

---

## 5. Key Takeaways

1. **Layered encryption matters.** Even if a network proxy strips TLS, the
   AES-GCM application layer keeps commands and results opaque.

2. **Timing is a detection signal.** A perfectly regular beacon is a red flag
   in SIEM dashboards. Jitter blurs the pattern but doesn't eliminate it.

3. **Protocol choice affects blend-in.** HTTP(S) beaconing blends with
   legitimate web traffic far better than a raw TCP connection to port 4444.

4. **Self-signed certs are a giveaway.** TLS inspection or JA3 fingerprinting
   can flag atypical cert chains. A real red-team implant would use a CA-signed
   cert on a parked domain.
