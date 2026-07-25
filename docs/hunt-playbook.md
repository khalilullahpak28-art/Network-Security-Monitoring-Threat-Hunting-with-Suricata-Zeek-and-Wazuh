# Hunt Playbook — Internal Port Scan Detection

A record of one complete threat hunt: hypothesis, data source, search, finding, and root-cause explanation for why automated detection missed it. Written in the format real hunt teams use to document and repeat hunts.

---

## Hunt Metadata

| Field | Detail |
|---|---|
| Hunt ID | HUNT-2026-07-25-001 |
| Analyst | Khalil |
| Date | 2026-07-25 |
| Data sources used | Zeek `conn.log` (via Wazuh archive index), Suricata `eve.json` (via Wazuh alert index) |
| Environment | Lab — Windows 10 (192.168.56.102) and Kali (192.168.56.1) on VirtualBox Host-only network |

---

## 1. Trigger / Motivation

Prior detection engineering work (Project 2) validated endpoint-based detection using Wazuh + Sysmon. This hunt asks a different question: with network-layer visibility now in place (Suricata + Zeek), does a common reconnaissance technique — port scanning — get caught automatically, and if not, can it still be found by directly analyzing raw connection data?

---

## 2. Hypothesis

**If an internal host were scanning another host's open ports, Zeek's connection log should show:**
- Multiple connection records
- Same source IP, same destination IP
- Each targeting a different destination port
- All occurring within a very tight time window (seconds, not minutes)
- Most or all resulting in a `REJ` (rejected) or similar non-established connection state, since most ports on a typical host are closed

This hypothesis was written **before** searching, following proper hunting methodology — the search was designed to test a specific, falsifiable idea, not just "look for anything weird."

---

## 3. Test Data Generation

An initial attempt to generate scan traffic using Atomic Red Team's `T1046-10` (subnet-wide PowerShell port scan) produced no usable data — confirmed via live packet capture (`tcpdump -i vboxnet0 -n`) that the traffic consisted almost entirely of ARP broadcast requests ("who has this IP?"), because the target subnet was almost entirely unpopulated (only 2 real hosts exist on this lab network). Windows never proceeded to real connection attempts against addresses with no responding host.

**Adapted test:** a direct scan against a real, responding host (Kali) was run instead:
```powershell
$ports = 22,80,443,445,3389,8080,3306,5432
foreach ($port in $ports) {
    Test-NetConnection -ComputerName 192.168.56.1 -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
}
```

---

## 4. Search Executed

**Step 1 — Check for automatic detection (Suricata, alerts index):**
```
agent.name:"host-kali" and data.event_type:"alert"
```
Result: no alert corresponding to this activity — only an unrelated, previously-configured test rule (ICMP ping detection) appeared, from earlier validation testing, not this scan.

**Step 2 — Manual hunt (Zeek, archive index):**
```
agent.name:"host-kali" and data.id_orig_h:"192.168.56.102" and data.id_resp_h:"192.168.56.1" and data.conn_state:"REJ"
```
Time range narrowed to the test execution window (~05:22, a few seconds wide).

---

## 5. Finding

Approximately **10 connection records** matched, all within a ~6-second window:
- `data.id_orig_h`: 192.168.56.102 (Windows 10) — consistent across all
- `data.id_resp_h`: 192.168.56.1 (Kali) — consistent across all
- `data.id_resp_p`: varied (matching the tested port list: 22, 80, 443, 445, 3389, 8080, 3306, 5432)
- `data.conn_state`: REJ — consistent across all
- `data.duration`: sub-millisecond in each case (e.g., 0.000042s)

This exactly matches the pre-written hypothesis: same source/destination pair, multiple ports, tight time window, rejected state.

**Hypothesis confirmed.**

---

## 6. Why It Wasn't Automatically Detected

Investigated directly rather than assumed. Suricata's default Emerging Threats Open ruleset (52,087 rules loaded) does contain scan-related signatures, but they are written with explicit directionality, e.g.:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SCAN Suspicious inbound to mySQL port 3306"; ...)
```

These rules are scoped to traffic considered to originate **outside** the network (`$EXTERNAL_NET`) directed **inward** (`$HOME_NET`). Since both the scanning host (Windows 10) and the target (Kali) reside within the same internally-trusted address range in this lab, the traffic never matched the "external attacker" pattern these signatures assume — a documented, real characteristic of many default IDS rulesets, not a misconfiguration.

---

## 7. Outcome & Recommendation

- **Confirmed gap:** default Suricata ruleset does not cover internal-to-internal reconnaissance scanning in this environment.
- **Recommendation for a production environment:** either write a custom Suricata rule scoped to internal subnets specifically (matching repeated `REJ`/RST patterns from one internal host to many ports on another), or rely on a scheduled/automated hunt query against Zeek data (the search used here) run on a recurring basis, rather than assuming signature-based detection alone provides sufficient internal visibility.
- **Broader takeaway:** this hunt is a concrete demonstration of why threat hunting exists as a discipline distinct from detection engineering — signature coverage has structural blind spots (in this case, directionality assumptions), and hypothesis-driven manual investigation of raw telemetry can close gaps that no existing rule addresses.

---

## 8. Follow-up Hunts (Not Yet Performed)

- DNS-based hunt: search for hosts making unusually frequent or unusually long DNS queries (possible tunneling)
- Beaconing hunt: search for connections recurring at suspiciously regular intervals to the same external destination
- Data volume hunt: search for connections with abnormally high `orig_bytes` relative to typical baseline traffic (possible exfiltration)
