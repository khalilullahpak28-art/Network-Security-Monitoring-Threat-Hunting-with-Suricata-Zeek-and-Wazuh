# Network-Security-Monitoring-Threat-Hunting-with-Suricata-Zeek-and-Wazuh
Added network visibility to my SOC, then hunted for a port scan manually in Zeek's logs after Suricata's 52k rules missed it — found the pattern, root-caused why (its rules only watch external→internal traffic), documented as a hunt playbook.
# Network Security Monitoring & Threat Hunting

A project building network-layer visibility (Suricata + Zeek) alongside an existing endpoint-focused Wazuh SIEM, then using that visibility to run a real hypothesis-driven threat hunt — deliberately testing what automated signature-based detection misses, and what manual analysis of raw connection data can still catch.

This is the fourth project in a progressive SOC portfolio: (1) SOC automation with Wazuh/Shuffle/TheHive, (2) MITRE ATT&CK-mapped detection engineering with a custom MISP integration, (3) memory forensics and incident timeline reconstruction (DFIR), and (4) this project, adding the one layer of visibility missing from all prior work: the network itself.

---

## Table of Contents

- [Project Goal](#project-goal)
- [Lab Architecture](#lab-architecture)
- [Phase 1: Suricata Deployment](#phase-1-suricata-deployment)
- [Phase 2: Zeek Deployment](#phase-2-zeek-deployment)
- [Phase 3/4: Wazuh Integration](#phase-34-wazuh-integration)
- [Phase 5/6: The Hunt](#phase-56-the-hunt)
- [Why Suricata Missed It: A Documented Explanation](#why-suricata-missed-it-a-documented-explanation)
- [Hunt Playbook Summary](#hunt-playbook-summary)
- [Challenges & Lessons Learned](#challenges--lessons-learned)
- [Limitations & Future Work](#limitations--future-work)

---

## Project Goal

Every prior project in this portfolio gave strong **endpoint** visibility (Sysmon, Wazuh agents, memory/disk forensics on a single Windows host). None of them could see what was actually happening **on the wire** between machines — which is exactly where attacker behavior like lateral movement, reconnaissance scanning, and command-and-control traffic often becomes visible, even when it's invisible at the endpoint.

This project asks two separate questions, deliberately kept distinct:

1. **Detection engineering question:** what does an out-of-the-box, heavily-populated Suricata ruleset (52,000+ community signatures) automatically catch on this network?
2. **Threat hunting question:** starting from a hypothesis about what attacker behavior *should* look like in raw connection data, what can a human analyst find manually, even when nothing was automatically flagged?

The distinction between these two questions is the actual point of the project — detection engineering (Project 2) writes rules for known patterns; threat hunting is a separate discipline that assumes rules will always have gaps, and searches for evidence directly.

---

## Lab Architecture

| Component | Role |
|---|---|
| Windows 10 (VM) | Endpoint under observation — Sysmon, Wazuh agent (from prior projects) |
| Kali (host) | Network monitoring point — Suricata, Zeek, and a Wazuh agent, all newly added |
| Debian (VM) | Wazuh Manager (from prior projects), now also receiving Kali's network telemetry |

**A key infrastructure change from prior projects:** Kali (the physical host running VirtualBox) was never actually a participant in the existing `192.168.100.x` Internal Network used by the VMs — it only ran VirtualBox itself and accessed the Wazuh dashboard through a browser inside a VM. To let Kali actually observe network traffic between VMs, a new **VirtualBox Host-only Network** (`192.168.56.0/24`) was created and added as a second network adapter on both Windows 10 and the Wazuh manager, alongside their existing adapters — deliberately left untouched to avoid disrupting the working setup from prior projects.

```
+---------------------+
|   Windows 10 (VM)    |
|   192.168.56.102     |------+
+---------------------+      |
                              |  (vboxnet0 - Host-only network)
+---------------------+      |
|   Kali (host)        |<-----+
|   192.168.56.1        |
|                       |
|  +-----------------+  |
|  | Suricata (IDS)   |--+--> /var/log/suricata/eve.json
|  +-----------------+  |
|  +-----------------+  |
|  | Zeek (NSM)       |--+--> ~/zeek-logs/conn.log
|  +-----------------+  |
|  +-----------------+  |
|  | Wazuh Agent      |--+--> Debian Wazuh Manager (192.168.56.101)
|  +-----------------+  |
+---------------------+
```

---

## Phase 1: Suricata Deployment

**What Suricata is:** a network Intrusion Detection System (IDS) — it inspects live traffic against a large library of signatures (known-bad patterns) and generates alerts on matches. Conceptually the network-layer equivalent of the custom Wazuh rules built in Project 2, except matching network packets instead of Windows command lines.

**Setup:**
```bash
sudo apt install suricata -y
sudo suricata-update
```
This downloaded and enabled 52,087 rules from the Emerging Threats Open ruleset — Suricata's default, freely available signature source.

**Validation:** a custom test rule was written and confirmed working end-to-end before relying on the larger ruleset:
```
alert icmp 192.168.56.102 any -> 192.168.56.1 any (msg:"TEST: Ping from Windows10 VM detected"; sid:1000001; rev:1;)
```
A ping from Windows 10 correctly triggered this rule, confirming Suricata was watching the right interface and could generate alerts correctly.

---

## Phase 2: Zeek Deployment

**What Zeek is:** unlike Suricata, Zeek does not primarily look for "bad" patterns — it records a detailed, structured summary of *every* network connection it observes (source/destination, protocol, duration, byte counts, connection state), regardless of whether anything appears malicious. This makes Zeek's logs the raw material for **threat hunting**: searching through comprehensive connection records for patterns no signature was written for.

**Setup:**
```bash
# Added Zeek's official repository (Debian 12 base), then:
sudo apt install zeek -y
```

A short validation run confirmed Zeek could observe traffic on the same `vboxnet0` interface Suricata was using, producing a clean `conn.log` connection summary for test traffic (an ICMP ping).

---

## Phase 3/4: Wazuh Integration

Both tools' log files were fed into Wazuh by installing a **Wazuh agent directly on Kali** (`host-kali`), then configuring it to monitor both log files via `<localfile>` blocks in `ossec.conf` — the same mechanism used for Sysmon logs on Windows 10 in prior projects.

### A significant integration bug, and its real root cause

Suricata's `eve.json` integrated cleanly on the first attempt. Zeek's `conn.log`, configured identically, silently failed to appear anywhere in Wazuh — not even in the raw archive index — despite the Wazuh agent's own logs confirming it was actively reading the file.

**Root cause (confirmed via direct, isolated testing):** Zeek's native JSON output uses dotted field names for connection endpoints (`id.orig_h`, `id.resp_h`, etc.). Wazuh is built on OpenSearch, which interprets a dot in a JSON key as a **nested object separator** — meaning `id.orig_h` is interpreted as "field `orig_h` inside object `id`." Because Suricata's own JSON output had already caused OpenSearch to establish a different, conflicting interpretation of the `id` field elsewhere in the same index, documents containing Zeek's dotted `id.*` fields were likely rejected outright by OpenSearch's mapping validation — silently, with no visible error in Wazuh's own logs, since the rejection happens at the indexing layer, not the log-collection layer.

**Fix:** Zeek supports a documented mechanism for exactly this situation — `Log::default_field_name_map`, which renames fields before they are ever written to disk. A local Zeek script was added:

```zeek
redef LogAscii::use_json = T;
redef Log::default_field_name_map = {
    ["id.orig_h"] = "id_orig_h",
    ["id.orig_p"] = "id_orig_p",
    ["id.resp_h"] = "id_resp_h",
    ["id.resp_p"] = "id_resp_p"
};
```

This resolved the issue completely — Zeek's connection data began appearing in Wazuh's archive index with clean, correctly parsed fields (`data.id_orig_h`, `data.id_resp_h`, etc.), fully searchable.

**A secondary, self-inflicted issue along the way:** repeatedly stopping and restarting Zeek during troubleshooting caused its log file to be replaced each time, triggering Wazuh's own built-in "Log file size reduced" rule (`rule.id: 592`, mapped to MITRE T1565.001 — Stored Data Manipulation) — a real security detection, correctly firing on what looked like log tampering, but was actually just repeated testing. Resolved by running both tools as stable, persistent background processes (`nohup ... &`) instead of manually restarting them in the foreground.

---

## Phase 5/6: The Hunt

### Setting up a meaningful test

An initial attempt using Atomic Red Team's `T1046-10` (subnet port scan) produced no observable network traffic at all. Investigation (confirmed via live `tcpdump` on the monitoring interface) showed the scan was almost entirely composed of ARP ("who has this IP?") broadcast requests — because the lab's Host-only network contains only two real devices, the vast majority of the scanned address range had no host to respond to, and Windows never proceeded to attempt real TCP/UDP connections to non-existent addresses. This is a genuine, documented limitation of testing subnet-wide reconnaissance techniques in a small, sparsely-populated lab network, rather than a tooling failure.

**Adapted approach:** a direct, real port scan was run from Windows 10 against Kali specifically (a real, responding host), checking 8 common ports:
```powershell
$ports = 22,80,443,445,3389,8080,3306,5432
foreach ($port in $ports) {
    Test-NetConnection -ComputerName 192.168.56.1 -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue
}
```

### Result 1 -- Suricata (automatic detection)

No alert was generated for this scan.

### Result 2 -- Zeek (manual hunt)

**Hypothesis formed before searching:** "A port scan against a real host should appear in connection logs as multiple short-duration connections from the same source to the same destination, across different destination ports, in a tight time window, most resulting in a rejected or reset state."

**Search performed** against Zeek's archived connection data:
```
agent.name:"host-kali" and data.id_orig_h:"192.168.56.102" and data.id_resp_h:"192.168.56.1" and data.conn_state:"REJ"
```

**Finding:** approximately 10 connection attempts, all within a ~6-second window, all in `REJ` (rejected) state, each targeting a different destination port -- an unambiguous, textbook reconnaissance signature, found entirely through manual investigation of raw connection data with zero supporting alert from Suricata.

---

## Why Suricata Missed It: A Documented Explanation

This was investigated properly rather than left as an unexplained gap. Suricata's default Emerging Threats Open ruleset does include scan-detection signatures -- but they are explicitly **directional**, written around variables like `$EXTERNAL_NET` and `$HOME_NET`. A representative real rule from the ruleset:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SCAN Suspicious inbound to mySQL port 3306"; ...)
```

This rule -- and others like it -- only fires for traffic considered to originate **outside** the protected network, directed **inward**. In this lab, both Windows 10 and Kali fall within the same internally-trusted network range, so traffic between them does not match the "external attacker scanning inward" pattern these signatures are built to detect.

**This is a genuine, real-world blind spot in signature-based, direction-aware network IDS deployments**: they are frequently tuned around the assumption that attackers scan in from the outside, leaving **internal, lateral-movement-style scanning between already-trusted hosts** significantly less covered by default. This is precisely the scenario threat hunting is meant to compensate for -- and precisely what this hunt demonstrated.

---

## Hunt Playbook Summary

| Field | Detail |
|---|---|
| **Hypothesis** | A port scan against a real host produces multiple short-duration, same-source/same-destination connections across different ports, in a tight time window, mostly in a rejected/reset state |
| **Data source checked** | Zeek `conn.log`, via Wazuh archive index |
| **Search used** | `agent.name:"host-kali" and data.id_orig_h:"192.168.56.102" and data.id_resp_h:"192.168.56.1" and data.conn_state:"REJ"` |
| **Finding** | ~10 REJ-state connections across 8 distinct destination ports within a 6-second window |
| **Automated detection status** | Not flagged by Suricata (52,087 rules loaded) -- confirmed root cause: directional rule design (`$EXTERNAL_NET -> $HOME_NET`) does not cover internal-to-internal scanning |
| **Outcome** | Confirmed detection gap for lateral/internal reconnaissance; documented as a real, explainable limitation rather than a tooling failure |

---

## Challenges & Lessons Learned

- **Kali was never part of the existing VM network.** Diagnosed by checking `ip a` and finding no shared subnet with the VMs; resolved by adding a new VirtualBox Host-only Network, deliberately as an additional adapter rather than modifying the existing Internal Network setup, to avoid breaking prior projects' connectivity.
- **Suricata's User-Agent-spoofing and Nmap SYN-scan tests both failed to trigger any alert**, despite genuine traffic being generated and confirmed via packet capture -- an early, honest signal that "the ruleset doesn't have a matching signature" is a real, common outcome, not a setup failure, and worth verifying with a controlled custom rule (which did fire correctly) before assuming Suricata itself was broken.
- **Zeek's JSON integration silently failed** due to an OpenSearch field-mapping conflict from dotted field names -- root-caused through isolated testing (a manual test line without dots succeeded; real Zeek data with dots did not) rather than assumption, and resolved using Zeek's own documented `field_name_map` mechanism.
- **Repeatedly restarting Zeek during troubleshooting triggered a legitimate Wazuh security rule** ("Log file size reduced" / T1565.001) -- a useful, if initially confusing, real-world reminder that operational testing activity can itself produce security-relevant noise.
- **Atomic Red Team's subnet-wide scan test produced no real traffic** in this specific lab topology, since the address range was almost entirely unpopulated; verified directly via live packet capture (`tcpdump`) rather than assumed, and adapted to a direct, real-host scan instead.

---

## Limitations & Future Work

- Only one hunting hypothesis (port-scan pattern via `conn_state:REJ`) was tested in depth; a fuller hunting engagement would test multiple hypotheses (e.g., DNS tunneling via unusually long/frequent DNS queries, beaconing via regular-interval outbound connections)
- Suricata's ruleset was used as-is (Emerging Threats Open, default); a custom scan-detection rule scoped to internal-to-internal traffic was not written in this iteration, though the investigation clearly identifies what such a rule would need to cover
- The lab network's small size (2 real hosts) limits how realistically subnet-wide reconnaissance techniques can be tested; a larger lab with several dummy hosts would allow more realistic large-scale scan simulation
- Zeek's much richer protocol-level logs (DNS, HTTP, files) were not explored in this iteration beyond `conn.log`; future work could hunt across these additional log types
