# Network-Security-Monitoring-Threat-Hunting-with-Suricata-Zeek-and-Wazuh
Added network visibility to my SOC, then hunted for a port scan manually in Zeek's logs after Suricata's 52k rules missed it — found the pattern, root-caused why (its rules only watch external→internal traffic), documented as a hunt playbook.
