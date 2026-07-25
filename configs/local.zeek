# Custom Zeek site configuration
# Project: Network Security Monitoring & Threat Hunting
# Location on Kali: /opt/zeek/share/zeek/site/local.zeek
#
# Purpose: Zeek's default JSON output uses dotted field names for connection
# endpoints (id.orig_h, id.resp_h, id.orig_p, id.resp_p). Wazuh is built on
# OpenSearch, which interprets a dot in a JSON key as a nested-object
# separator. When multiple log sources (e.g. Suricata + Zeek) write JSON
# into the same Wazuh index and disagree about whether a given field name
# is a flat value or a nested object, OpenSearch can silently reject
# documents that violate the field mapping it already established.
#
# This config renames the dotted fields to underscore equivalents before
# Zeek ever writes them to disk, avoiding the conflict entirely.
#
# Usage: zeek -C -i <interface> /opt/zeek/share/zeek/site/local.zeek

redef LogAscii::use_json = T;

redef Log::default_field_name_map = {
    ["id.orig_h"] = "id_orig_h",
    ["id.orig_p"] = "id_orig_p",
    ["id.resp_h"] = "id_resp_h",
    ["id.resp_p"] = "id_resp_p"
};
