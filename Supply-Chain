#!/bin/bash

# Define rule files
DNS_RULES_FILE="/usr/share/suricata/rules/dns-events.rules"
HTTP_RULES_FILE="/usr/share/suricata/rules/http-events.rules"

# Define DNS rules
DNS_RULES="""alert dns any any -> any any (msg:\"SURICATA DNS Z flag set\"; app-layer-event:dns.z_flag_set; classtype:protocol-command-decode; sid:2240006; rev:2;)
alert dns any any -> any any (msg:\"SURICATA DNS Invalid opcode\"; app-layer-event:dns.invalid_opcode; classtype:protocol-command-decode; sid:2240007; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"akamaicontainer.com\"; nocase; sid:1000001; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"akamaitechcloudservices.com\"; nocase; sid:1000002; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"azuredeploystore.com\"; nocase; sid:1000003; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"azureonlinecloud.com\"; nocase; sid:1000004; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"azureonlinestorage.com\"; nocase; sid:1000005; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"dunamistrd.com\"; nocase; sid:1000006; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"glcloudservice.com\"; nocase; sid:1000007; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"journalide.org\"; nocase; sid:1000008; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"msedgepackageinfo.com\"; nocase; sid:1000009; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"msedgeupdate.net\"; nocase; sid:1000010; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"msstorageazure.com\"; nocase; sid:1000011; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"msstorageboxes.com\"; nocase; sid:1000012; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"officeaddons.com\"; nocase; sid:1000013; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"officestoragebox.com\"; nocase; sid:1000014; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"pbxcloudeservices.com\"; nocase; sid:1000015; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"pbxphonenetwork.com\"; nocase; sid:1000016; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"pbxsources.com\"; nocase; sid:1000017; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"qwepoi123098.com\"; nocase; sid:1000018; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"sbmsa.wiki\"; nocase; sid:1000019; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"sourceslabs.com\"; nocase; sid:1000020; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"visualstudiofactory.com\"; nocase; sid:1000021; rev:1;)
alert dns any any -> any any (msg:\"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected\"; dns.query; content:\"zacharryblogs.com\"; nocase; sid:1000022; rev:1;)"""

# Define HTTP rule
HTTP_RULE="alert http any any -> any any (msg:\"SURICATA HTTP Potential malicious .ICO file download from 3CXDesktopApp\"; flow:established,to_server; content:\"GET\"; http_method; content:\"IconStorages/images/main/icon\"; http_uri; content:\".ico\"; http_uri; classtype:trojan-activity; sid:1090091; rev:1;)"

# Export DNS rules
echo "Exporting DNS rules to $DNS_RULES_FILE"
echo -e "$DNS_RULES" > "$DNS_RULES_FILE"

# Export HTTP rule
echo "Exporting HTTP rule to $HTTP_RULES_FILE"
echo "$HTTP_RULE" > "$HTTP_RULES_FILE"

# Update Suricata rules
echo "Updating Suricata rules"
suricata-update

# Restart Suricata server
echo "Restarting Suricata server"
systemctl restart suricata

# Confirm status
echo "Checking Suricata status"
systemctl status suricata
