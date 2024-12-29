#!/bin/bash

# Define rule files
DNS_RULES_FILE="/usr/share/suricata/rules/dns-events.rules"
HTTP_RULES_FILE="/usr/share/suricata/rules/http-events.rules"

# Append DNS rules to the file
cat <<EOL > "$DNS_RULES_FILE"
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"akamaicontainer.com"; nocase; sid:1000001; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"akamaitechcloudservices.com"; nocase; sid:1000002; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"azuredeploystore.com"; nocase; sid:1000003; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"azureonlinecloud.com"; nocase; sid:1000004; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"azureonlinestorage.com"; nocase; sid:1000005; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"dunamistrd.com"; nocase; sid:1000006; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"glcloudservice.com"; nocase; sid:1000007; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"journalide.org"; nocase; sid:1000008; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"msedgepackageinfo.com"; nocase; sid:1000009; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"msedgeupdate.net"; nocase; sid:1000010; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"msstorageazure.com"; nocase; sid:1000011; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"msstorageboxes.com"; nocase; sid:1000012; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"officeaddons.com"; nocase; sid:1000013; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"officestoragebox.com"; nocase; sid:1000014; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"pbxcloudeservices.com"; nocase; sid:1000015; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"pbxphonenetwork.com"; nocase; sid:1000016; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"pbxsources.com"; nocase; sid:1000017; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"qwepoi123098.com"; nocase; sid:1000018; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"sbmsa.wiki"; nocase; sid:1000019; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"sourceslabs.com"; nocase; sid:1000020; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"visualstudiofactory.com"; nocase; sid:1000021; rev:1;)
alert dns any any -> any any (msg:"Potential 3CX Supply Chain Compromise - Suspicious DNS Query Detected"; dns.query; content:"zacharryblogs.com"; nocase; sid:1000022; rev:1;)
EOL

# Append HTTP rules to the file
cat <<EOL > "$HTTP_RULES_FILE"
alert http any any -> any any (msg:"SURICATA HTTP Potential malicious .ICO file download from 3CXDesktopApp"; flow:established,to_server; content:"GET"; http_method; content:"IconStorages/images/main/icon"; http_uri; content:".ico"; http_uri; classtype:trojan-activity; sid:1090091; rev:1;)
EOL

# Update Suricata rules
echo "Updating Suricata rules..."
suricata-update

# Restart Suricata
echo "Restarting Suricata service..."
systemctl restart suricata

echo "Rules have been applied and Suricata has been restarted."
