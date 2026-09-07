# 🛡️ Splunk BOTS v1 Threat Investigation & SOC Analysis

An end-to-end Incident Response (IR) analysis and threat-hunting project using the **Splunk Boss of the SOC (BOTS) v1** dataset. This repository documents setup steps, SPL queries, and real-world SOC log analysis methodologies.

---

## 🚀 Environment Setup & Troubleshooting

### 1. Splunk Auto-Start Configuration (Ubuntu VM)
To ensure the Splunk daemon starts automatically on system boot without manual CLI execution:

```bash
# Enable Splunk boot-start service via systemd
sudo /opt/splunk/bin/splunk enable boot-start -user root --accept-license

# Enable and start the system service
sudo systemctl enable splunk
sudo systemctl start splunk

```


## The L1 SOC Analyst Scanning Mindset


### 1. When? (Timestamps)
2016-08-24 12:27:43: Identify the event timestamp. Note if there is a mismatch between index time and event time (often due to time zones).

### 2. Who & Where? (Network Orientation)
srcip=188.243.155.61 (srccountry="Russian Federation"): External source. Dynamic high-range port (srcport=6631).

dstip=71.39.18.122 (dstcountry="United States"): Internal/Perimeter asset target.

Direction: Inbound from WAN to LAN (srcintf="wan1").

### 3. What? (Protocol & Threat Context)
dstport=23 (service="TELNET"): Unencrypted legacy remote access protocol. Port 23 is heavily targeted by automated botnets (e.g., Mirai) scanning for default credentials.

crlevel=high (crscore=30): The firewall's internal risk scoring flagged this connection attempt as suspicious.

### 4. Outcome & Impact? (The Most Critical Part)
action=deny: The firewall dropped the packet.

policyid=0: Blocked by the default "Implicit Deny" rule (meaning no open port rule exists for this).

sentbyte=0 / rcvdbyte=0: Zero bytes exchanged. No data leakage, no session established.


## Quick summary

This event captures an unsolicited inbound Telnet probe (Port 23) originating from an IP in Russia targeting a public IP in the United States. The FortiGate firewall correctly identified it as high-risk probe traffic and dropped the connection immediately (action=deny) via its default security policy (policyid=0), resulting in zero data leakage.



