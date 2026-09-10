### 📑 SOC Incident Report: Inbound Perimeter Scan

Report ID: INC-2016-0824-01

Severity: High (Device Risk Rating) | Low (Impact Rating)

Status: Closed — True Positive (Mitigated)

## Executive Summary
On August 24, 2016, at 12:27:43 UTC, the perimeter firewall (gotham-fortigate) detected and blocked an unauthorized inbound connection attempt targeting port 23 (Telnet). The traffic originated from an external IP address located in the Russian Federation (188.243.155.61) and targeted a public U.S. IP address (71.39.18.122). The connection was immediately dropped by the firewall's default implicit deny policy (policyid=0), resulting in zero bytes exchanged and no network exposure.



## 5-W Framework Breakdown


Who: External host 188.243.155.61 (Geolocated to Russia).

What: Initiated an unencrypted Telnet connection request over TCP port 23.

Where: Directed at internal/perimeter interface wan1 targeting public IP 71.39.18.122.

When: August 24, 2016, at 12:27:43 UTC.

Why / Outcome: Connection dropped instantly by firewall rule Policy 0. The attempt represents automated reconnaissance or botnet scanning for exposed Telnet servic
