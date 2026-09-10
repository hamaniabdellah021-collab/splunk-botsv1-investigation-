# Incident Ticket

**Title:** High-Severity External Telnet Connection Attempt

**Severity:** High

**Status:** Investigating

**Detection Source:** FortiGate Firewall / Splunk

## 1. Summary

A high-severity external Telnet connection attempt was detected by the FortiGate firewall. The connection originated from external IP address `188.243.155.61` and targeted `71.39.18.122` over TCP port `23` (Telnet).

The firewall blocked the connection attempt.

## 2. Event Details

* **Timestamp:** 24-Aug-2016 12:27:43
* **Source IP:** `188.243.155.61`
* **Source Port:** `6631`
* **Source Country:** Russian Federation
* **Destination IP:** `71.39.18.122`
* **Destination Port:** `23`
* **Service:** TELNET
* **Protocol:** TCP
* **Action:** DENY
* **Policy ID:** `0`
* **Severity:** High
* **Sent Bytes:** `0`
* **Received Bytes:** `0`
* **Device:** `gotham-fortigate`
* **Sourcetype:** `fgt_traffic`

## 3. Investigation

The alert was reviewed in Splunk using the source IP as the primary Indicator of Compromise (IOC).

Initial investigation focused on:

1. Searching for additional activity associated with source IP `188.243.155.61`.
2. Determining whether the source IP targeted additional destination hosts.
3. Identifying other destination ports and services associated with the source.
4. Checking whether related traffic was allowed or denied.
5. Reviewing historical activity associated with the source IP.
6. Correlating the IOC with other available security data sources.

## 4. Initial Findings

The observed event represents an attempted TCP connection to Telnet port `23`.

The FortiGate firewall recorded the action as `DENY`, with `0` sent bytes and `0` received bytes for this session.

Based on this event alone, there is evidence of a blocked connection attempt, but there is not sufficient evidence from this single event to confirm successful compromise.

## 5. Impact / Scope

**Current assessment:** No successful connection or compromise has been established from the provided event alone.

Further investigation is required to determine whether:

* The source IP made repeated connection attempts.
* Other internal/external hosts were targeted.
* Other services or ports were targeted.
* Related malicious activity was detected by IDS or other security controls.

## 6. Recommended Actions

* Continue monitoring source IP `188.243.155.61` for repeated activity.
* Review related firewall events for additional destinations and ports.
* Correlate the source IP with IDS/network-security logs.
* Escalate if successful connections or additional malicious indicators are identified.
* Consider blocking the source IP according to the organization's incident-response policy if repeated malicious activity is confirmed.

## 7. Current Classification

**Preliminary Classification:** Suspicious / Blocked Connection Attempt

**Confidence:** Medium

**Reason:** The event shows a high-severity external Telnet connection attempt that was blocked by the firewall. Additional correlation is required before classifying the activity as a confirmed compromise.
