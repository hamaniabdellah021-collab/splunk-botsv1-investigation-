# 1. Search the IOC — Search for the IP Across All Data

**Question:** Has this IP appeared in any other activity?

```spl
index=botsv1 188.243.155.61
| table _time host sourcetype srcip dstip src_port dstport action user
| sort _time
```

This is usually the **first query** after extracting an IOC from the alert.

---

# 2. Determine the Scope — How Many Devices Did It Reach?

**Question:** Did it target one device or multiple devices?

```spl
index=botsv1 srcip=188.243.155.61
| stats count as attempts dc(dstip) as unique_destinations values(dstip) as destinations by srcip
```

Or, in more detail:

```spl
index=botsv1 srcip=188.243.155.61
| stats count by dstip
| sort - count
```

This helps you identify **scanning / repeated targeting**.

---

# 3. Check Ports and Services — What Was It Trying to Access?

**Question:** Was it only Telnet, or were there also SSH/HTTP/DNS and other services?

```spl
index=botsv1 srcip=188.243.155.61
| stats count by dstport, service, action
| sort - count
```

For example, if you find:

```text
23   TELNET   deny
22   SSH      deny
80   HTTP     allow
443  HTTPS    allow
```

Then the situation becomes more significant than just a single Telnet attempt.

---

# 4. Check Allow vs. Deny — Did the Connections Succeed?

This is one of the most important queries in real-world investigations.

```spl
index=botsv1 srcip=188.243.155.61
| stats count by action
```

Or:

```spl
index=botsv1 srcip=188.243.155.61
| stats count(eval(action="allow")) as allowed
        count(eval(action="deny")) as denied
        count as total
```

Then ask:

> Was all the activity blocked, or was some traffic allowed?

**This point can completely change the severity.**

---

# 5. Check Historical Activity — Is This IP Old or New?

**Question:** Did this IP appear before the alert?

```spl
index=botsv1 srcip=188.243.155.61
| stats min(_time) as first_seen max(_time) as last_seen count as total_events
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
```

This query is very important during an investigation.

You want to determine:

```text
First Seen
     ↓
Repeated Activity?
     ↓
Alert Time
     ↓
Last Seen
```

---

# 6. Build the Timeline — Build a Timeline of the Incident

This is one of the most important skills for a SOC Analyst.

```spl
index=botsv1 srcip=188.243.155.61
| sort _time
| table _time sourcetype host srcip srcport dstip dstport service action
```

Now you can see:

```text
12:20 → connection
12:21 → connection
12:22 → Telnet
12:23 → another destination
12:25 → denied
12:27 → denied
```

This is where you start **understanding the story** instead of looking at individual events separately.

---

# 7. Search the Destination IOC — Investigate the Targeted Device

Don't investigate only the Source IP.

You also have:

`dstip=71.39.18.122`

Search for it:

```spl
index=botsv1 71.39.18.122
| table _time host sourcetype srcip srcport dstip dstport service action user
| sort _time
```

The question here is:

> Are there other sources communicating with this destination?

Then:

```spl
index=botsv1 dstip=71.39.18.122
| stats count by srcip, dstport, action
| sort - count
```

This may reveal that the device is being targeted by multiple sources.

---

# 8. Cross-Source Correlation — Correlate the IP with Other Security Sources

In your case, you have:

* `fgt_traffic` → Firewall
* `suricata` → IDS
* `stream:dns` → DNS
* `stream:tcp` → Network traffic

So search for the IOC across all sourcetypes:

```spl
index=botsv1 188.243.155.61
| stats count by sourcetype, host
| sort - count
```

Then you can narrow the search:

```spl
index=botsv1 sourcetype=suricata 188.243.155.61
| table _time src_ip dest_ip dest_port app_proto alert.signature alert.category
| sort _time
```

And the question becomes:

> Did only the Firewall see it, or did the IDS also detect suspicious activity?

This is **Correlation**.

---

# 9. Detect Repeated / Distributed Activity — Is It Scanning or Brute Force?

A very important query for a SOC:

```spl
index=botsv1 srcip=188.243.155.61
| bin _time span=5m
| stats count dc(dstip) as unique_destinations dc(dstport) as unique_ports by _time, srcip
| where count > 10 OR unique_destinations > 5 OR unique_ports > 5
| sort _time
```

The idea is:

> Within 5 minutes, how many connections? How many destinations? How many ports?

If you see:

```text
count = 500
unique_destinations = 50
unique_ports = 20
```

then this is much more interesting than a single event.

---

# 10. Find Similar Attackers — Are There Other IPs Doing the Same Thing?

This is an advanced and very important query.

Instead of asking:

> What did `188.243.155.61` do?

You ask:

> Are there other IPs performing the same behavior?

For example, Telnet:

```spl
index=botsv1 sourcetype=fgt_traffic dstport=23
| stats count as attempts dc(dstip) as destinations values(action) as actions by srcip
| sort - attempts
```

You can then see which IPs are making the most Telnet attempts.

---

# The 10 Queries as a SOC Investigation Workflow

Don't memorize them as **10 separate commands**. Memorize the **mental sequence**:

```text
1. IOC Search
       ↓
2. Scope
       ↓
3. Ports / Services
       ↓
4. Allow vs. Deny
       ↓
5. Historical Activity
       ↓
6. Timeline
       ↓
7. Destination Investigation
       ↓
8. Cross-Source Correlation
       ↓
9. Detect Pattern / Scanning
       ↓
10. Find Similar Activity
       ↓
      CONCLUSION
       ↓
```

