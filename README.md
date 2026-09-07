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
