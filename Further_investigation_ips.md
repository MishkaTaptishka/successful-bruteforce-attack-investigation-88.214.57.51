# 🔍 Further Investigation – Suspicious External IPs

This document lists IP addresses that were contacted by the compromised host during or following the XorDDoS activity window. These IPs should be prioritized for threat intelligence enrichment, historical traffic review, and possible IOC correlation.

---

## 📌 Suspicious IPs for Enrichment and Review
- `169.239.130.5`
- `169.254.169.254`
- `185.199.108.133`
- `185.199.109.133`
- `185.199.110.133`
- `185.199.111.133`

---

## Suggested Investigation Steps

1. **Check threat intelligence feeds** for each IP:
   - Reputational analysis (abuse IPDB, VirusTotal, Cisco Talos).
   - Any known ties to malware, botnets, or C2 infrastructure.

2. **Perform historical log analysis**:
   - Check proxy/firewall/DNS logs for additional communication with these IPs.
   - Identify if other internal hosts contacted the same addresses.

3. **Enrich with context**:
   - GeoIP lookup, ASN ownership, reverse DNS.
   - Known hosting providers or anonymization services.

4. **Pivot from any known malicious IPs**:
   - Search for related domains, URLs, or malware samples.
   - Trace relationships between IPs and potential attacker infrastructure.
