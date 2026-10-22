"""Public CTI source registry.

The registry is deliberately metadata-first: sources are described even when a
student deployment disables them by default because a provider changes its URL,
rate-limits anonymous clients, or requires an API key.  This lets the research
prototype report coverage honestly and activate sources through configuration.
"""

SOURCE_CATALOG = [
    {"name": "blocklist.de", "url": "https://lists.blocklist.de/lists/all.txt", "types": ["ip"], "format": "text", "license": "public", "enabled": True},
    {"name": "FireHOL Level 1", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "types": ["ip"], "format": "netset", "license": "public", "enabled": True},
    {"name": "IPsum Level 7", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt", "types": ["ip"], "format": "text", "license": "public", "enabled": True},
    {"name": "URLhaus URLs", "url": "https://urlhaus.abuse.ch/downloads/text/", "types": ["url"], "format": "text", "license": "abuse.ch", "enabled": True},
    {"name": "URLhaus Hosts", "url": "https://urlhaus.abuse.ch/downloads/hostfile/", "types": ["domain", "ip"], "format": "text", "license": "abuse.ch", "enabled": True},
    {"name": "MalwareBazaar recent", "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/", "types": ["sha256"], "format": "text", "license": "abuse.ch", "enabled": True},
    {"name": "ThreatFox IOCs", "url": "https://threatfox.abuse.ch/export/csv/recent/", "types": ["ip", "domain", "url", "sha256"], "format": "csv", "license": "abuse.ch", "enabled": True},
    {"name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "types": ["ip"], "format": "text", "license": "abuse.ch", "enabled": True},
    {"name": "SSL Blacklist", "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", "types": ["ip"], "format": "text", "license": "abuse.ch", "enabled": True},
    {"name": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop.txt", "types": ["ip"], "format": "netset", "license": "public", "enabled": True},
    {"name": "Spamhaus EDROP", "url": "https://www.spamhaus.org/drop/edrop.txt", "types": ["ip"], "format": "netset", "license": "public", "enabled": True},
    {"name": "CINS Army", "url": "https://cinsscore.com/list/ci-badguys.txt", "types": ["ip"], "format": "text", "license": "public", "enabled": True},
    {"name": "SANS ISC Suspicious", "url": "https://isc.sans.edu/ipsascii.html?limit=100", "types": ["ip"], "format": "html", "license": "public"},
    {"name": "DigitalSide Threat-Intel", "url": "https://raw.githubusercontent.com/davidonzo/Threat-Intel/master/lists/latestips.txt", "types": ["ip"], "format": "text", "license": "public", "enabled": True},
    {"name": "Emerging Threats compromised", "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "types": ["ip"], "format": "text", "license": "public", "enabled": True},
    {"name": "C2 Tracker", "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/log4j.txt", "types": ["domain", "ip"], "format": "text", "license": "public", "enabled": True},
    {"name": "OpenPhish feed", "url": "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt", "types": ["url"], "format": "text", "license": "public", "enabled": True},
    {"name": "PhishTank", "url": "http://data.phishtank.com/data/online-valid.csv", "types": ["url"], "format": "csv", "license": "public", "enabled": True},
    {"name": "Cisco Talos IP Blacklist", "url": "https://talosintelligence.com/documents/ip-blacklist", "types": ["ip"], "format": "text", "license": "public", "enabled": True},
    {"name": "MITRE ATT&CK STIX", "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json", "types": ["actor", "malware", "campaign", "technique"], "format": "stix", "license": "CC BY 4.0"},
    {"name": "NVD CVE JSON", "url": "https://nvd.nist.gov/vuln/data-feeds", "types": ["cve"], "format": "json", "license": "public"},
    {"name": "CISA KEV Catalog", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "types": ["cve"], "format": "json", "license": "public"},
    {"name": "AlienVault OTX pulses", "url": "https://otx.alienvault.com/api/v1/pulses/subscribed", "types": ["ip", "domain", "url", "hash"], "format": "json", "license": "API key"},
    {"name": "AbuseIPDB reports", "url": "https://api.abuseipdb.com/api/v2/blacklist", "types": ["ip"], "format": "json", "license": "API key"},
    {"name": "MISP warninglists", "url": "https://github.com/MISP/misp-warninglists", "types": ["domain", "ip", "hash"], "format": "json", "license": "public"},
    {"name": "Phishing Database Domains", "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", "types": ["domain"], "format": "text", "license": "public", "enabled": True},
    {"name": "Spam404 Domain Blacklist", "url": "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt", "types": ["domain"], "format": "text", "license": "public", "enabled": True},
    {"name": "ThreatView High-Confidence IPs", "url": "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt", "types": ["ip"], "format": "text", "license": "public", "enabled": True},
]


def source_catalog_summary():
    return {
        "configured_count": len(SOURCE_CATALOG),
        "active_feed_count": sum(bool(item.get("enabled")) for item in SOURCE_CATALOG),
        "public_count": sum(item["license"] != "API key" for item in SOURCE_CATALOG),
        "sources": SOURCE_CATALOG,
    }
