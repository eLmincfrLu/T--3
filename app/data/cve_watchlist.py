"""Static CVE / vulnerability-watchlist data for the AZ Threat Radar
platform. Consolidated from the internal Phase 2 vulnerability-intelligence
research layer — every entry traces back to a named public source (CISA
advisory, NVD record, or named vendor research). Nothing here is invented;
where a source described an exploited flaw without a CVE number, it was
intentionally left out rather than guessed (see the original report).

This module is pure data (no DB, no network). Extend it by editing the
list below and restarting the app. See app/services/cve_service.py for the
optional live CISA KEV cross-check.
"""

CVE_LIST = [
    {
        "id": "CVE-2019-11510",
        "product": "Pulse Connect Secure VPN",
        "cvss": 10.0,
        "severity": "critical",
        "kev": True,
        "what_it_allows": "Pre-authentication arbitrary file read, exposes plaintext credentials",
        "actor_id": "apt29",
        "source": "CISA AA21-116A",
    },
    {
        "id": "CVE-2020-1472",
        "product": "Microsoft Netlogon (\"Zerologon\")",
        "cvss": 10.0,
        "severity": "critical",
        "kev": True,
        "what_it_allows": "Cryptographic flaw lets an attacker impersonate a domain controller, full domain compromise",
        "actor_id": "muddywater",
        "source": "CISA AA22-055A",
    },
    {
        "id": "CVE-2019-19781",
        "product": "Citrix ADC and Gateway",
        "cvss": 9.8,
        "severity": "critical",
        "kev": True,
        "what_it_allows": "Directory traversal leading to unauthenticated remote code execution",
        "actor_id": "apt29",
        "source": "CISA AA21-116A",
    },
    {
        "id": "CVE-2018-13379",
        "product": "Fortinet FortiOS SSL VPN",
        "cvss": 9.8,
        "severity": "critical",
        "kev": True,
        "what_it_allows": "Path traversal, unauthenticated access to session files and credentials",
        "actor_id": "apt29",
        "source": "CISA AA21-116A",
    },
    {
        "id": "CVE-2019-9670",
        "product": "Synacor Zimbra Collaboration Suite",
        "cvss": 9.8,
        "severity": "critical",
        "kev": True,
        "what_it_allows": "XML External Entity (XXE) injection, credential and file theft",
        "actor_id": "apt29",
        "source": "CISA AA21-116A",
    },
    {
        "id": "CVE-2021-26855",
        "product": "Microsoft Exchange Server (\"ProxyLogon\")",
        "cvss": 9.8,
        "severity": "critical",
        "kev": True,
        "what_it_allows": "Server-Side Request Forgery (SSRF), bypasses authentication and impersonates any user",
        "actor_id": "famoussparrow",
        "source": "ESET, Sept 2021; CISA AA21-116A",
    },
    {
        "id": "CVE-2023-42793",
        "product": "JetBrains TeamCity (on-premises)",
        "cvss": 9.8,
        "severity": "critical",
        "kev": True,
        "what_it_allows": "Authentication bypass leading to unauthenticated RCE on the CI/CD server (supply-chain risk)",
        "actor_id": "apt29",
        "source": "CISA joint advisory, Dec 2023",
    },
    {
        "id": "CVE-2023-27350",
        "product": "PaperCut MF/NG print management software",
        "cvss": 9.8,
        "severity": "critical",
        "kev": True,
        "what_it_allows": "Authentication bypass leading to unauthenticated RCE",
        "actor_id": "muddywater",
        "source": "Industry reporting, 2023-2026",
    },
    {
        "id": "CVE-2020-0688",
        "product": "Microsoft Exchange Server",
        "cvss": 8.8,
        "severity": "high",
        "kev": True,
        "what_it_allows": "Server uses a fixed cryptographic key at install, authenticated RCE",
        "actor_id": "muddywater",
        "source": "CISA AA22-055A",
    },
    {
        "id": "CVE-2020-4006",
        "product": "VMware Workspace ONE Access / Identity Manager",
        "cvss": 7.2,
        "severity": "high",
        "kev": True,
        "what_it_allows": "Authenticated command injection (requires admin console access), leads to RCE",
        "actor_id": "apt29",
        "source": "CISA AA21-116A",
    },
    {
        "id": "CVE-2021-36934",
        "product": "Windows 10/11 (\"HiveNightmare\" / \"SeriousSAM\")",
        "cvss": 7.8,
        "severity": "high",
        "kev": True,
        "what_it_allows": "Overly permissive ACLs let a low-privilege local user read the SAM registry hive, password hash theft",
        "actor_id": "apt29",
        "source": "Picus Security, NVD",
    },
    {
        "id": "CVE-2023-38831",
        "product": "WinRAR (Windows)",
        "cvss": 7.8,
        "severity": "high",
        "kev": True,
        "what_it_allows": "Crafted archive triggers code execution when a file inside is opened; used against European embassies",
        "actor_id": "apt29",
        "source": "CISA KEV, industry reporting",
    },
    {
        "id": "CVE-2021-26857",
        "product": "Microsoft Exchange Server (Unified Messaging)",
        "cvss": 7.8,
        "severity": "high",
        "kev": True,
        "what_it_allows": "Insecure deserialization, code execution as SYSTEM (requires Unified Messaging role)",
        "actor_id": "famoussparrow",
        "source": "ESET; technical analysis (Qualys, BI.ZONE)",
    },
    {
        "id": "CVE-2021-26858",
        "product": "Microsoft Exchange Server",
        "cvss": 7.8,
        "severity": "high",
        "kev": True,
        "what_it_allows": "Post-authentication arbitrary file write, chained after CVE-2021-26855",
        "actor_id": "famoussparrow",
        "source": "ESET, CloudSEK",
    },
    {
        "id": "CVE-2021-27065",
        "product": "Microsoft Exchange Server",
        "cvss": 7.8,
        "severity": "high",
        "kev": True,
        "what_it_allows": "Post-authentication arbitrary file write, chained after CVE-2021-26855, leads to web shell deployment",
        "actor_id": "famoussparrow",
        "source": "ESET, CloudSEK",
    },
    {
        "id": "CVE-2022-27924",
        "product": "Synacor Zimbra Collaboration Suite",
        "cvss": 7.5,
        "severity": "high",
        "kev": True,
        "what_it_allows": "Unauthenticated Memcache command injection, cleartext email credential theft",
        "actor_id": "apt29",
        "source": "CISA AA22-228A",
    },
]


def get_cve(cve_id: str) -> dict | None:
    for cve in CVE_LIST:
        if cve["id"] == cve_id:
            return cve
    return None


def unique_products() -> list[str]:
    """Distinct product names, for the 'am I exposed' self-assessment
    checklist — ordered by first appearance for a stable UI."""
    seen = []
    for cve in CVE_LIST:
        if cve["product"] not in seen:
            seen.append(cve["product"])
    return seen