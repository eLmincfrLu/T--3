"""Static threat-actor intelligence data for the AZ Threat Radar platform.

Consolidated from three internal Threat Landscape research phases (Phase 1
actor/sector report, Phase 2 CVE/vulnerability layer, Phase 3 hacktivism +
attribution update). Every field traces back to a named public source in
those reports (CISA advisories, ESET/Mandiant/Bitdefender research, Security
Affairs, Eurasianet, etc.) — nothing here is invented.

This module is pure data (no DB, no network). Extend it by editing the
lists below and restarting the app.
"""

# ---------------------------------------------------------------------------
# State-sponsored APT groups
# ---------------------------------------------------------------------------

APT_ACTORS = [
    {
        "id": "apt29",
        "name": "APT29",
        "aliases": ["Cozy Bear", "Midnight Blizzard", "The Dukes", "NOBELIUM"],
        "origin": "Rusiya (SVR)",
        "origin_flag": "🇷🇺",
        "motivation": "Kəşfiyyat, uzunmüddətli məlumat toplama",
        "sophistication": "Çox Yüksək",
        "sophistication_level": 5,
        "targets": [
            "Dövlət və diplomatik qurumlar",
            "Fikir mərkəzləri və tədqiqat institutları",
            "Enerji sektoru",
            "Post-Sovet ölkələri",
        ],
        "ttps": [
            {"id": "T1566.001", "name": "Spearphishing Attachment"},
            {"id": "T1078", "name": "Valid Account Abuse"},
            {"id": "T1003", "name": "Credential Dumping"},
            {"id": "T1195", "name": "Supply Chain Compromise"},
            {"id": "T1218", "name": "Living-off-the-Land (LOLBins)"},
        ],
        "cves": [
            "CVE-2019-11510", "CVE-2019-19781", "CVE-2018-13379",
            "CVE-2019-9670", "CVE-2020-4006", "CVE-2021-36934",
            "CVE-2022-27924", "CVE-2023-42793", "CVE-2023-38831",
        ],
        "notable_attacks": [
            "SolarWinds Təchizat Zənciri Hücumu (2020) — 18,000+ təşkilat",
            "Demokratik Milli Komitə sızması (2016)",
            "Microsoft korporativ e-poçt sızması (2024)",
        ],
        "az_relevance": (
            "APT29 post-Sovet dövlətlərini və diplomatik qurumları aktiv "
            "hədəf alır. Azərbaycanın Rusiya və İranla sərhədi olan Cənubi "
            "Qafqazdakı geosiyasi mövqeyi onu yüksək maraq doğuran kəşfiyyat "
            "hədəfinə çevirir. Nazirliklər, səfirliklər və diplomatik "
            "kommunikasiyalar ən yüksək riskdədir."
        ),
        "source": "CISA AA21-116A",
    },
    {
        "id": "muddywater",
        "name": "MuddyWater",
        "aliases": ["Static Kitten", "Mercury", "Pioneer Kitten"],
        "origin": "İran (MOIS)",
        "origin_flag": "🇮🇷",
        "motivation": "Regional casusluq, nəzarət, geosiyasi üstünlük",
        "sophistication": "Yüksək",
        "sophistication_level": 4,
        "targets": [
            "Dövlət və ictimai idarəetmə",
            "Telekommunikasiya",
            "Enerji sektoru",
            "Müdafiə təşkilatları",
        ],
        "ttps": [
            {"id": "T1566.002", "name": "Spearphishing via Link"},
            {"id": "T1059.001", "name": "PowerShell Abuse"},
            {"id": "T1219", "name": "Remote Access Tool Deployment"},
            {"id": "T1133", "name": "External Remote Services (VPN)"},
            {"id": "T1053.005", "name": "Scheduled Task Persistence"},
        ],
        "cves": ["CVE-2020-1472", "CVE-2020-0688", "CVE-2023-27350"],
        "notable_attacks": [
            "Yaxın Şərq, Türkiyə və Azərbaycan üzrə sənədləşmiş kampaniyalar",
            "Nəzarət əməliyyatları üçün telekom provayderlərinin hədəflənməsi",
            "Cənubi Qafqaz üzrə dövlət spear-phishing kampaniyaları",
        ],
        "az_relevance": (
            "İranın Azərbaycanla ortaq sərhəd, etnik demoqrafiya və enerji "
            "rəqabəti səbəbindən birbaşa geosiyasi maraqları var. MuddyWater "
            "Azərbaycan telekommunikasiya və dövlət qurumlarına qarşı "
            "birbaşa sənədləşdirilmiş kampaniyalar aparıb."
        ),
        "source": "CISA AA22-055A",
    },
    {
        "id": "famoussparrow",
        "name": "FamousSparrow",
        "aliases": ["UAT-9244", "GhostEmperor (əlaqəli)"],
        "origin": "Çinlə əlaqəli (dövlət dəstəkli şübhə)",
        "origin_flag": "🇨🇳",
        "motivation": "Uzunmüddətli casusluq, strateji kəşfiyyat",
        "sophistication": "Yüksək",
        "sophistication_level": 4,
        "targets": [
            "Mehmanxana və qonaqpərvərlik (kəşfiyyat kanalı)",
            "Dövlət qurumları",
            "Mühəndislik və texnologiya şirkətləri",
            "Strateji infrastruktur, o cümlədən enerji",
        ],
        "ttps": [
            {"id": "T1190", "name": "Exploit Public-Facing Application (ProxyLogon/ProxyNotShell)"},
            {"id": "T1587.001", "name": "Custom Backdoor — SparrowDoor / Deed RAT"},
            {"id": "T1021.002", "name": "Lateral Movement via SMB"},
            {"id": "T1041", "name": "Data Exfiltration over C2 Channel"},
            {"id": "T1071.001", "name": "Command & Control via HTTPS"},
        ],
        "cves": ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"],
        "notable_attacks": [
            "Microsoft Exchange ProxyLogon zəifliklərinin istismarı (2021)",
            "Yaxın Şərq, Avropa və Amerika üzrə kampaniyalar",
            "Azərbaycan enerji sektoruna qarşı çoxdalğalı kampaniya (Dek 2025–Fev 2026)",
        ],
        "az_relevance": (
            "Azərbaycanın strateji tranzit dəhlizi rolu və enerji sektoru "
            "onu Çinlə əlaqəli aktorlar üçün kəşfiyyat hədəfinə çevirir. "
            "Bitdefender tədqiqatına görə (may 2026) FamousSparrow, Dekabr "
            "2025 – Fevral 2026 arası Azərbaycan neft-qaz şirkətinə qarşı "
            "aparılan çoxdalğalı kampaniyanın arxasında dayanır (Deed RAT "
            "və TernDoor istifadə edərək, ProxyNotShell giriş vektoru ilə)."
        ),
        "source": "ESET (2021); Bitdefender / The Hacker News, May 2026",
    },
]

# ---------------------------------------------------------------------------
# Hacktivist / regional-conflict aligned actors (Nagorno-Karabakh context)
# ---------------------------------------------------------------------------

HACKTIVIST_ACTORS = [
    {
        "id": "anti-armenia-team",
        "name": "Anti-Armenia Team",
        "alignment": "Azərbaycan tərəfdar",
        "flag": "🇦🇿",
        "activity": (
            "Uzunmüddətli hakerlik qrupu; Ermənistan dövlət serverlərindən "
            "pasport/təhlükəsizlik xidməti məlumatlarını sızdırıb."
        ),
        "source": "Security Affairs",
    },
    {
        "id": "poetrat",
        "name": "PoetRAT",
        "alignment": "Ehtimal edilən dövlətlə əlaqəli, AZ-ə qarşı",
        "flag": "🎯",
        "activity": (
            "2020-ci il münaqişə eskalasiyası zamanı Azərbaycan dövlət "
            "məmurlarına qarşı istifadə olunan casusluq aləti, sonradan "
            "yeni ekfiltrasiya üsulları ilə yenilənib."
        ),
        "source": "Cisco Talos, via CyberScoop",
    },
    {
        "id": "oxtarat",
        "name": "OxtaRAT",
        "alignment": "Azərbaycan dövlət marağı ilə uyğunlaşan",
        "flag": "🎯",
        "activity": (
            "Tarixən Azərbaycan fəallarına qarşı hədəflənən zərərli "
            "proqram kampaniyası; noyabr 2022 dalğası ilk dəfə Erməni "
            "şəxs/korporasiyalarına qarşı müşahidə olunub."
        ),
        "source": "Check Point Research, via Infosecurity Magazine",
    },
    {
        "id": "monte-mekonian",
        "name": "Monte Mekonian Cyber Army",
        "alignment": "Ermənistan tərəfdar",
        "flag": "🇦🇲",
        "activity": (
            "Azərbaycan dövlət saytlarına sızma iddiası; Azərbaycan "
            "əsgərlərinin şəxsi məlumatlarını yayıb."
        ),
        "source": "Eurasianet",
    },
    {
        "id": "turk-hack-team",
        "name": "Turk Hack Team / Aslan Neverler Tim",
        "alignment": "Azərbaycan/Türkiyə tərəfdar",
        "flag": "🇦🇿🇹🇷",
        "activity": (
            "Ermənistan dövlət, müdafiə və nazirlik saytlarına qarşı DDoS "
            "və defacement hücumları."
        ),
        "source": "Eurasianet",
    },
]

# ---------------------------------------------------------------------------
# Incident timeline
# ---------------------------------------------------------------------------

INCIDENTS = [
    {
        "date_label": "2020",
        "sort_key": "2020-01",
        "title": "PoetRAT kampaniyası",
        "description": (
            "Azərbaycan dövlət məmurlarına qarşı casusluq aləti istifadə "
            "olunub, diplomatik pasport məlumatlarına giriş əldə edilib."
        ),
        "attribution": "Naməlum kəşfiyyat qrupu (PoetRAT)",
        "actor_id": "poetrat",
    },
    {
        "date_label": "Dekabr 2023",
        "sort_key": "2023-12",
        "title": "Spear-phishing kampaniyası",
        "description": (
            "Azərbaycan şirkəti və biznes tərəfdaşlarına qarşı, "
            "Azərbaycan-Ermənistan münaqişəsinə istinad edən şəkil "
            "fayllarında zərərli proqram gizlədilərək aparılıb."
        ),
        "attribution": "Atribusiya edilməyib (kəşfiyyat məqsədli qiymətləndirilir)",
        "actor_id": None,
    },
    {
        "date_label": "Fevral 2025",
        "sort_key": "2025-02",
        "title": "Media infrastrukturuna hibrid hücum",
        "description": (
            "Azərbaycanın media infrastrukturuna geniş miqyaslı hibrid "
            "hücum — sistemlər pozulub, məlumat məhvi cəhdi edilib, "
            "dezinformasiya/panika əməliyyatları müşahidə olunub."
        ),
        "attribution": "Rusiya kəşfiyyat xidmətləri (araşdırma hesabatlarına görə)",
        "actor_id": "apt29",
    },
    {
        "date_label": "Dekabr 2025 – Fevral 2026",
        "sort_key": "2025-12",
        "title": "Enerji sektoruna çoxdalğalı kampaniya",
        "description": (
            "Azərbaycan neft-qaz şirkətinə qarşı 3 dalğadan ibarət "
            "kəşfiyyat kampaniyası (Deed RAT, TernDoor). Azərbaycan Dövlət "
            "CERT tərəfindən araşdırılıb, may 2026-da FamousSparrow-a "
            "atribusiya edilib."
        ),
        "attribution": "FamousSparrow (Bitdefender araşdırması, may 2026)",
        "actor_id": "famoussparrow",
    },
]

# ---------------------------------------------------------------------------
# Sector targeting distribution (for the dashboard chart)
# ---------------------------------------------------------------------------

SECTOR_DISTRIBUTION = [
    {"name": "Texnologiya və İT", "pct": 26},
    {"name": "Enerji, Neft və Qaz", "pct": 23},
    {"name": "Dövlət və İctimai İdarəetmə", "pct": 21},
    {"name": "Maliyyə və Bank", "pct": 18},
    {"name": "Media və Telekommunikasiya", "pct": 12},
]


def get_actor(actor_id: str) -> dict | None:
    for actor in APT_ACTORS:
        if actor["id"] == actor_id:
            return actor
    return None