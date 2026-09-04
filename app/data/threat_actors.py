"""Static threat-actor intelligence data for the AZ Threat Radar platform.

Consolidated from three internal Threat Landscape research phases (Phase 1
actor/sector report, Phase 2 CVE/vulnerability layer, Phase 3 hacktivism +
attribution update). Every field traces back to a named public source in
those reports (CISA advisories, ESET/Mandiant/Bitdefender research, Security
Affairs, Eurasianet, etc.) — nothing here is invented.

Every user-facing text field is stored as a {"az": ..., "en": ..., "ru": ...}
dict so it can be rendered in the currently selected UI language. Use
`localize_apt_actor` / `localize_hacktivist_actor` / `localize_incident` /
`localize_sector` (or `localize_all`) to turn a raw entry into a
locale-resolved dict before passing it to a template.

This module is pure data (no DB, no network). Extend it by editing the
lists below and restarting the app.
"""

from app.i18n import localize as _loc

# ---------------------------------------------------------------------------
# State-sponsored APT groups
# ---------------------------------------------------------------------------

APT_ACTORS = [
    {
        "id": "apt29",
        "name": "APT29",
        "aliases": {
            "az": ["Cozy Bear", "Midnight Blizzard", "The Dukes", "NOBELIUM"],
            "en": ["Cozy Bear", "Midnight Blizzard", "The Dukes", "NOBELIUM"],
            "ru": ["Cozy Bear", "Midnight Blizzard", "The Dukes", "NOBELIUM"],
        },
        "origin": {
            "az": "Rusiya (SVR)",
            "en": "Russia (SVR)",
            "ru": "Россия (СВР)",
        },
        "origin_flag": "🇷🇺",
        "motivation": {
            "az": "Kəşfiyyat, uzunmüddətli məlumat toplama",
            "en": "Espionage, long-term intelligence collection",
            "ru": "Шпионаж, долгосрочный сбор разведданных",
        },
        "sophistication": {
            "az": "Çox Yüksək",
            "en": "Very High",
            "ru": "Очень высокий",
        },
        "sophistication_level": 5,
        "targets": {
            "az": [
                "Dövlət və diplomatik qurumlar",
                "Fikir mərkəzləri və tədqiqat institutları",
                "Enerji sektoru",
                "Post-Sovet ölkələri",
            ],
            "en": [
                "Government and diplomatic institutions",
                "Think tanks and research institutes",
                "Energy sector",
                "Post-Soviet countries",
            ],
            "ru": [
                "Государственные и дипломатические учреждения",
                "Аналитические центры и научно-исследовательские институты",
                "Энергетический сектор",
                "Постсоветские страны",
            ],
        },
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
        "notable_attacks": {
            "az": [
                "SolarWinds Təchizat Zənciri Hücumu (2020) — 18,000+ təşkilat",
                "Demokratik Milli Komitə sızması (2016)",
                "Microsoft korporativ e-poçt sızması (2024)",
            ],
            "en": [
                "SolarWinds Supply Chain Attack (2020) — 18,000+ organizations",
                "Democratic National Committee breach (2016)",
                "Microsoft corporate email breach (2024)",
            ],
            "ru": [
                "Атака на цепочку поставок SolarWinds (2020) — свыше 18 000 организаций",
                "Взлом Национального комитета Демократической партии (2016)",
                "Утечка корпоративной почты Microsoft (2024)",
            ],
        },
        "az_relevance": {
            "az": (
                "APT29 post-Sovet dövlətlərini və diplomatik qurumları aktiv "
                "hədəf alır. Azərbaycanın Rusiya və İranla sərhədi olan Cənubi "
                "Qafqazdakı geosiyasi mövqeyi onu yüksək maraq doğuran kəşfiyyat "
                "hədəfinə çevirir. Nazirliklər, səfirliklər və diplomatik "
                "kommunikasiyalar ən yüksək riskdədir."
            ),
            "en": (
                "APT29 actively targets post-Soviet states and diplomatic "
                "institutions. Azerbaijan's geopolitical position in the South "
                "Caucasus, bordering both Russia and Iran, makes it a "
                "high-interest intelligence target. Ministries, embassies, and "
                "diplomatic communications are at the highest risk."
            ),
            "ru": (
                "APT29 активно нацелена на постсоветские государства и "
                "дипломатические учреждения. Геополитическое положение "
                "Азербайджана на Южном Кавказе, граничащего с Россией и Ираном, "
                "делает его привлекательной разведывательной целью. "
                "Министерства, посольства и дипломатическая переписка "
                "подвержены наибольшему риску."
            ),
        },
        "source": "CISA AA21-116A",
    },
    {
        "id": "muddywater",
        "name": "MuddyWater",
        "aliases": {
            "az": ["Static Kitten", "Mercury", "Pioneer Kitten"],
            "en": ["Static Kitten", "Mercury", "Pioneer Kitten"],
            "ru": ["Static Kitten", "Mercury", "Pioneer Kitten"],
        },
        "origin": {
            "az": "İran (MOIS)",
            "en": "Iran (MOIS)",
            "ru": "Иран (МОИБ)",
        },
        "origin_flag": "🇮🇷",
        "motivation": {
            "az": "Regional casusluq, nəzarət, geosiyasi üstünlük",
            "en": "Regional espionage, surveillance, geopolitical advantage",
            "ru": "Региональный шпионаж, слежка, геополитическое преимущество",
        },
        "sophistication": {
            "az": "Yüksək",
            "en": "High",
            "ru": "Высокий",
        },
        "sophistication_level": 4,
        "targets": {
            "az": [
                "Dövlət və ictimai idarəetmə",
                "Telekommunikasiya",
                "Enerji sektoru",
                "Müdafiə təşkilatları",
            ],
            "en": [
                "Government and public administration",
                "Telecommunications",
                "Energy sector",
                "Defense organizations",
            ],
            "ru": [
                "Государственное и муниципальное управление",
                "Телекоммуникации",
                "Энергетический сектор",
                "Оборонные организации",
            ],
        },
        "ttps": [
            {"id": "T1566.002", "name": "Spearphishing via Link"},
            {"id": "T1059.001", "name": "PowerShell Abuse"},
            {"id": "T1219", "name": "Remote Access Tool Deployment"},
            {"id": "T1133", "name": "External Remote Services (VPN)"},
            {"id": "T1053.005", "name": "Scheduled Task Persistence"},
        ],
        "cves": ["CVE-2020-1472", "CVE-2020-0688", "CVE-2023-27350"],
        "notable_attacks": {
            "az": [
                "Yaxın Şərq, Türkiyə və Azərbaycan üzrə sənədləşmiş kampaniyalar",
                "Nəzarət əməliyyatları üçün telekom provayderlərinin hədəflənməsi",
                "Cənubi Qafqaz üzrə dövlət spear-phishing kampaniyaları",
            ],
            "en": [
                "Documented campaigns across the Middle East, Turkey, and Azerbaijan",
                "Targeting of telecom providers for surveillance operations",
                "State-linked spear-phishing campaigns across the South Caucasus",
            ],
            "ru": [
                "Задокументированные кампании на Ближнем Востоке, в Турции и Азербайджане",
                "Атаки на телеком-провайдеров в целях слежки",
                "Государственные спир-фишинговые кампании на Южном Кавказе",
            ],
        },
        "az_relevance": {
            "az": (
                "İranın Azərbaycanla ortaq sərhəd, etnik demoqrafiya və enerji "
                "rəqabəti səbəbindən birbaşa geosiyasi maraqları var. MuddyWater "
                "Azərbaycan telekommunikasiya və dövlət qurumlarına qarşı "
                "birbaşa sənədləşdirilmiş kampaniyalar aparıb."
            ),
            "en": (
                "Iran has direct geopolitical interests in Azerbaijan due to "
                "their shared border, ethnic demographics, and energy "
                "competition. MuddyWater has run documented campaigns directly "
                "against Azerbaijani telecom and government institutions."
            ),
            "ru": (
                "Иран имеет прямые геополитические интересы в отношении "
                "Азербайджана из-за общей границы, этнической демографии и "
                "конкуренции в энергетике. MuddyWater проводила "
                "задокументированные кампании непосредственно против "
                "азербайджанских телекоммуникационных и государственных "
                "структур."
            ),
        },
        "source": "CISA AA22-055A",
    },
    {
        "id": "famoussparrow",
        "name": "FamousSparrow",
        "aliases": {
            "az": ["UAT-9244", "GhostEmperor (əlaqəli)"],
            "en": ["UAT-9244", "GhostEmperor (linked)"],
            "ru": ["UAT-9244", "GhostEmperor (связана)"],
        },
        "origin": {
            "az": "Çinlə əlaqəli (dövlət dəstəkli şübhə)",
            "en": "China-linked (suspected state-sponsored)",
            "ru": "Связана с Китаем (предположительно государственная)",
        },
        "origin_flag": "🇨🇳",
        "motivation": {
            "az": "Uzunmüddətli casusluq, strateji kəşfiyyat",
            "en": "Long-term espionage, strategic intelligence",
            "ru": "Долгосрочный шпионаж, стратегическая разведка",
        },
        "sophistication": {
            "az": "Yüksək",
            "en": "High",
            "ru": "Высокий",
        },
        "sophistication_level": 4,
        "targets": {
            "az": [
                "Mehmanxana və qonaqpərvərlik (kəşfiyyat kanalı)",
                "Dövlət qurumları",
                "Mühəndislik və texnologiya şirkətləri",
                "Strateji infrastruktur, o cümlədən enerji",
            ],
            "en": [
                "Hospitality and hotel sector (intelligence-gathering channel)",
                "Government institutions",
                "Engineering and technology companies",
                "Strategic infrastructure, including energy",
            ],
            "ru": [
                "Гостиничный сектор (канал сбора разведданных)",
                "Государственные учреждения",
                "Инженерные и технологические компании",
                "Стратегическая инфраструктура, включая энергетику",
            ],
        },
        "ttps": [
            {"id": "T1190", "name": "Exploit Public-Facing Application (ProxyLogon/ProxyNotShell)"},
            {"id": "T1587.001", "name": "Custom Backdoor — SparrowDoor / Deed RAT"},
            {"id": "T1021.002", "name": "Lateral Movement via SMB"},
            {"id": "T1041", "name": "Data Exfiltration over C2 Channel"},
            {"id": "T1071.001", "name": "Command & Control via HTTPS"},
        ],
        "cves": ["CVE-2021-26855", "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065"],
        "notable_attacks": {
            "az": [
                "Microsoft Exchange ProxyLogon zəifliklərinin istismarı (2021)",
                "Yaxın Şərq, Avropa və Amerika üzrə kampaniyalar",
                "Azərbaycan enerji sektoruna qarşı çoxdalğalı kampaniya (Dek 2025–Fev 2026)",
            ],
            "en": [
                "Exploitation of Microsoft Exchange ProxyLogon vulnerabilities (2021)",
                "Campaigns across the Middle East, Europe, and the Americas",
                "Multi-wave campaign against Azerbaijan's energy sector (Dec 2025–Feb 2026)",
            ],
            "ru": [
                "Эксплуатация уязвимостей ProxyLogon в Microsoft Exchange (2021)",
                "Кампании на Ближнем Востоке, в Европе и Америке",
                "Многоволновая кампания против энергетического сектора Азербайджана (дек. 2025 – февр. 2026)",
            ],
        },
        "az_relevance": {
            "az": (
                "Azərbaycanın strateji tranzit dəhlizi rolu və enerji sektoru "
                "onu Çinlə əlaqəli aktorlar üçün kəşfiyyat hədəfinə çevirir. "
                "Bitdefender tədqiqatına görə (may 2026) FamousSparrow, Dekabr "
                "2025 – Fevral 2026 arası Azərbaycan neft-qaz şirkətinə qarşı "
                "aparılan çoxdalğalı kampaniyanın arxasında dayanır (Deed RAT "
                "və TernDoor istifadə edərək, ProxyNotShell giriş vektoru ilə)."
            ),
            "en": (
                "Azerbaijan's role as a strategic transit corridor and its "
                "energy sector make it an intelligence target for China-linked "
                "actors. According to Bitdefender research (May 2026), "
                "FamousSparrow was behind a multi-wave campaign against an "
                "Azerbaijani oil-and-gas company between December 2025 and "
                "February 2026, using Deed RAT and TernDoor via a ProxyNotShell "
                "entry vector."
            ),
            "ru": (
                "Роль Азербайджана как стратегического транзитного коридора и "
                "его энергетический сектор делают страну разведывательной "
                "целью для связанных с Китаем группировок. Согласно "
                "исследованию Bitdefender (май 2026), FamousSparrow стояла за "
                "многоволновой кампанией против азербайджанской нефтегазовой "
                "компании в период с декабря 2025 по февраль 2026 года, "
                "используя Deed RAT и TernDoor через вектор проникновения "
                "ProxyNotShell."
            ),
        },
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
        "alignment": {
            "az": "Azərbaycan tərəfdar",
            "en": "Pro-Azerbaijan",
            "ru": "Проазербайджанская",
        },
        "flag": "🇦🇿",
        "activity": {
            "az": (
                "Uzunmüddətli hakerlik qrupu; Ermənistan dövlət serverlərindən "
                "pasport/təhlükəsizlik xidməti məlumatlarını sızdırıb."
            ),
            "en": (
                "Long-running hacking group; has leaked passport and "
                "security-service data from Armenian government servers."
            ),
            "ru": (
                "Давно действующая хакерская группа; сливала паспортные "
                "данные и данные служб безопасности с государственных "
                "серверов Армении."
            ),
        },
        "source": "Security Affairs",
    },
    {
        "id": "poetrat",
        "name": "PoetRAT",
        "alignment": {
            "az": "Ehtimal edilən dövlətlə əlaqəli, AZ-ə qarşı",
            "en": "Suspected state-linked, targeting Azerbaijan",
            "ru": "Предположительно связана с государством, действует против Азербайджана",
        },
        "flag": "🎯",
        "activity": {
            "az": (
                "2020-ci il münaqişə eskalasiyası zamanı Azərbaycan dövlət "
                "məmurlarına qarşı istifadə olunan casusluq aləti, sonradan "
                "yeni ekfiltrasiya üsulları ilə yenilənib."
            ),
            "en": (
                "Espionage tool used against Azerbaijani government officials "
                "during the 2020 conflict escalation, later updated with new "
                "exfiltration methods."
            ),
            "ru": (
                "Шпионский инструмент, применявшийся против азербайджанских "
                "госслужащих во время эскалации конфликта 2020 года, позднее "
                "обновлён новыми методами эксфильтрации данных."
            ),
        },
        "source": "Cisco Talos, via CyberScoop",
    },
    {
        "id": "oxtarat",
        "name": "OxtaRAT",
        "alignment": {
            "az": "Azərbaycan dövlət marağı ilə uyğunlaşan",
            "en": "Aligned with Azerbaijani state interests",
            "ru": "Совпадает с интересами азербайджанского государства",
        },
        "flag": "🎯",
        "activity": {
            "az": (
                "Tarixən Azərbaycan fəallarına qarşı hədəflənən zərərli "
                "proqram kampaniyası; noyabr 2022 dalğası ilk dəfə Erməni "
                "şəxs/korporasiyalarına qarşı müşahidə olunub."
            ),
            "en": (
                "Malware campaign historically targeting Azerbaijani "
                "activists; a November 2022 wave was observed for the first "
                "time targeting Armenian individuals and organizations."
            ),
            "ru": (
                "Кампания вредоносного ПО, исторически направленная против "
                "азербайджанских активистов; волна ноября 2022 года впервые "
                "была замечена против армянских лиц и организаций."
            ),
        },
        "source": "Check Point Research, via Infosecurity Magazine",
    },
    {
        "id": "monte-mekonian",
        "name": "Monte Mekonian Cyber Army",
        "alignment": {
            "az": "Ermənistan tərəfdar",
            "en": "Pro-Armenia",
            "ru": "Проармянская",
        },
        "flag": "🇦🇲",
        "activity": {
            "az": (
                "Azərbaycan dövlət saytlarına sızma iddiası; Azərbaycan "
                "əsgərlərinin şəxsi məlumatlarını yayıb."
            ),
            "en": (
                "Claims to have breached Azerbaijani government websites; has "
                "published personal data of Azerbaijani soldiers."
            ),
            "ru": (
                "Заявляет о взломах правительственных сайтов Азербайджана; "
                "публиковала персональные данные азербайджанских "
                "военнослужащих."
            ),
        },
        "source": "Eurasianet",
    },
    {
        "id": "turk-hack-team",
        "name": "Turk Hack Team / Aslan Neverler Tim",
        "alignment": {
            "az": "Azərbaycan/Türkiyə tərəfdar",
            "en": "Pro-Azerbaijan/Turkey",
            "ru": "Проазербайджанская/протурецкая",
        },
        "flag": "🇦🇿🇹🇷",
        "activity": {
            "az": (
                "Ermənistan dövlət, müdafiə və nazirlik saytlarına qarşı DDoS "
                "və defacement hücumları."
            ),
            "en": (
                "DDoS and defacement attacks against Armenian government, "
                "defense, and ministry websites."
            ),
            "ru": (
                "DDoS-атаки и дефейс сайтов правительства, обороны и "
                "министерств Армении."
            ),
        },
        "source": "Eurasianet",
    },
]

# ---------------------------------------------------------------------------
# Incident timeline
# ---------------------------------------------------------------------------

INCIDENTS = [
    {
        "date_label": {"az": "2020", "en": "2020", "ru": "2020"},
        "sort_key": "2020-01",
        "title": {
            "az": "PoetRAT kampaniyası",
            "en": "PoetRAT campaign",
            "ru": "Кампания PoetRAT",
        },
        "description": {
            "az": (
                "Azərbaycan dövlət məmurlarına qarşı casusluq aləti istifadə "
                "olunub, diplomatik pasport məlumatlarına giriş əldə edilib."
            ),
            "en": (
                "An espionage tool was used against Azerbaijani government "
                "officials, gaining access to diplomatic passport data."
            ),
            "ru": (
                "Против азербайджанских госслужащих применялся шпионский "
                "инструмент, получен доступ к данным дипломатических "
                "паспортов."
            ),
        },
        "attribution": {
            "az": "Naməlum kəşfiyyat qrupu (PoetRAT)",
            "en": "Unknown intelligence group (PoetRAT)",
            "ru": "Неустановленная разведывательная группа (PoetRAT)",
        },
        "actor_id": "poetrat",
    },
    {
        "date_label": {"az": "Dekabr 2023", "en": "December 2023", "ru": "Декабрь 2023"},
        "sort_key": "2023-12",
        "title": {
            "az": "Spear-phishing kampaniyası",
            "en": "Spear-phishing campaign",
            "ru": "Спир-фишинговая кампания",
        },
        "description": {
            "az": (
                "Azərbaycan şirkəti və biznes tərəfdaşlarına qarşı, "
                "Azərbaycan-Ermənistan münaqişəsinə istinad edən şəkil "
                "fayllarında zərərli proqram gizlədilərək aparılıb."
            ),
            "en": (
                "Conducted against an Azerbaijani company and its business "
                "partners, with malware hidden inside image files "
                "referencing the Azerbaijan-Armenia conflict."
            ),
            "ru": (
                "Проведена против азербайджанской компании и её деловых "
                "партнёров; вредоносное ПО было скрыто в файлах изображений, "
                "ссылающихся на азербайджано-армянский конфликт."
            ),
        },
        "attribution": {
            "az": "Atribusiya edilməyib (kəşfiyyat məqsədli qiymətləndirilir)",
            "en": "Not attributed (assessed as intelligence-motivated)",
            "ru": "Атрибуция не установлена (оценивается как разведывательная деятельность)",
        },
        "actor_id": None,
    },
    {
        "date_label": {"az": "Fevral 2025", "en": "February 2025", "ru": "Февраль 2025"},
        "sort_key": "2025-02",
        "title": {
            "az": "Media infrastrukturuna hibrid hücum",
            "en": "Hybrid attack on media infrastructure",
            "ru": "Гибридная атака на медиаинфраструктуру",
        },
        "description": {
            "az": (
                "Azərbaycanın media infrastrukturuna geniş miqyaslı hibrid "
                "hücum — sistemlər pozulub, məlumat məhvi cəhdi edilib, "
                "dezinformasiya/panika əməliyyatları müşahidə olunub."
            ),
            "en": (
                "A large-scale hybrid attack on Azerbaijan's media "
                "infrastructure — systems were compromised, data destruction "
                "was attempted, and disinformation/panic operations were "
                "observed."
            ),
            "ru": (
                "Масштабная гибридная атака на медиаинфраструктуру "
                "Азербайджана — были скомпрометированы системы, "
                "предпринята попытка уничтожения данных, зафиксированы "
                "операции дезинформации и создания паники."
            ),
        },
        "attribution": {
            "az": "Rusiya kəşfiyyat xidmətləri (araşdırma hesabatlarına görə)",
            "en": "Russian intelligence services (per investigative reports)",
            "ru": "Российские спецслужбы (по данным журналистских расследований)",
        },
        "actor_id": "apt29",
    },
    {
        "date_label": {
            "az": "Dekabr 2025 – Fevral 2026",
            "en": "December 2025 – February 2026",
            "ru": "Декабрь 2025 – февраль 2026",
        },
        "sort_key": "2025-12",
        "title": {
            "az": "Enerji sektoruna çoxdalğalı kampaniya",
            "en": "Multi-wave campaign against the energy sector",
            "ru": "Многоволновая кампания против энергетического сектора",
        },
        "description": {
            "az": (
                "Azərbaycan neft-qaz şirkətinə qarşı 3 dalğadan ibarət "
                "kəşfiyyat kampaniyası (Deed RAT, TernDoor). Azərbaycan Dövlət "
                "CERT tərəfindən araşdırılıb, may 2026-da FamousSparrow-a "
                "atribusiya edilib."
            ),
            "en": (
                "A three-wave espionage campaign (Deed RAT, TernDoor) against "
                "an Azerbaijani oil-and-gas company. Investigated by "
                "Azerbaijan's state CERT and attributed to FamousSparrow in "
                "May 2026."
            ),
            "ru": (
                "Трёхволновая разведывательная кампания (Deed RAT, TernDoor) "
                "против азербайджанской нефтегазовой компании. Расследована "
                "государственным CERT Азербайджана, в мае 2026 года "
                "атрибутирована группе FamousSparrow."
            ),
        },
        "attribution": {
            "az": "FamousSparrow (Bitdefender araşdırması, may 2026)",
            "en": "FamousSparrow (Bitdefender research, May 2026)",
            "ru": "FamousSparrow (исследование Bitdefender, май 2026)",
        },
        "actor_id": "famoussparrow",
    },
]

# ---------------------------------------------------------------------------
# Sector targeting distribution (for the dashboard chart)
# ---------------------------------------------------------------------------

SECTOR_DISTRIBUTION = [
    {
        "name": {"az": "Texnologiya və İT", "en": "Technology & IT", "ru": "Технологии и ИТ"},
        "pct": 26,
    },
    {
        "name": {"az": "Enerji, Neft və Qaz", "en": "Energy, Oil & Gas", "ru": "Энергетика, нефть и газ"},
        "pct": 23,
    },
    {
        "name": {
            "az": "Dövlət və İctimai İdarəetmə",
            "en": "Government & Public Administration",
            "ru": "Государственное управление",
        },
        "pct": 21,
    },
    {
        "name": {"az": "Maliyyə və Bank", "en": "Finance & Banking", "ru": "Финансы и банковский сектор"},
        "pct": 18,
    },
    {
        "name": {
            "az": "Media və Telekommunikasiya",
            "en": "Media & Telecommunications",
            "ru": "СМИ и телекоммуникации",
        },
        "pct": 12,
    },
]


def get_actor(actor_id: str) -> dict | None:
    for actor in APT_ACTORS:
        if actor["id"] == actor_id:
            return actor
    return None


# ---------------------------------------------------------------------------
# Locale-resolution helpers — turn a raw (multi-locale) entry into a
# flat dict of plain strings for the given locale, ready for templates.
# ---------------------------------------------------------------------------

def localize_apt_actor(actor: dict, locale: str) -> dict:
    return {
        **actor,
        "aliases": _loc(actor["aliases"], locale),
        "origin": _loc(actor["origin"], locale),
        "motivation": _loc(actor["motivation"], locale),
        "sophistication": _loc(actor["sophistication"], locale),
        "targets": _loc(actor["targets"], locale),
        "notable_attacks": _loc(actor["notable_attacks"], locale),
        "az_relevance": _loc(actor["az_relevance"], locale),
    }


def localize_hacktivist_actor(actor: dict, locale: str) -> dict:
    return {
        **actor,
        "alignment": _loc(actor["alignment"], locale),
        "activity": _loc(actor["activity"], locale),
    }


def localize_incident(incident: dict, locale: str) -> dict:
    return {
        **incident,
        "date_label": _loc(incident["date_label"], locale),
        "title": _loc(incident["title"], locale),
        "description": _loc(incident["description"], locale),
        "attribution": _loc(incident["attribution"], locale),
    }


def localize_sector(sector: dict, locale: str) -> dict:
    return {**sector, "name": _loc(sector["name"], locale)}
