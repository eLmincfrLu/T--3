<div align="center">

# 🛡️ AZ Threat Radar

### Kibertəhdidlərin aşkarlanması və risk qiymətləndirmə platforması

IP ünvanların, domenlərin və URL-lərin **çoxmənbəli** (VirusTotal, AbuseIPDB, Google Safe Browsing, AlienVault OTX + daxili IOC bazası) analizi, risk skorlama, təhdid aktoru/CVE izləmə və vizual dashboard.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/SQLite-SQLAlchemy-07405E?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlalchemy.org/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)](https://www.virustotal.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](#)

</div>

<br>

> [!NOTE]
> Bu layihə kibertəhdidlərin aşkarlanması, qiymətləndirilməsi və idarə olunması prosesini sadələşdirmək, təhlükəsizlik analitiklərinə daha sürətli qərar verməyə kömək etmək məqsədilə hazırlanıb. Xüsusi diqqət Azərbaycanı hədəf alan təhdid aktorlarına və zəifliklərə yönəldilib.

---

## 📑 İçindəkilər

- [✨ Əsas imkanlar](#-əsas-imkanlar)
- [📊 Risk qiymətləndirmə sistemi](#-risk-qiymətləndirmə-sistemi)
- [🖥️ Dashboard](#️-dashboard)
- [🕵️ Təhdid Aktorları](#️-təhdid-aktorları)
- [🐛 Zəiflik Gözləmə Paneli](#-zəiflik-gözləmə-paneli)
- [📄 Hesabatlar](#-hesabatlar)
- [🔌 REST API](#-rest-api)
- [🧰 Texnologiyalar](#-texnologiyalar)
- [🚀 Quraşdırma](#-quraşdırma)
- [▶️ İşə salınması](#️-i̇şə-salınması)
- [🗄️ Verilənlər bazası](#️-verilənlər-bazası)
- [🗂️ Layihə strukturu](#️-layihə-strukturu)
- [🧪 Nümunə analizlər](#-nümunə-analizlər)
- [🔑 Demo giriş](#-demo-giriş)
- [🗺️ Gələcək planlar](#️-gələcək-inkişaf-planları)

---

## ✨ Əsas imkanlar

<table>
<tr>
<td width="50%" valign="top">

### 👤 İstifadəçi sistemi

- ✅ Qeydiyyat + e-mail təsdiqi (Resend)
- ✅ Giriş / çıxış (Flask-Login)
- ✅ **Şifrəni unutdum** axını — token linki e-mailə göndərilir, link vasitəsilə yeni parol təyin olunur
- ✅ **İki-mərhələli doğrulama (2FA)** — TOTP (Google Authenticator və s.), ehtiyat kodları, deaktiv etmə axını
- ✅ **My Profile** — ad-soyad redaktəsi, sidebar-da e-mail əvəzinə ad-soyad göstərilir
- ✅ Şifrə dəyişmə, brute-force qorunması (Flask-Limiter)
- ✅ Bildiriş parametrləri — zərərli nəticədə dərhal e-mail xəbərdarlığı + həftəlik xülasə
- ✅ Çoxdilli interfeys (AZ / EN / RU)

</td>
<td width="50%" valign="top">

### 🔍 Təhdid analizi

- ✅ IP · Domen · URL analizi, avtomatik növ aşkarlanması
- ✅ **Çoxmənbəli skan**: VirusTotal + AbuseIPDB + Google Safe Browsing + AlienVault OTX
- ✅ **Daxili IOC bazası** — 1000+ bilinən phishing/zərərli domen, API açarı tələb etmədən dərhal yoxlanılır
- ✅ Şəbəkə məlumatları (ölkə, ISP, ASN, host) + WHOIS sorğusu
- ✅ Bütün mənbələrin konsensusuna əsaslanan risk balı + tövsiyə

</td>
</tr>
</table>

---

## 📊 Risk qiymətləndirmə sistemi

Hər analiz üçün **0–100** arası risk balı hesablanır — VirusTotal-ın baza balı üzərinə hər əlavə mənbənin (AbuseIPDB, Safe Browsing, OTX, daxili IOC bazası) təsdiqi əlavə çəki gətirir:

| 🎯 Risk balı | 🚦 Təhlükə səviyyəsi | 💡 Tövsiyə |
|:---:|:---:|:---|
| 🟢 **0 – 30** | **Təhlükə yoxdur** | Heç bir tədbir tələb olunmur |
| 🟡 **31 – 70** | **Şübhəli** | Nəzarətdə saxlayın |
| 🔴 **71 – 100** | **Zərərli** | Dərhal bloklayın |

---

## 🖥️ Dashboard

> Real-vaxt statistika və vizual icmal bir baxışda.

- 📈 Ümumi analiz statistikası (cəmi / təhlükəsiz / şübhəli / zərərli)
- 🥧 Risk bölgüsü qrafiki
- 🚨 Aktiv xəbərdarlıqlar (şübhəli & zərərli statuslu son analizlər)
- 🏷️ Ən çox rast gəlinən təhlükə kateqoriyaları
- 🕓 Son analizlərin siyahısı
- 🔗 Təhdid Aktorları səhifəsinə keçid kartı

---

## 🕵️ Təhdid Aktorları

Azərbaycanı hədəf alan bilinən dövlət-dəstəkli APT qrupları (APT29/Cozy Bear, MuddyWater, FamousSparrow) və regional hacktivist qruplar (PoetRAT, OxtaRAT, Anti-Armenia Team və s.) — hər biri üçün:

- Mənşə, motivasiya, sofistikasiya səviyyəsi
- MITRE ATT&CK TTP-ləri
- Əlaqəli CVE-lər
- Məşhur hücumlar və Azərbaycana aidiyyəti
- Sektor üzrə hədəflənmə statistikası + son hadisələr xronologiyası

---

## 🐛 Zəiflik Gözləmə Paneli

Bu üç aktora aid, real mənbələrdən (CISA KEV, NVD) təsdiqlənmiş CVE-lərin prioritetləşdirilmiş siyahısı — CVSS balı, KEV statusu və CISA-nın canlı JSON feed-i ilə zənginləşdirilmiş "aid edilmə tarixi / son müddət" məlumatı.

---

## 📄 Hesabatlar

| Format | Təsvir |
|---|---|
| 🔎 **Filtr** | Tarixçəni məqsəd, növ və status üzrə axtarış/filtrləmə |
| 💾 **Saxlama** | Analizi hesabat kimi saxlama |
| 📊 **CSV** | UTF-8 BOM ilə ixrac (Excel-də AZ hərfləri düzgün görünür) |
| 📕 **PDF** | DejaVu Unicode fontu ilə — tam AZ əlifbası (ə, ğ, ş, ç, ö, ü, ı, İ) və Kiril dəstəyi |

---

## 🔌 REST API

<table>
<tr><th align="left">Endpoint</th><th align="left">Təsvir</th></tr>
<tr>
<td>

```http
POST /api/analyze
```

</td>
<td>Yeni təhdid analizi başladır<br><sub>Body: <code>{ "target": "...", "target_type": "ip|domain|url" }</code></sub></td>
</tr>
<tr>
<td>

```http
GET /api/dashboard/summary
```

</td>
<td>Dashboard statistikasını qaytarır</td>
</tr>
</table>

---

## 🧰 Texnologiyalar

| Sahə | Texnologiyalar |
|---|---|
| 🐍 Backend | Python, Flask |
| 🗄️ Verilənlər bazası | SQLite, SQLAlchemy |
| 🔐 Autentifikasiya | Flask-Login, TOTP (2FA) |
| ⏱️ Rate limiting | Flask-Limiter |
| 🕵️ Threat intel | VirusTotal, AbuseIPDB, Google Safe Browsing, AlienVault OTX, daxili IOC bazası |
| 🎯 Zəiflik məlumatı | CISA KEV canlı feed |
| ⏰ Fon tapşırıqları | APScheduler (həftəlik e-mail xülasəsi) |
| ✉️ E-mail | Resend / Brevo |
| 📄 PDF generasiyası | fpdf2 (DejaVu Unicode) |
| 🎨 Frontend | HTML5, CSS3, Bootstrap 5, JavaScript |
| 📊 Qrafiklər | Chart.js |
| ⚙️ Konfiqurasiya | python-dotenv |

---

## 🚀 Quraşdırma

**1️⃣ Repository-ni klonlayın**

```bash
git clone https://github.com/hajieew/threat-intelligence-platform.git
cd threat-intelligence-platform
```

**2️⃣ Virtual mühit yaradın**

```bash
python -m venv .venv
```

<details>
<summary>🪟 Windows</summary>

```bash
.venv\Scripts\activate
```

</details>

<details>
<summary>🐧 Linux / 🍎 macOS</summary>

```bash
source .venv/bin/activate
```

</details>

**3️⃣ Kitabxanaları quraşdırın**

```bash
pip install -r requirements.txt
```

**4️⃣ `.env` faylını hazırlayın**

```bash
cp .env.example .env
```

> [!IMPORTANT]
> Əsas dəyişən (mütləq):
>
> | Dəyişən | Təsvir |
> |---|---|
> | `SECRET_KEY` | Flask sessiya açarı |
> | `VIRUSTOTAL_API_KEY` | Əsas threat intel mənbəyi (VirusTotal-dan pulsuz əldə edilə bilər) |
>
> Könüllü — əlavə mənbələri aktivləşdirmək üçün (boş qalarsa, həmin mənbə sadəcə keçilir, xəta vermir):
>
> | Dəyişən | Təsvir |
> |---|---|
> | `ABUSEIPDB_API_KEY` | IP reputasiya yoxlaması üçün |
> | `GOOGLE_SAFE_BROWSING_API_KEY` | URL/domen üçün Google-ın zərərli sayt bazası |
> | `OTX_API_KEY` | AlienVault OTX icma təhdid feed-i |
> | `RESEND_API_KEY` | Qeydiyyat zamanı e-mail təsdiqi üçün — boş qalarsa link birbaşa UI-də göstərilir |
> | `BREVO_API_KEY` | "Zərərli aşkarlananda e-mail göndər" / həftəlik xülasə bildirişləri üçün |
> | `APP_URL` | Fon tapşırığından (scheduler) göndərilən e-maillərdəki linklər üçün (məs. `http://localhost:5000`) |
> | `RATELIMIT_STORAGE_URI` | Lokal işə salma üçün `memory://` kifayətdir; production üçün Redis tövsiyə olunur |

> [!WARNING]
> `.env.example` faylında hazırda real görünən bir `VIRUSTOTAL_API_KEY` dəyəri var — bu, ehtimal ki, təsadüfən commit olunub. Repo-nu public edərkən həmin açarı VirusTotal panelindən ləğv edib (**revoke**) öz `.env` faylınızda yenisini istifadə edin; `.env.example`-də isə yalnız boş/placeholder dəyər qalmalıdır.

---

## ▶️ İşə salınması

```bash
python run.py
```

və ya

```bash
flask --app app.main:create_app run --debug
```

🌐 Brauzerdə açın: **http://127.0.0.1:5000**

---

## 🗄️ Verilənlər bazası

Layihə **SQLite** verilənlər bazasından istifadə edir. `database.db` faylı proqram ilk dəfə işə salındıqda avtomatik yaradılır — eyni zamanda demo istifadəçi hesabı da avtomatik təmin olunur.

---

## 🗂️ Layihə strukturu

```text
threat-intelligence-platform/
│
├── app/
│   ├── data/
│   │   ├── threat_actors.py       # Təhdid aktoru profilləri (statik)
│   │   ├── cve_watchlist.py       # CVE siyahısı (statik)
│   │   ├── local_ioc_store.py     # Daxili IOC bazasının yükləyicisi
│   │   ├── iocs_domains.txt       # Bilinən zərərli domenlər
│   │   └── iocs_ips.txt           # Bilinən zərərli IP-lər
│   ├── database/
│   │   └── connection.py
│   ├── models/
│   │   ├── user.py
│   │   ├── threat_analysis.py
│   │   ├── report.py
│   │   └── search_history.py
│   ├── routes/
│   │   ├── auth_routes.py
│   │   ├── dashboard_routes.py
│   │   ├── analysis_routes.py
│   │   ├── history_routes.py
│   │   ├── report_routes.py
│   │   ├── threat_actors_routes.py
│   │   └── cve_routes.py
│   ├── services/
│   │   ├── auth_service.py
│   │   ├── twofa_service.py
│   │   ├── threat_service.py      # Bütün mənbələri birləşdirən əsas servis
│   │   ├── virustotal_service.py
│   │   ├── abuseipdb_service.py
│   │   ├── safe_browsing_service.py
│   │   ├── otx_service.py
│   │   ├── local_ioc_service.py
│   │   ├── cve_service.py         # CISA KEV canlı zənginləşdirmə
│   │   ├── email_service.py
│   │   ├── notification_service.py
│   │   └── scheduler_service.py   # Fon tapşırıqları (həftəlik e-mail)
│   ├── static/
│   │   ├── img/                   # Favicon / platforma ikonu
│   │   └── fonts/                 # DejaVu Unicode fontları (PDF üçün)
│   ├── templates/
│   ├── utils/
│   │   ├── helpers.py
│   │   ├── security.py
│   │   ├── tokens.py
│   │   ├── totp.py
│   │   └── validators.py
│   ├── i18n/
│   ├── extensions.py
│   └── main.py
│
├── requirements.txt
├── run.py
├── .env
└── README.md
```

---

## 🧪 Nümunə analizlər

| 🎯 Giriş | 📋 Gözlənilən nəticə |
|---|:---:|
| `google.com` | 🟢 Təhlükə yoxdur |
| `8.8.8.8` | 🟢 Təhlükə yoxdur |
| `185.199.108.153` | 🔴 Zərərli |

---

## 🔑 Demo giriş

> [!TIP]
> Sınaq üçün hazır demo hesabı istifadə edin (proqram ilk dəfə işə salındıqda avtomatik yaradılır):

| | |
|---|---|
| 📧 **Email** | `123@holbertonstudents.com` |
| 🔒 **Password** | `Holbie123!` |

---

## 🗺️ Gələcək inkişaf planları

- [ ] 🔗 OpenCTI inteqrasiyası
- [ ] 📡 Əlavə Threat Intelligence Feed-ləri
- [ ] 🧩 IOC Enrichment
- [ ] 📦 STIX 2.1 dəstəyi
- [ ] 🎭 Brend təqlidinin (Brand Impersonation) aşkarlanması
- [ ] 👁️ Watchlist sistemi
- [ ] 🤖 Süni intellekt əsaslı risk qiymətləndirilməsi
- [ ] 🔐 Role-Based Access Control (RBAC)
- [ ] 🔗 SIEM və EDR sistemləri ilə inteqrasiya

---

<div align="center">

### 🎯 Layihənin məqsədi

AZ Threat Radar kibertəhdidlərin aşkarlanması, qiymətləndirilməsi və idarə olunması üçün hazırlanmış veb tətbiqidir.
Layihə xüsusi olaraq **Azərbaycanı hədəf alan təhdid aktorlarına** (APT29, MuddyWater, FamousSparrow və regional hacktivist qruplar) və onlara aid zəifliklərə diqqət yönəldir. Uzunmüddətli məqsəd — beynəlxalq Threat Intelligence yanaşmalarını Azərbaycan bazarına uyğunlaşdırmaq, lokal risk qiymətləndirmə modeli yaratmaq və gələcəkdə **OpenCTI əsaslı** genişləndirilə bilən Cyber Threat Intelligence platformasına çevrilmək.

<br>

**⭐ Faydalı olubsa, ulduz verməyi unutmayın!**

</div>