<div align="center">

# 🛡️ AZ Threat Radar

### Kibertəhdidlərin aşkarlanması və risk qiymətləndirmə platforması

IP ünvanların, domenlərin və URL-lərin **VirusTotal** ilə inteqrasiya olunmuş analizi, risk skorlama və vizual dashboard.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/SQLite-SQLAlchemy-07405E?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlalchemy.org/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)](https://www.virustotal.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](#)

</div>

<br>

> [!NOTE]
> Bu layihə kibertəhdidlərin aşkarlanması, qiymətləndirilməsi və idarə olunması prosesini sadələşdirmək, təhlükəsizlik analitiklərinə daha sürətli qərar verməyə kömək etmək məqsədilə hazırlanıb.

---

## 📑 İçindəkilər

- [✨ Əsas imkanlar](#-əsas-imkanlar)
- [📊 Risk qiymətləndirmə sistemi](#-risk-qiymətləndirmə-sistemi)
- [🖥️ Dashboard](#️-dashboard)
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

- ✅ Qeydiyyat + e-mail təsdiqi (Resend / Brevo)
- ✅ Giriş / çıxış (Flask-Login)
- ✅ Təhlükəsiz parol şifrələnməsi
- ✅ Brute-force qorunması (Flask-Limiter)
- ✅ Profil redaktəsi və şifrə dəyişmə
- ✅ Çoxdilli interfeys (AZ / RU dəstəyi)

</td>
<td width="50%" valign="top">

### 🔍 Təhdid analizi

- ✅ IP · Domen · URL analizi
- ✅ Avtomatik növ aşkarlanması
- ✅ **VirusTotal API** reputasiya yoxlaması
- ✅ Şəbəkə məlumatları (ölkə, ISP, ASN, host)
- ✅ WHOIS sorğusu
- ✅ Risk balı + tövsiyə

</td>
</tr>
</table>

---

## 📊 Risk qiymətləndirmə sistemi

Hər analiz üçün **0–100** arası risk balı hesablanır:

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
| 🔐 Autentifikasiya | Flask-Login |
| ⏱️ Rate limiting | Flask-Limiter |
| 🕵️ Threat intel | VirusTotal API |
| ✉️ E-mail | Resend / Brevo (sib-api-v3-sdk) |
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
> Ən azı bu dəyişənləri doldurun:
>
> | Dəyişən | Təsvir |
> |---|---|
> | `SECRET_KEY` | Flask sessiya açarı |
> | `VIRUSTOTAL_API_KEY` | Threat intel sorğuları üçün (VirusTotal-dan pulsuz əldə edilə bilər) |
> | `RESEND_API_KEY` | E-mail verifikasiyası üçün — boş qalarsa, link e-mail əvəzinə birbaşa UI-də göstərilir |
> | `RATELIMIT_STORAGE_URI` | Lokal işə salma üçün `memory://` kifayətdir; production üçün Redis tövsiyə olunur |

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
│   │   └── report_routes.py
│   ├── services/
│   │   ├── auth_service.py
│   │   ├── threat_service.py
│   │   └── virustotal_service.py
│   ├── static/
│   │   └── fonts/            # DejaVu Unicode fontları (PDF üçün)
│   ├── templates/
│   ├── utils/
│   │   ├── helpers.py
│   │   └── validators.py
│   ├── i18n.py
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
- [ ] 🚫 AbuseIPDB inteqrasiyası
- [ ] 📡 Əlavə Threat Intelligence Feed-ləri
- [ ] 🧩 IOC Enrichment
- [ ] 📦 STIX 2.1 dəstəyi
- [ ] 🎭 Brend təqlidinin (Brand Impersonation) aşkarlanması
- [ ] 👁️ Watchlist sistemi
- [ ] 🤖 Süni intellekt əsaslı risk qiymətləndirilməsi
- [ ] 🔐 Role-Based Access Control (RBAC)
- [ ] 🔗 SIEM və EDR sistemləri ilə inteqrasiya
- [ ] 🇦🇿 Azərbaycan bazarı üçün lokal risk qiymətləndirmə modeli

---

<div align="center">

### 🎯 Layihənin məqsədi

AZ Threat Radar kibertəhdidlərin aşkarlanması, qiymətləndirilməsi və idarə olunması üçün hazırlanmış veb tətbiqidir.
Uzunmüddətli məqsəd — beynəlxalq Threat Intelligence yanaşmalarını Azərbaycan bazarına uyğunlaşdırmaq, lokal risk qiymətləndirmə modeli yaratmaq və gələcəkdə **OpenCTI əsaslı** genişləndirilə bilən Cyber Threat Intelligence platformasına çevrilmək.

<br>

**⭐ Faydalı olubsa, ulduz verməyi unutmayın!**

</div>
