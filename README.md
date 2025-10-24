#
<div align="center">

# 🌍 Domain Scope — IP & Domain Intelligence Toolkit


</div>

> 🧠 All‑in‑one OSINT toolkit for domains: WHOIS, DNS, geolocation, abuse risk, metadata, and VirusTotal security — with bulk scanning and CSV export.

---

## ✨ Overview

- **WHOIS & DNS**: Registrar, dates, A/MX/NS/AAAA, age
- **IP Intelligence**: IP, country, region, city, lat/lon, ISP
- **Risk & Abuse**: AbuseIPDB confidence score (if key provided)
- **Web Metadata (Metascraper)**: Title, description, images, social cards, JSON‑LD, feeds, more
- **Security (VirusTotal)**: Vendor detections, reputation, categories, DNS/SSL history, risk level
- **Bulk Scan + CSV**: Scan multiple domains and export results

---

## 🏆 Why Domain Scope stands out

- **Metascraper+: 30+ fields with quality scoring**
  - Title, description, OG/Twitter, keywords, favicon/logo, feeds, JSON‑LD
  - 6 organized tabs and a metadata completeness score
- **Bulletproof metadata fetching**
  - Multi‑proxy CORS fallback (allorigins → corsproxy → codetabs) with timeouts
  - Graceful errors; backend results still work even if proxies fail
- **Deep security via VirusTotal**
  - Risk level, malicious/suspicious counts, vendor detections, reputation, categories
  - DNS/SSL history, JARM, WHOIS snapshot
- **Bulk scan that actually enriches**
  - WHOIS/IP/Geo + ISP fallback + AbuseIPDB score (if key), progress tracking
- **One‑click CSV that won’t break**
  - Robust CSV escaping for commas, quotes, and newlines
- **Beautiful, responsive UI with dark mode**
  - Modern cards, gradients, iconography, and keyboard‑friendly interactions

---

## 🚀 Live

- UI: https://domain-scope-three.vercel.app

---

## 🧩 Features

- **Backend results card** (WHOIS/DNS/IP/Geo/ISP/Abuse)
- **Metascraper card** with 6 tabs (Basic, Social, Content, Tech, Media, Schema)
- **VirusTotal card** with 6 tabs (Security, Detection, Reputation, Categories, DNS/SSL, Info)
- **Bulk scanner** with progress and optional enrichment
- **CSV export** for backend results with safe CSV escaping
- **Dark mode**, responsive UI, modern design

---

## 🛠 Tech Stack

- Frontend: React + Vite + TypeScript + TailwindCSS + shadcn/ui
- Intelligence: AbuseIPDB, VirusTotal, IP geolocation (from API), Metascraper-style parsing
- Deploy: Vercel (UI), Render (API)

---

## ⚡ Quick Start

1) Clone & install
```bash
npm install
npm run dev
```

2) Configure environment (create `.env` in project root)
```env
VITE_API_BASE=https://whois-aoi.onrender.com
VITE_VIRUSTOTAL_API_KEY=your_virustotal_api_key   # optional but recommended
VITE_ABUSEIPDB_API_KEY=your_abuseipdb_api_key     # optional (improves risk score)
```

3) Open http://localhost:5173 and analyze a domain (e.g., `github.com`).

---

## 🔑 Environment

- `VITE_API_BASE` — Backend WHOIS/DNS API base URL
- `VITE_VIRUSTOTAL_API_KEY` — Enables VirusTotal security panel
- `VITE_ABUSEIPDB_API_KEY` — Enables abuse score enrichment (single + bulk)

Restart the dev server after changing `.env`.

---

## 🧭 Usage

- **Single Scan**
  - Enter a domain in `DomainAnalysisCard` and run scan
  - Three panels populate: Backend, Metascraper, VirusTotal (if keys set)

- **Bulk Scan**
  - Open Bulk Scanner, paste or upload `.txt` (one domain per line)
  - Bulk WHOIS/IP/Geo + ISP enrichment + AbuseIPDB (if key)
  - Exports appear in the Results panel via “Export CSV” (backend fields)

- **Export CSV**
  - `ResultsPanel` exports backend results to CSV with proper quoting/escaping
  - Metadata and VirusTotal panels are visual by default (can be extended)

---

## 📡 API Endpoints (Backend)

| Route               | Purpose                            |
|---------------------|------------------------------------|
| `GET /whois/?domain=` | WHOIS, IPs, geolocation, nameservers |
| `GET /dns/?domain=`   | DNS records (A, AAAA, MX, NS, TXT)    |
| `GET /ipgeo/?ip=`     | IP geolocation (if provided)          |
| `GET /abuse/?ip=`     | AbuseIPDB risk (requires API key)     |

VirusTotal is called directly from the client via `https://www.virustotal.com/api/v3/domains/{domain}`.

---

## 🧪 Metascraper (Web Metadata)

- Fetches HTML via a **multi‑proxy fallback** to avoid CORS issues:
  - allorigins.win → corsproxy.io → codetabs.com (8s timeout each)
- Extracts 30+ fields: Title, Description, Keywords, OG/Twitter, Feeds, Schema/JSON‑LD, Robots, Generator, Viewport, Theme Color, Favicon/Logo, etc.
- Computes a “completeness score” as a quick SEO quality indicator.

---

## 🛡️ VirusTotal (Security)

- Shows detection stats, reputation, categories, popularity, DNS/SSL, WHOIS snapshot, JARM, and vendor results.
- Risk levels: 🟢 Clean, 🟡 Low, 🟠 Medium, 🔴 High.
- Free tier limits: ~4 req/min, 500/day; add your API key in `.env`.

---

## 🌐 CORS & Reliability

- Metadata fetch uses a multi‑proxy chain with timeouts and graceful errors.
- Backend WHOIS/DNS panel is not affected by CORS and works independently.

---

## 🧯 Troubleshooting (Quick)

- **No metadata / timeouts**: Proxies busy or site blocks scraping → try again; backend data still works.
- **VirusTotal errors**: Check `VITE_VIRUSTOTAL_API_KEY`, respect rate limits, restart dev server after `.env` changes.
- **CSV looks broken**: Now escaped (quotes/newlines/commas). Re‑export from the latest build.

---

## 📁 Project Structure (simplified)

```
src/
  components/
    DomainAnalysisCard.tsx     # Single scan (Backend + Meta + VT)
    BulkScannerCard.tsx        # Bulk scan (Backend + AbuseIPDB)
    ResultsPanel.tsx           # Export CSV (backend data)
    MetascraperResults.tsx     # Web metadata (6 tabs)
    VirusTotalResults.tsx      # Security analysis (6 tabs)
```

---

## 📜 License

MIT — free for personal and commercial use.

