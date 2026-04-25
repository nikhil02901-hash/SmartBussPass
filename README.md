# Smart Bus Pass Management System

A **Final Semester** web application to manage bus pass applications with a **Fraud Detection (ML‑ready) risk score**, **QR verification**, **PDF pass generation**, and an **Admin analytics dashboard**.

## Key Features
- User registration & login
- Apply for bus pass (route + pass type)
- **Fraud Risk Scoring** (Low / Medium / High) with score + reasons
- Admin workflow: **Approve / Reject / Pending** with remarks
- **Status timeline** (applied → reviewed → approved/rejected → validity)
- **QR Code** download for verification
- **PDF Bus Pass** download (only when Approved)
- **Renewal Requests** (user) + approval queue (admin)
- **Audit logs** (recent actions per pass)
- **Analytics dashboard** with charts (status, risk, last 7 days)

## Tech Stack
- Backend: Flask + SQLite
- Frontend: Jinja2 templates + custom theme
- Charts: Chart.js (CDN)
- QR: `qrcode` + Pillow
- PDF: ReportLab

## How to Run
```bash
python -m pip install -r requirements.txt
python app.py
```
Open:
- http://127.0.0.1:5000

## Default Admin (Demo)
- Email: `admin@admin.com`
- Password: `admin123`

## Notes for Viva
Fraud detection is **ML‑ready**: currently rule-based risk scoring, and can be replaced by a trained model (pickle) in `ml_model/fraud_model.py`.


## Next‑Level Add-ons (added)
- ✅ **Real Phone OTP (Twilio-ready)** with demo fallback (logs + email backup)
- ✅ **EMI Installment Schedule** (3/6/12 months) with due tracking + reminder endpoint
- ✅ **Live Bus Tracking** (Admin updates coordinates + User live map)
- ✅ **Email Notifications** (approval / rejection / payment / EMI reminders) via SMTP env vars
- ✅ **Signed QR (Anti‑Fake)**: QR contains signed URL; tampering is detected
- ✅ **Document Verification Module**: users upload docs, staff verifies in admin panel
- ✅ **Security upgrades**: basic rate-limit guard + Audit Log UI

## Setup (Windows / Linux / Mac)
### 1) Create venv + install
```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
```

### 2) Environment variables (optional but recommended)
Create a `.env` (or set env vars):
- **Email (SMTP)**
  - `SMTP_USER`
  - `SMTP_PASS` (Gmail App Password recommended)
  - `SMTP_HOST` (default: smtp.gmail.com)
  - `SMTP_PORT` (default: 587)
- **Twilio SMS (optional)**
  - `TWILIO_SID`
  - `TWILIO_TOKEN`
  - `TWILIO_FROM`
- **QR signing**
  - `QR_SECRET` (defaults to Flask secret key)
- **Rate limit**
  - `RATE_LIMIT_PER_MINUTE` (default: 60)

### 3) Run
```bash
python app.py
```

## Useful URLs
- User dashboard: `/dashboard`
- Apply pass: `/apply_pass`
- Live tracking: `/track_bus`
- Upload documents: `/upload_docs/<pass_id>`
- Admin dashboard: `/admin_dashboard`
- Admin analytics: `/admin/analytics`
- Admin documents: `/admin/documents`
- Admin audit logs: `/admin/audit`
- Admin bus update: `/admin/bus_update`
- EMI schedule: `/emi/<pass_id>`
- Trigger EMI reminders (demo): `/cron/emi_reminders`

