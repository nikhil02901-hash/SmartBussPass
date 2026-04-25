from flask import (
    Flask, render_template, request, redirect, session,
    url_for, flash, send_file, jsonify, send_from_directory
)
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import io
import csv
import random
import qrcode
import hmac
import hashlib
import base64
from PIL import Image
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from ml_model.fraud_model import fraud_risk_score

APP_TITLE = "Smart Bus Pass Management System"
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "smart_bus_pass.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

app = Flask(__name__)
app.secret_key = "smart_bus_pass_secret_key_change_me"

# ---------------- Security: Rate Limit (demo) ----------------
# NOTE: In production, use Redis-based limiter (Flask-Limiter). This is an in-memory demo.
RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "60"))
_rate_bucket = {}  # (ip, endpoint, minute) -> count

@app.before_request
def _rate_limit_guard():
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
        endpoint = (request.endpoint or "unknown")
        minute = datetime.now().strftime("%Y%m%d%H%M")
        key = (ip, endpoint, minute)
        _rate_bucket[key] = _rate_bucket.get(key, 0) + 1
        if _rate_bucket[key] > RATE_LIMIT_PER_MINUTE:
            return render_template("403.html", title="403 | " + APP_TITLE), 403
    except Exception:
        pass



# ---------------- DB HELPERS ----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def row_get(row, key, default=None):
    try:
        if row is None:
            return default
        keys = row.keys() if hasattr(row, 'keys') else row
        if key in keys:
            val = row[key]
            return default if val is None else val
    except Exception:
        pass
    return default


def _add_column_if_missing(conn, table: str, col_def: str):
    col_name = col_def.split()[0]
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r["name"] for r in cur.fetchall()]
    if col_name not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
        conn.commit()


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    conn = get_db()
    cur = conn.cursor()

    # ---------- USERS ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL
    )
    """)

    # ---------- BUS PASS ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bus_pass (
        pass_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        user_name TEXT NOT NULL,
        email TEXT NOT NULL,
        route TEXT NOT NULL,
        pass_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        remarks TEXT DEFAULT '',
        fraud_score INTEGER DEFAULT 0,
        fraud_flag TEXT DEFAULT 'Low',
        created_at TEXT NOT NULL,
        reviewed_at TEXT,
        approved_at TEXT,
        rejected_at TEXT,
        valid_from TEXT,
        valid_till TEXT,
        renewal_count INTEGER DEFAULT 0,
        photo_path TEXT,
        college_name TEXT,
        enrollment_no TEXT,
        verified INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # ---------- AUDIT LOGS ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_email TEXT NOT NULL,
        action TEXT NOT NULL,
        pass_id INTEGER,
        details TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # ---------- RENEWALS ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS renewals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pass_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        requested_at TEXT NOT NULL,
        processed_at TEXT,
        remarks TEXT DEFAULT '',
        FOREIGN KEY(pass_id) REFERENCES bus_pass(pass_id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # ---------- ELIGIBLE STUDENTS ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS eligible_students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        college_name TEXT NOT NULL,
        enrollment_no TEXT NOT NULL,
        student_name TEXT,
        is_active INTEGER DEFAULT 1,
        UNIQUE(college_name, enrollment_no)
    )
    """)

    
    # ---------- DOCUMENTS (Verification) ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pass_id INTEGER NOT NULL,
        doc_type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        remarks TEXT DEFAULT '',
        uploaded_at TEXT NOT NULL,
        verified_by TEXT,
        verified_at TEXT,
        FOREIGN KEY(pass_id) REFERENCES bus_pass(pass_id)
    )
    """)

    # ---------- BUS LIVE LOCATION ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS bus_location (
        bus_no TEXT PRIMARY KEY,
        lat REAL NOT NULL,
        lng REAL NOT NULL,
        updated_at TEXT NOT NULL,
        updated_by TEXT
    )
    """)

    # ---------- EMI INSTALLMENTS ----------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS emi_installments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pass_id INTEGER NOT NULL,
        installment_no INTEGER NOT NULL,
        due_date TEXT NOT NULL,
        amount INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'Due',  -- Due/Paid/Overdue
        paid_at TEXT,
        txn_id TEXT,
        UNIQUE(pass_id, installment_no),
        FOREIGN KEY(pass_id) REFERENCES bus_pass(pass_id)
    )
    """)

# ---------- MIGRATION SAFETY ----------
    _add_column_if_missing(conn, "users", "phone TEXT")
    _add_column_if_missing(conn, "bus_pass", "reviewed_at TEXT")
    _add_column_if_missing(conn, "bus_pass", "approved_at TEXT")
    _add_column_if_missing(conn, "bus_pass", "rejected_at TEXT")
    _add_column_if_missing(conn, "bus_pass", "valid_from TEXT")
    _add_column_if_missing(conn, "bus_pass", "valid_till TEXT")
    _add_column_if_missing(conn, "bus_pass", "renewal_count INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "bus_pass", "fraud_score INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "bus_pass", "fraud_flag TEXT DEFAULT 'Low'")
    _add_column_if_missing(conn, "bus_pass", "remarks TEXT DEFAULT ''")
    _add_column_if_missing(conn, "bus_pass", "photo_path TEXT")
    _add_column_if_missing(conn, "bus_pass", "college_name TEXT")
    _add_column_if_missing(conn, "bus_pass", "enrollment_no TEXT")
    _add_column_if_missing(conn, "bus_pass", "verified INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "bus_pass", "price INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "bus_pass", "payment_status TEXT DEFAULT 'Pending'")
    _add_column_if_missing(conn, "bus_pass", "payment_method TEXT")
    _add_column_if_missing(conn, "bus_pass", "txn_id TEXT")
    _add_column_if_missing(conn, "bus_pass", "paid_at TEXT")
    _add_column_if_missing(conn, "bus_pass", "emi_months INTEGER DEFAULT 0")
    _add_column_if_missing(conn, "bus_pass", "emi_monthly_amount INTEGER DEFAULT 0")

    _add_column_if_missing(conn, "bus_pass", "price INTEGER DEFAULT 0")

    # ---------- DEFAULT ADMIN ----------
    cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO users (name,email,password_hash,role,created_at) VALUES (?,?,?,?,?)",
            ("Admin", "admin@admin.com", generate_password_hash("admin123"), "admin",
             datetime.now().isoformat(timespec="seconds"))
        )

    # ---------- SEED ELIGIBLE STUDENTS ----------
    seed = [
        ("DPG Degree College", "MCA2024001", "Student 1"),
        ("DPG Degree College", "MCA2024002", "Student 2"),
        ("DPG Degree College", "MCA2024003", "Student 3"),
        ("DPG Degree College", "MCA2024004", "Student 4"),
        ("DPG Degree College", "MCA2024005", "Student 5"),
        ("DPG Degree College", "MCA2024006", "Student 6"),
        ("DPG Degree College", "MCA2024007", "Student 7"),
        ("DPG Degree College", "MCA2024008", "Student 8"),
        ("DPG Degree College", "MCA2024009", "Student 9"),
        ("DPG Degree College", "MCA2024010", "Student 10"),
    ]
    for c, e, n in seed:
        try:
            cur.execute(
                "INSERT INTO eligible_students (college_name,enrollment_no,student_name,is_active) VALUES (?,?,?,1)",
                (c.strip().lower(), e.strip().upper(), n)
            )
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()


def log_action(action: str, pass_id=None, details: str = ""):
    actor = session.get("email", "system")
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (actor_email,action,pass_id,details,created_at) VALUES (?,?,?,?,?)",
        (actor, action, pass_id, details, datetime.now().isoformat(timespec="seconds")),
    )
    conn.commit()
    conn.close()


def require_login():
    return 'user_id' in session


def require_admin():
    return session.get('role') == 'admin'


def require_staff():
    return session.get('role') in ('admin', 'verifier')


QR_SECRET = os.environ.get("QR_SECRET", app.secret_key)

def _sign_qr(pid: int, ts: str) -> str:
    msg = f"{pid}|{ts}".encode("utf-8")
    key = (QR_SECRET or "").encode("utf-8")
    sig = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")

def _qr_image_for_pass(pass_id: int) -> Image.Image:
    # Signed, anti-fake QR (public verify URL)
    ts = datetime.now().isoformat(timespec="seconds")
    sig = _sign_qr(pass_id, ts)
    payload = f"/verify_qr?pid={pass_id}&ts={ts}&sig={sig}"
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    return img



def _make_txn_id(prefix="TXN"):
    # Simple unique id for demo (not a real gateway txn id)
    return f"{prefix}-{datetime.now().strftime('%Y%m%d%H%M%S')}-{os.urandom(3).hex()}"



# ---------------- EMAIL (SMTP) ----------------
# Set these in environment variables for security:
#   SMTP_USER=nikhil02901@gmail.com
#   SMTP_PASS=<GMAIL_APP_PASSWORD>
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")

def send_email(to_email: str, subject: str, body: str):
    """Send email using SMTP. Requires SMTP_USER/SMTP_PASS env vars."""
    if not SMTP_USER or not SMTP_PASS:
        # If not configured, skip silently (demo mode)
        app.logger.warning("SMTP not configured; skipping email to %s", to_email)
        return
    try:
        import smtplib
        from email.message import EmailMessage
        msg = EmailMessage()
        msg["From"] = SMTP_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception as e:
        app.logger.exception("Email send failed: %s", e)


# ---------------- SMS (Twilio-ready) ----------------
TWILIO_SID = os.environ.get("TWILIO_SID", "")
TWILIO_TOKEN = os.environ.get("TWILIO_TOKEN", "")
TWILIO_FROM = os.environ.get("TWILIO_FROM", "")

def send_sms(to_phone: str, body: str):
    """Send SMS via Twilio if configured, else fallback to app logs (demo)."""
    if TWILIO_SID and TWILIO_TOKEN and TWILIO_FROM:
        try:
            from twilio.rest import Client
            client = Client(TWILIO_SID, TWILIO_TOKEN)
            client.messages.create(from_=TWILIO_FROM, to=to_phone, body=body)
            return True
        except Exception as e:
            app.logger.exception("Twilio SMS failed, falling back to demo: %s", e)

    # Demo fallback
    app.logger.info("DEMO_SMS to %s: %s", to_phone, body)
    return False

# ---------------- Upload serve ----------------
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


# ---------------- AUTH ----------------
@app.route('/')
def login():
    return render_template('login.html', title=f"Login | {APP_TITLE}")


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register with phone + email, then verify OTP.

    NOTE: "Real" phone-SMS OTP needs an SMS gateway API (Fast2SMS/Twilio etc.).
    This demo sends OTP to email via SMTP and also prints it in server logs.
    """
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        phone = request.form.get('phone', '').strip()

        if not name or not email or not password or not phone:
            flash("All fields are required (including phone).")
            return redirect(url_for('register'))

        conn = get_db()
        exists = conn.execute(
            "SELECT 1 FROM users WHERE email=? OR phone=? LIMIT 1",
            (email, phone)
        ).fetchone()
        conn.close()

        if exists:
            flash("Email/Phone already registered. Please login.")
            return redirect(url_for('login'))

        otp = str(random.randint(100000, 999999))
        session["pending_reg"] = {"name": name, "email": email, "password": password, "phone": phone}
        session["reg_otp"] = otp
        session["reg_otp_time"] = datetime.now().isoformat(timespec="seconds")

        try:
            # Send OTP on phone (Twilio-ready). Email is kept as backup.
            send_sms(phone, f"Your Smart Bus Pass OTP is {otp}")
            send_email(
                email,
                "Smart Bus Pass Registration OTP",
                f"Your OTP is: {otp}\n\nIf SMS is configured (Twilio), OTP is also sent to your phone."
            )
        except Exception:
            pass

        app.logger.info("REG_OTP for %s (%s) = %s", email, phone, otp)
        flash("OTP sent. Please verify to complete registration.")
        return redirect(url_for('verify_register_otp'))

    return render_template('register.html', title=f"Register | {APP_TITLE}")

@app.route('/verify_register_otp', methods=['GET', 'POST'])
def verify_register_otp():
    pending = session.get("pending_reg")
    otp_expected = session.get("reg_otp")

    if not pending or not otp_expected:
        flash("OTP session expired. Please register again.")
        return redirect(url_for('register'))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        if otp != otp_expected:
            flash("Wrong OTP ❌")
            return redirect(url_for('verify_register_otp'))

        # create user
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (name,email,phone,password_hash,role,created_at) VALUES (?,?,?,?,?,?)",
                (
                    pending["name"], pending["email"], pending["phone"],
                    generate_password_hash(pending["password"]),
                    "user",
                    datetime.now().isoformat(timespec="seconds")
                )
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Email/Phone already registered.")
            conn.close()
            return redirect(url_for('login'))
        conn.close()

        session.pop("pending_reg", None)
        session.pop("reg_otp", None)
        session.pop("reg_otp_time", None)

        flash("Registered successfully ✅ Please login.")
        return redirect(url_for('login'))

    return render_template('verify_register_otp.html', title=f"Verify OTP | {APP_TITLE}")

@app.route('/login_check', methods=['POST'])
def login_check():
    # Login by email + password (simple).
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        session.clear()
        session['user_id'] = user['id']
        session['user'] = user['name']
        session['email'] = user['email']
        session['role'] = user['role']
        session['phone'] = row_get(user, 'phone', '')
        log_action("LOGIN", details=f"role={user['role']}")

        if session.get('role') in ('admin', 'verifier'):
            return redirect(url_for('admin_analytics'))
        return redirect(url_for('dashboard'))

    flash("Invalid login details.")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    log_action("LOGOUT")
    session.clear()
    return redirect(url_for('login'))


# ---------------- USER ----------------
@app.route('/dashboard')
def dashboard():
    if not require_login():
        return redirect(url_for('login'))

    conn = get_db()
    passes = conn.execute(
        "SELECT * FROM bus_pass WHERE user_id=? ORDER BY pass_id DESC",
        (session['user_id'],)
    ).fetchall()
    renewals = conn.execute(
        "SELECT * FROM renewals WHERE user_id=? ORDER BY id DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()

    return render_template('dashboard.html', title=f"Dashboard | {APP_TITLE}", passes=passes, renewals=renewals)



# ---------------- LIVE BUS TRACKING (Demo) ----------------
@app.route('/track_bus')
def track_bus():
    if not require_login():
        return redirect(url_for('login'))
    return render_template('track_bus.html', title=f"Live Tracking | {APP_TITLE}")


# ---------------- BUS TRACKING (Admin update + User live map) ----------------
@app.route('/api/bus/<bus_no>')
def api_bus_location_by_no(bus_no):
    conn = get_db()
    row = conn.execute("SELECT bus_no,lat,lng,updated_at FROM bus_location WHERE bus_no=?",(bus_no,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error":"not_found"}), 404
    return jsonify(dict(row))

@app.route('/admin/bus_update', methods=['GET','POST'])
def admin_bus_update():
    if not require_admin():
        return render_template('403.html', title="403 | " + APP_TITLE), 403
    if request.method == 'POST':
        bus_no = request.form.get('bus_no','').strip().upper() or "SGT-SHUTTLE-01"
        try:
            lat = float(request.form.get('lat','0'))
            lng = float(request.form.get('lng','0'))
        except ValueError:
            flash("Invalid lat/lng")
            return redirect(url_for('admin_bus_update'))
        conn = get_db()
        conn.execute(
            """INSERT INTO bus_location (bus_no,lat,lng,updated_at,updated_by)
               VALUES (?,?,?,?,?)
               ON CONFLICT(bus_no) DO UPDATE SET
                 lat=excluded.lat,lng=excluded.lng,updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
            (bus_no, lat, lng, datetime.now().isoformat(timespec='seconds'), session.get('email','admin'))
        )
        conn.commit()
        conn.close()
        log_action("BUS_LOCATION_UPDATE", None, f"{bus_no} -> ({lat},{lng})")
        flash("Bus location updated ✅")
        return redirect(url_for('admin_bus_update'))
    return render_template('admin_bus_update.html', title="Bus Update | " + APP_TITLE)

@app.route('/api/bus_location')
def api_bus_location():
    # Simple demo moving coordinates near Gurugram
    import time
    t = int(time.time()) % 60
    lat = 28.4595 + (t * 0.00025)
    lng = 77.0266 + (t * 0.00025)
    return jsonify({
        "bus_no": "SGT-SHUTTLE-01",
        "lat": lat,
        "lng": lng,
        "updated_at": datetime.now().isoformat(timespec="seconds")
    })

@app.route('/apply_pass', methods=['GET', 'POST'])
def apply_pass():
    if not require_login():
        return redirect(url_for('login'))
    if require_staff():
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        route_from = request.form.get('route_from', '').strip()
        if not route_from:
            flash("Please enter From Location.")
            return redirect(url_for('apply_pass'))

        route = f"{route_from} → SGT University"
        pass_type = request.form.get('pass_type', '').strip()
        student_validity = request.form.get('student_validity', '').strip()
        college_name = request.form.get('college_name', '').strip()
        enrollment_no = request.form.get('enrollment_no', '').strip()

        if not pass_type or not college_name or not enrollment_no:
            flash("Please fill all fields (including college details).")
            return redirect(url_for('apply_pass'))

        college_key = college_name.strip().lower()
        enroll_key = enrollment_no.strip().upper()

        # photo upload (optional)
        photo_path = None
        f = request.files.get("photo")
        if f and f.filename:
            fname = secure_filename(f.filename)
            ext = os.path.splitext(fname)[1].lower()
            if ext not in (".png", ".jpg", ".jpeg", ".webp"):
                flash("Photo must be png/jpg/webp.")
                return redirect(url_for('apply_pass'))
            os.makedirs(UPLOAD_DIR, exist_ok=True)
            safe_name = f"user_{session['user_id']}_{int(datetime.now().timestamp())}{ext}"
            save_to = os.path.join(UPLOAD_DIR, safe_name)
            f.save(save_to)
            photo_path = f"uploads/{safe_name}"

        conn = get_db()
        cur = conn.cursor()

        # ✅ Authority eligibility check
        ok = cur.execute(
            "SELECT 1 FROM eligible_students WHERE college_name=? AND enrollment_no=? AND is_active=1",
            (college_key, enroll_key)
        ).fetchone()
        if not ok:
            conn.close()
            flash("Not eligible: Enrollment No not found in college records.")
            return redirect(url_for('apply_pass'))

        # fraud scoring
        cur.execute("SELECT COUNT(*) AS c FROM bus_pass WHERE email=?", (session['email'],))
        prev_count = cur.fetchone()["c"]

        score, flag, reason = fraud_risk_score(
            name=session['user'],
            email=session['email'],
            route=route,
            pass_type=pass_type,
            previous_applications=prev_count
        )

        valid_from = None
        valid_till = None
        if pass_type == "Student" and student_validity:
            try:
                months = int(student_validity)
            except ValueError:
                months = 1
            valid_from = datetime.now().date().isoformat()
            valid_till = (datetime.now() + timedelta(days=30 * months)).date().isoformat()

        price = 0
        if pass_type == "Student" and student_validity:
            try:
                months = int(student_validity)
                if months == 6:
                    price = 15000
                elif months == 12:
                    price = 30000
            except:
                price = 0
    

        now = datetime.now().isoformat(timespec="seconds")

        # ✅ FIXED INSERT: columns 16 => placeholders 16
        cur.execute(
            """
            INSERT INTO bus_pass
            (user_id,user_name,email,route,pass_type,status,remarks,fraud_score,fraud_flag,created_at, photo_path,college_name,enrollment_no,verified,valid_from,valid_till,price)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                session['user_id'], session['user'], session['email'],
                route, pass_type,
                'Pending', reason, score, flag, now,
                photo_path, college_name, enrollment_no, 0,
                valid_from, valid_till, price
            )
        )

        conn.commit()
        pass_id = cur.lastrowid
        conn.close()

        log_action("APPLY_PASS", pass_id=pass_id, details=f"fraud={flag}({score})")
        flash("Bus Pass Applied Successfully ✅ (Awaiting Authority Verification)")
        return redirect(url_for('pass_details', pass_id=pass_id))

    return render_template('apply_pass.html', title=f"Apply Pass | {APP_TITLE}")


@app.route('/pass/<int:pass_id>')
def pass_details(pass_id):
    if not require_login():
        return redirect(url_for('login'))

    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    logs = conn.execute(
        "SELECT * FROM audit_logs WHERE pass_id=? ORDER BY id DESC LIMIT 10",
        (pass_id,)
    ).fetchall()
    conn.close()

    if not bp:
        flash("Pass not found.")
        return redirect(url_for('dashboard'))

    if session.get('role') != 'admin' and bp['user_id'] != session.get('user_id'):
        flash("Not allowed.")
        return redirect(url_for('dashboard'))

    return render_template('pass_details.html', title=f"Pass Details | {APP_TITLE}", bp=bp, logs=logs)


@app.route('/request_renewal/<int:pass_id>', methods=['POST'])
def request_renewal(pass_id):
    if not require_login() or require_admin():
        return redirect(url_for('login'))

    conn = get_db()
    bp = conn.execute(
        "SELECT * FROM bus_pass WHERE pass_id=? AND user_id=?",
        (pass_id, session['user_id'])
    ).fetchone()
    if not bp:
        conn.close()
        flash("Pass not found.")
        return redirect(url_for('dashboard'))

    if bp['status'] != 'Approved':
        conn.close()
        flash("Renewal allowed only for Approved passes.")
        return redirect(url_for('pass_details', pass_id=pass_id))

    now = datetime.now().isoformat(timespec="seconds")
    conn.execute(
        "INSERT INTO renewals (pass_id,user_id,status,requested_at) VALUES (?,?,?,?)",
        (pass_id, session['user_id'], 'Pending', now)
    )
    conn.commit()
    conn.close()

    log_action("REQUEST_RENEWAL", pass_id=pass_id)
    flash("Renewal request submitted ✅")
    return redirect(url_for('dashboard'))


# ---------------- ADMIN ----------------
@app.route('/admin')
def admin_dashboard():
    if not require_login() or not require_staff():
        return redirect(url_for('login'))

    status = request.args.get("status", "").strip()
    risk = request.args.get("risk", "").strip()
    q = request.args.get("q", "").strip()
    tab = request.args.get("tab", "all").strip()  # all | highrisk

    if tab == "highrisk" and not risk:
        risk = "High"

    where = []
    params = []
    if status:
        where.append("status=?")
        params.append(status)
    if risk:
        where.append("fraud_flag=?")
        params.append(risk)
    if q:
        where.append("(CAST(pass_id AS TEXT) LIKE ? OR user_name LIKE ? OR email LIKE ? OR route LIKE ?)")
        params.extend([f"%{q}%"] * 4)

    sql = "SELECT * FROM bus_pass"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY pass_id DESC"

    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 10))
    per_page = min(max(per_page, 5), 50)
    offset = (page - 1) * per_page

    conn = get_db()
    rows = conn.execute(sql + " LIMIT ? OFFSET ?", params + [per_page, offset]).fetchall()
    total = conn.execute("SELECT COUNT(*) AS c FROM (" + sql + ")", params).fetchone()["c"]
    pages = (total + per_page - 1) // per_page if total else 1

    kpi = conn.execute("""
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status='Approved' THEN 1 ELSE 0 END) AS approved,
          SUM(CASE WHEN status='Rejected' THEN 1 ELSE 0 END) AS rejected,
          SUM(CASE WHEN status='Pending' THEN 1 ELSE 0 END) AS pending,
          SUM(CASE WHEN fraud_flag='High' THEN 1 ELSE 0 END) AS high_risk
        FROM bus_pass
    """).fetchone()

    renewal_pending = conn.execute("SELECT COUNT(*) AS c FROM renewals WHERE status='Pending'").fetchone()["c"]
    conn.close()

    can_decide = (session.get("role") == "admin")

    return render_template(
        "admin_dashboard.html",
        title=f"Admin Dashboard | {APP_TITLE}",
        passes=rows,
        kpi=kpi,
        renewal_pending=renewal_pending,
        can_decide=can_decide,
        filters={"status": status, "risk": risk, "q": q, "tab": tab,
                 "page": page, "per_page": per_page, "pages": pages, "total": total},
    )


@app.route('/admin/export.csv')
def export_csv():
    if not require_login() or not require_staff():
        return redirect(url_for('login'))

    status = request.args.get("status", "").strip()
    risk = request.args.get("risk", "").strip()
    q = request.args.get("q", "").strip()

    where = []
    params = []
    if status:
        where.append("status=?")
        params.append(status)
    if risk:
        where.append("fraud_flag=?")
        params.append(risk)
    if q:
        where.append("(CAST(pass_id AS TEXT) LIKE ? OR user_name LIKE ? OR email LIKE ? OR route LIKE ?)")
        params.extend([f"%{q}%"] * 4)

    sql = """SELECT pass_id,user_name,email,college_name,enrollment_no,route,pass_type,status,verified,
                    fraud_flag,fraud_score,created_at,valid_from,valid_till,renewal_count
             FROM bus_pass"""
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY pass_id DESC"

    conn = get_db()
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["pass_id","user_name","email","college_name","enrollment_no","route","pass_type","status","verified",
                "fraud_flag","fraud_score","created_at","valid_from","valid_till","renewal_count"])
    for r in rows:
        w.writerow([r["pass_id"], r["user_name"], r["email"], r["college_name"], r["enrollment_no"],
                    r["route"], r["pass_type"], r["status"], r["verified"],
                    r["fraud_flag"], r["fraud_score"], r["created_at"], r["valid_from"], r["valid_till"], r["renewal_count"]])

    data = out.getvalue().encode("utf-8")
    return send_file(io.BytesIO(data), mimetype="text/csv", as_attachment=True, download_name="bus_pass_export.csv")


@app.route('/admin/analytics')
def admin_analytics():
    if not require_login() or not require_admin():
        return redirect(url_for('login'))

    conn = get_db()
    status_counts = conn.execute("""
        SELECT status, COUNT(*) AS c
        FROM bus_pass
        GROUP BY status
        ORDER BY c DESC
    """).fetchall()

    risk_counts = conn.execute("""
        SELECT fraud_flag, COUNT(*) AS c
        FROM bus_pass
        GROUP BY fraud_flag
        ORDER BY c DESC
    """).fetchall()

    last7 = []
    for i in range(6, -1, -1):
        day = (datetime.now() - timedelta(days=i)).date().isoformat()
        c = conn.execute("SELECT COUNT(*) AS c FROM bus_pass WHERE created_at LIKE ?", (day + "%",)).fetchone()["c"]
        last7.append({"day": day, "count": c})

    renews = conn.execute("""
        SELECT r.*, b.user_name, b.email, b.pass_id
        FROM renewals r
        JOIN bus_pass b ON b.pass_id=r.pass_id
        ORDER BY r.id DESC
        LIMIT 25
    """).fetchall()

    conn.close()
    return render_template(
        "admin_analytics.html",
        title=f"Analytics | {APP_TITLE}",
        status_counts=status_counts,
        risk_counts=risk_counts,
        last7=last7,
        renewals=renews
    )


@app.route('/update_pass/<int:pass_id>/<status>', methods=['GET', 'POST'])
def update_pass(pass_id, status):
    if not require_login() or not require_admin():
        return redirect(url_for('login'))

    if status not in ("Approved", "Rejected", "Pending"):
        flash("Invalid status.")
        return redirect(url_for('admin_dashboard'))

    remarks = request.form.get('remarks', '').strip() if request.method == 'POST' else request.args.get('remarks', '').strip()

    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    if not bp:
        conn.close()
        flash("Pass not found.")
        return redirect(url_for('admin_dashboard'))

    now = datetime.now().isoformat(timespec="seconds")
    reviewed_at = now
    approved_at = bp['approved_at']
    rejected_at = bp['rejected_at']
    valid_from = bp['valid_from']
    valid_till = bp['valid_till']

    if status == "Approved":
        approved_at = now
        rejected_at = None
        valid_from = datetime.now().date().isoformat()
        valid_till = (datetime.now() + timedelta(days=30)).date().isoformat()
        verified = 1
    elif status == "Rejected":
        rejected_at = now
        approved_at = None
        valid_from = None
        valid_till = None
        verified = 0
    else:
        approved_at = None
        rejected_at = None
        valid_from = None
        valid_till = None
        verified = 0

    conn.execute("""
        UPDATE bus_pass
        SET status=?, remarks=?, reviewed_at=?, approved_at=?, rejected_at=?, valid_from=?, valid_till=?, verified=?
        WHERE pass_id=?
    """, (status, remarks, reviewed_at, approved_at, rejected_at, valid_from, valid_till, verified, pass_id))
    conn.commit()
    conn.close()

    # Email notification (approval/rejection)
    try:
        subject = f"Bus Pass {status} - {APP_TITLE}"
        body = f"Hi {bp['user_name']},\n\nYour bus pass (ID: {pass_id}) has been {status}.\nRemarks: {remarks or '-'}\n\nRoute: {bp['route']}\nPass Type: {bp['pass_type']}\n\n- {APP_TITLE}"
        send_email(bp['email'], subject, body)
    except Exception:
        pass

    log_action("UPDATE_PASS", pass_id=pass_id, details=f"{status}; remarks={remarks[:80]}")
    flash(f"Pass {status} ✅")
    return redirect(url_for('pass_details', pass_id=pass_id))


@app.route('/admin/renewal/<int:renewal_id>/<decision>', methods=['POST'])
def admin_renewal_decision(renewal_id, decision):
    if not require_login() or not require_admin():
        return redirect(url_for('login'))

    if decision not in ("Approved", "Rejected"):
        flash("Invalid decision.")
        return redirect(url_for('admin_analytics'))

    remarks = request.form.get("remarks", "").strip()
    now = datetime.now().isoformat(timespec="seconds")

    conn = get_db()
    r = conn.execute("SELECT * FROM renewals WHERE id=?", (renewal_id,)).fetchone()
    if not r:
        conn.close()
        flash("Renewal not found.")
        return redirect(url_for('admin_analytics'))

    conn.execute("UPDATE renewals SET status=?, processed_at=?, remarks=? WHERE id=?",
                 (decision, now, remarks, renewal_id))

    if decision == "Approved":
        bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (r["pass_id"],)).fetchone()
        if bp and bp["status"] == "Approved":
            new_till = (datetime.now() + timedelta(days=30)).date().isoformat()
            conn.execute("""
                UPDATE bus_pass
                SET valid_till=?, renewal_count=renewal_count+1
                WHERE pass_id=?
            """, (new_till, r["pass_id"]))

    conn.commit()
    conn.close()

    log_action("RENEWAL_DECISION", pass_id=r["pass_id"], details=f"{decision}; {remarks[:80]}")
    flash("Renewal updated ✅")
    return redirect(url_for('admin_analytics'))


@app.route('/mark_reviewed/<int:pass_id>', methods=['POST'])
def mark_reviewed(pass_id):
    if not require_login() or not require_staff():
        return redirect(url_for('login'))

    remarks = request.form.get("remarks", "").strip()
    now = datetime.now().isoformat(timespec="seconds")
    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    if not bp:
        conn.close()
        flash("Pass not found.")
        return redirect(url_for('admin_dashboard'))

    if bp["status"] == "Pending":
        conn.execute("UPDATE bus_pass SET reviewed_at=? WHERE pass_id=?", (now, pass_id))
        if remarks:
            conn.execute("UPDATE bus_pass SET remarks=? WHERE pass_id=?", (remarks, pass_id))
        conn.commit()
        log_action("MARK_REVIEWED", pass_id=pass_id, details=remarks[:120])
        flash("Marked as Reviewed ✅")

    conn.close()
    return redirect(url_for('pass_details', pass_id=pass_id))



# ---------------- PAYMENT (Demo) ----------------
@app.route('/pay/<int:pass_id>', methods=['GET', 'POST'])
def pay(pass_id):
    if not require_login():
        return redirect(url_for('login'))

    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    conn.close()

    if not bp:
        flash("Pass not found.")
        return redirect(url_for('dashboard'))

    # user can pay only for their own pass (admin can view)
    if session.get('role') != 'admin' and bp['user_id'] != session.get('user_id'):
        flash("Not allowed.")
        return redirect(url_for('dashboard'))

    # only allow payment when pass is Approved (common rule). Change if your teacher wants otherwise.
    if bp['status'] != 'Approved':
        flash("Payment available only after Approval.")
        return redirect(url_for('pass_details', pass_id=pass_id))

    # if already paid
    if row_get(bp,'payment_status','Pending') == 'Paid':
        flash("Already paid ✅")
        return redirect(url_for('pass_details', pass_id=pass_id))

    amount = int(bp['price'] or 0)
    if amount <= 0:
        # fallback (in case old rows)
        amount = 15000 if bp['pass_type'] == 'Student' else 0

    if request.method == 'POST':
        method = request.form.get('method', '').strip()
        if method not in ('UPI', 'CARD', 'EMI', 'CASH'):
            flash("Select payment method.")
            return redirect(url_for('pay', pass_id=pass_id))

        # High-risk -> OTP step
        if (bp['fraud_flag'] or '').lower() == 'high':
            otp = str(random.randint(100000, 999999))
            session[f"otp_{pass_id}"] = otp
            session[f"otp_method_{pass_id}"] = method
            # For demo: show OTP via flash (or check terminal logs)
            flash(f"OTP (demo): {otp}")
            return redirect(url_for('pay_otp', pass_id=pass_id))

        return redirect(url_for('pay_process', pass_id=pass_id, method=method))

    return render_template("pay.html", title=f"Payment | {APP_TITLE}", bp=bp, amount=amount)


@app.route('/pay/<int:pass_id>/otp', methods=['GET', 'POST'])
def pay_otp(pass_id):
    if not require_login():
        return redirect(url_for('login'))

    otp_expected = session.get(f"otp_{pass_id}")
    method = session.get(f"otp_method_{pass_id}")

    if not otp_expected or not method:
        flash("OTP session expired. Please try again.")
        return redirect(url_for('pay', pass_id=pass_id))

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        if otp != otp_expected:
            flash("Wrong OTP ❌")
            return redirect(url_for('pay_otp', pass_id=pass_id))

        # OTP ok
        session.pop(f"otp_{pass_id}", None)
        session.pop(f"otp_method_{pass_id}", None)
        return redirect(url_for('pay_process', pass_id=pass_id, method=method))

    return render_template("pay_otp.html", title=f"OTP Verify | {APP_TITLE}", pass_id=pass_id)


@app.route('/pay/<int:pass_id>/upi_qr.png')
def pay_upi_qr(pass_id):
    # returns QR image png for UPI payment page
    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    conn.close()
    if not bp:
        return "Not found", 404
    amount = int(bp['price'] or 0)
    if amount <= 0:
        amount = 15000 if bp['pass_type'] == 'Student' else 0
    upi_id = "demo@upi"
    note = f"PASS_{pass_id}"
    upi_uri = f"upi://pay?pa={upi_id}&pn=SmartBusPass&am={amount}&cu=INR&tn={note}"
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(upi_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype='image/png')


@app.route('/pay/<int:pass_id>/process/<method>', methods=['GET', 'POST'])
def pay_process(pass_id, method):
    if not require_login():
        return redirect(url_for('login'))

    method = method.upper().strip()
    if method not in ('UPI', 'CARD', 'EMI', 'CASH'):
        flash("Invalid method.")
        return redirect(url_for('pay', pass_id=pass_id))

    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    conn.close()
    if not bp:
        flash("Pass not found.")
        return redirect(url_for('dashboard'))

    if session.get('role') != 'admin' and bp['user_id'] != session.get('user_id'):
        flash("Not allowed.")
        return redirect(url_for('dashboard'))

    if bp['status'] != 'Approved':
        flash("Payment available only after Approval.")
        return redirect(url_for('pass_details', pass_id=pass_id))

    amount = int(bp['price'] or 0)
    if amount <= 0:
        amount = 15000 if bp['pass_type'] == 'Student' else 0

    # ---------- UPI ----------
    if method == 'UPI':
        if request.method == 'POST':
            return redirect(url_for('pay_success', pass_id=pass_id, method='UPI'))
        return render_template('pay_upi.html', title=f"UPI Payment | {APP_TITLE}", pass_id=pass_id, amount=amount)

    # ---------- CARD ----------
    if method == 'CARD':
        if request.method == 'POST':
            return redirect(url_for('pay_success', pass_id=pass_id, method='CARD'))
        return render_template('pay_card.html', title=f"Card Payment | {APP_TITLE}", pass_id=pass_id, amount=amount)

    # ---------- EMI ----------
    if method == 'EMI':
        if request.method == 'POST':
            try:
                emi_months = int(request.form.get('emi_months', '0'))
            except ValueError:
                emi_months = 0

            if emi_months not in (3, 6, 12):
                flash("Select valid EMI months (3/6/12).")
                return redirect(url_for('pay_process', pass_id=pass_id, method='EMI'))

            monthly = int(round(amount / emi_months)) if emi_months else amount
            return redirect(url_for('pay_success_emi', pass_id=pass_id, emi_months=emi_months, monthly=monthly))

        return render_template('pay_emi.html', title=f"EMI Payment | {APP_TITLE}", pass_id=pass_id, amount=amount)

    # ---------- CASH ----------
    if request.method == 'POST':
        return redirect(url_for('pay_success', pass_id=pass_id, method='CASH'))
    return render_template('pay_cash.html', title=f"Cash Payment | {APP_TITLE}", pass_id=pass_id, amount=amount)

@app.route('/pay/<int:pass_id>/success/<method>')
def pay_success(pass_id, method):
    if not require_login():
        return redirect(url_for('login'))

    method = method.upper().strip()
    if method not in ('UPI', 'CARD', 'EMI', 'CASH'):
        flash("Invalid method.")
        return redirect(url_for('pay', pass_id=pass_id))

    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    if not bp:
        conn.close()
        flash("Pass not found.")
        return redirect(url_for('dashboard'))

    if session.get('role') != 'admin' and bp['user_id'] != session.get('user_id'):
        conn.close()
        flash("Not allowed.")
        return redirect(url_for('dashboard'))

    amount = int(bp['price'] or 0)
    if amount <= 0:
        amount = 15000 if bp['pass_type'] == 'Student' else 0

    txn_id = _make_txn_id(method)
    now = datetime.now().isoformat(timespec="seconds")

    conn.execute(
        "UPDATE bus_pass SET payment_status='Paid', payment_method=?, txn_id=?, paid_at=? WHERE pass_id=?",
        (method, txn_id, now, pass_id)
    )
    conn.commit()
    conn.close()

    try:
        send_email(bp['email'], f"Payment Successful - {APP_TITLE}", f"Hi {bp['user_name']},\n\nPayment successful for Pass ID {pass_id}.\nMethod: {method}\nAmount: ₹{amount}\nTxn: {txn_id}\n\n- {APP_TITLE}")
    except Exception:
        pass

    log_action("PAYMENT_SUCCESS", pass_id=pass_id, details=f"{method}; amount={amount}; txn={txn_id}")
    flash(f"Payment Successful ✅ Txn: {txn_id}")
    return redirect(url_for('pass_details', pass_id=pass_id))

@app.route('/pay/<int:pass_id>/success_emi')
def pay_success_emi(pass_id):
    if not require_login():
        return redirect(url_for('login'))

    try:
        emi_months = int(request.args.get('emi_months', '0'))
        monthly = int(request.args.get('monthly', '0'))
    except ValueError:
        emi_months, monthly = 0, 0

    if emi_months not in (3, 6, 12) or monthly <= 0:
        flash("Invalid EMI details.")
        return redirect(url_for('pay', pass_id=pass_id))

    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    if not bp:
        conn.close()
        flash("Pass not found.")
        return redirect(url_for('dashboard'))

    if session.get('role') != 'admin' and bp['user_id'] != session.get('user_id'):
        conn.close()
        flash("Not allowed.")
        return redirect(url_for('dashboard'))

    amount = int(bp['price'] or 0)
    txn_id = _make_txn_id('EMI')
    now = datetime.now().isoformat(timespec="seconds")

    conn.execute(
        "UPDATE bus_pass SET payment_status='EMI', payment_method='EMI', txn_id=?, paid_at=?, emi_months=?, emi_monthly_amount=? WHERE pass_id=?",
        (txn_id, now, emi_months, monthly, pass_id)
    )

    # Create EMI installment schedule: first installment considered paid at activation time
    # Remaining installments are Due every 30 days (demo logic).
    conn.execute("DELETE FROM emi_installments WHERE pass_id=?", (pass_id,))
    for n in range(1, emi_months + 1):
        due_dt = (datetime.now() + timedelta(days=30*(n-1))).date().isoformat()
        status = "Paid" if n == 1 else "Due"
        paid_at = now if n == 1 else None
        conn.execute(
            "INSERT OR REPLACE INTO emi_installments (pass_id, installment_no, due_date, amount, status, paid_at, txn_id) VALUES (?,?,?,?,?,?,?)",
            (pass_id, n, due_dt, monthly, status, paid_at, txn_id if n == 1 else None)
        )

    conn.commit()
    conn.close()

    try:
        send_email(bp['email'], f"EMI Activated - {APP_TITLE}", f"Hi {bp['user_name']},\n\nEMI activated for Pass ID {pass_id}.\nMonths: {emi_months}\nMonthly: ₹{monthly}\nTxn: {txn_id}\n\nYou can view your schedule at /emi/{pass_id}.\n\n- {APP_TITLE}")
    except Exception:
        pass

    log_action("PAYMENT_SUCCESS", pass_id=pass_id, details=f"EMI; amount={amount}; months={emi_months}; monthly={monthly}; txn={txn_id}")
    flash(f"EMI Activated ✅ {emi_months} months | ₹{monthly}/month | Txn: {txn_id}")
    return redirect(url_for('pass_details', pass_id=pass_id))




@app.route('/emi/<int:pass_id>')
def emi_schedule(pass_id):
    if not require_login():
        return redirect(url_for('login'))
    conn = get_db()
    bp = conn.execute("SELECT pass_id,user_id,emi_months,emi_monthly_amount,payment_status FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    if not bp:
        conn.close()
        flash("Pass not found.")
        return redirect(url_for('dashboard'))
    if session.get('role') != 'admin' and bp['user_id'] != session.get('user_id'):
        conn.close()
        return render_template('403.html', title="403 | " + APP_TITLE), 403
    inst = conn.execute("SELECT * FROM emi_installments WHERE pass_id=? ORDER BY installment_no", (pass_id,)).fetchall()
    conn.close()
    return render_template("emi_schedule.html", bp=bp, installments=inst, title="EMI Schedule | " + APP_TITLE)

@app.route('/admin/emi_mark_paid/<int:inst_id>', methods=['POST'])
def admin_emi_mark_paid(inst_id):
    if not require_admin():
        return render_template('403.html', title="403 | " + APP_TITLE), 403
    conn = get_db()
    row = conn.execute("SELECT pass_id,amount,status FROM emi_installments WHERE id=?", (inst_id,)).fetchone()
    if not row:
        conn.close()
        flash("Not found.")
        return redirect(url_for("admin_dashboard"))
    if row["status"] == "Paid":
        conn.close()
        flash("Already paid.")
        return redirect(url_for("emi_schedule", pass_id=row["pass_id"]))
    txn = _make_txn_id("EMIINST")
    now = datetime.now().isoformat(timespec="seconds")
    conn.execute("UPDATE emi_installments SET status='Paid', paid_at=?, txn_id=? WHERE id=?", (now, txn, inst_id))
    conn.commit()
    conn.close()
    log_action("EMI_MARK_PAID", row["pass_id"], f"inst_id={inst_id} txn={txn}")
    flash("Installment marked paid ✅")
    return redirect(url_for("emi_schedule", pass_id=row["pass_id"]))

@app.route('/cron/emi_reminders')
def cron_emi_reminders():
    # Simple endpoint to trigger reminders (demo). Protect with admin token in production.
    conn = get_db()
    today = datetime.now().date()
    upcoming = (today + timedelta(days=3)).isoformat()
    rows = conn.execute(
        """SELECT ei.*, bp.email, bp.user_name
           FROM emi_installments ei
           JOIN bus_pass bp ON bp.pass_id=ei.pass_id
           WHERE ei.status='Due' AND ei.due_date<=?""",
        (upcoming,)
    ).fetchall()
    for r in rows:
        send_email(
            r["email"],
            "EMI Payment Reminder - Smart Bus Pass",
            f"Hi {r['user_name']},\n\nYour EMI installment #{r['installment_no']} of ₹{r['amount']} is due on {r['due_date']}.\n\n- Smart Bus Pass"
        )
    conn.close()
    return jsonify({"reminders_sent": len(rows)})


@app.route('/receipt/<int:pass_id>')
def receipt_pdf(pass_id):
    if not require_login():
        return redirect(url_for('login'))

    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    conn.close()
    if not bp:
        flash("Pass not found.")
        return redirect(url_for('dashboard'))

    if session.get('role') != 'admin' and bp['user_id'] != session.get('user_id'):
        flash("Not allowed.")
        return redirect(url_for('dashboard'))

    if row_get(bp,'payment_status','Pending') not in ('Paid','EMI'):
        flash("Receipt available only after payment.")
        return redirect(url_for('pass_details', pass_id=pass_id))

    pdf_path = os.path.join(BASE_DIR, f"receipt_{pass_id}.pdf")
    c = canvas.Canvas(pdf_path, pagesize=A4)
    w, h = A4

    c.setFont("Helvetica-Bold", 18)
    c.drawString(60, h - 70, "PAYMENT RECEIPT")
    c.setFont("Helvetica", 10)
    c.drawString(60, h - 88, APP_TITLE)

    c.roundRect(50, h - 460, w - 100, 360, 12, stroke=1, fill=0)

    c.setFont("Helvetica-Bold", 12)
    c.drawString(70, h - 140, "RECEIPT DETAILS")
    c.setFont("Helvetica", 11)

    items = [
        ("Pass ID", bp["pass_id"]),
        ("Name", bp["user_name"]),
        ("Email", bp["email"]),
        ("Amount", f"₹{bp['price'] or 0}"),
        ("Payment Status", bp["payment_status"] or "Pending"),
        ("Payment Method", bp["payment_method"] or "-"),
        ("Txn ID", bp["txn_id"] or "-"),
        ("Paid At", bp["paid_at"] or "-"),
    ]
    y = h - 180
    for k, v in items:
        c.drawString(70, y, f"{k}:")
        c.drawString(220, y, str(v))
        y -= 20

    c.setFont("Helvetica-Oblique", 9)
    c.drawString(60, 70, "This receipt is system-generated. No signature required.")
    c.showPage()
    c.save()

    return send_file(pdf_path, as_attachment=True)


# ---------------- QR & PDF ----------------
@app.route('/download_qr/<int:pass_id>')
def download_qr(pass_id):
    if not require_login():
        return redirect(url_for('login'))

    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    conn.close()
    if not bp:
        flash("Pass not found.")
        return redirect(url_for('dashboard'))

    if session.get('role') != 'admin' and bp['user_id'] != session.get('user_id'):
        flash("Not allowed.")
        return redirect(url_for('dashboard'))

    img = _qr_image_for_pass(pass_id)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype='image/png', as_attachment=True, download_name=f"pass_{pass_id}_qr.png")


@app.route('/download_pdf/<int:pass_id>')
def download_pdf(pass_id):
    if not require_login():
        return redirect(url_for('login'))

    conn = get_db()
    bp = conn.execute("SELECT * FROM bus_pass WHERE pass_id=?", (pass_id,)).fetchone()
    conn.close()
    if not bp:
        flash("Pass not found.")
        return redirect(url_for('dashboard'))

    if session.get('role') != 'admin' and bp['user_id'] != session.get('user_id'):
        flash("Not allowed.")
        return redirect(url_for('dashboard'))

    if bp['status'] != 'Approved':
        flash("PDF available only for Approved passes.")
        return redirect(url_for('pass_details', pass_id=pass_id))

    pdf_path = os.path.join(BASE_DIR, f"bus_pass_{pass_id}.pdf")

    c = canvas.Canvas(pdf_path, pagesize=A4)
    w, h = A4

    c.setFont("Helvetica-Bold", 18)
    c.drawString(60, h - 70, "SMART BUS PASS")
    c.setFont("Helvetica", 10)
    c.drawString(60, h - 88, "Bus Pass Management System (Final Semester Project)")

    c.roundRect(50, h - 440, w - 100, 320, 12, stroke=1, fill=0)

    c.setFont("Helvetica-Bold", 12)
    c.drawString(70, h - 140, "PASS DETAILS")
    c.setFont("Helvetica", 11)
    y = h - 170
    items = [
        ("Pass ID", bp["pass_id"]),
        ("Name", bp["user_name"]),
        ("Email", bp["email"]),
        ("College", bp["college_name"] or "-"),
        ("Enrollment No", bp["enrollment_no"] or "-"),
        ("Verified", "YES" if bp["verified"] else "NO"),
        ("Route", bp["route"]),
        ("Pass Type", bp["pass_type"]),
        ("Valid From", bp["valid_from"] or "-"),
        ("Valid Till", bp["valid_till"] or "-"),
        ("Renewals", bp["renewal_count"]),
        ("Fraud Risk", f'{bp["fraud_flag"]} ({bp["fraud_score"]})'),
    ]
    for k, v in items:
        c.drawString(70, y, f"{k}:")
        c.drawString(200, y, str(v))
        y -= 18

    qr_img = _qr_image_for_pass(pass_id)
    qr_buf = io.BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_buf.seek(0)
    qr_pil = Image.open(qr_buf)
    c.drawInlineImage(qr_pil, w - 190, h - 340, 120, 120)
    c.setFont("Helvetica", 9)
    c.drawString(w - 190, h - 350, "Scan QR for Pass ID")

    c.setFont("Helvetica-Oblique", 9)
    c.drawString(60, 70, f"Issued on {datetime.now().date().isoformat()} | Generated by system")
    c.drawString(60, 55, "This is a system-generated pass. No signature required.")
    c.showPage()
    c.save()

    return send_file(pdf_path, as_attachment=True)



# ---------------- QR VERIFY (Signed) ----------------
@app.route('/verify_qr')
def verify_qr():
    pid = request.args.get("pid", "").strip()
    ts = request.args.get("ts", "").strip()
    sig = request.args.get("sig", "").strip()
    if not pid.isdigit() or not ts or not sig:
        return "<h2>Invalid QR ❌</h2>", 400
    pid_int = int(pid)
    expected = _sign_qr(pid_int, ts)
    if not hmac.compare_digest(expected, sig):
        return "<h2>Fake / Tampered QR ❌</h2>", 400
    # Optional: reject very old QR timestamps (anti-replay) - allow 365 days in demo
    try:
        t = datetime.fromisoformat(ts)
        if datetime.now() - t > timedelta(days=365):
            return "<h2>QR Expired ❌</h2>", 400
    except Exception:
        pass
    return redirect(url_for("verify_pass", pass_id=pid_int))


# ---------------- QR VERIFY (Public) ----------------
@app.route('/verify/<int:pass_id>')
def verify_pass(pass_id):
    conn = get_db()
    bp = conn.execute(
        "SELECT pass_id,user_name,route,pass_type,status,valid_till,verified FROM bus_pass WHERE pass_id=?",
        (pass_id,)
    ).fetchone()
    conn.close()
    if not bp:
        return "<h2>Invalid Pass ❌</h2>"

    return render_template("verify.html", bp=bp, title="Verify Pass | " + APP_TITLE)


# ---------------- DOCUMENT UPLOAD + VERIFICATION ----------------

ALLOWED_DOC_EXT = {"png", "jpg", "jpeg", "pdf"}


def _allowed_doc(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_DOC_EXT


@app.route("/upload_docs/<int:pass_id>", methods=["GET", "POST"])
def upload_docs(pass_id: int):
    """User uploads verification documents for a specific pass."""
    if not require_login():
        return redirect(url_for("login"))

    conn = get_db()
    bp = conn.execute(
        "SELECT pass_id,user_id,user_name,email,status FROM bus_pass WHERE pass_id=?",
        (pass_id,),
    ).fetchone()
    if not bp:
        conn.close()
        return render_template("404.html", title="404 | " + APP_TITLE), 404

    # Only owner (or staff/admin) can upload
    if (bp["user_id"] != session.get("user_id")) and (not require_staff()):
        conn.close()
        return render_template("403.html", title="403 | " + APP_TITLE), 403

    if request.method == "POST":
        doc_type = (request.form.get("doc_type") or "Other").strip() or "Other"
        f = request.files.get("doc_file")
        if not f or not f.filename:
            flash("Please choose a document file.", "error")
            return redirect(url_for("upload_docs", pass_id=pass_id))
        if not _allowed_doc(f.filename):
            flash("Only PNG/JPG/PDF files are allowed.", "error")
            return redirect(url_for("upload_docs", pass_id=pass_id))

        safe_name = secure_filename(f.filename)
        doc_dir = os.path.join(UPLOAD_DIR, "documents", str(pass_id))
        os.makedirs(doc_dir, exist_ok=True)
        save_path = os.path.join(doc_dir, f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{safe_name}")
        f.save(save_path)

        conn.execute(
            "INSERT INTO documents (pass_id, doc_type, file_path, status, uploaded_at) VALUES (?,?,?,?,?)",
            (pass_id, doc_type, save_path, "Pending", datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()
        conn.close()

        log_action("DOC_UPLOADED", pass_id, f"type={doc_type}; file={os.path.basename(save_path)}")
        flash("Document uploaded successfully!", "success")
        return redirect(url_for("upload_docs", pass_id=pass_id))

    docs = conn.execute(
        "SELECT id, doc_type, status, remarks, uploaded_at, verified_by, verified_at FROM documents WHERE pass_id=? ORDER BY id DESC",
        (pass_id,),
    ).fetchall()
    conn.close()
    return render_template(
        "upload_docs.html",
        title=f"Upload Documents | {APP_TITLE}",
        bp=bp,
        docs=docs,
    )


@app.route("/admin/documents")
def admin_documents():
    if not require_staff():
        return render_template("403.html", title="403 | " + APP_TITLE), 403
    conn = get_db()
    docs = conn.execute(
        """SELECT d.id,d.pass_id,d.doc_type,d.status,d.remarks,d.uploaded_at,d.verified_by,d.verified_at,
                  b.user_name,b.email,b.status as pass_status
           FROM documents d
           JOIN bus_pass b ON b.pass_id=d.pass_id
           ORDER BY d.id DESC"""
    ).fetchall()
    conn.close()
    return render_template("admin_documents.html", title=f"Document Verification | {APP_TITLE}", docs=docs)


@app.route("/admin/documents/<int:doc_id>/set", methods=["POST"])
def admin_set_document_status(doc_id: int):
    if not require_staff():
        return render_template("403.html", title="403 | " + APP_TITLE), 403

    new_status = (request.form.get("status") or "Pending").strip()
    remarks = (request.form.get("remarks") or "").strip()
    if new_status not in ("Pending", "Verified", "Rejected"):
        flash("Invalid status.", "error")
        return redirect(url_for("admin_documents"))

    conn = get_db()
    row = conn.execute("SELECT pass_id FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not row:
        conn.close()
        flash("Document not found.", "error")
        return redirect(url_for("admin_documents"))

    pass_id = row["pass_id"]
    conn.execute(
        """UPDATE documents
           SET status=?, remarks=?, verified_by=?, verified_at=?
           WHERE id=?""",
        (
            new_status,
            remarks,
            session.get("email", ""),
            datetime.now().isoformat(timespec="seconds"),
            doc_id,
        ),
    )
    conn.commit()
    conn.close()

    log_action("DOC_STATUS", pass_id, f"doc_id={doc_id}; status={new_status}; remarks={remarks}")
    flash("Document status updated.", "success")
    return redirect(url_for("admin_documents"))


@app.route("/admin/audit")
def admin_audit():
    if not require_staff():
        return render_template("403.html", title="403 | " + APP_TITLE), 403
    conn = get_db()
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return render_template("admin_audit.html", title=f"Audit Logs | {APP_TITLE}", logs=logs)


# ---------------- API / Swagger ----------------
@app.route('/api/openapi.json')
def openapi_json():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Smart Bus Pass API", "version": "1.0.0"},
        "paths": {
            "/api/passes/{pass_id}": {
                "get": {
                    "summary": "Get pass details",
                    "parameters": [{"name": "pass_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "OK"}}
                }
            },
            "/verify/{pass_id}": {
                "get": {"summary": "Public verification page", "responses": {"200": {"description": "OK"}}}
            }
        }
    }
    return jsonify(spec)


@app.route('/api/docs')
def api_docs():
    return render_template("swagger.html", title="API Docs | " + APP_TITLE)


@app.route('/api/passes/<int:pass_id>')
def api_get_pass(pass_id):
    conn = get_db()
    bp = conn.execute(
        """SELECT pass_id,user_name,email,college_name,enrollment_no,verified,route,pass_type,status,
                  valid_from,valid_till,fraud_flag,fraud_score
           FROM bus_pass WHERE pass_id=?""",
        (pass_id,)
    ).fetchone()
    conn.close()
    if not bp:
        return jsonify({"error": "not_found"}), 404
    return jsonify(dict(bp))


# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(403)
def e403(e):
    return render_template("403.html", title="403 | " + APP_TITLE), 403


@app.errorhandler(404)
def e404(e):
    return render_template("404.html", title="404 | " + APP_TITLE), 404


@app.errorhandler(500)
def e500(e):
    app.logger.exception("Server error: %s", e)
    return render_template("500.html", title="500 | " + APP_TITLE), 500


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
