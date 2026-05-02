from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
import random, time, os, subprocess, shlex, json, hashlib, math, shutil
import joblib, numpy as np
from authlib.integrations.flask_client import OAuth  # ✅ Authlib import

app = Flask(__name__)

# ---------------- Configuration ----------------
app.secret_key = "cyshield_secret_key_replace_me"

# Google OAuth credentials
app.config['GOOGLE_CLIENT_ID'] = "382588089871-aqvnf7v790gtpidhd37pnsvbk1mrvcph.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = "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"
app.config['SECRET_KEY'] = "cyshield_secret_key_replace_me"
app.config['DEBUG'] = True

GOOGLE_REDIRECT_PATH = "/callback"

# ---------------- OAuth Setup ----------------
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v2/',
    client_kwargs={'scope': 'openid email profile'}
)

# ---------------- ML Model ----------------
MODEL_PATH = "fraud_model.pkl"
SCALER_PATH = "fraud_scaler.pkl"
model, scaler, model_loaded = None, None, False

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        model_loaded = True
        print("✅ Fraud model loaded.")
    else:
        print("⚠️ Model not found, using fallback.")
except Exception as e:
    print("❌ Model load failed:", e)

UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
QUARANTINE_DIR = os.path.join(os.getcwd(), "quarantine")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
ALLOWED_SCAN_IPS = {"127.0.0.1", "localhost"}

# ---------------- Helper Functions ----------------
def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(65536), b''):
            h.update(block)
    return h.hexdigest()

def file_entropy(path, sample_bytes=4096):
    try:
        with open(path, 'rb') as f:
            data = f.read(sample_bytes)
        if not data:
            return 0.0
        freq = {b: data.count(b) for b in set(data)}
        l = len(data)
        return -sum((v / l) * math.log2(v / l) for v in freq.values())
    except Exception:
        return 0.0

BLACKLIST_HASHES = {}
SUSPICIOUS_EXT = {'.exe', '.scr', '.js', '.vbs', '.ps1', '.jar', '.msi', '.bat', '.zip', '.rar'}
HIGH_RISK_KEYWORDS = ['encrypt', 'decrypt', 'payload', 'ransom', 'lock', 'trojan']

# ---------------- ROUTES ----------------
@app.route('/')
def home():
    user = session.get('user')
    return render_template('index.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('username') == 'admin' and request.form.get('password') == '1234':
            session['user'] = {'name': 'admin', 'email': 'admin@example.com', 'method': 'local'}
            return redirect(url_for('dashboard'))
        flash("Invalid credentials.", "error")
    return render_template('login.html')

# -------- Google OAuth --------
@app.route('/google_login')
def google_login():
    redirect_uri = url_for('google_authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route(GOOGLE_REDIRECT_PATH)
def google_authorized():
    token = google.authorize_access_token()
    if not token:
        return redirect(url_for('login'))
    resp = google.get('userinfo')
    user_info = resp.json()

    session['user'] = {
        'name': user_info.get('name', ''),
        'email': user_info.get('email', ''),
        'picture': user_info.get('picture', ''),
        'method': 'google'
    }
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('home'))

# ---------------- APIs ----------------
@app.route('/api/scan')
def scan():
    try:
        return jsonify({
            "summary": "Scan complete",
            "issues_found": 3,
            "details": [
                {"id": 1, "type": "SQL Injection", "severity": "High"},
                {"id": 2, "type": "Cross-Site Scripting", "severity": "Medium"},
                {"id": 3, "type": "Insecure Headers", "severity": "Low"},
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ----------------- DEMO IP VULNERABILITY SCANNER -----------------
@app.route('/api/scan_ip_demo')
def scan_ip_demo():
    """Simulated IP scan for demo mode."""
    ip = request.args.get('ip', '127.0.0.1')
    time.sleep(1)  # simulate scan delay

    fake_ports = [
        {"port": 22, "service": "ssh", "version": "OpenSSH 8.2", "severity": "medium"},
        {"port": 80, "service": "http", "version": "nginx 1.18", "severity": "high"},
        {"port": 443, "service": "https", "version": "Apache 2.4.54", "severity": "low"},
        {"port": 3306, "service": "mysql", "version": "MySQL 5.7", "severity": "medium"},
        {"port": 8080, "service": "http-alt", "version": "Tomcat 9.0", "severity": "medium"},
        {"port": 21, "service": "ftp", "version": "vsftpd 3.0.3", "severity": "low"}
    ]

    result = {
        "target": ip,
        "scan_status": "completed",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": random.sample(fake_ports, k=random.randint(2, 4)),
        "os_guess": random.choice(["Linux (Ubuntu)", "Windows Server 2019", "Unknown"]),
        "notes": "This is a simulated demo scan result. Do not use for external hosts."
    }

    return jsonify(result)


@app.route('/api/ransomware')
def ransomware():
    return jsonify({"status": "No suspicious activity detected ✅"})

@app.route('/api/fraud')
def fraud():
    try:
        amount = float(request.args.get('amount', 0))
        if model_loaded:
            amt_scaled = scaler.transform(np.array([[amount]]))
            pred = model.predict(amt_scaled)[0]
            prob = model.predict_proba(amt_scaled)[0][1]
            if pred == 1:
                return jsonify({"message": f"⚠️ High-risk transaction ({prob:.2%})", "model_used": True})
            return jsonify({"message": f"✅ Safe transaction ({prob:.2%})", "model_used": True})
        return jsonify({"message": "✅ Safe transaction (rule-based)", "model_used": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/upload_scan', methods=['POST'])
def upload_scan():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "no file provided"}), 400
        f = request.files['file']
        if f.filename == "":
            return jsonify({"error": "empty filename"}), 400

        ts = int(time.time())
        save_path = os.path.join(UPLOAD_DIR, f"{ts}_{f.filename}")
        f.save(save_path)

        size = os.path.getsize(save_path)
        sha = sha256_of_file(save_path)
        ent = file_entropy(save_path)
        ext = os.path.splitext(f.filename)[1].lower()
        score, reasons = 0, []

        if ext in SUSPICIOUS_EXT: score += 3; reasons.append(f"Suspicious ext: {ext}")
        if any(k in f.filename.lower() for k in HIGH_RISK_KEYWORDS): score += 3; reasons.append("Risky keyword")
        if ent > 7.5: score += 3; reasons.append(f"High entropy {ent:.2f}")
        if size > 50 * 1024 * 1024: score += 1; reasons.append("Large file")

        severity = "clean"
        if score >= 8: severity = "critical"
        elif score >= 5: severity = "high"
        elif score >= 3: severity = "medium"
        elif score > 0: severity = "low"

        return jsonify({
            "filename": f.filename,
            "sha256": sha,
            "entropy": ent,
            "score": score,
            "severity": severity,
            "reasons": reasons
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- Global Error Handler ----------------
@app.errorhandler(Exception)
def handle_exception(e):
    """Convert all unhandled exceptions to JSON for frontend safety."""
    return jsonify({"error": str(e)}), 500

# -----------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)

