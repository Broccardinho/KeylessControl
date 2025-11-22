from flask import Flask, render_template, request, redirect, url_for, session
import time
import os
import pymysql
import requests
from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub

# Google OAuth
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import google.oauth2.id_token

# -------------------------------------------------------
# Flask Setup
# -------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback")

# Allow HTTP during testing (remove later)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# -------------------------------------------------------
# Environment Variables
# -------------------------------------------------------
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASS = os.environ.get("DB_PASS")
DB_NAME = os.environ.get("DB_NAME")

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

if not all([DB_HOST, DB_USER, DB_PASS, DB_NAME]):
    print("❌ ERROR: Missing DB environment variables")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    print("❌ ERROR: Missing Google OAuth credentials")

# -------------------------------------------------------
# Database Helper (Lazy Connect)
# -------------------------------------------------------
def get_db():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )

# -------------------------------------------------------
# PubNub Setup
# -------------------------------------------------------
pnconfig = PNConfiguration()
pnconfig.subscribe_key = "sub-c-764683fa-a709-42d5-a0bb-a9eca9c99146"
pnconfig.publish_key = "pub-c-28efa47f-1d37-4aa8-8cb0-bae3648e5eb2"
pnconfig.uuid = "flask_server"
pubnub = PubNub(pnconfig)

door_status = "Locked"

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
def log_unlock_event(user_email=None):
    """Log unlock events to MySQL + publish to PubNub."""
    global door_status
    door_status = "Unlocked"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            "INSERT INTO LogTimes (user_id, log_datetime) VALUES (%s, %s)",
            (None, timestamp)
        )
        db.commit()
    db.close()

    pubnub.publish().channel("door_updates").message({
        "device_id": "door_hardware_1",
        "status": door_status,
        "timestamp": timestamp
    }).sync()


def get_logs():
    """Return log entries for dashboard."""
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("""
            SELECT LogTimes.log_datetime, Users.name
            FROM LogTimes
            LEFT JOIN Users ON Users.user_id = LogTimes.user_id
            ORDER BY LogTimes.log_datetime DESC;
        """)
        results = cursor.fetchall()
    db.close()
    return results

# -------------------------------------------------------
# Routes
# -------------------------------------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html', title="Login")

@app.route('/dashboard')
def dashboard():
    if "google_user" not in session:
        return redirect(url_for("login"))
    logs = get_logs()
    return render_template(
        "dashboard.html",
        logs=logs,
        user=session["google_user"],
        title="Dashboard"
    )

@app.route('/control', methods=['GET', 'POST'])
def control():
    if "google_user" not in session:
        return redirect(url_for("login"))
    global door_status
    if request.method == "POST":
        log_unlock_event()
    return render_template("control.html", door_status=door_status, title="Control")

@app.route('/send_unlock', methods=['POST'])
def send_unlock():
    if "google_user" not in session:
        return redirect(url_for("login"))
    log_unlock_event()
    return redirect(url_for("control"))

@app.route('/send_face', methods=['POST'])
def send_face():
    if "google_user" not in session:
        return redirect(url_for("login"))
    print("Test face image sent")
    return redirect(url_for("control"))

# -------------------------------------------------------
# GOOGLE OAUTH
# -------------------------------------------------------
def build_google_flow():
    return Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "project_id": "keylesscontrol",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uris": ["https://keylesscontrol.eu/google/callback"]
            }
        },
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]
    )

@app.route("/login/google")
def login_with_google():
    flow = build_google_flow()
    flow.redirect_uri = "https://keylesscontrol.eu/google/callback"

    authorization_url, state = flow.authorization_url()
    session["google_oauth_state"] = state
    return redirect(authorization_url)

@app.route("/google/callback")
def google_callback():
    state = session["google_oauth_state"]

    flow = build_google_flow()
    flow.redirect_uri = "https://keylesscontrol.eu/google/callback"

    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials

    session_client = requests.session()
    cached_session = cachecontrol.CacheControl(session_client)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = google.oauth2.id_token.verify_oauth2_token(
        credentials._id_token,
        token_request,
        GOOGLE_CLIENT_ID
    )

    session["google_user"] = id_info
    return redirect("/dashboard")

# -------------------------------------------------------
# Local Run (ignored by mod_wsgi)
# -------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
