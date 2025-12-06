from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import time
import os
import pymysql
import requests

from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub
from .face_recognition import compare_to_database

# Google OAuth
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import google.oauth2.id_token


# -------------------------------------------------------
# Flask Setup
# -------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback-secret")

# Remove this in production once HTTPS is fully enforced
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


# -------------------------------------------------------
# DB Helper (opens fresh connection every call)
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
# Logging Helper
# -------------------------------------------------------
def log_action(user_id: int, action: str):
    """
    Log a lock/unlock action to logtimes and optionally publish via PubNub.
    Assumes logtimes schema:
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      action VARCHAR(20) NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ip_address VARCHAR(50)
    """
    ip = request.remote_addr or ""

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO logtimes (user_id, action, ip_address)
            VALUES (%s, %s, %s)
            """,
            (user_id, action, ip)
        )
        db.commit()
    db.close()

    # Publish to PubNub
    pubnub.publish().channel("door_updates").message({
        "status": action,
        "ip": ip,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }).sync()

def get_logs(limit: int = 50):
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            """
            SELECT 
                logtimes.timestamp,
                logtimes.action,
                logtimes.ip_address,
                accounts.username
            FROM logtimes
            LEFT JOIN accounts ON accounts.user_id = logtimes.user_id
            ORDER BY logtimes.timestamp DESC
            LIMIT %s
            """,
            (limit,)
        )
        logs = cursor.fetchall()
    db.close()
    return logs


# -------------------------------------------------------
# Auth Helpers
# -------------------------------------------------------
def get_current_user():
    """
    Returns the unified logged-in user dict or None.
    Structure:
      {
        "user_id": int,
        "name": str,
        "email": str,
        "auth_via": "password" | "google"
      }
    """
    return session.get("auth_user")


def require_login():
    """
    Redirect to login if no user is logged in.
    """
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))
    return None


# -------------------------------------------------------
# Routes
# -------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html", title="Home", user=get_current_user())


# -----------------------------
# Email/Password Login
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        db = get_db()
        with db.cursor() as cursor:
            cursor.execute(
                "SELECT user_id, username, email, password_hash FROM accounts WHERE email = %s",
                (email,)
            )
            account = cursor.fetchone()
        db.close()

        if account and check_password_hash(account["password_hash"], password):
            session["auth_user"] = {
                "user_id": account["user_id"],
                "name": account["username"],
                "email": account["email"],
                "auth_via": "password"
            }
            return redirect(url_for("dashboard"))

        return render_template("login.html", title="Login", error="Invalid email or password")

    return render_template("login.html", title="Login")


@app.route("/logout")
def logout():
    session.pop("auth_user", None)
    # keep google tokens/id if you want, but not required
    session.pop("google_oauth_state", None)
    return redirect(url_for("home"))


# -----------------------------
# Signup
# -----------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]

        password_hash = generate_password_hash(password)

        db = get_db()
        with db.cursor() as cursor:
            try:
                cursor.execute(
                    "INSERT INTO accounts (email, username, password_hash) VALUES (%s, %s, %s)",
                    (email, username, password_hash)
                )
                db.commit()
            except pymysql.err.IntegrityError:
                db.close()
                return render_template(
                    "signup.html",
                    error="Email or username already exists"
                )
        db.close()

        return redirect(url_for("login"))

    return render_template("signup.html")


# -----------------------------
# Dashboard (requires login)
# -----------------------------
@app.route("/dashboard")
def dashboard():
    must_login = require_login()
    if must_login:
        return must_login

    logs = get_logs()

    return render_template(
        "dashboard.html",
        logs=logs,
        user=get_current_user(),
        title="Dashboard"
    )


# -----------------------------
# Upload (into Users table)
# -----------------------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    must_login = require_login()
    if must_login:
        return must_login

    if request.method == "POST":
        name = request.form["name"]
        age = request.form["age"]
        image = request.files["image"]

        if image and allowed_file(image.filename):
            filename = image.filename
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image.save(save_path)

            # path to store in MySQL (not absolute)
            db_path = f"/static/uploads/{filename}"

            # store in Users table
            db = get_db()
            with db.cursor() as cursor:
                cursor.execute("""
    INSERT INTO Users (user_id, name, age, last_logged_date, image)
    VALUES (%s, %s, %s, CURDATE(), %s)
""", (
    str(int(time.time())),  # generate unique ID
    name,
    age,
    db_path
))
                db.commit()
            db.close()

            return redirect(url_for("dashboard"))

    return render_template("upload.html")


# -----------------------------
# Control Page
# -----------------------------
@app.route("/control", methods=["GET"])
def control():
    must_login = require_login()
    if must_login:
        return must_login

    global door_status
    return render_template(
        "control.html",
        door_status=door_status,
        user=get_current_user(),
        title="Control"
    )


@app.route("/send_unlock", methods=["POST"])
def send_unlock():
    must_login = require_login()
    if must_login:
        return must_login

    user = get_current_user()
    password = request.form.get("password")

    global door_status

    # Optional: if you want a secondary PIN/password check for unlocking
    if not password or password.strip() == "":
        door_status = "Locked"
        return redirect(url_for("control"))

    # If password check is needed, you can verify here against some user-specific PIN
    # For now, any non-empty value unlocks.
    door_status = "Unlocked"

    # Log action
    log_action(user_id=user["user_id"], action="Unlocked")

    return redirect(url_for("control"))


@app.route("/send_lock", methods=["POST"])
def send_lock():
    must_login = require_login()
    if must_login:
        return must_login

    user = get_current_user()

    global door_status
    door_status = "Locked"

    # Log action
    log_action(user_id=user["user_id"], action="Locked")

    return redirect(url_for("control"))


@app.route("/profiles/edit/<user_id>", methods=["GET", "POST"])
def edit_profile(user_id):
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM Users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()

    if not user:
        return "User not found", 404

    if request.method == "POST":
        name = request.form["name"]
        age = request.form["age"]

        with db.cursor() as cursor:
            cursor.execute("""
                UPDATE Users
                SET name = %s, age = %s
                WHERE user_id = %s
            """, (name, age, user_id))
            db.commit()

        db.close()
        return redirect("/profiles")

    db.close()
    return render_template("edit_profile.html", user=user)

@app.route("/profiles/delete/<user_id>")
def delete_profile(user_id):
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("DELETE FROM Users WHERE user_id = %s", (user_id,))
        db.commit()
    db.close()

    return redirect("/profiles")

# -------------------------------------------------------
# GOOGLE LOGIN
# -------------------------------------------------------
def build_google_flow():
    return Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "project_id": "keylesscontrol",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
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
    state = session.get("google_oauth_state")

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

    google_email = id_info.get("email")
    google_name = id_info.get("name", "Unknown")

    # 1) Ensure user exists in accounts table so logging uses accounts.user_id
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            "SELECT user_id, username, email FROM accounts WHERE email = %s",
            (google_email,)
        )
        account = cursor.fetchone()

        if not account:
            # Create a shadow account for Google user
            random_pw = os.urandom(16).hex()
            password_hash = generate_password_hash(random_pw)
            cursor.execute(
                "INSERT INTO accounts (email, username, password_hash) VALUES (%s, %s, %s)",
                (google_email, google_name, password_hash)
            )
            db.commit()
            user_id = cursor.lastrowid
            username = google_name
            email = google_email
        else:
            user_id = account["user_id"]
            username = account["username"]
            email = account["email"]

    db.close()

    # 2) Optionally mirror into Users table (for profile/upload stuff)
    db = get_db()
    with db.cursor() as cursor:
        # If Users has a user_id column tied to Google, you can adapt this.
        # For now we just ensure a simple name-only row if needed.
        cursor.execute(
            "SELECT * FROM Users WHERE name = %s LIMIT 1",
            (google_name,)
        )
        exists = cursor.fetchone()
        if not exists:
            cursor.execute(
                "INSERT INTO Users (name, date_of_registration) VALUES (%s, CURDATE())",
                (google_name,)
            )
            db.commit()
    db.close()

    # Save unified auth user
    session["auth_user"] = {
        "user_id": user_id,
        "name": username,
        "email": email,
        "auth_via": "google"
    }

    return redirect(url_for("dashboard"))

@app.route("/profiles")
def profiles():
    must_login = require_login()
    if must_login:
        return must_login

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("""
            SELECT 
                user_id,
                name,
                age,
                last_logged_date,
                image
            FROM Users
            ORDER BY last_logged_date DESC;
        """)
        profiles = cursor.fetchall()
    db.close()

    return render_template(
        "profiles.html",
        profiles=profiles,
        user=get_current_user(),
        title="Profiles"
    )

# -------------------------------------------------------
# Upload Config
# -------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

# -------------------------------------------------------
# racongition Config
# -------------------------------------------------------

@app.route("/recognize", methods=["GET", "POST"])
def recognize():
    must_login = require_login()
    if must_login:
        return must_login

    if request.method == "POST":
        image = request.files.get("image")

        if not image:
            return render_template("recognize.html", error="No image uploaded")

        # Save uploaded image temporarily
        temp_path = os.path.join(UPLOAD_FOLDER, "temp_recognition.jpg")
        image.save(temp_path)

        # Load all users
        db = get_db()
        with db.cursor() as cursor:
            cursor.execute("SELECT user_id, name, image FROM Users")
            users = cursor.fetchall()
        db.close()

        # Compare uploaded image vs DB
        match, user_row = compare_to_database(temp_path, users)

        if match:
            return render_template(
                "recognize_result.html",
                status="match",
                user=user_row
            )

        return render_template(
            "recognize_result.html",
            status="nomatch",
            user=None
        )

    # GET request → render form
    return render_template("recognize.html")

# -------------------------------------------------------
# Local run
# -------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
