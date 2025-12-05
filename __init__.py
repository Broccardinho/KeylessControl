from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
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
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback-secret")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"   # remove in production


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
DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASS = os.environ.get("DB_PASS")
DB_NAME = os.environ.get("DB_NAME")


DB_HOST = "127.0.0.1"
DB_USER = "root"
DB_PASS = ""     # empty password for XAMPP
DB_NAME = "keylesscontrol"



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
# Log Event
# -------------------------------------------------------
def log_unlock_event():
    """Log unlock event to DB and publish via PubNub."""

    global door_status
    door_status = "Unlocked"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    google_user_id = session["google_user"]["sub"]

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            "INSERT INTO LogTimes (user_id, log_datetime) VALUES (%s, %s)",
            (google_user_id, timestamp)
        )
        db.commit()
    db.close()

    pubnub.publish().channel("door_updates").message({
        "device_id": "door_hardware_1",
        "status": "Unlocked",
        "timestamp": timestamp
    }).sync()


def get_logs():
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("""
            SELECT LogTimes.log_datetime, Users.name
            FROM LogTimes
            LEFT JOIN Users ON Users.user_id = LogTimes.user_id
            ORDER BY LogTimes.log_datetime DESC;
        """)
        logs = cursor.fetchall()
    db.close()
    return logs


# -------------------------------------------------------
# Routes
# -------------------------------------------------------
@app.route('/')
def home():
    return render_template("index.html", title="Home")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        db = get_db()
        with db.cursor() as cursor:
            cursor.execute("SELECT user_id, username, password_hash FROM accounts WHERE email = %s", (email,))
            account = cursor.fetchone()

        if account and check_password_hash(account["password_hash"], password):
            session["auth_user"] = {
                "user_id": account["user_id"],
                "name": account["username"]
            }
            return redirect("/dashboard")

        return render_template("login.html", title="Login", error="Invalid login")

    return render_template("login.html", title="Login")




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
                return render_template("signup.html", error="Email or username already exists")

        db.close()

        return redirect("/login")

    return render_template("signup.html")



@app.route('/dashboard')
def dashboard():
    if "google_user" not in session:
        return redirect(url_for("login"))

    logs = get_logs()

    return render_template(
        "dashboard.html",
        logs=logs,
        user=session.get("google_user"),
        title="Dashboard"
    )

@app.route("/upload", methods=["GET", "POST"])
def upload():
    
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

            # store in DB
            db = get_db()
            with db.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO Users (name, age, date_of_registration, image_path)
                    VALUES (%s, %s, CURDATE(), %s)
                """, (name, age, db_path))
                db.commit()
            db.close()

            return redirect("/dashboard")

    return render_template("upload.html")



@app.route('/control', methods=['GET', 'POST'])
def control():
    session["google_user"] = {
        "name": "Alice Johnson",
        "sub": 1
    }

    if "google_user" not in session:
        return redirect(url_for("login"))

    global door_status
    if request.method == "POST":
        log_unlock_event()

    return render_template(
        "control.html",
        door_status=door_status,
        title="Control"
    )


@app.route('/send_unlock', methods=['POST'])
def send_unlock():
    # Ensure user is logged in
    user = session.get("auth_user")
    if not user:
        return redirect("/login")

    password = request.form.get("password")

    global door_status

    # If no password → stay locked
    if not password or password.strip() == "":
        door_status = "Locked"
        return redirect(url_for("control"))

    # Password entered → unlock
    door_status = "Unlocked"

    user_id = user["user_id"]
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            "INSERT INTO logtimes (user_id, action, log_datetime) VALUES (%s, %s, %s)",
            (user_id, "Unlocked", timestamp)
        )
    db.commit()
    db.close()

    # Optional PubNub update
    pubnub.publish().channel("door_updates").message({
        "status": "Unlocked",
        "timestamp": timestamp
    }).sync()

    return redirect(url_for("control"))


@app.route('/send_lock', methods=['POST'])
def send_lock():
    user = session.get("auth_user")
    if not user:
        return redirect("/login")

    global door_status
    door_status = "Locked"

    user_id = user["user_id"]
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            "INSERT INTO logtimes (user_id, action, log_datetime) VALUES (%s, %s, %s)",
            (user_id, "Locked", timestamp)
        )
    db.commit()
    db.close()

    return redirect(url_for("control"))


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

    # -----------------------------
    # Automatically add Google user to DB
    # -----------------------------
    google_user_id = id_info["sub"]
    google_name = id_info.get("name", "Unknown")

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM Users WHERE user_id = %s", (google_user_id,))
        exists = cursor.fetchone()

        if not exists:
            cursor.execute(
                "INSERT INTO Users (user_id, name) VALUES (%s, %s)",
                (google_user_id, google_name)
            )
            db.commit()
    db.close()

    # Save user into session
    session["google_user"] = id_info

    return redirect("/dashboard")

UPLOAD_FOLDER = os.path.join(os.getcwd(), "static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT



# -------------------------------------------------------
# Local run
# -------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)

