from flask import Flask, render_template, request, redirect, url_for
import time
import pymysql
from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub

# ---------------------------------
# Flask App Setup
# ---------------------------------
app = Flask(__name__)

# ---------------------------------
# MySQL Database Connection
# ---------------------------------
db = pymysql.connect(
    host="localhost",
    user="root",
    password="YOUR_MYSQL_PASSWORD",
    database="keylessdb",
    cursorclass=pymysql.cursors.DictCursor
)

# ---------------------------------
# PubNub Initialization
# ---------------------------------
pnconfig = PNConfiguration()
pnconfig.subscribe_key = "sub-c-764683fa-a709-42d5-a0bb-a9eca9c99146"
pnconfig.publish_key = "pub-c-28efa47f-1d37-4aa8-8cb0-bae3648e5eb2"
pnconfig.uuid = "flask_server"
pubnub = PubNub(pnconfig)

door_status = "Locked"


# ---------------------------------
# Helper Functions
# ---------------------------------
def log_unlock_event(user_id=None):
    """Logs a door unlock event into MySQL and publishes it via PubNub."""
    global door_status
    door_status = "Unlocked"

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    # Insert into LogTimes table
    with db.cursor() as cursor:
        cursor.execute(
            "INSERT INTO LogTimes (user_id, log_datetime) VALUES (%s, %s)",
            (user_id, timestamp)
        )
        db.commit()

    # Prepare event for PubNub
    log_entry = {
        "device_id": "door_hardware_1",
        "status": door_status,
        "timestamp": timestamp
    }

    # Publish event to PubNub channel
    pubnub.publish().channel("door_updates").message(log_entry).sync()


def get_logs():
    """Fetch log entries from MySQL for the dashboard."""
    with db.cursor() as cursor:
        cursor.execute("""
            SELECT LogTimes.log_datetime, Users.name
            FROM LogTimes
            LEFT JOIN Users ON Users.user_id = LogTimes.user_id
            ORDER BY LogTimes.log_datetime DESC;
        """)
        return cursor.fetchall()


# ---------------------------------
# Flask Routes
# ---------------------------------
@app.route('/', methods=['GET'])
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # In a real system: verify username/password
        return redirect(url_for('dashboard'))

    return render_template('login.html', title="Login")


@app.route('/dashboard')
def dashboard():
    logs = get_logs()
    return render_template('dashboard.html', logs=logs, title="Dashboard")


@app.route('/control', methods=['GET', 'POST'])
def control():
    global door_status
    if request.method == 'POST':
        log_unlock_event()    # default: no user_id
    return render_template('control.html', door_status=door_status, title="Control")


@app.route('/send_unlock', methods=['POST'])
def send_unlock():
    log_unlock_event()
    return redirect(url_for('control'))


@app.route('/send_face', methods=['POST'])
def send_face():
    print("Test face image sent (simulated)")
    return redirect(url_for('control'))


# ---------------------------------
# Run Flask (if local)
# ---------------------------------
if __name__ == '__main__':
    app.run(debug=True)
