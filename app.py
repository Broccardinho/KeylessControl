from flask import Flask, render_template, request, redirect, url_for
import time
from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub

# Flask App Setup
app = Flask(__name__)

# PubNub Initialization
pnconfig = PNConfiguration()
pnconfig.subscribe_key = "sub-c-764683fa-a709-42d5-a0bb-a9eca9c99146"
pnconfig.publish_key = "pub-c-28efa47f-1d37-4aa8-8cb0-bae3648e5eb2"
pnconfig.uuid = "flask_server"  # unique ID for this server instance
pubnub = PubNub(pnconfig)


# Variables and Functions
logs = []
door_status = "Locked"

def unlock_door():
    """Simulate unlocking the door and publish update to PubNub."""
    global door_status
    door_status = "Unlocked"
    print("DOOR UNLOCKED! (simulated)")

    log_entry = {
        "device_id": "door_hardware_1",
        "status": door_status,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    logs.append(log_entry)

    # Publish event to PubNub channel
    pubnub.publish().channel("door_updates").message(log_entry).sync()

# Flask Routes
@app.route('/', methods=['GET'])
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return redirect(url_for('dashboard'))
    return render_template('login.html', title="Login")

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', logs=logs, title="Dashboard")

@app.route('/control', methods=['GET', 'POST'])
def control():
    global door_status
    if request.method == 'POST':
        unlock_door()
    return render_template('control.html', door_status=door_status, title="Control")

@app.route('/send_unlock', methods=['POST'])
def send_unlock():
    unlock_door()
    return redirect(url_for('control'))

@app.route('/send_face', methods=['POST'])
def send_face():
    print("Test face image sent (simulated)")
    return redirect(url_for('control'))

# -----------------------------
# Run Flask
# -----------------------------
if __name__ == '__main__':
    app.run(debug=True)
#