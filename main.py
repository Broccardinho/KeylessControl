# main.py
from communication.pubnub_handler import HardwareCommunicator
import time

def unlock_door():
    print("DOOR UNLOCKED! (simulated)")

# Create the communicator
comm = HardwareCommunicator(unlock_door)

# Start listening for unlock commands
print("Step 1: Starting to listen for commands...")
comm.start_listening()

# Send a test message
print("Step 2: Sending test face image...")
comm.send_face_image("test_image")

print("Step 3: Now waiting for unlock commands...")
print("If the backend sends an 'unlock' command, we'll see it here!")

# Keep running to listen for messages
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Stopped by user")

