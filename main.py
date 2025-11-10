# main.py
from communication.pubnub_handler import HardwareCommunicator

def unlock_door():
    print("DOOR UNLOCKED! (simulated)")

# Create the communicator
comm = HardwareCommunicator(unlock_door)

# Test it
print("Testing hardware system...")
comm.send_face_image("test_image")
print("Test completed!")