# communication/pubnub_handler.py
import json
import base64
import logging
from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub
from pubnub.callbacks import SubscribeCallback
from pubnub.enums import PNStatusCategory

class HardwareSubscribeCallback(SubscribeCallback):
    def __init__(self, unlock_callback):
        self.unlock_callback = unlock_callback

    def message(self, pubnub, message):
        try:
            print(f"Received message: {message.message}")
            if message.message.get('command') == 'unlock':
                print("Received UNLOCK command from backend!")
                self.unlock_callback()
        except Exception as e:
            print(f"Error processing message: {e}")

    def status(self, pubnub, status):
        if status.category == PNStatusCategory.PNConnectedCategory:
            print("Connected to PubNub and listening for commands...")
        elif status.category == PNStatusCategory.PNReconnectedCategory:
            print("Reconnected to PubNub")
        elif status.category == PNStatusCategory.PNUnexpectedDisconnectCategory:
            print("Unexpectedly disconnected from PubNub")

class HardwareCommunicator:
    def __init__(self, unlock_callback):
        pnconfig = PNConfiguration()
        pnconfig.subscribe_key = "sub-c-aa5af376-63bb-448c-b9c8-1baadac12d17"
        pnconfig.publish_key = "pub-c-248b0033-e2d8-40e5-b7d4-0123cb0d4ab6"
        pnconfig.uuid = "door_hardware_1"

        self.pubnub = PubNub(pnconfig)
        self.unlock_callback = unlock_callback
        self.callback = HardwareSubscribeCallback(unlock_callback)
        print("PubNub communicator initialized!")

    def start_listening(self):
        #Listen for unlock commands from backend
        self.pubnub.add_listener(self.callback)
        self.pubnub.subscribe().channels(['door_commands']).execute()
        print("Started listening on 'door_commands' channel...")

    def send_face_image(self, image_data):
        #send face to backend
        #REPLACE WITH ACTUAL IMAGE
        try:
            message = {
                "device_id": "door_hardware_1",
                "image": "simulated_face_data",
                "timestamp": "2024-01-01 10:00:00",
                "status": "need_verification"
            }

            envelope = self.pubnub.publish().channel("face_requests").message(message).sync()

            if envelope.status.is_error():
                print(f"FAILED to send: {envelope.status.error_data}")
                return False
            else:
                print(f"Message sent to 'face_requests' channel!")
                return True

        except Exception as e:
            print(f"Error sending message: {e}")
            return False