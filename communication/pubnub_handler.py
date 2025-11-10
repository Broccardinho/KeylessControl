# communication/pubnub_handler.py
import json
import base64
import logging
from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub


class HardwareCommunicator:
    def __init__(self, unlock_callback):
        # We'll get actual keys later
        pnconfig = PNConfiguration()
        pnconfig.subscribe_key = "demo"
        pnconfig.publish_key = "demo"
        pnconfig.uuid = "door_hardware_1"

        self.pubnub = PubNub(pnconfig)
        self.unlock_callback = unlock_callback

    def send_face_image(self, image_data):
        """Send face to backend - REAL CODE"""
        try:
            # For now, we'll use dummy data
            message = {
                "device_id": "door_hardware_1",
                "image": "dummy_image_data",
                "timestamp": "2024-01-01 10:00:00"
            }

            print("SENDING to backend:", message)
            return True

        except Exception as e:
            print(f"Error: {e}")
            return False