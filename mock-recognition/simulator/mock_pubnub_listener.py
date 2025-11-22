# simulator/mock_pubnub_listener.py
from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub
from pubnub.callbacks import SubscribeCallback
from simulator.mock_recognizer import mock_recognize

class MockListener(SubscribeCallback):
    def __init__(self, respond_callback):
        self.respond_callback = respond_callback

    def message(self, pubnub, message):
        print(" Incoming:", message.message)

        if message.message.get("mock_photo"):
            print(" Mock photo request received")
            self.respond_callback()

class MockPubNubSimulator:
    def __init__(self):
        pnconfig = PNConfiguration()
        pnconfig.subscribe_key = "pub-c-28efa47f-1d37-4aa8-8cb0-bae3648e5eb2"
        pnconfig.publish_key  = "pub-c-28efa47f-1d37-4aa8-8cb0-bae3648e5eb2"
        pnconfig.uuid = "mock_recognition_client"

        self.pubnub = PubNub(pnconfig)

    def start(self):
        listener = MockListener(self.send_result)
        self.pubnub.add_listener(listener)
        self.pubnub.subscribe().channels("face_captures").execute()
        print(" Listening for mock_photo...")

    def send_result(self):
        recognized, user = mock_recognize()

        msg = {
            "recognized": recognized,
            "user": user
        }

        print(" Sending result:", msg)
        self.pubnub.publish() \
            .channel("recognition_results") \
            .message(msg) \
            .sync()
