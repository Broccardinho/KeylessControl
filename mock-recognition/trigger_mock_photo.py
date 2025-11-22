# trigger_mock_photo.py
from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub

pnconfig = PNConfiguration()
pnconfig.subscribe_key = "pub-c-28efa47f-1d37-4aa8-8cb0-bae3648e5eb2"
pnconfig.publish_key  = "pub-c-28efa47f-1d37-4aa8-8cb0-bae3648e5eb2"
pnconfig.uuid = "tester"

pubnub = PubNub(pnconfig)

pubnub.publish() \
    .channel("face_captures") \
    .message({ "mock_photo": True }) \
    .sync()

print("Sent mock_photo request!")
