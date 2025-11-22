# run_simulator.py
from simulator.mock_pubnub_listener import MockPubNubSimulator

sim = MockPubNubSimulator()
sim.start()

print(" Mock Face Recognition Simulator Running")
print("Waiting for { 'mock_photo': true } ...")

while True:
    pass
