import time
import random
import numpy as np
from ddos_detector import DDoSDetector
from utils.signal_relay import SignalRelay

# Dummy signal relay to print log messages
class DummySignal:
    def emit(self, message):
        print("Signal:", message)

class DummySignalRelay:
    def __init__(self):
        self.log_signal = DummySignal()
        self.alert_signal = DummySignal()

def simulate_normal_traffic():
    # Generate values below the detection thresholds
    sent_rate = random.randint(100000, 500000)      # bytes/sec
    recv_rate = random.randint(100000, 500000)
    packet_rate = random.randint(50, 300)
    conn_count = random.randint(10, 80)
    return [sent_rate, recv_rate, packet_rate, conn_count]

def simulate_anomalous_traffic():
    # Generate values that are significantly above normal to trigger anomaly detection
    sent_rate = random.randint(2_000_000, 3_000_000)  # Increase anomaly values
    recv_rate = random.randint(2_000_000, 3_000_000)
    packet_rate = random.randint(1000, 2000)
    conn_count = random.randint(200, 500)
    return [sent_rate, recv_rate, packet_rate, conn_count]

def main():
    dummy_relay = DummySignalRelay()
    detector = DDoSDetector(signal_relay=dummy_relay)
    history = []
    
    # Increase baseline: simulate 30 data points of normal traffic
    print("Simulating normal traffic...")
    for i in range(30):
        data = simulate_normal_traffic()
        history.append(data)
        result = detector.detect_ddos(history)
        if result:
            print(f"Unexpected anomaly detected at point {i+1}: {result}")
        else:
            print(f"Normal traffic point {i+1} processed. History length: {len(history)}")
        time.sleep(0.5)  # Simulate 0.5 sec interval between readings

    # Now inject anomalous data points to simulate a DDoS spike
    print("\nSimulating anomalous traffic...")
    for i in range(5):
        data = simulate_anomalous_traffic()
        history.append(data)
        result = detector.detect_ddos(history)
        if result:
            print(f"Anomaly detected at point {30+i+1}: {result}")
        else:
            print(f"No anomaly detected when there should be one at point {30+i+1}!")
        time.sleep(0.5)

if __name__ == '__main__':
    main()
