import numpy as np
import time
from typing import List, Optional, Set, Dict, Any
from collections import deque
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from utils.signal_relay import SignalRelay
from utils.constants import (
    ISOLATION_FOREST_CONTAMINATION,
    SVM_NU,
    LOF_NEIGHBORS,
    ANOMALY_THRESHOLD,
    DETECTION_MODES,
    BASELINE_WINDOW_SIZE,
    UPDATE_INTERVAL,
    MIN_SAMPLES_FOR_ML,
    ADAPTIVE_THRESHOLD_CONFIG,
    LOG_LEVELS
)
from ip_analyzer import IPAnalyzer

class DDoSDetector:
    """Enhanced DDoS detection with adaptive thresholds and multiple detection modes."""
    
    def __init__(self, signal_relay: SignalRelay):
        self.signal_relay = signal_relay
        self.anomalies = []
        self.anomaly_count = 0
        self.running = False
        self.blocked_ips: Set[str] = set()
        
        # Detection mode configuration
        self.detection_mode = DETECTION_MODES["HYBRID"]
        self.required_votes = ANOMALY_THRESHOLD
        
        # Initialize baseline tracking
        self.baseline_window = deque(maxlen=BASELINE_WINDOW_SIZE)
        self.last_baseline_update = time.time()
        self.baseline_stats = {
            'sent_mean': 0, 'sent_std': 0,
            'recv_mean': 0, 'recv_std': 0,
            'packet_mean': 0, 'packet_std': 0,
            'conn_mean': 0, 'conn_std': 0
        }
        
        # Initialize ML models with partial_fit capability
        self.initialize_ml_models()
        
        # Diagnostic information
        self.last_detection_info = {}
        
    def initialize_ml_models(self):
        """Initialize ML models with incremental learning capability where possible."""
        self.iso_forest = IsolationForest(
            contamination=ISOLATION_FOREST_CONTAMINATION,
            warm_start=True  # Enable incremental learning
        )
        self.svm_detector = OneClassSVM(nu=SVM_NU)
        self.lof_detector = LocalOutlierFactor(
            n_neighbors=LOF_NEIGHBORS,
            novelty=True
        )
        
    def update_baseline_stats(self, new_data: np.ndarray):
        """Update baseline statistics using exponential moving average."""
        if len(self.baseline_window) == 0:
            self.baseline_stats = {
                'sent_mean': new_data[0], 'sent_std': 0,
                'recv_mean': new_data[1], 'recv_std': 0,
                'packet_mean': new_data[2], 'packet_std': 0,
                'conn_mean': new_data[3], 'conn_std': 0
            }
        else:
            lr = ADAPTIVE_THRESHOLD_CONFIG["LEARNING_RATE"]
            for i, key in enumerate(['sent', 'recv', 'packet', 'conn']):
                # Update mean
                old_mean = self.baseline_stats[f'{key}_mean']
                new_mean = (1 - lr) * old_mean + lr * new_data[i]
                
                # Update standard deviation
                old_std = self.baseline_stats[f'{key}_std']
                new_std = (1 - lr) * old_std + lr * abs(new_data[i] - old_mean)
                
                self.baseline_stats[f'{key}_mean'] = new_mean
                self.baseline_stats[f'{key}_std'] = new_std
        
        self.baseline_window.append(new_data)
        self.last_baseline_update = time.time()
        
    def get_adaptive_thresholds(self) -> Dict[str, float]:
        """Calculate adaptive thresholds based on current baseline stats."""
        multiplier = ADAPTIVE_THRESHOLD_CONFIG["BASELINE_MULTIPLIER"]
        return {
            'sent': max(
                self.baseline_stats['sent_mean'] + multiplier * self.baseline_stats['sent_std'],
                ADAPTIVE_THRESHOLD_CONFIG["MIN_THRESHOLD_BYTES"]
            ),
            'recv': max(
                self.baseline_stats['recv_mean'] + multiplier * self.baseline_stats['recv_std'],
                ADAPTIVE_THRESHOLD_CONFIG["MIN_THRESHOLD_BYTES"]
            ),
            'packet': max(
                self.baseline_stats['packet_mean'] + multiplier * self.baseline_stats['packet_std'],
                ADAPTIVE_THRESHOLD_CONFIG["MIN_THRESHOLD_PACKETS"]
            ),
            'conn': max(
                self.baseline_stats['conn_mean'] + multiplier * self.baseline_stats['conn_std'],
                ADAPTIVE_THRESHOLD_CONFIG["MIN_THRESHOLD_CONNS"]
            )
        }
        
    def basic_threshold_check(self, data_point: np.ndarray) -> bool:
        """Perform basic threshold-based anomaly detection."""
        thresholds = self.get_adaptive_thresholds()
        return any([
            data_point[0] > thresholds['sent'],
            data_point[1] > thresholds['recv'],
            data_point[2] > thresholds['packet'],
            data_point[3] > thresholds['conn']
        ])
        
    def ml_detection(self, data_point: np.ndarray) -> int:
        """Perform ML-based detection and return number of models detecting anomaly."""
        # Get predictions for the latest data point
        latest_point = data_point.reshape(1, -1)
        
        try:
            iso_pred = self.iso_forest.predict(latest_point)[0]
            svm_pred = self.svm_detector.predict(latest_point)[0]
            lof_pred = self.lof_detector.predict(latest_point)[0]
            
            return sum(1 for pred in [iso_pred, svm_pred, lof_pred] if pred == -1)
        except Exception as e:
            self.log_message(f"ML detection error: {str(e)}", LOG_LEVELS["ERROR"])
            return 0
            
    def detect_ddos(self, history: List[List[float]]) -> Optional[List[float]]:
        """Enhanced DDoS detection with multiple modes and adaptive thresholds."""
        if len(history) < 10:
            return None
            
        try:
            X = np.array(history)
            latest_data = X[-1]
            
            # Update baseline statistics
            self.update_baseline_stats(latest_data)
            
            # Store detection info for diagnostics
            self.last_detection_info = {
                'timestamp': datetime.now().isoformat(),
                'data_point': latest_data.tolist(),
                'thresholds': self.get_adaptive_thresholds(),
                'baseline_stats': self.baseline_stats.copy()
            }
            
            is_anomaly = False
            if self.detection_mode in [DETECTION_MODES["BASIC"], DETECTION_MODES["HYBRID"]]:
                is_anomaly = self.basic_threshold_check(latest_data)
                
            if not is_anomaly and self.detection_mode in [DETECTION_MODES["ML"], DETECTION_MODES["HYBRID"]]:
                if len(self.baseline_window) >= MIN_SAMPLES_FOR_ML:
                    # Incrementally update models
                    if len(X) > 1:  # Only update if we have more than one sample
                        try:
                            self.iso_forest.fit(X)
                            self.svm_detector.fit(X)
                            self.lof_detector.fit(X)
                        except Exception as e:
                            self.log_message(f"Model update error: {str(e)}", LOG_LEVELS["ERROR"])
                    
                    # Check for anomaly using ML models
                    anomaly_votes = self.ml_detection(latest_data)
                    is_anomaly = anomaly_votes >= self.required_votes
                    
                    # Update detection info
                    self.last_detection_info['ml_votes'] = anomaly_votes
            
            if is_anomaly:
                self.log_detection(latest_data)
                return latest_data.tolist()
                
        except Exception as e:
            self.log_message(f"Error in DDoS detection: {str(e)}", LOG_LEVELS["ERROR"])
            
        return None
        
    def log_detection(self, data_point: np.ndarray):
        """Enhanced logging for anomaly detections."""
        detection_info = {
            'timestamp': self.last_detection_info['timestamp'],
            'sent_rate': f"{data_point[0]:.2f} B/s",
            'recv_rate': f"{data_point[1]:.2f} B/s",
            'packet_rate': f"{data_point[2]:.2f} packets/s",
            'conn_count': int(data_point[3]),
            'thresholds': self.last_detection_info['thresholds'],
            'baseline': {
                k: f"{v:.2f}" for k, v in self.baseline_stats.items()
            }
        }
        
        if 'ml_votes' in self.last_detection_info:
            detection_info['ml_votes'] = self.last_detection_info['ml_votes']
            
        self.log_message(
            f"Anomaly detected:\n{detection_info}",
            LOG_LEVELS["WARNING"]
        )
        
    def log_message(self, message: str, level: int):
        """Log a message with the specified level."""
        self.signal_relay.log_signal.emit(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")
        
    def set_detection_mode(self, mode: str):
        """Set the detection mode."""
        if mode in DETECTION_MODES.values():
            self.detection_mode = mode
            self.log_message(f"Detection mode changed to: {mode}", LOG_LEVELS["INFO"])
        
    def set_sensitivity(self, required_votes: int):
        """Set the number of required votes for ML detection."""
        self.required_votes = max(1, min(3, required_votes))
        self.log_message(f"Detection sensitivity set to {self.required_votes} votes", LOG_LEVELS["INFO"])
        
    def reset(self):
        """Reset the detector state."""
        self.baseline_window.clear()
        self.anomalies = []
        self.anomaly_count = 0
        self.blocked_ips.clear()
        self.last_detection_info = {}
        self.baseline_stats = {k: 0 for k in self.baseline_stats}
        self.initialize_ml_models()
        self.log_message("Detector state reset", LOG_LEVELS["INFO"])

    def detect_and_block_suspicious_ips(self) -> List[str]:
        """Detect and block suspicious IPs."""
        import psutil
        connections = psutil.net_connections()
        suspicious_ips = set()

        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                remote_ip = conn.raddr.ip

                if IPAnalyzer.is_private_ip(remote_ip):
                    continue

                if IPAnalyzer.get_ip_reputation(remote_ip):
                    suspicious_ips.add(remote_ip)

        # Block suspicious IPs
        for ip in suspicious_ips:
            if ip not in self.blocked_ips:
                error = IPAnalyzer.block_ip(ip)
                if error:
                    self.signal_relay.log_signal.emit(f"❌ {error}")
                self.blocked_ips.add(ip)

        if suspicious_ips:
            blocking_msg = f"🚫 Blocked {len(suspicious_ips)} suspicious IPs: {', '.join(suspicious_ips)}"
            self.signal_relay.log_signal.emit(blocking_msg)
            self.signal_relay.alert_signal.emit(blocking_msg)
            return list(suspicious_ips)

        return []

    def log_anomalies(self):
        """Log detected anomalies to file."""
        with open("ddos_logs.txt", "a") as log_file:
            for anomaly in self.anomalies:
                log_file.write(
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')} - "
                    f"Anomaly Detected: {anomaly}\n"
                ) 