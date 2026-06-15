import os
import csv
import time
import threading
from datetime import datetime
from app.ml.model import classifier
from app.ai.engine import generate_threat_summary
from app.store.alert_store import save_alert, SessionLocal

class TrafficSimulator:
    def __init__(self, data_path="data/CICIDS2017_sample.csv"):
        self.data_path = data_path
        self._thread = None
        self._stop_event = threading.Event()
        self.ai_cache = {}  # In-memory cache to prevent Gemini rate limit errors
        
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            print("Simulator is already running.")
            return False
            
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_simulation, daemon=True)
        self._thread.start()
        print("Simulator thread started.")
        return True
        
    def stop(self):
        if self._thread is None or not self._thread.is_alive():
            print("Simulator is not running.")
            return False
            
        self._stop_event.set()
        self._thread.join(timeout=2.0)
        self._thread = None
        print("Simulator thread stopped.")
        return True
        
    def is_running(self):
        return self._thread is not None and self._thread.is_alive()
        
    def _run_simulation(self):
        # Fallback if running inside backend folder or custom directories
        if not os.path.exists(self.data_path):
            alt_path = os.path.join("..", self.data_path)
            if os.path.exists(alt_path):
                self.data_path = alt_path

        if not os.path.exists(self.data_path):
            print(f"Simulator error: dataset file not found at {self.data_path}")
            return
            
        db = SessionLocal()
        try:
            while not self._stop_event.is_set():
                with open(self.data_path, mode="r") as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        if self._stop_event.is_set():
                            break
                            
                        # Extract metadata fields
                        src_ip = row["Source IP"]
                        src_port = int(row["Source Port"])
                        dst_ip = row["Destination IP"]
                        dst_port = int(row["Destination Port"])
                        true_label = row["Label"]
                        
                        # Pack feature variables for the ML classifier
                        features = {}
                        for key, val in row.items():
                            if key not in ["Timestamp", "Source IP", "Source Port", "Destination IP", "Label"]:
                                features[key] = float(val)
                        
                        # Add Label mapping to features dictionary for model fallback mode
                        features["Label"] = true_label
                        
                        # Classify flow using trained RandomForest
                        result = classifier.predict(features)
                        attack_type = result["attack_type"]
                        
                        # Only log attacks (non-BENIGN classifications)
                        if attack_type != "BENIGN":
                            confidence = result["confidence"]
                            severity = result["severity"]
                            
                            # Cache-based AI Threat Summary generation to manage API rate limit
                            if attack_type not in self.ai_cache:
                                print(f"Calling Gemini API to generate threat report for: {attack_type}...")
                                summary = generate_threat_summary(attack_type, confidence, severity, features)
                                self.ai_cache[attack_type] = summary
                            else:
                                summary = self.ai_cache[attack_type]
                                
                            alert_data = {
                                "src_ip": src_ip,
                                "src_port": src_port,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "attack_type": attack_type,
                                "confidence": confidence,
                                "severity": severity,
                                "features": features,
                                "ai_summary": summary
                            }
                            
                            try:
                                save_alert(db, alert_data)
                                print(f"Alert Saved: [{severity}] {attack_type} from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                            except Exception as db_err:
                                print(f"Error saving alert to DB: {db_err}")
                                
                            # Wait between alert triggers to simulate real-time logging
                            time.sleep(1.0)
                            
        except Exception as e:
            print(f"Simulator exception in thread: {e}")
        finally:
            db.close()

# Global simulator manager instance
simulator = TrafficSimulator()
