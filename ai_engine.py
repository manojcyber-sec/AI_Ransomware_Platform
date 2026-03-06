import json
import time
import os
import joblib
import pandas as pd
import socketio
import psutil
import subprocess
from datetime import datetime

# AUTO-SHUTDOWN FLAG 
system_shutdown_triggered = False

LOG_FILE = "ransomware_detector.log"
MODEL_FILE = "ransomware_model.pkl"

# PROTECTED FOLDERS 
PROTECTED_FOLDERS = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Downloads"),
]

folders_locked = False

# SOCKET.IO CLIENT 
sio = socketio.Client(reconnection=True)
def connect_to_socket():
    while not sio.connected:
        try:
            sio.connect("http://localhost:5000")
            print("🔗 Connected to Flask dashboard")
        except Exception:
            print("⏳ Waiting for Flask server...")
            time.sleep(2)
@sio.event
def disconnect():
    print(" socket disconnected.Reconnecting...")
    connect_to_socket()
connect_to_socket()

# LOAD MODEL
try:
    model = joblib.load(MODEL_FILE)
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"⚠️ Model loading failed: {e}")
    exit(1)

# JSON SAFE PARSER 
def extract_json(line):
    start = line.find("{")
    end = line.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(line[start:end + 1])
    except:
        return None

# FEATURE EXTRACTION
def extract_features(alert):
    details = alert.get("details", {})
    desc = alert.get("description", "").lower()

    return pd.DataFrame([{
        "entropy": details.get("entropy", 0),
        "cpu": details.get("cpu", 0),
        "rename": 1 if "from" in details else 0,
        "keyword": 1 if any(k in desc for k in ["encrypt", "crypt", "lock"]) else 0
    }])

# RISK LABEL
def risk_label(score):
    if score < 0.3:
        return "NORMAL"
    elif score < 0.6:
        return "SUSPICIOUS"
    elif score < 0.8:
        return "HIGH RISK"
    else:
        return "RANSOMWARE"

# AUTO-KILL PROCESS 
def kill_process(details):
    pid = details.get("pid")
    if not pid:
        return
    try:
        process = psutil.Process(pid)
        process.terminate()
        print(f"🔴 Process killed: PID {pid}")
    except Exception as e:
        print(f"⚠️ Kill failed: {e}")

# LOCK / UNLOCK FOLDERS 
def lock_folders():
    global folders_locked
    if folders_locked:
        return

    for folder in PROTECTED_FOLDERS:
        if os.path.exists(folder):
            subprocess.run(
                ["icacls", folder, "/deny", "Everyone:(W)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

    folders_locked = True
    print("🔐 Folders LOCKED")

def unlock_folders():
    global folders_locked
    if not folders_locked:
        return

    for folder in PROTECTED_FOLDERS:
        if os.path.exists(folder):
            subprocess.run(
                ["icacls", folder, "/remove:d", "Everyone"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

    folders_locked = False
    print("🔓 Folders UNLOCKED")

#  MAIN MONITOR LOOP 
def monitor():
    global system_shutdown_triggered

    print("🤖 AI Engine running...")

    if not os.path.exists(LOG_FILE):
        print("⚠️ Log file not found!")
        return

    with open(LOG_FILE, encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue

            alert = extract_json(line)
            if not alert:
                continue

            X = extract_features(alert)

            # SAFE probability handling
            if hasattr(model, "predict_proba"):
                prob = model.predict_proba(X)[0][1]
            else:
                prob = float(model.predict(X)[0])

            label = risk_label(prob)

            print(f"[AI] Risk={prob:.2f} → {label}")

            file_path = alert.get("details", {}).get("file")
            folder_path = None
            if file_path and isinstance(file_path, str):
                folder_path = os.path.dirname(file_path)

            # SEND AI RISK 
            sio.emit("ai_risk", {
                "score": float(prob),
                "label": label,
                "file": file_path,
                "folder": folder_path,
                "time": datetime.now().isoformat()
            })

            # SEND GRAPH DATA 
            sio.emit("ai_risk_timeline_update", {
                "time": datetime.now().strftime("%H:%M:%S"),
                "risk": float(prob)
            })

            #  AUTO RESPONSE 
            if prob >= 0.85:
                kill_process(alert.get("details", {}))
                lock_folders()
                if sio.connected:
                    sio.emit("ai_flash_update", {"state": "ON"})
                # CRITICAL LEVEL → ALERT ONLY (NO SHUTDOWN)
                if prob >= 0.95:
                    print("🚨 CRITICAL THREAT DETECTED")

                    sio.emit("critical_alert", {
                        "message": "Critical ransomware behaviour detected!",
                        "risk": float(prob),
                        "time": datetime.now().isoformat()
                })

            else:
                unlock_folders()
                sio.emit("ai_flash_update", {"state": "OFF"})

#  ENTRY 
if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped manually")
        unlock_folders()
