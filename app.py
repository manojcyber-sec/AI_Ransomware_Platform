import os
import time
import json
import math
import logging
import threading
import psutil
import hashlib
import subprocess
import sys
from datetime import datetime
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

#  LOGGING 
logging.basicConfig(
    filename="ransomware_detector.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

#  FLASK 
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

#  CONFIG 

USER_HOME = os.path.expanduser("~")

DEFAULT_WATCH = [
    os.path.join(USER_HOME, "Downloads"),
      os.path.join(USER_HOME, "OneDrive", "Desktop"),
      os.path.join(USER_HOME, "OneDrive", "Pictures"),

]
SAFE_PROCESSES = ["chrome.exe","explorer.exe","code.exe","python.exe"]

print("Watching folders:")
for path in DEFAULT_WATCH:
    print(" →", path)


EXCLUDED = ["AppData", ".git", "node_modules", "Cache", "Temp"]
RANSOM_NOTES = ["readme","decrypt","recover","ransom","restore"]

ENCRYPTED_EXTS = [
    ".encrypted", ".enc", ".crypt", ".locked", ".lock", ".crypto",
    ".ryuk", ".wanna", ".dark", ".evil", ".pay", ".payme", ".lockbit"
]

#  HELPERS 
def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = 0
        length = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy
    except Exception as e:
        logging.error(f"Entropy calculation error: {str(e)}")
        return 0

def is_encrypted_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    return ext in ENCRYPTED_EXTS or calculate_entropy(file_path) > 7.0

def get_file_hash(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Hash generation error: {str(e)}")
        return None

def excluded(path):
    return any(x.lower() in path.lower() for x in EXCLUDED)

# FILE HANDLER 
class FileHandler(FileSystemEventHandler):
    def __init__(self, detector):
        self.d = detector
        self.executor = ThreadPoolExecutor(max_workers=4)

    def scan_file(self, file_path):
        try:
            if is_encrypted_file(file_path):
                self.d.raise_alert(
                    "ENCRYPTED FILE DETECTED",
                    {"file": file_path},
                    "CRITICAL",
                    "T1486"
                )
            name = os.path.basename(file_path).lower()
            if any(word in name for word in RANSOM_NOTES) and name.endswith((".txt",".html",".hta")):
                self.d.raise_alert(
                    "POSSIBLE RANSOM NOTE",
                    {"file": file_path},
                    "WARNING",
                    "T1486"
                )

            file_hash = get_file_hash(file_path)
            if file_hash:
                if file_hash in self.d.known_hashes:
                    self.d.raise_alert(
                        "DUPLICATE FILE DETECTED",
                        {
                            "file": file_path,
                            "original": self.d.known_hashes[file_hash]
                        },
                        "WARNING",
                        "T1070"
                    )
                else:
                    self.d.known_hashes[file_hash] = file_path
        except Exception as e:
            logging.error(f"Scan error: {str(e)}")

    def on_modified(self, event):
        if event.is_directory or excluded(event.src_path):
            return
        if not os.path.exists(event.src_path):
            return
        self.d.file_events.append(time.time())

        if len(self.d.file_events) > 50:
            if self.d.file_events[-1] - self.d.file_events[0] < 10:
                self.d.raise_alert(
                    "HIGH FILE ACTIVITY",
                    {"count": len(self.d.file_events)},
                    "WARNING",
                    "T1486"
                )
        self.executor.submit(self.scan_file, event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        if os.path.splitext(event.dest_path)[1].lower() in ENCRYPTED_EXTS:
            self.d.raise_alert(
                "SUSPICIOUS FILE RENAME",
                {"from": event.src_path, "to": event.dest_path},
                "CRITICAL",
                "T1486"
            )

#  PROCESS MONITOR 
class ProcessMonitor:
    def __init__(self, detector):
        self.detector = detector
    
    def kill_process(self, pid):
        try:
            p = psutil.Process(pid)
            p.terminate()
            self.detector.raise_alert(
                "PROCESS TERMINATED",
                {"pid": pid},
                "CRITICAL",
                "T1489"
        )
        except Exception as e:
            logging.error(str(e))

    def monitor_processes(self):
        while True:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if proc.name().lower() in SAFE_PROCESSES:
                            continue
                        cmd = " ".join(proc.cmdline()).lower()
                        if any(x in cmd for x in ["encrypt", "crypt", "lock", "ransom"]):
                            self.detector.raise_alert(
                                "SUSPICIOUS PROCESS DETECTED",
                                {
                                    "pid": proc.pid,
                                    "name": proc.name(),
                                    "cmd": cmd
                                },
                                "CRITICAL",
                                "T1059"
                            )
                            self.kill_process(proc.pid)
                        
                        if proc.cpu_percent(interval= 0.5) > 80:
                            self.detector.raise_alert(
                                "HIGH CPU USAGE",
                                {
                                    "pid": proc.pid,
                                    "name": proc.name(),
                                    "cpu": proc.cpu_percent()
                                },
                                "WARNING",
                                "T1070"
                            )
                    except:
                        continue
            except Exception as e:
                logging.error(f"Process monitoring error: {str(e)}")

            time.sleep(1)

#  DETECTOR 
class RansomwareDetector:
    def __init__(self):
        self.running = False
        self.alerts = deque(maxlen=500)
        self.observer = Observer()
        self.watch_paths = list(DEFAULT_WATCH)
        self.known_hashes = {}
        self.file_events = deque(maxlen=1000)
        self.process_monitor = ProcessMonitor(self)

    def start(self):
        if self.running:
            return
        self.running = True

        handler = FileHandler(self)
        watched_any = False
        for p in self.watch_paths:
            if os.path.exists(p):
                try:
                    self.observer.schedule(handler, p, recursive=True)
                    print(f"Watching: {p}")
                    watched_any = True
                except PermissionError:
                    print(f"Permission denied: {p}")
                except Exception as e:
                    print("Skipping:", p, "Error:", str(e))
        if watched_any:
            try:
                self.observer.start()
                print("Monitoring started.")
            except Exception as e:
                print("Failed to start monitoring:", str(e))
                return
        else:
            print("NO folders to watch. Please add valid paths.")
            return

        threading.Thread(
            target=self.process_monitor.monitor_processes,
            daemon=True
        ).start()

        self.emit_status()

    def stop(self):
        self.running = False
        self.observer.stop()
        self.observer.join()
        self.emit_status()

    def raise_alert(self, description, details, severity, mitre):
        alert = {
            "time": datetime.now().isoformat(),
            "description": description,
            "details": details,
            "severity": severity,
            "mitre": mitre
        }
        self.alerts.append(alert)
        socketio.emit("new_alert", alert)
        socketio.emit("dashboard_update", alert)
        logging.warning(json.dumps(alert))

    def emit_status(self):
        socketio.emit("status_update", {
            "running": self.running,
            "alerts": len(self.alerts),
            "folders": self.watch_paths
        })

detector = RansomwareDetector()

# ROUTES 
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def status():
    return jsonify({"running": detector.running})

@app.route("/api/control", methods=["POST"])
def control():
    action = request.json.get("action")
    if action == "start":
        detector.start()
    elif action == "stop":
        detector.stop()
    return jsonify({"running": detector.running})

@app.route("/api/folders", methods=["POST"])
def folders():
    detector.watch_paths = request.json.get("folders", [])
    return {"ok": True}

@socketio.on("connect")
def connect():
    detector.emit_status()

def start_services():
    print("\n🚀 Starting Background Services...\n")

    # start data collector
    subprocess.Popen([sys.executable, "data_collector.py"])
    print("[+] data_collector.py started")

    # train model if missing
    if not os.path.exists("ransomware_model.pkl"):
        print("[*] Training model...")
        subprocess.run([sys.executable, "train_models.py"])

    # start AI engine
    subprocess.Popen([sys.executable, "ai_engine.py"])
    print("[+] ai_engine.py started\n")


#  MAIN 
import os

if __name__ == "__main__":

    running_on_render = os.environ.get("RENDER") == "true"

    if not running_on_render:
        print("Running locally → Starting full system")
        start_services()
    else:
        print("Running on Render → Dashboard mode only")

    port = int(os.environ.get("PORT", 10000))
    socketio.run(app, host="0.0.0.0", port=port, allow_unsafe_werkzeug=True)
