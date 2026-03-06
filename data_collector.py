import json
import csv
import re
import os

LOG_FILE = "ransomware_detector.log"
OUT_FILE = "ransomware_dataset.csv"

FIELDS = [
    "entropy",
    "cpu",
    "rename",
    "keyword",
    "severity",
    "label"
]

def extract_json(line):
    start = line.find("{")
    end = line.rfind("}")
    if start == -1 or end == -1:
        return None
    try:
        return json.loads(line[start:end+1])
    except:
        return None

def collect():
    write_header = not os.path.exists(OUT_FILE)

    with open(OUT_FILE, "a", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        if write_header:
            writer.writerow(FIELDS)

        with open(LOG_FILE, encoding="utf-8") as log:
            for line in log:
                alert = extract_json(line)
                if not alert:
                    continue

                details = alert.get("details", {})
                desc = alert.get("description", "").lower()

                entropy = details.get("entropy", 0)
                cpu = details.get("cpu", 0)
                rename = 1 if "from" in details else 0
                keyword = 1 if re.search(r"encrypt|crypt|lock", desc) else 0
                severity = 2 if alert.get("severity") == "CRITICAL" else 1

                label = 1 if severity == 2 else 0

                writer.writerow([
                    entropy, cpu, rename, keyword, severity, label
                ])

    print("[+] Dataset updated successfully")

if __name__ == "__main__":
    collect()
