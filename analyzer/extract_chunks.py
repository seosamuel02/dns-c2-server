# 📦 로그 분석기: extract_chunks.py
# 위치: ~/dns-c2/analyzer/extract_chunks.py

import re, os
from datetime import datetime

LOG_FILE = "/root/dns-c2/logs/raw/dns_query.log"
OUT_DIR = "/root/dns-c2/logs/results"
TIMELINE = "/root/dns-c2/logs/timeline.log"

pattern = re.compile(r"CHUNK:(\d+) \| VICTIM:([^.\s]+) \| B64:([A-Za-z0-9+/=]+)")

def write_timeline(victim, chunk):
    with open(TIMELINE, "a") as f:
        f.write(f"[{datetime.utcnow()}] {victim} -> chunk{chunk}\n")

def extract():
    with open(LOG_FILE) as f:
        for line in f:
            match = pattern.search(line)
            if match:
                chunk_num, victim, b64 = match.groups()
                folder = os.path.join(OUT_DIR, victim)
                os.makedirs(folder, exist_ok=True)
                with open(f"{folder}/chunk{chunk_num}.b64", "w") as out:
                    out.write(b64)
                write_timeline(victim, chunk_num)

if __name__ == "__main__":
    extract()
