from flask import Flask, request, jsonify
import os
from datetime import datetime

app = Flask(__name__)

COMMAND_LOG = "../logs/commands.log"
CMD_FILE = "/etc/bind/commands/cmd.txt"

@app.route('/command', methods=['POST'])
def add_command():
    cmd = request.json.get("cmd", "").strip()
    if not cmd:
        return jsonify({"error": "No command provided"}), 400

    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {cmd}\n"
    with open(COMMAND_LOG, "a") as f:
        f.write(log_entry)

    with open(CMD_FILE, "w") as f:
        f.write(cmd)

    os.system("/usr/local/bin/update-txt.sh")

    return jsonify({"status": "command saved", "cmd": cmd})

@app.route('/command', methods=['GET'])
def get_command():
    if not os.path.exists(CMD_FILE):
        return jsonify({"cmd": ""})
    with open(CMD_FILE) as f:
        cmd = f.read().strip()
    return jsonify({"cmd": cmd})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
