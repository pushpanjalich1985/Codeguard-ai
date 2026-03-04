# CodeGuard AI - Backend
# Author: Chennuru Pushpanjali
# FOSS Hack 2026

# CodeGuard AI - Backend
# Author: Chennuru Pushpanjali
# FOSS Hack 2026

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return "CodeGuard AI backend is running."

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    code = data.get("code", "")
    language = data.get("language", "python")

    if not code:
        return jsonify({"error": "No code provided"}), 400

    results = []

    # Syntax checking will be added here
    # Security rules will be added here
    # Logic rules will be added here

    return jsonify({
        "language": language,
        "issues": results,
        "total": len(results)
    })

if __name__ == "__main__":
    app.run(debug=True)