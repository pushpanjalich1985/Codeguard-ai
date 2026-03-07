# CodeGuard AI - Backend
# Author: Chennuru Pushpanjali
# FOSS Hack 2026

# CodeGuard AI - Backend
# Author: Chennuru Pushpanjali
# FOSS Hack 2026

# CodeGuard AI - Backend
# Author: Chennuru Pushpanjali
# FOSS Hack 2026

import ast
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def check_syntax(code):
    issues = []
    try:
        ast.parse(code)
    except IndentationError as e:
        issues.append({
            "id": "indentation_error",
            "title": "Indentation Error",
            "severity": "critical",
            "line": e.lineno,
            "explanation": f"Line {e.lineno}: Your code has wrong indentation. "
                          f"Python is very strict about spaces and tabs. "
                          f"Problem: {e.msg}",
            "badCode": "if True:\nprint('hello')",
            "goodCode": "if True:\n    print('hello')",
            "steps": [
                "Find line " + str(e.lineno) + " in your code",
                "Make sure it is indented with 4 spaces",
                "Never mix tabs and spaces in Python"
            ]
        })
    except SyntaxError as e:
        issues.append({
            "id": "syntax_error",
            "title": "Syntax Error",
            "severity": "critical",
            "line": e.lineno,
            "explanation": f"Line {e.lineno}: Your code has a syntax error. "
                          f"Python cannot even read this code. "
                          f"Problem: {e.msg}",
            "badCode": "for i in range(10)\n    print(i)",
            "goodCode": "for i in range(10):\n    print(i)",
            "steps": [
                "Go to line " + str(e.lineno) + " in your code",
                "Check for missing colons after if, for, while, def",
                "Check for missing brackets or quotes"
            ]
        })
    return issues

def check_logic(code):
    issues = []
    lines = code.split("\n")

    # Check for hardcoded secrets
    for i, line in enumerate(lines, 1):
        lower = line.lower()
        if any(k in lower for k in
               ["password =", "password=", "secret =",
                "secret=", "api_key =", "api_key="]):
            if '"' in line or "'" in line:
                issues.append({
                    "id": "hardcoded_secret",
                    "title": "Hardcoded Password or Secret Key",
                    "severity": "critical",
                    "line": i,
                    "explanation": f"Line {i}: You have a hardcoded secret in your code. "
                                  f"Anyone who sees your code can steal it instantly.",
                    "badCode": 'password = "mypassword123"',
                    "goodCode": "import os\npassword = os.getenv('PASSWORD')",
                    "steps": [
                        "Remove the hardcoded secret from line " + str(i),
                        "Create a .env file and store it there",
                        "Use os.getenv() to read it safely"
                    ]
                })

    # Check for eval usage
    for i, line in enumerate(lines, 1):
        if "eval(" in line and not line.strip().startswith("#"):
            issues.append({
                "id": "eval_usage",
                "title": "Dangerous eval() Usage",
                "severity": "critical",
                "line": i,
                "explanation": f"Line {i}: eval() runs any string as real code. "
                              f"This is extremely dangerous with user input.",
                "badCode": "result = eval(user_input)",
                "goodCode": "import ast\nresult = ast.literal_eval(user_input)",
                "steps": [
                    "Remove eval() from line " + str(i),
                    "Use ast.literal_eval() instead for safe parsing",
                    "Validate all inputs before processing"
                ]
            })

    # Check for infinite loops
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if (stripped == "while True:" or
            stripped == "while true:" or
            stripped == "while(True):"):
            has_break = any("break" in l for l in lines[i:i+20])
            if not has_break:
                issues.append({
                    "id": "infinite_loop",
                    "title": "Infinite Loop Detected",
                    "severity": "high",
                    "line": i,
                    "explanation": f"Line {i}: This loop has no exit condition "
                                  f"and will run forever, freezing your program.",
                    "badCode": "while True:\n    process_data()",
                    "goodCode": "while True:\n    process_data()\n    if done:\n        break",
                    "steps": [
                        "Find the while True loop at line " + str(i),
                        "Add a break condition inside it",
                        "Test that the loop eventually exits"
                    ]
                })

    # Check for division by zero risk
    for i, line in enumerate(lines, 1):
        if ("/" in line and
            not line.strip().startswith("#") and
            any(v in line for v in
                ["len(", "count", "total", "size", "num"])):
            issues.append({
                "id": "division_risk",
                "title": "Possible Division by Zero",
                "severity": "high",
                "line": i,
                "explanation": f"Line {i}: You are dividing by a variable that "
                              f"could be zero, which crashes your program instantly.",
                "badCode": "average = total / count",
                "goodCode": "if count == 0:\n    average = 0\nelse:\n    average = total / count",
                "steps": [
                    "Find the division on line " + str(i),
                    "Add a check: if the variable could be zero",
                    "Return a safe default value when it is zero"
                ]
            })

    return issues

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

    if language == "python":
        results += check_syntax(code)
        results += check_logic(code)

    return jsonify({
        "language": language,
        "issues": results,
        "total": len(results)
    })

if __name__ == "__main__":
    app.run(debug=True)