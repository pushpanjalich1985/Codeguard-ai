# CodeGuard AI - Backend
# Author: Chennuru Pushpanjali
# FOSS Hack 2026

import ast
import re
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def check_syntax(code):
    issues = []
    lines = code.split("\n")
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
            "badCode": lines[e.lineno - 1].rstrip() if e.lineno and e.lineno <= len(lines) else "if True:\nprint('hello')",
            "goodCode": "    " + lines[e.lineno - 1].strip() if e.lineno and e.lineno <= len(lines) else "if True:\n    print('hello')",
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
            "badCode": lines[e.lineno - 1].rstrip() if e.lineno and e.lineno <= len(lines) else "for i in range(10)\n    print(i)",
            "goodCode": "# Fix the syntax error on this line\n" + lines[e.lineno - 1].rstrip(),
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

    C_PATTERNS = ["printf(", "scanf(", "int ", "float ", "void ", "#include", "->", "::"]
    if any(p in code for p in C_PATTERNS):
        issues.append({
            "id": "wrong_language",
            "title": "This looks like C/C++ code, not Python",
            "severity": "critical",
            "line": 1,
            "explanation": "Line 1: This code appears to be C or C++, not Python. Running C code in a Python environment will fail completely.",
            "badCode": 'int x = 10;\nprintf("hello");',
            "goodCode": 'x = 10\nprint("hello")',
            "steps": [
                "Check that you selected the correct language",
                "If writing Python, remove C-style syntax",
                "If writing C, use a C compiler instead"
            ]
        })


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

    # Check for empty except blocks
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("except ") and stripped != "except:":
            if i < len(lines):
                next_line = lines[i].strip() if i < len(lines) else ""
                if next_line == "pass":
                    issues.append({
                        "id": "empty_except",
                        "title": "Empty except Block with pass",
                        "severity": "medium",
                        "line": i,
                        "explanation": f"Line {i}: You are silently ignoring "
                                      f"errors with pass. This hides bugs and "
                                      f"makes debugging nearly impossible.",
                        "badCode": "try:\n    do_something()\nexcept:\n    pass",
                        "goodCode": "try:\n    do_something()\nexcept Exception as e:\n    print('Error:', e)",
                        "steps": [
                            "Find the except block at line " + str(i),
                            "Replace pass with actual error handling",
                            "At minimum print the error so you know it happened"
                        ]
                    })

    # Check for missing return in functions
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("def ") and stripped.endswith(":"):
            VOID_FUNCS = {"__init__", "__del__", "__str__", "__repr__",
                          "__enter__", "__exit__", "setUp", "tearDown", "main"}
            try:
                func_name = stripped[4:stripped.index("(")].strip()
            except ValueError:
                continue
            if func_name in VOID_FUNCS:
                continue
            func_lines = lines[i:i+20]
            has_return = any("return" in l for l in func_lines)
            if not has_return:
                issues.append({
                    "id": "no_return",
                    "title": "Function Has No Return Statement",
                    "severity": "low",
                    "line": i,
                    "explanation": f"Line {i}: This function does not return "
                                  f"anything. If you expect a result from it, "
                                  f"it will return None silently.",
                    "badCode": "def calculate(x, y):\n    result = x + y",
                    "goodCode": "def calculate(x, y):\n    result = x + y\n    return result",
                    "steps": [
                        "Find the function at line " + str(i),
                        "Add a return statement at the end",
                        "Make sure it returns the value you need"
                    ]
                })

    # Check for SQL injection
    for i, line in enumerate(lines, 1):
        if (("SELECT" in line or "INSERT" in line or
             "DELETE" in line or "UPDATE" in line) and
            ("+" in line or "%" in line or ".format(" in line)):
            issues.append({
                "id": "sql_injection_backend",
                "title": "SQL Injection Risk in Query",
                "severity": "critical",
                "line": i,
                "explanation": f"Line {i}: You are building a SQL query using "
                              f"string concatenation. Attackers can inject "
                              f"malicious SQL and steal your database.",
                "badCode": 'query = "SELECT * FROM users WHERE id = " + user_id',
                "goodCode": 'query = "SELECT * FROM users WHERE id = ?"\ncursor.execute(query, [user_id])',
                "steps": [
                    "Find the SQL query on line " + str(i),
                    "Replace string concatenation with ? placeholders",
                    "Pass values separately to cursor.execute()"
                ]
            })

    # Check for unused imports
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            if "import " in stripped:
                parts = stripped.split("import ")
                if len(parts) > 1:
                    imported = parts[1].strip().split(" as ")[0].strip()
                    imported = imported.split(",")[0].strip()
                    rest_of_code = "\n".join(lines[i:])
                    if imported and imported not in rest_of_code:
                        issues.append({
                            "id": "unused_import",
                            "title": "Possibly Unused Import",
                            "severity": "low",
                            "line": i,
                            "explanation": f"Line {i}: You imported '{imported}' "
                                          f"but it does not appear to be used "
                                          f"anywhere in your code.",
                            "badCode": f"import {imported}\n# never used below",
                            "goodCode": "# Remove unused imports\n# Only import what you actually use",
                            "steps": [
                                "Check if " + imported + " is actually used",
                                "Remove the import if it is not needed",
                                "Clean imports make code easier to read"
                            ]
                        })

    # Check for print statements left in code (debug leftovers)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("print(") and not line.strip().startswith("#"):
            issues.append({
                "id": "debug_print",
                "title": "Debug print() Left in Code",
                "severity": "low",
                "line": i,
                "explanation": f"Line {i}: You left a print() statement in your code. "
                              f"In production, use logging instead of print().",
                "badCode": 'print("user data:", user)',
                "goodCode": "import logging\nlogging.info('user data: %s', user)",
                "steps": [
                    "Find the print() on line " + str(i),
                    "Replace it with logging.info() or logging.debug()",
                    "Set up logging at the top: logging.basicConfig(level=logging.INFO)"
                ]
            })

    # Check for mutable default arguments
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("def ") and ("=[]" in stripped or "= []" in stripped or
           "={}" in stripped or "= {}" in stripped):
            issues.append({
                "id": "mutable_default_arg",
                "title": "Mutable Default Argument",
                "severity": "high",
                "line": i,
                "explanation": f"Line {i}: Using a list or dict as a default argument "
                              f"is a classic Python bug. The same object is shared "
                              f"across all function calls.",
                "badCode": "def add_item(item, items=[]):\n    items.append(item)\n    return items",
                "goodCode": "def add_item(item, items=None):\n    if items is None:\n        items = []\n    items.append(item)\n    return items",
                "steps": [
                    "Find the function at line " + str(i),
                    "Replace the default [] or {} with None",
                    "Inside the function, set items = [] if items is None"
                ]
            })

    # Check for bare except (catches everything including KeyboardInterrupt)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped == "except:":
            issues.append({
                "id": "bare_except",
                "title": "Bare except Clause",
                "severity": "high",
                "line": i,
                "explanation": f"Line {i}: A bare except: catches every possible error, "
                              f"including system exits and keyboard interrupts. "
                              f"This can hide serious problems.",
                "badCode": "try:\n    risky()\nexcept:\n    pass",
                "goodCode": "try:\n    risky()\nexcept Exception as e:\n    print('Error:', e)",
                "steps": [
                    "Find the bare except on line " + str(i),
                    "Change it to: except Exception as e:",
                    "Log or handle the error properly"
                ]
            })

    # Check for open() without context manager (with statement)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if re.search(r'\bopen\(', stripped) and not stripped.startswith("with") and not stripped.startswith("#"):
            issues.append({
                "id": "file_not_closed",
                "title": "File Opened Without Context Manager",
                "severity": "high",
                "line": i,
                "explanation": f"Line {i}: You opened a file without using 'with'. "
                              f"If an error occurs, the file will never be closed, "
                              f"causing memory leaks.",
                "badCode": 'f = open("data.txt", "r")\ndata = f.read()',
                "goodCode": 'with open("data.txt", "r") as f:\n    data = f.read()',
                "steps": [
                    "Find the open() call on line " + str(i),
                    "Wrap it in a with statement",
                    "The file will close automatically even if errors occur"
                ]
            })

    # Check for == None instead of is None
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if "== None" in stripped and not stripped.startswith("#"):
            issues.append({
                "id": "equality_none",
                "title": "Use 'is None' Instead of '== None'",
                "severity": "low",
                "line": i,
                "explanation": f"Line {i}: Comparing to None with == can give wrong "
                              f"results if an object overrides __eq__. "
                              f"Always use 'is None'.",
                "badCode": "if result == None:\n    print('empty')",
                "goodCode": "if result is None:\n    print('empty')",
                "steps": [
                    "Find '== None' on line " + str(i),
                    "Replace it with 'is None'",
                    "Same fix for '!= None' → use 'is not None'"
                ]
            })
        
     # Check for == True / == False comparisons
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if ("== True" in stripped or "== False" in stripped) and not stripped.startswith("#"):
            issues.append({
                "id": "bool_comparison",
                "title": "Unnecessary Boolean Comparison",
                "severity": "low",
                "line": i,
                "explanation": f"Line {i}: Comparing directly to True or False is "
                              f"unnecessary and considered bad practice in Python.",
                "badCode": "if is_valid == True:\n    do_something()",
                "goodCode": "if is_valid:\n    do_something()",
                "steps": [
                    "Find the boolean comparison on line " + str(i),
                    "Replace 'if x == True:' with just 'if x:'",
                    "Replace 'if x == False:' with 'if not x:'"
                ]
            })

    # Check for var usage in JavaScript
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("var ") and not stripped.startswith("#"):
            issues.append({
                "id": "var_usage",
                "title": "Outdated 'var' Keyword Used",
                "severity": "medium",
                "line": i,
                "explanation": f"Line {i}: 'var' is outdated JavaScript. It has "
                              f"confusing scope rules and can cause hard-to-find bugs. "
                              f"Use 'let' or 'const' instead.",
                "badCode": "var username = 'john'\nvar count = 0",
                "goodCode": "const username = 'john'\nlet count = 0",
                "steps": [
                    "Find 'var' on line " + str(i),
                    "Replace with 'const' if the value never changes",
                    "Replace with 'let' if the value will be reassigned"
                ]
            })

    # Check for input() used directly in math without int()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if "input(" in stripped and not stripped.startswith("#"):
            if any(op in stripped for op in [" + ", " - ", " * ", " / ", " > ", " < ", " >= ", " <= "]):
                issues.append({
                    "id": "input_no_cast",
                    "title": "input() Used in Math Without int()",
                    "severity": "high",
                    "line": i,
                    "explanation": f"Line {i}: input() always returns a string. "
                                  f"Using it directly in math or comparisons will "
                                  f"crash your program with a TypeError.",
                    "badCode": "age = input('Enter age: ')\nif age > 18:",
                    "goodCode": "age = int(input('Enter age: '))\nif age > 18:",
                    "steps": [
                        "Find input() on line " + str(i),
                        "Wrap it with int() for numbers: int(input(...))",
                        "Or float() if you need decimal numbers"
                    ]
                })

    return issues

@app.route("/")
def home():
    return "CodeGuard AI backend is running."

@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0"})

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    code = data.get("code", "")
    language = data.get("language", "python")

    if not code:
        return jsonify({"error": "No code provided"}), 400
    
    if len(code) > 10000:
        return jsonify({"error": "Code too long. Max 10,000 characters."}), 400

    results = []

    if language == "python":
        results += check_syntax(code)
        results += check_logic(code)
    elif language in ["javascript", "general"]:
        results += check_logic(code)

    seen = set()
    unique_results = []
    for issue in results:
        key = (issue["id"], issue.get("line"))
        if key not in seen:
            seen.add(key)
            unique_results.append(issue)
    results = unique_results

    return jsonify({
        "language": language,
        "issues": results,
        "total": len(results)
    })

if __name__ == "__main__":
    app.run(debug=False)