# CodeGuard AI

CodeGuard AI is a free and open source code analyzer that detects 
security vulnerabilities, syntax errors, logic bugs, and bad practices 
in your code. It does not just find the problem, it explains why it 
is dangerous and shows you exactly how to fix it.

Built for FOSS Hack 2026 by Chennuru Pushpanjali.


## The Problem

Developers today rely heavily on AI tools like ChatGPT and GitHub 
Copilot to generate code. But AI-generated code often contains serious 
issues that beginners do not notice. There is no free open source tool 
that catches security issues, syntax errors, and logic bugs all in one 
place and actually teaches you how to fix them. CodeGuard does that.


## What It Detects

Security issues like SQL injection, hardcoded passwords, dangerous 
eval() usage, and XSS vulnerabilities. Logic bugs like infinite loops, 
division by zero, and missing input validation. Syntax errors like 
missing colons in Python. Bad practices like leaving debug print 
statements in production code and using bare except clauses.


## How To Run

Make sure you have Python 3 installed. Then install the dependencies:

    pip install flask

Then run the backend:

    python app.py

Then open index.html in your browser.


## Tech Stack

Frontend is built with HTML, CSS and JavaScript. Backend is built 
with Python and Flask. Code analysis uses Python's built-in ast module.


## Project Structure

    codeguard-ai/
        index.html        - Frontend UI
        app.py            - Python backend
        requirements.txt  - Dependencies
        .gitignore        - Git ignore rules
        README.md         - Documentation


## License

MIT License. Free to use, modify and distribute.
```
