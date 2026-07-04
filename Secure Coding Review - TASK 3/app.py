"""
VULNERABLE SAMPLE APP - Notes & Login System
For educational security-audit purposes only.
This code intentionally contains common vulnerabilities.
DO NOT deploy this anywhere.
"""

from flask import Flask, request, render_template_string, redirect, g
import sqlite3
import hashlib
import os

app = Flask(__name__)

# --- FINDING 1: Hardcoded secret key in source code ---
app.secret_key = "sk_live_9a8f7d6e5c4b3a2919283746abcdef0"

DB_PATH = "notes.db"


def get_db():
    db = sqlite3.connect(DB_PATH)
    return db


def init_db():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users
                  (id INTEGER PRIMARY KEY, username TEXT, password TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS notes
                  (id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT)""")
    db.commit()
    db.close()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # --- FINDING 2: Weak password hashing (MD5, no salt) ---
    hashed = hashlib.md5(password.encode()).hexdigest()

    db = get_db()
    # --- FINDING 3: SQL Injection via string formatting ---
    query = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, hashed)
    db.execute(query)
    db.commit()
    db.close()
    return "Registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    hashed = hashlib.md5(password.encode()).hexdigest()

    db = get_db()
    # --- FINDING 3 (continued): SQL Injection via string concatenation ---
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hashed + "'"
    cursor = db.execute(query)
    user = cursor.fetchone()
    db.close()

    if user:
        return redirect("/notes?user_id=" + str(user[0]))
    return "Invalid credentials"


@app.route("/notes")
def notes():
    # --- FINDING 4: Broken access control (no auth/session check, IDOR) ---
    user_id = request.args.get("user_id")
    db = get_db()
    query = "SELECT * FROM notes WHERE user_id = " + user_id  # SQLi + IDOR combined
    cursor = db.execute(query)
    rows = cursor.fetchall()
    db.close()

    content = "<h1>Your Notes</h1>"
    for row in rows:
        content += "<p>" + row[2] + "</p>"
    return content


@app.route("/add_note", methods=["POST"])
def add_note():
    user_id = request.form["user_id"]
    note = request.form["note"]

    db = get_db()
    db.execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", (user_id, note))
    db.commit()
    db.close()

    # --- FINDING 5: Reflected XSS - user input rendered unescaped ---
    template = "<p>Note added: " + note + "</p>"
    return render_template_string(template)


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    # --- FINDING 6: Unrestricted file upload - no type/size/extension validation ---
    save_path = os.path.join("uploads", file.filename)
    file.save(save_path)
    return "Uploaded"


if __name__ == "__main__":
    init_db()
    # --- FINDING 7: Debug mode enabled + bound to all interfaces in "production" ---
    app.run(host="0.0.0.0", debug=True)
