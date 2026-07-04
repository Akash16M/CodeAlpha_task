"""
REMEDIATED SAMPLE APP - Notes & Login System
Fixed version addressing all findings from SECURITY_REPORT.md
"""

from flask import Flask, request, session, redirect, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape
import sqlite3
import os
import secrets

app = Flask(__name__)

# FIX 1: Secret key loaded from environment, never committed to source.
# Set this in your shell/host before running: export SECRET_KEY="..."
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

DB_PATH = "notes.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "png", "jpg", "jpeg"}
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users
                  (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS notes
                  (id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT)""")
    db.commit()
    db.close()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        abort(400, "username and password required")

    # FIX 2: Strong, salted password hashing (Werkzeug -> PBKDF2/SHA256 by default)
    password_hash = generate_password_hash(password)

    db = get_db()
    try:
        # FIX 3: Parameterized query - no string concatenation/formatting
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return "Username already exists", 409
    finally:
        db.close()
    return "Registered", 201


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    db = get_db()
    # FIX 3 (continued): Parameterized query
    cursor = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    db.close()

    if user and check_password_hash(user["password_hash"], password):
        # FIX 4: Establish an authenticated session instead of trusting a URL param
        session.clear()
        session["user_id"] = user["id"]
        return redirect("/notes")

    return "Invalid credentials", 401


@app.route("/notes")
def notes():
    # FIX 4 (continued): Access control via server-side session, not client-supplied ID
    user_id = session.get("user_id")
    if user_id is None:
        return redirect("/login")

    db = get_db()
    cursor = db.execute("SELECT * FROM notes WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()
    db.close()

    # FIX 5: Escape user content before rendering to prevent stored/reflected XSS
    content = "<h1>Your Notes</h1>"
    for row in rows:
        content += f"<p>{escape(row['content'])}</p>"
    return content


@app.route("/add_note", methods=["POST"])
def add_note():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect("/login")

    note = request.form.get("note", "")

    db = get_db()
    db.execute("INSERT INTO notes (user_id, content) VALUES (?, ?)", (user_id, note))
    db.commit()
    db.close()

    # FIX 5 (continued): Escape before echoing back
    return f"<p>Note added: {escape(note)}</p>"


@app.route("/upload", methods=["POST"])
def upload():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect("/login")

    file = request.files.get("file")
    if not file or file.filename == "":
        abort(400, "no file provided")

    # FIX 6: Validate extension, sanitize filename, enforce size limit (via MAX_CONTENT_LENGTH)
    if not allowed_file(file.filename):
        abort(400, "file type not allowed")

    filename = secure_filename(file.filename)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)
    return "Uploaded", 201


if __name__ == "__main__":
    init_db()
    # FIX 7: Debug disabled, controlled via environment; bind to localhost by default
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="127.0.0.1", debug=debug_mode)
