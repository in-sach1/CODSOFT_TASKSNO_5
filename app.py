import os
import sqlite3
import uuid
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO

from cryptography.fernet import Fernet, InvalidToken
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired,
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)
from werkzeug.utils import secure_filename


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DATABASE = os.path.join(
    BASE_DIR,
    "files.db"
)

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

KEY_FILE = os.path.join(
    BASE_DIR,
    "secret.key"
)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

ALLOWED_EXTENSIONS = {
    "txt",
    "pdf",
    "png",
    "jpg",
    "jpeg",
    "csv",
    "docx",
    "xlsx",
}


# Create upload directory if necessary
os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


# ------------------------------------------------------------
# Secret key for Flask sessions
# ------------------------------------------------------------

FLASK_SECRET_KEY = os.environ.get(
    "FLASK_SECRET_KEY"
)

if not FLASK_SECRET_KEY:
    # Development fallback.
    # For production, use an environment variable.
    FLASK_SECRET_KEY = (
        "change-this-development-secret-key"
    )

app.secret_key = FLASK_SECRET_KEY


# Serializer used for temporary download links
serializer = URLSafeTimedSerializer(
    app.secret_key
)


# ============================================================
# ENCRYPTION
# ============================================================

def load_encryption_key():
    """
    Load the Fernet encryption key.

    If it does not exist, create one.
    """

    if not os.path.exists(KEY_FILE):

        key = Fernet.generate_key()

        with open(
            KEY_FILE,
            "wb"
        ) as key_file:

            key_file.write(key)

        return key

    with open(
        KEY_FILE,
        "rb"
    ) as key_file:

        return key_file.read()


ENCRYPTION_KEY = load_encryption_key()

cipher = Fernet(
    ENCRYPTION_KEY
)


# ============================================================
# DATABASE
# ============================================================

def get_db_connection():

    connection = sqlite3.connect(
        DATABASE
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    connection = get_db_connection()

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            stored_name TEXT UNIQUE NOT NULL,
            uploaded_by INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (uploaded_by)
            REFERENCES users(id)
        )
        """
    )

    connection.commit()

    connection.close()


initialize_database()


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(
            ".",
            1
        )[1].lower()
        in ALLOWED_EXTENSIONS
    )


def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:

            flash(
                "Please log in to continue.",
                "warning"
            )

            return redirect(
                url_for("login")
            )

        return function(
            *args,
            **kwargs
        )

    return wrapper


def user_can_access(file_record):

    # Administrators can access all files
    if session.get("role") == "admin":
        return True

    # Normal users can only access their own files
    return (
        file_record["uploaded_by"]
        == session.get("user_id")
    )


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if "user_id" in session:

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Username and password are required.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        if len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        password_hash = generate_password_hash(
            password
        )

        connection = get_db_connection()

        try:

            connection.execute(
                """
                INSERT INTO users
                (
                    username,
                    password,
                    role,
                    created_at
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    username,
                    password_hash,
                    "user",
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                )
            )

            connection.commit()

        except sqlite3.IntegrityError:

            connection.close()

            flash(
                "Username already exists.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        connection.close()

        flash(
            "Registration successful. Please log in.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        connection = get_db_connection()

        user = connection.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        if (
            user
            and
            check_password_hash(
                user["password"],
                password
            )
        ):

            session.clear()

            session["user_id"] = user["id"]

            session["username"] = (
                user["username"]
            )

            session["role"] = user["role"]

            flash(
                "Login successful.",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid username or password.",
            "danger"
        )

    return render_template(
        "login.html"
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
@login_required
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    connection = get_db_connection()

    if session.get("role") == "admin":

        files = connection.execute(
            """
            SELECT
                files.*,
                users.username
            FROM files
            JOIN users
            ON files.uploaded_by = users.id
            ORDER BY files.id DESC
            """
        ).fetchall()

    else:

        files = connection.execute(
            """
            SELECT
                files.*,
                users.username
            FROM files
            JOIN users
            ON files.uploaded_by = users.id
            WHERE files.uploaded_by = ?
            ORDER BY files.id DESC
            """,
            (
                session["user_id"],
            )
        ).fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        files=files
    )


# ============================================================
# UPLOAD FILE
# ============================================================

@app.route(
    "/upload",
    methods=["POST"]
)
@login_required
def upload_file():

    if "file" not in request.files:

        flash(
            "No file selected.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":

        flash(
            "No file selected.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    if not allowed_file(
        uploaded_file.filename
    ):

        flash(
            "File type is not allowed.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    original_name = secure_filename(
        uploaded_file.filename
    )

    if not original_name:

        flash(
            "Invalid filename.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    file_data = uploaded_file.read()

    # Encrypt file BEFORE storing it
    encrypted_data = cipher.encrypt(
        file_data
    )

    # Generate random storage filename
    stored_name = (
        uuid.uuid4().hex
        + ".encrypted"
    )

    storage_path = os.path.join(
        UPLOAD_FOLDER,
        stored_name
    )

    with open(
        storage_path,
        "wb"
    ) as encrypted_file:

        encrypted_file.write(
            encrypted_data
        )

    connection = get_db_connection()

    connection.execute(
        """
        INSERT INTO files
        (
            original_name,
            stored_name,
            uploaded_by,
            uploaded_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            original_name,
            stored_name,
            session["user_id"],
            datetime.now(
                timezone.utc
            ).isoformat()
        )
    )

    connection.commit()

    connection.close()

    flash(
        "File encrypted and uploaded successfully.",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# DOWNLOAD FILE
# ============================================================

@app.route(
    "/download/<int:file_id>"
)
@login_required
def download_file(file_id):

    connection = get_db_connection()

    file_record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    ).fetchone()

    connection.close()

    if not file_record:

        flash(
            "File not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    if not user_can_access(
        file_record
    ):

        flash(
            "You do not have permission to access this file.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    return send_decrypted_file(
        file_record
    )


# ============================================================
# DECRYPT AND SEND FILE
# ============================================================

def send_decrypted_file(file_record):

    file_path = os.path.join(
        UPLOAD_FOLDER,
        file_record["stored_name"]
    )

    if not os.path.exists(
        file_path
    ):

        flash(
            "Encrypted file is missing.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    with open(
        file_path,
        "rb"
    ) as encrypted_file:

        encrypted_data = (
            encrypted_file.read()
        )

    try:

        decrypted_data = cipher.decrypt(
            encrypted_data
        )

    except InvalidToken:

        flash(
            "Unable to decrypt file.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file_record[
            "original_name"
        ]
    )


# ============================================================
# GENERATE TEMPORARY DOWNLOAD LINK
# ============================================================

@app.route(
    "/generate-link/<int:file_id>"
)
@login_required
def generate_link(file_id):

    connection = get_db_connection()

    file_record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    ).fetchone()

    connection.close()

    if not file_record:

        flash(
            "File not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    if not user_can_access(
        file_record
    ):

        flash(
            "Access denied.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    token = serializer.dumps(
        {
            "file_id": file_id,
            "owner_id": file_record[
                "uploaded_by"
            ]
        },
        salt="temporary-download"
    )

    temporary_url = url_for(
        "temporary_download",
        token=token,
        _external=True
    )

    flash(
        (
            "Temporary link valid for 5 minutes: "
            + temporary_url
        ),
        "info"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# TEMPORARY DOWNLOAD
# ============================================================

@app.route(
    "/shared/<token>"
)
def temporary_download(token):

    try:

        data = serializer.loads(
            token,
            salt="temporary-download",
            max_age=300
        )

    except SignatureExpired:

        return (
            "This download link has expired.",
            410
        )

    except BadSignature:

        return (
            "Invalid download link.",
            403
        )

    file_id = data.get(
        "file_id"
    )

    owner_id = data.get(
        "owner_id"
    )

    connection = get_db_connection()

    file_record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        AND uploaded_by = ?
        """,
        (
            file_id,
            owner_id
        )
    ).fetchone()

    connection.close()

    if not file_record:

        return (
            "File not found.",
            404
        )

    return send_decrypted_file(
        file_record
    )


# ============================================================
# DELETE FILE
# ============================================================

@app.route(
    "/delete/<int:file_id>",
    methods=["POST"]
)
@login_required
def delete_file(file_id):

    connection = get_db_connection()

    file_record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    ).fetchone()

    if not file_record:

        connection.close()

        flash(
            "File not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    if not user_can_access(
        file_record
    ):

        connection.close()

        flash(
            "Access denied.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    file_path = os.path.join(
        UPLOAD_FOLDER,
        file_record["stored_name"]
    )

    if os.path.exists(
        file_path
    ):

        os.remove(
            file_path
        )

    connection.execute(
        """
        DELETE FROM files
        WHERE id = ?
        """,
        (file_id,)
    )

    connection.commit()

    connection.close()

    flash(
        "File deleted successfully.",
        "success"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# FILE SIZE ERROR
# ============================================================

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File is too large. Maximum size is 10 MB.",
        "danger"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5001,
        debug=False
    )