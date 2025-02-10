import sqlite3
import zipfile
import os
import ast
import pyotp.totp
import bcrypt
import random
from datetime import datetime, timedelta
from flask import render_template, request, flash, send_file, redirect
from flask_login import UserMixin, LoginManager, login_user, current_user, logout_user, login_required
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask
import re
from collections import Counter
import math
import markdown
import html_sanitizer
import qrcode

DATABASE = "notes.db"
app = Flask(__name__)
app.config['SECRET_KEY'] = 'qwertyuiojhgfdscvbnm'
app.config['DATABASE'] = os.path.join(app.instance_path, 'notes.db')

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    pass

@login_manager.user_loader
def user_loader(username):
    if username is None:
        return None

    con = sqlite3.connect(DATABASE)
    cursor = con.cursor()
    cursor.execute("SELECT username, password_hash FROM users WHERE username = (?) ", (username,))
    row = cursor.fetchone()
    con.commit()
    con.close()

    try:
        username, password = row
    except:
        return None

    user = User()
    user.id = username
    user.password = password
    return user

@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = user_loader(username)
    return user


failed_logins = {}
@app.route('/', methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = user_loader(username)

        if user is None:
            flash("Bad credentials", category="error")
            return render_template("login.html")

        now = datetime.now()
        user_attempts = failed_logins.get(username, {"attempts": 0, "block_until": None})
        if user_attempts["block_until"] and user_attempts["block_until"] > now:
            flash("Account locked. Try again later.", category="error")
            return render_template("login.html")

        if bcrypt.checkpw(password.encode(), user.password):
            login_user(user)
            return redirect("/login2fa")
        else:
            attempts = user_attempts["attempts"] + 1
            block_until = None
            if attempts >= 3:
                block_until = now + timedelta(minutes=10)
            failed_logins[username] = {"attempts": attempts, "block_until": block_until}
            if block_until:
                flash("Account locked. Try again later.", category="error")
                return render_template("login.html")
            flash("Bad credentials", category="error")
            return render_template("login.html")

@app.route('/login2fa', methods=["GET", "POST"])
def login2fa():
    if request.method == "GET":
        return render_template("login2fa.html")

    if request.method == "POST":
        code = request.form.get("code")
        username = current_user.get_id()

        db = sqlite3.connect(DATABASE)
        sql = db.cursor()
        sql.execute(f"SELECT token FROM users WHERE username = '{username}'")
        token = sql.fetchall()
        match = re.search(r"secret=([A-Z2-7]+)", token[0][0])
        if match:
            token = match.group(1)
        totp = pyotp.TOTP(token)
        if totp.verify(code):
            return redirect("/home")
        return render_template("login2fa.html")


def validate_username(username):
    if len(username) < 3:
        return False
    return True

def entropy(password, threshold=40):
    length = len(password)
    char_counts = Counter(password)
    entropy = -sum((count / length) * math.log2(count / length) for count in char_counts.values())
    total_entropy = entropy * length
    return total_entropy >= threshold
def validate_password(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$'
    return re.match(pattern, password) and entropy(password)

def confirm_password(password1, password2):
    if password1 != password2:
        return False
    return True

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem



@app.route('/logout')
def logout():
    logout_user()
    return redirect("/")

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password1 = request.form.get("password")
        password_hash = bcrypt.hashpw(password1.encode(), bcrypt.gensalt())
        password2 = request.form.get("password_confirm")


        if not (validate_username(username) and validate_password(password1) and confirm_password(password1, password2)):
            flash("Invalid input! Make sure your username is unique and your password is strong enough.", category="error")
            return render_template("register.html")

        elif validate_username(username) and validate_password(password1) and confirm_password(password1, password2):
            totp = pyotp.TOTP(pyotp.random_base32())
            qr_uri = totp.provisioning_uri(name=username, issuer_name="notes")

            qr_img = qrcode.make(qr_uri)
            private_key, public_key = generate_key_pair()
            base_path = "/tmp"
            private_key_path = os.path.join(base_path, f"{username}_private_key.pem")
            qr_code_path = os.path.join(base_path, f"{username}_qr_2fa.png")
            zip_path = os.path.join(base_path, f"{username}_secret.zip")

            with open(private_key_path, "wb") as f:
                f.write(private_key)

            qr_img.save(qr_code_path)

            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.write(private_key_path, os.path.basename(private_key_path))
                zip_file.write(qr_code_path, os.path.basename(qr_code_path))

            os.remove(private_key_path)
            os.remove(qr_code_path)

            con = sqlite3.connect(DATABASE)
            cursor = con.cursor()
            cursor.execute("INSERT INTO users (username, password_hash, public_key, token) VALUES (?, ?, ?, ?);", (username, password_hash, public_key.decode("utf-8"), qr_uri))
            con.commit()
            con.close()

            return send_file(zip_path, as_attachment=True, download_name=f"{username}_secret.zip",
                                 mimetype="application/zip")
    return render_template("register.html")




@app.route("/home", methods=['GET', 'POST'])
@login_required
def hello():
    if request.method == 'GET':
        username = current_user.id

        con = sqlite3.connect(DATABASE)
        cursor = con.cursor()
        cursor.execute(f"SELECT * FROM notes WHERE is_public = 1;")
        notes_public = cursor.fetchall()

        cursor.execute(f"SELECT * FROM notes WHERE ',' || REPLACE(shared_with, ' ', '') || ',' LIKE ?;", (f"%,{username},%",))
        notes_shared = cursor.fetchall()
        con.commit()
        con.close()

        return render_template("home.html", username=username, notes_public=notes_public, notes_shared=notes_shared)

def derive_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())
def encrypt_note(content_plain, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    content_encrypted = aesgcm.encrypt(nonce, content_plain.encode(), None)
    result_tuple = (salt.hex(), nonce.hex(), content_encrypted.hex())
    return str(result_tuple)

def decrypt_note(salt, nonce, content_encrypted, password):
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    content_plain = aesgcm.decrypt(nonce, content_encrypted, None)
    return content_plain.decode()

@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "GET":
        return render_template("create.html")
    if request.method == "POST":
        note_title = request.form.get("title")
        note_content = request.form.get("content")
        is_public = 1 if request.form.get("public") else 0
        shared_with = request.form.get("users")
        password = request.form.get("password")
        is_encrypted = 1 if request.form.get("encrypt") and len(password) > 0 else 0
        password_hash = None
        owner_username = current_user.id
        random_id = random.randint(1e18, 1e19)
        private_key_pem = request.files.get("private-key")
        if private_key_pem and private_key_pem.filename:
            private_key_content = private_key_pem.read().decode("utf-8")
            private_key = serialization.load_pem_private_key(private_key_content.encode(), password=None)
            signature = private_key.sign(note_content.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        else:
            signature = None

        if is_encrypted:
            if password:
                if validate_password(password):
                    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                    note_content = encrypt_note(note_content, password)
                else:
                    flash("Note creation failed: password too weak")
                    return render_template("create.html")

        con = sqlite3.connect(DATABASE)
        cursor = con.cursor()
        cursor.execute("""
        INSERT INTO notes (title, content, is_public, shared_with, is_encrypted, password_hash, owner_username, signature, random_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) """, (note_title, note_content, is_public, shared_with, is_encrypted, password_hash, owner_username, signature, random_id))
        con.commit()
        con.close()
        flash("Note added", category="success")
        return render_template("create.html")

def render(note):
    sanitizer_settings = dict(html_sanitizer.sanitizer.DEFAULT_SETTINGS)
    sanitizer_settings["tags"].add("img")
    sanitizer_settings["empty"].add("img")
    sanitizer_settings["attributes"].update({"img": ("src", )})
    sanitizer = html_sanitizer.Sanitizer(settings=sanitizer_settings)
    rendered = markdown.markdown(note)
    rendered = sanitizer.sanitize(rendered)
    return rendered

def get_note_by_id(note_id, unlocked=False, password=None):
    con = sqlite3.connect(DATABASE)
    cursor = con.cursor()
    cursor.execute(f"SELECT * FROM notes WHERE random_id = ?", (note_id,))
    note = cursor.fetchone()
    con.commit()
    con.close()

    if note:
        if note[5] == 1:
            if unlocked:
                note_tuple = ast.literal_eval(note[2])
                salt = bytes.fromhex(note_tuple[0])
                nonce = bytes.fromhex(note_tuple[1])
                content_encrypted = bytes.fromhex(note_tuple[2])
                note_content = decrypt_note(salt, nonce, content_encrypted, password)
                note_rendered = render(note_content)
            else:
                return render_template("enter_password.html", note_id=note[9])
        else:
            note_content = note[2]
            note_rendered = render(note[2])

        author_name = note[7]
        signature = note[8]
        if signature is None:
            signature_status = "(author unverified: no signature)"
        else:
            con = sqlite3.connect(DATABASE)
            cursor = con.cursor()
            cursor.execute(f"SELECT public_key from users WHERE username = ?", (author_name,))
            public_key_pem = cursor.fetchone()[0]
            con.commit()
            con.close()

            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            try:
                public_key.verify(signature, note_content.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                signature_status = "(author verified with a signature)"
            except Exception:
                signature_status = "(author unverified: wrong signature!)"

        return render_template("note.html", title=note[1], note_rendered=note_rendered, author_name=author_name, signature_status=signature_status)
    else:
        return "Note not found", 404


failed_unlocks = {}
@app.route('/note/<int:note_id>', methods=["GET", "POST"])
def show_note_by_id(note_id):
    if request.method == "POST":
        password = request.form["password"]

        con = sqlite3.connect(DATABASE)
        cursor = con.cursor()
        cursor.execute(f"SELECT password_hash FROM notes WHERE random_id = ?", (note_id,))
        password_hash = cursor.fetchone()[0]
        con.commit()
        con.close()

        now = datetime.now()
        unlock_attempts = failed_unlocks.get(note_id, {"attempts": 0, "block_until": None})
        if unlock_attempts["block_until"] and unlock_attempts["block_until"] > now:
            flash("Too many attempts. Try again later.", category="error", note_id=note_id)
            return render_template("enter_password.html")

        if bcrypt.checkpw(password.encode(), password_hash):
            return get_note_by_id(note_id, unlocked=True, password=password)
        else:
            attempts = unlock_attempts["attempts"] + 1
            block_until = None
            if attempts >= 3:
                block_until = now + timedelta(minutes=10)
            failed_unlocks[note_id] = {"attempts": attempts, "block_until": block_until}
            if block_until:
                flash("Too many attempts. Try again later.", category="error")
                return render_template("enter_password.html", note_id=note_id)
            flash("Password incorrect", category="error")
            return render_template("enter_password.html", note_id=note_id)

    return get_note_by_id(note_id)


if __name__=='__main__':
    app.run()

