from flask import Flask, json, jsonify, request
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import uuid
import time
import sqlite3
import base64
import os

app = Flask(__name__)

database = 'totally_not_my_privateKeys.db'

# Initializes the database for the keys
def init_db():
    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()

        # Creates the key table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                private_key BLOB NOT NULL,
                expiry TIMESTAMP NOT NULL
            )
        ''')

        # Creates the user table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP      
            )
        ''')

        # Creates the authentication logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')    

        conn.commit()

init_db()
expiry_duration = timedelta(minutes=30)

# Handles authentication logs
def log_auth_request(user_id, request_ip):
    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)
        ''', (request_ip, user_id))
        conn.commit()


# argon2 hashing config
ph = PasswordHasher(
    time_cost=2,
    memory_cost=102400,
    parallelism=8,
    hash_len=32,
    salt_len=16
)

# Generates a random password
def generate_password():
    return str(uuid.uuid64())

# Hashes user passwords
def hash_password(password):
    return ph.hash(password)

# Handles new user registration
def register_user(username, password, email):
    hashed_pass = hash_password(password)
    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)
                ''', (username, hashed_pass, email))
            conn.commit()
            return {"message": "User registered successfully"}, 201
        except sqlite3.IntegrityError as e:
            return {"error": "Username or email already exists", "details": str(e)}, 400

# Fetches the symmetric key
def get_symm_key():
    key = os.environ.get('NOT_MY_KEY')
    if key is None or len(key) != 32:
        raise ValueError("Encryption key must be set and 32-bytes long")
    return key.encode()

# Encrypts the data using an AES cipher in CFB mode
def encrypt_data(data):
    key = get_symm_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()

# Decrypts encrypted data
def decrypt_data(encrypted_data):
    key = get_symm_key()
    encrypted_data = base64.b64decode(encrypted_data)
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data.decode()

# Generates an RSA key
def generate_key():
    key = jwk.JWK.generate(kty = 'RSA', size=2048)
    return key

# Stores a private key into the SQLite database
def store_key(kid, private_key, expiry):
    encrypted_priv_key = encrypt_data(private_key.export_to_pem(private_key=True).decode())
    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO keys (kid, private_key, expiry) VALUES (?, ?, ?)
        ''', (kid, encrypted_priv_key, expiry))
        conn.commit()

# Retrieves a private key from the SQLite database
def get_key():
    curr_time = datetime.now(datetime.timezone.utc)

    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT kid, private_key, expiry FROM keys WHERE expiry > ?', (curr_time,))
        row = cursor.fetchone()

    if row is None:
        private_key = generate_key()
        kid = (str(int(time.time())))
        expire_time = curr_time + expiry_duration

        store_key(kid, private_key, expire_time)
        return kid, {'key': private_key, 'expiry': expire_time}
    
    kid, encrypted_priv_key, expiry = row
    priv_key_str = decrypt_data(encrypted_priv_key)
    private_key = jwk.JWK.from_pem(priv_key_str.encode())

    return kid, {'key': private_key, 'expiry': expiry}

# Handles the jwks keys
@app.route('/.well-known/jwks.json')
def jwks():
    keys = []

    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT kid, private_key FROM keys')

        for kid, private_key_str in cursor.fetchall():
            private_key = jwk.JWK.from_pem(decrypt_data(private_key_str).encode())
            jwk_public = json.loads(private_key.export_public(as_dict=True))
            jwk_public['kid'] = kid
            keys.append(jwk_public)

    jwks = {"keys": keys}
    return jsonify(jwks)

# Generates the JWT
def generate_jwt(private_key, kid, expired=False):
    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + (60 if expired else 600)
    }

    token = jwt.JWT(header={"alg": "RS256", "kid": kid}, claims=payload)
    token.make_signed_token(private_key)
    return token.serialize()

# Handles the authentication of the keys/tokens
@app.route('/auth', methods=['POST'])
def authenticate():
    use_expired_key = request.args.get('use_expired_key', 'false').lower() == 'true'
    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username is required"}), 400

    request_ip = request.remote_addr
    user_id = None

    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user:
            user_id = user[0]

    log_auth_request(user_id, request_ip)

    if use_expired_key:
        with sqlite3.connect(database) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT kid, private_key FROM keys WHERE expiry <= ?', (datetime.now(datetime.utc.now),))
            expired_row = cursor.fetchone()
            if expired_row:
                kid, private_key_str = expired_row
                key_data = {'key': jwk.JWK.from_pem(private_key_str.encode())}
            else:
                return jsonify({"message": "No expired keys available"}), 400
    else:
        kid, key_data = get_key()
    
    token = generate_jwt(key_data['key'], kid, expired=use_expired_key)
    return jsonify({"token": token})

# Verifies the tokens
@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    token = data.get("token")

    jwks_response = jwks()
    jwks_data = jwks_response.get_json()

    try:
        decoded_token = jwt.JWT(jwt=token)
        kid = decoded_token.token.jose_header['kid']

        key_data = next((k for k in jwks_data['keys'] if k['kid'] == kid), None)
        if not key_data:
            return jsonify({"message": "Invalid kid"}), 400

        public_key = jwk.JWK.from_json(json.dumps(key_data))
        decoded_token = jwt.JWT(jwt=token, key=public_key)
        return jsonify({"message": "Token is valid", "claims": json.loads(decoded_token.claims)})
    
    except jwt.JWTExpired:
        return jsonify({"message": "Token has expired"}), 401
    except Exception as e:
        return jsonify({"message": str(e)}), 400

# User registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")

    if not username or not email:
        return jsonify({"error": "Username and email are required"})

    password = generate_password()
    
    response, status_code = register_user(username, password, email)
    if status_code == 201:
        return jsonify({"password": password}), status_code

    return jsonify(response), status_code

# Default homepage for the website
@app.route('/')
def home():
    return 'Welcome to my website!'

# Configures the way it runs (I had issues where the port was already being used)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)