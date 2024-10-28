from flask import Flask, json, jsonify, request
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
import time
import sqlite3

app = Flask(__name__)

database = 'totally_not_my_privateKeys.db'

# Initializes the database for the keys
def init_db():
    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                private_key BLOB NOT NULL,
                expiry TIMESTAMP NOT NULL
            )
        ''')
        conn.commit()

init_db()
expiry_duration = timedelta(minutes=30)

# Generates an RSA key
def generate_key():
    key = jwk.JWK.generate(kty = 'RSA', size=2048)
    return key

# Stores a private key into the SQLite database
def store_key(kid, private_key, expiry):
    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO keys (kid, private_key, expiry) VALUES (?, ?, ?)
        ''', (kid, private_key.export_to_pem(private_key=True).decode(), expiry))
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
    
    kid, private_key_str, expiry = row
    private_key = jwk.JWK.from_pem(private_key_str.encode())
    return kid, {'key': private_key, 'expiry': expire_time}

# Handles the jwks keys
@app.route('/.well-known/jwks.json')
def jwks():
    keys = []

    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT kid, private_key FROM keys')

        for kid, private_key_str in cursor.fetchall():
            jwk_public = jwk.JWK.from_pem(private_key_str.encode().export_public(as_dict=True))
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

# Default homepage for the website
@app.route('/')
def home():
    return 'Welcome to my website!'

# Configures the way it runs (I had issues where the port was already being used)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)