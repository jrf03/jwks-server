from flask import Flask, json, jsonify, request
from jwcrypto import jwk, jwt
from datetime import datetime, timedelta
import time

app = Flask(__name__)

key_store = {}
expired_key_store = {}
expiry_duration = timedelta(minutes=30)

def generate_key():
    key = jwk.JWK.generate(kty = 'RSA', size=2048)
    return key

def get_key():
    curr_time = datetime.utcnow()
    if not key_store or curr_time > list(key_store.values())[0]['expiry']:
        private_key = generate_key()
        kid = str(int(time.time()))
        expire_time = curr_time + expiry_duration

        key_store.clear()
        key_store[kid] = {
            'key': private_key,
            'expiry': expire_time
        }
    
    kid = list(key_store.keys())[0]
    return kid, key_store[kid]

@app.route('/jwks.json')
def jwks():
    keys = []

    for kid, key_data in key_store.items():
        jwk_public = key_data['key'].export_public(as_dict=True)
        jwk_public['kid'] = kid
        keys.append(jwk_public)
    
    for kid, key_data in expired_key_store.items():
        jwk_public = key_data['key'].export_public(as_dict=True)
        jwk_public['kid'] = kid
        keys.append(jwk_public)

    jwks = {"keys": keys}
    return jsonify(jwks)

def generate_jwt(private_key, kid, expired=False):
    payload = {
        "sub": "user123",
        "iat": int(time.time()),
        "exp": int(time.time()) + (60 if expired else 600)
    }

    token = jwt.JWT(header={"alg": "RS256", "kid": kid}, claims=payload)
    token.make_signed_token(private_key)
    return token.serialize()

@app.route('/auth', methods=['POST'])
def authenticate():
    use_expired_key = request.args.get('use_expired_key', 'false').lower() == 'true'

    if use_expired_key and expired_key_store:
        kid, key_data = next(iter(expired_key_store.items()))
    else:
        kid, key_data = get_key()
    
    token = generate_jwt(key_data['key'], kid, expired=use_expired_key)
    return jsonify({"token": token})

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)