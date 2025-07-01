# oauth_server.py

# --- Imports ---
import base64
import jwt
import time
import datetime
from functools import wraps
from flask import Flask, request, jsonify
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# --- Configuration for Testing ---
CLIENTS = {
    "testclient_id": {
        "client_secret": "testclient_secret",
        "allowed_scopes": ["read", "write", "admin:data", "no-scope-needed"]
    },
    "another_client": {
        "client_secret": "another_secret",
        "allowed_scopes": ["read"]
    }
}
JWT_SECRET_KEY = "your_super_secret_jwt_key_for_testing_only_make_it_long_and_random_in_prod"
TOKEN_EXPIRATION_SECONDS = 3600

# --- Flask App Initialization ---
# THIS LINE MUST BE AT THE TOP LEVEL OF THE FILE, OUTSIDE ANY `if __name__ == '__main__':` BLOCK
app = Flask(__name__)

# --- Helper Functions (These can be defined anywhere as long as they are callable by the routes) ---

def authenticate_client(req):
    # ... (your existing code for authenticate_client) ...
    auth_header = req.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        return None, "Missing or invalid Basic Auth header"

    try:
        encoded_credentials = auth_header.split(' ')[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
        client_id, client_secret = decoded_credentials.split(':', 1)
    except Exception:
        return None, "Error decoding Basic Auth header"

    client_info = CLIENTS.get(client_id)
    if client_info and client_info["client_secret"] == client_secret:
        return client_id, None
    return None, "Invalid client credentials"


def validate_scopes(requested_scopes_str, allowed_scopes):
    # ... (your existing code for validate_scopes) ...
    if not requested_scopes_str:
        return [], None

    requested_scopes = set(requested_scopes_str.split(' '))
    granted_scopes = [s for s in requested_scopes if s in allowed_scopes]

    if len(granted_scopes) != len(requested_scopes):
        return None, f"One or more requested scopes are invalid or not allowed: {requested_scopes_str}"
    return granted_scopes, None

def generate_access_token(client_id, scopes):
    # ... (your existing code for generate_access_token) ...
    payload = {
        "iss": "local-oauth-server",
        "aud": "your-resource-server",
        "sub": client_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRATION_SECONDS,
        "scope": " ".join(scopes)
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
    return token

def verify_access_token(req):
    # ... (your existing code for verify_access_token) ...
    auth_header = req.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, "Missing or invalid Bearer token"

    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError:
        return None, "Invalid token"
    except Exception as e:
        return None, f"Token verification failed: {str(e)}"

def require_scopes(required_scopes_list):
    # ... (your existing code for require_scopes) ...
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            payload, error = verify_access_token(request)
            if payload is None:
                return jsonify({"error": "unauthorized", "message": error}), 401

            token_scopes_str = payload.get('scope', '')
            token_scopes = set(token_scopes_str.split(' '))

            if not all(s in token_scopes for s in required_scopes_list):
                return jsonify({"error": "insufficient_scope", "message": f"Required scopes: {', '.join(required_scopes_list)}"}), 403

            request.token_payload = payload
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Endpoints ---
# These MUST use the 'app' defined at the top level
@app.route('/oauth/token', methods=['POST'])
def get_token():
    logging.info(f"Incoming /oauth/token request from: {request.remote_addr}")
    logging.info(f"Request Header: {request.headers}")
    logging.info(f"Request Args: {request.args}")
    # ... (your existing code for get_token) ...
    grant_type = request.form.get('grant_type')
    requested_scopes_str = request.form.get('scope', '')

    if grant_type != 'client_credentials':
        return jsonify({"error": "unsupported_grant_type", "message": "Only 'client_credentials' grant type is supported"}), 400

    client_id, auth_error = authenticate_client(request)
    if client_id is None:
        return jsonify({"error": "invalid_client", "message": auth_error}), 401

    client_info = CLIENTS.get(client_id)
    client_allowed_scopes = client_info["allowed_scopes"]

    granted_scopes, scope_error = validate_scopes(requested_scopes_str, client_allowed_scopes)

    if granted_scopes is None:
        return jsonify({"error": "invalid_scope", "message": scope_error}), 400

    access_token = generate_access_token(client_id, granted_scopes)

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_EXPIRATION_SECONDS,
        "scope": " ".join(granted_scopes)
    }), 200

@app.route('/protected', methods=['GET'])
@require_scopes(['read'])
def protected_resource():
    # ... (your existing code for protected_resource) ...
    client_id = request.token_payload.get('sub')
    return jsonify({"message": f"Hello, {client_id}! You accessed a protected resource with 'read' scope."}), 200

@app.route('/protected/admin', methods=['GET']) # Ensure this method matches your Postman request (GET/POST)
@require_scopes(['admin:data', 'write'])
def protected_admin_resource():
    # ... (your existing code for protected_admin_resource) ...
    client_id = request.token_payload.get('sub')
    return jsonify({"message": f"Hello, {client_id}! You performed an admin action."}), 200

@app.route('/protected/no-scope', methods=['GET'])
@require_scopes([])
def protected_no_scope_resource():
    # ... (your existing code for protected_no_scope_resource) ...
    client_id = request.token_payload.get('sub')
    return jsonify({"message": f"Hello, {client_id}! You accessed a protected resource requiring just a valid token."}), 200


# --- OPTIONAL: For very basic local development testing only ---
# This block is ignored by Gunicorn when deployed.
if __name__ == '__main__':
    print(f"Local OAuth Server (Development Mode) starting...")
    print(f"Client Credentials: {CLIENTS}")
    print(f"JWT Secret: {JWT_SECRET_KEY}")
    # Run the Flask development server, binding to 0.0.0.0 for external access
    app.run(host='0.0.0.0', port=5000, debug=True)
