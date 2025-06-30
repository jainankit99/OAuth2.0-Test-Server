from flask import Flask, request, jsonify
import base64
import jwt
import time
import datetime
from functools import wraps

app = Flask(__name__)

# --- Configuration for Testing ---
# IMPORTANT: In a real app, never hardcode secrets like this!
# Use environment variables, a secret manager, or a database.
CLIENTS = {
    "testclient_id": {
        "client_secret": "testclient_secret",
        "allowed_scopes": ["read", "write", "admin:data"]
    },
    "another_client": {
        "client_secret": "another_secret",
        "allowed_scopes": ["read"]
    }
}

# JWT Secret Key (for signing tokens)
JWT_SECRET_KEY = "your_super_secret_jwt_key_for_testing_only"
TOKEN_EXPIRATION_SECONDS = 3600 # 1 hour

# --- Helper Functions ---

def authenticate_client(req):
    """
    Authenticates client using Basic Authorization header.
    Returns client_id if successful, None otherwise.
    """
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
    """
    Validates if all requested scopes are allowed for the client.
    Returns list of valid scopes or None if any requested scope is not allowed.
    """
    if not requested_scopes_str:
        return [], None # No scopes requested, return empty list of granted scopes

    requested_scopes = set(requested_scopes_str.split(' '))
    granted_scopes = [s for s in requested_scopes if s in allowed_scopes]

    if len(granted_scopes) != len(requested_scopes):
        # Some requested scopes were not allowed
        return None, f"One or more requested scopes are invalid or not allowed: {requested_scopes_str}"
    return granted_scopes, None

def generate_access_token(client_id, scopes):
    """
    Generates a simple JWT access token.
    """
    payload = {
        "iss": "local-oauth-server",
        "aud": "your-resource-server",
        "sub": client_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRATION_SECONDS,
        "scope": " ".join(scopes) # Space-separated string of granted scopes
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
    return token

def verify_access_token(req):
    """
    Verifies the Bearer token in the Authorization header.
    Returns decoded payload if valid, None otherwise.
    """
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

def require_scopes(required_scopes):
    """
    Decorator to protect resource endpoints with scope validation.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            payload, error = verify_access_token(request)
            if payload is None:
                return jsonify({"error": "unauthorized", "message": error}), 401

            token_scopes = payload.get('scope', '').split(' ')
            if not all(s in token_scopes for s in required_scopes):
                return jsonify({"error": "insufficient_scope", "message": f"Requires scopes: {required_scopes}"}), 403

            request.token_payload = payload # Attach payload to request for later use
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- Endpoints ---

@app.route('/oauth/token', methods=['POST'])
def get_token():
    """
    Handles OAuth 2.0 Client Credentials Grant requests.
    """
    grant_type = request.form.get('grant_type')
    requested_scopes_str = request.form.get('scope', '')

    if grant_type != 'client_credentials':
        return jsonify({"error": "unsupported_grant_type", "message": "Only 'client_credentials' grant type is supported"}), 400

    client_id, auth_error = authenticate_client(request)
    if client_id is None:
        return jsonify({"error": "invalid_client", "message": auth_error}), 401

    client_allowed_scopes = CLIENTS[client_id]["allowed_scopes"]
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
@require_scopes(['read']) # This resource requires 'read' scope
def protected_resource():
    """
    A sample protected resource requiring 'read' scope.
    """
    client_id = request.token_payload.get('sub')
    return jsonify({"message": f"Hello, {client_id}! You accessed a protected resource with 'read' scope."}), 200

@app.route('/protected/admin', methods=['POST'])
@require_scopes(['admin:data', 'write']) # This resource requires both 'admin:data' AND 'write' scopes
def protected_admin_resource():
    """
    A sample protected admin resource requiring 'admin:data' and 'write' scope.
    """
    client_id = request.token_payload.get('sub')
    return jsonify({"message": f"Hello, {client_id}! You performed an admin action."}), 200


if __name__ == '__main__':
    print(f"Local OAuth Server started at http://127.0.0.1:5000")
    print(f"Client Credentials: {CLIENTS}")
    print(f"JWT Secret: {JWT_SECRET_KEY}")
    app.run(debug=True) # debug=True enables auto-reloading and better error messages
