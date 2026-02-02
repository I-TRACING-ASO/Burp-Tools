import time
import json
import base64

# List of allowed domains for JWT authentication
SCOPE = ["api.example.com", "backend.example.com"]

# Dictionary to store JWTs by color
jwt_store = {"blue": "", "green": ""}
credentials_store = {"blue": {"client_id": "", "client_secret": ""}, "green": {"client_id": "", "client_secret": ""}}

TOKEN_BASE = "https://example.com"
TOKEN_HOST = "example.com"
TOKEN_PATH = "/auth/realms/realm/protocol/openid-connect/token"
TOKEN_URL = "https://example.com/auth/realms/realm/protocol/openid-connect/token"
OID_SCOPE = "scope1%20scope2"

def is_domain_in_scope(request):
    """
    Checks if the request domain is in the allowed domains list.
    Returns True if allowed, False otherwise.
    """
    try:
        host = request.headerValue("Host")
        if not host:
            return False
        
        # Extract just the host without port
        host = host.split(':')[0]
        return host in SCOPE
    except Exception:
        return False

def parse_jwt_expiry(token):
    """
    Extracts the expiration date ('exp') from the JWT.
    Returns None if not found or if decoding error.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        data = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(data)
        
        return payload.get('exp')
    except Exception:
        return None

def is_jwt_valid(token):
    """
    Returns True if the JWT is not expired, False otherwise.
    """
    exp_ts = parse_jwt_expiry(token)
    if exp_ts is None:
        return False
    return exp_ts > time.time()

def fetch_new_jwt_for_color(color, request):
    """
    Fetches a new JWT via client_credentials flow (OAuth2).

    Returns:
        str -> access_token
        None -> if failed
    """

    creds = credentials_store.get(color)
    if not creds:
        print("[PyBurp] Unknown color: %s" % color)
        return None

    body = (
        "scope=%s&grant_type=client_credentials&client_id=%s&client_secret=%s"
        % (OID_SCOPE, creds["client_id"], creds["client_secret"])
    )

    raw_request = (
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Accept: application/json\r\n"
        "Content-Length: %d\r\n"
        "\r\n"
        "%s"
    ) % (TOKEN_PATH, TOKEN_HOST, len(body), body)

    try:
        req = httpRequest(
            httpService(TOKEN_BASE),
            raw_request
        )

        http_request_response = sendRequest(req)
        response = http_request_response.response()

        # Séparation headers/body
        body_part = response.bodyToString()

        payload = json.loads(body_part)
        token = payload.get("access_token")

        if not token:
            print("[PyBurp] access_token missing in response")
            return None

        return token

    except Exception as e:
        print("[PyBurp] JWT fetch failed: %s" % str(e))
        return None

def handleRequest(request, annotations):
    """
    PyBurp function called for each HTTP request.
    """
    try:
        # Check if the request domain is in the allowed list
        if not is_domain_in_scope(request):
            return request, annotations  # Domain not allowed, no modifications
        
        # Gets the value of the X-PwnFox-Color header if present
        color_header = request.headerValue("X-PwnFox-Color")
        if not color_header:
            return request, annotations  # No relevant header, no modifications
        
        color = color_header.strip()
        
        # Looks for an existing JWT for this color
        token = jwt_store.get(color)
        
        # Verifies JWT validity
        if token is None or not is_jwt_valid(token):
            # Either no token or expired → fetch a new JWT
            new_token = fetch_new_jwt_for_color(color, request)
            if new_token:
                jwt_store[color] = new_token
                token = new_token
            else:
                # No JWT retrieved → return request without modification
                return request, annotations
        
        # Adding header Authorization: Bearer <token>
        auth_header = "Bearer %s" % token
        modified_request = request.withHeader("Authorization", auth_header)
        
        return modified_request, annotations
    
    except Exception as e:
        print("[PyBurp] erreur handleRequest: %s" % e)
        return request, annotations
