import time
import json

# Configuration
# List of allowed domains for JWT authentication
SCOPE = ["api.example.com", "backend.example.com"]
# Name of the header indicating which JWT to use
HEADER_NAME = "X-PwnFox-Color"
# Dictionary storing client credentials for each account
CREDENTIALS_STORE = {"blue": {"client_id": "", "client_secret": ""}, "green": {"client_id": "", "client_secret": ""}}
# OAuth2 token endpoint URL
TOKEN_URL = "https://example.com/auth/realms/realm/protocol/openid-connect/token"
# OAuth2 scopes (URL-encoded, space-separated)
OID_SCOPE = "scope1%20scope2"

# Dictionary to store JWTs by color - only add valid accounts identifiers here
JWT_STORE = {"blue": "", "green": ""}

def is_domain_in_scope(request):
    """
    Checks if the request domain is in the allowed domains list.
    Returns True if allowed, False otherwise.
    """
    try:
        host = str(request.httpService().host())
        if not host:
            return False
        
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
        data = base64decode(payload_b64)
        payload = json.loads(data)
        
        return payload.get('exp')
    except Exception as e:
        print("[PyBurp] error JWT decode and/or exp extract: %s" % e)
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

    creds = CREDENTIALS_STORE.get(color)
    if not creds:
        print("[PyBurp] Unknown color: %s" % color)
        return None

    body = (
        "scope=%s&grant_type=client_credentials&client_id=%s&client_secret=%s"
        % (OID_SCOPE, creds["client_id"], creds["client_secret"])
    )

    try:
        req = (httpRequestFromUrl(TOKEN_URL)
               .withMethod("POST")
               .withHeader("Content-Type", "application/x-www-form-urlencoded")
               .withHeader("Accept", "application/json")
               .withBody(body))

        http_request_response = sendRequest(req)
        body_part = http_request_response.response().bodyToString()

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
    PyBurp function called for each intercepted HTTP request.
    """
    try:
        # Check if the request domain is in the scope
        if not is_domain_in_scope(request):
            return request, annotations  # Domain not in scope, no modifications
        
        # Gets the value of the "session" header if present
        color_header = request.headerValue(HEADER_NAME)
        if not color_header:
            return request, annotations  # No relevant header, no modifications
        
        color = color_header.strip()
        
        # Looks for an existing JWT for this color
        token = JWT_STORE.get(color)
        
        # Verifies JWT validity
        if token is None or not is_jwt_valid(token):
            # Either no token or expired → fetch a new JWT
            new_token = fetch_new_jwt_for_color(color, request)
            if new_token:
                JWT_STORE[color] = new_token
                token = new_token
            else:
                # No JWT retrieved → return request without modification
                return request, annotations
        
        # Adds the Authorization header: Bearer <token>
        auth_header = "Bearer %s" % token
        modified_request = request.withHeader("Authorization", auth_header)
        
        return modified_request, annotations
    
    except Exception as e:
        # In case of error, log and continue with the original request
        print("[PyBurp] error handleRequest: %s" % e)
        return request, annotations
